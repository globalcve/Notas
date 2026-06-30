//! Resumable, crash-safe in-place conversion (DECISIONS.md D-13).
//!
//! **Encrypt:** the container grows by two header regions; data migrates
//! end→start, each chunk shifted up by `HEADER_REGION` and encrypted. The
//! backup header (flagged CONVERTING) is written before any data moves, so a
//! crash always leaves either recoverable plaintext or a resumable journal.
//! Order safety: chunks are processed from the end, so a chunk's destination
//! only ever overwrites source bytes that have already been migrated.
//!
//! **Decrypt:** the inverse; data migrates start→end shifted down, the file
//! is truncated at the end, destroying the headers last.
//!
//! The journal stores only a watermark (no secrets) and is MACed with a
//! VMK-derived key, so it cannot be forged or replayed across volumes. Every
//! chunk is written and flushed *before* the journal that records it, and
//! re-processing the watermark chunk after a crash is idempotent by
//! construction (the source bytes of the watermark chunk are never touched
//! by later chunks).

use minicbor::{Decode, Encode};
use subtle::ConstantTimeEq;

use crate::cascade::{CascadeEngine, CascadeSpec};
use crate::error::{Error, Result};
use crate::kmac;
use crate::secret::Vmk;
use crate::HEADER_REGION;

/// Abstract block IO, implemented by the agent over a file/device FD and by
/// tests over memory with fault injection.
pub trait BlockIo {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()>;
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<()>;
    /// Durability barrier (fsync/FUA). Nothing written before this call may
    /// be reordered after it.
    fn flush(&mut self) -> Result<()>;
    fn set_len(&mut self, len: u64) -> Result<()>;
    fn len(&self) -> u64;
}

/// Durable watermark storage (the agent backs this with an fsynced sidecar
/// file next to the container).
pub trait JournalStore {
    fn save(&mut self, bytes: &[u8]) -> Result<()>;
    fn load(&mut self) -> Result<Option<Vec<u8>>>;
    fn clear(&mut self) -> Result<()>;
}

pub const DEFAULT_CHUNK: u32 = HEADER_REGION as u32; // 256 KiB

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Encrypt,
    Decrypt,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
struct Journal {
    #[n(0)]
    version: u16,
    #[cbor(n(1), with = "minicbor::bytes")]
    uuid: [u8; 16],
    /// 0 = encrypt, 1 = decrypt.
    #[n(2)]
    direction: u8,
    #[n(3)]
    chunk_size: u32,
    #[n(4)]
    data_len: u64,
    /// Encrypt: bytes NOT yet migrated (counts down).
    /// Decrypt: bytes already migrated (counts up).
    #[n(5)]
    watermark: u64,
    #[cbor(n(6), with = "minicbor::bytes")]
    mac: [u8; 32],
}

impl Journal {
    fn compute_mac(&self, vmk: &Vmk) -> [u8; 32] {
        let mut c = self.clone();
        c.mac = [0u8; 32];
        let bytes = minicbor::to_vec(&c).expect("infallible encode");
        let mut mac = [0u8; 32];
        kmac::kmac256(vmk.as_bytes(), kmac::L_JOURNAL, &bytes, &mut mac);
        mac
    }

    fn sealed(mut self, vmk: &Vmk) -> Vec<u8> {
        self.mac = self.compute_mac(vmk);
        minicbor::to_vec(&self).expect("infallible encode")
    }

    fn open(bytes: &[u8], vmk: &Vmk) -> Result<Self> {
        if bytes.len() > 4096 {
            return Err(Error::JournalCorrupt);
        }
        let j: Journal = minicbor::decode(bytes).map_err(|_| Error::JournalCorrupt)?;
        let mac = j.compute_mac(vmk);
        if !bool::from(mac.ct_eq(&j.mac)) {
            return Err(Error::JournalCorrupt);
        }
        Ok(j)
    }
}

fn check_params(sector_size: u32, data_len: u64, chunk_size: u32) -> Result<()> {
    if chunk_size == 0
        || chunk_size as u64 > HEADER_REGION
        || chunk_size % sector_size != 0
    {
        return Err(Error::InvalidParameter(
            "chunk size must be sector-aligned and <= header region",
        ));
    }
    if data_len == 0 || data_len % sector_size as u64 != 0 {
        return Err(Error::Geometry("data length not sector-aligned"));
    }
    Ok(())
}

/// Encrypt a plaintext container in place.
///
/// Preconditions (enforced): `io.len() == plain_len` on fresh start (the
/// converter extends it), `plain_len` sector-aligned. The caller provides the
/// three header-region images: the final front region, the CONVERTING-flagged
/// backup region (written first), and the final backup region.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_in_place(
    io: &mut dyn BlockIo,
    journal: &mut dyn JournalStore,
    vmk: &Vmk,
    spec: &CascadeSpec,
    sector_size: u32,
    plain_len: u64,
    uuid: [u8; 16],
    front_region: &[u8],
    backup_region_converting: &[u8],
    backup_region_final: &[u8],
    chunk_size: u32,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<()> {
    check_params(sector_size, plain_len, chunk_size)?;
    if front_region.len() != HEADER_REGION as usize
        || backup_region_converting.len() != HEADER_REGION as usize
        || backup_region_final.len() != HEADER_REGION as usize
    {
        return Err(Error::InvalidParameter("header region size"));
    }
    let engine = CascadeEngine::new(vmk, spec, sector_size as usize)?;
    let total_len = plain_len + 2 * HEADER_REGION;
    let backup_off = total_len - HEADER_REGION;

    // resume or fresh start
    let mut remaining = match journal.load()? {
        Some(bytes) => {
            let j = Journal::open(&bytes, vmk)?;
            if j.direction != 0
                || j.uuid != uuid
                || j.chunk_size != chunk_size
                || j.data_len != plain_len
            {
                return Err(Error::JournalCorrupt);
            }
            if io.len() != total_len {
                return Err(Error::JournalCorrupt);
            }
            j.watermark
        }
        None => {
            // io.len() == total_len with no journal means we crashed after
            // extending but before the first journal write: nothing has
            // migrated yet, so restarting from scratch is safe.
            if io.len() == plain_len {
                io.set_len(total_len)?;
            } else if io.len() != total_len {
                return Err(Error::Geometry("container length changed"));
            }
            // backup header with CONVERTING flag goes down first
            io.write_at(backup_off, backup_region_converting)?;
            io.flush()?;
            let j = Journal {
                version: 1,
                uuid,
                direction: 0,
                chunk_size,
                data_len: plain_len,
                watermark: plain_len,
                mac: [0; 32],
            };
            journal.save(&j.sealed(vmk))?;
            plain_len
        }
    };

    let mut buf = vec![0u8; chunk_size as usize];
    while remaining > 0 {
        let chunk = (chunk_size as u64).min(remaining);
        let src = remaining - chunk;
        let dst = src + HEADER_REGION;
        let cbuf = &mut buf[..chunk as usize];
        io.read_at(src, cbuf)?;
        let first_sector = src / sector_size as u64;
        engine.encrypt_range(first_sector, cbuf)?;
        io.write_at(dst, cbuf)?;
        io.flush()?;
        remaining = src;
        let j = Journal {
            version: 1,
            uuid,
            direction: 0,
            chunk_size,
            data_len: plain_len,
            watermark: remaining,
            mac: [0; 32],
        };
        journal.save(&j.sealed(vmk))?;
        progress(plain_len - remaining, plain_len);
    }

    // finalize: front header, then final backup header, then drop journal
    io.write_at(0, front_region)?;
    io.flush()?;
    io.write_at(backup_off, backup_region_final)?;
    io.flush()?;
    journal.clear()?;
    Ok(())
}

/// Decrypt an encrypted container in place, returning it to plaintext.
/// On completion the file is truncated to exactly the plaintext length.
#[allow(clippy::too_many_arguments)]
pub fn decrypt_in_place(
    io: &mut dyn BlockIo,
    journal: &mut dyn JournalStore,
    vmk: &Vmk,
    spec: &CascadeSpec,
    sector_size: u32,
    data_len: u64,
    uuid: [u8; 16],
    chunk_size: u32,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<()> {
    check_params(sector_size, data_len, chunk_size)?;
    let engine = CascadeEngine::new(vmk, spec, sector_size as usize)?;
    let total_len = data_len + 2 * HEADER_REGION;

    let mut done = match journal.load()? {
        Some(bytes) => {
            let j = Journal::open(&bytes, vmk)?;
            if j.direction != 1
                || j.uuid != uuid
                || j.chunk_size != chunk_size
                || j.data_len != data_len
            {
                return Err(Error::JournalCorrupt);
            }
            j.watermark
        }
        None => {
            if io.len() != total_len {
                return Err(Error::Geometry("container length unexpected"));
            }
            let j = Journal {
                version: 1,
                uuid,
                direction: 1,
                chunk_size,
                data_len,
                watermark: 0,
                mac: [0; 32],
            };
            journal.save(&j.sealed(vmk))?;
            0
        }
    };

    let mut buf = vec![0u8; chunk_size as usize];
    while done < data_len {
        let chunk = (chunk_size as u64).min(data_len - done);
        let src = HEADER_REGION + done;
        let dst = done;
        let cbuf = &mut buf[..chunk as usize];
        io.read_at(src, cbuf)?;
        let first_sector = done / sector_size as u64;
        engine.decrypt_range(first_sector, cbuf)?;
        io.write_at(dst, cbuf)?;
        io.flush()?;
        done += chunk;
        let j = Journal {
            version: 1,
            uuid,
            direction: 1,
            chunk_size,
            data_len,
            watermark: done,
            mac: [0; 32],
        };
        journal.save(&j.sealed(vmk))?;
        progress(done, data_len);
    }

    io.flush()?;
    io.set_len(data_len)?; // destroys the (stale) backup header region
    io.flush()?;
    journal.clear()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::CipherId;

    /// In-memory BlockIo with optional write-fault injection.
    struct MemIo {
        data: Vec<u8>,
        /// Fail (once) when this many write/flush ops have happened.
        fail_after: Option<u64>,
        ops: u64,
    }

    impl MemIo {
        fn new(data: Vec<u8>) -> Self {
            Self {
                data,
                fail_after: None,
                ops: 0,
            }
        }

        fn tick(&mut self) -> Result<()> {
            self.ops += 1;
            if let Some(n) = self.fail_after {
                if self.ops >= n {
                    self.fail_after = None; // fail once, then recover
                    return Err(Error::Io("injected fault"));
                }
            }
            Ok(())
        }
    }

    impl BlockIo for MemIo {
        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
            let o = offset as usize;
            buf.copy_from_slice(&self.data[o..o + buf.len()]);
            Ok(())
        }
        fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
            self.tick()?;
            let o = offset as usize;
            self.data[o..o + buf.len()].copy_from_slice(buf);
            Ok(())
        }
        fn flush(&mut self) -> Result<()> {
            self.tick()
        }
        fn set_len(&mut self, len: u64) -> Result<()> {
            self.data.resize(len as usize, 0);
            Ok(())
        }
        fn len(&self) -> u64 {
            self.data.len() as u64
        }
    }

    #[derive(Default)]
    struct MemJournal(Option<Vec<u8>>);

    impl JournalStore for MemJournal {
        fn save(&mut self, bytes: &[u8]) -> Result<()> {
            self.0 = Some(bytes.to_vec());
            Ok(())
        }
        fn load(&mut self) -> Result<Option<Vec<u8>>> {
            Ok(self.0.clone())
        }
        fn clear(&mut self) -> Result<()> {
            self.0 = None;
            Ok(())
        }
    }

    fn regions() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        // header-region stand-ins with distinct markers
        let mut front = vec![0u8; HEADER_REGION as usize];
        front[..5].copy_from_slice(b"FRONT");
        let mut conv = vec![0u8; HEADER_REGION as usize];
        conv[..4].copy_from_slice(b"CONV");
        let mut fin = vec![0u8; HEADER_REGION as usize];
        fin[..5].copy_from_slice(b"BFINL");
        (front, conv, fin)
    }

    fn spec() -> CascadeSpec {
        CascadeSpec::new(&[CipherId::Aes256, CipherId::Serpent256]).unwrap()
    }

    fn plaintext(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 13 % 251) as u8).collect()
    }

    const SS: u32 = 512;
    const CHUNK: u32 = 4096;
    const DATA: usize = 40960; // 10 chunks

    fn run_encrypt(io: &mut MemIo, j: &mut MemJournal, vmk: &Vmk) -> Result<()> {
        let (front, conv, fin) = regions();
        encrypt_in_place(
            io,
            j,
            vmk,
            &spec(),
            SS,
            DATA as u64,
            [1; 16],
            &front,
            &conv,
            &fin,
            CHUNK,
            &mut |_, _| {},
        )
    }

    #[test]
    fn encrypt_then_decrypt_in_place_roundtrip() {
        let vmk = Vmk::from_bytes([3; 64]);
        let pt = plaintext(DATA);
        let mut io = MemIo::new(pt.clone());
        let mut j = MemJournal::default();
        run_encrypt(&mut io, &mut j, &vmk).unwrap();
        assert!(j.0.is_none(), "journal cleared after success");
        assert_eq!(io.len() as usize, DATA + 2 * HEADER_REGION as usize);
        assert_eq!(&io.data[..5], b"FRONT");
        assert_eq!(&io.data[DATA + HEADER_REGION as usize..][..5], b"BFINL");

        // ciphertext region differs from plaintext
        let hr = HEADER_REGION as usize;
        assert_ne!(&io.data[hr..hr + DATA], pt.as_slice());

        // verify content decrypts correctly via the engine
        let engine = CascadeEngine::new(&vmk, &spec(), SS as usize).unwrap();
        let mut body = io.data[hr..hr + DATA].to_vec();
        engine.decrypt_range(0, &mut body).unwrap();
        assert_eq!(body, pt);

        // now decrypt in place
        let mut j2 = MemJournal::default();
        decrypt_in_place(
            &mut io,
            &mut j2,
            &vmk,
            &spec(),
            SS,
            DATA as u64,
            [1; 16],
            CHUNK,
            &mut |_, _| {},
        )
        .unwrap();
        assert_eq!(io.len() as usize, DATA);
        assert_eq!(io.data, pt);
    }

    /// Crash at EVERY possible write/flush point during encryption, resume,
    /// and verify the final result is identical to the uninterrupted run.
    #[test]
    fn encrypt_survives_crash_at_every_barrier() {
        let vmk = Vmk::from_bytes([4; 64]);
        let pt = plaintext(DATA);

        // reference: uninterrupted run
        let mut ref_io = MemIo::new(pt.clone());
        let mut ref_j = MemJournal::default();
        run_encrypt(&mut ref_io, &mut ref_j, &vmk).unwrap();

        for fail_at in 1..60 {
            let mut io = MemIo::new(pt.clone());
            let mut j = MemJournal::default();
            io.fail_after = Some(fail_at);
            let r = run_encrypt(&mut io, &mut j, &vmk);
            if r.is_ok() {
                // fault landed after the last op of the run
                assert_eq!(io.data, ref_io.data);
                continue;
            }
            // resume after the crash
            run_encrypt(&mut io, &mut j, &vmk)
                .unwrap_or_else(|e| panic!("resume failed at op {fail_at}: {e}"));
            assert_eq!(io.data, ref_io.data, "divergence after crash at op {fail_at}");
            assert!(j.0.is_none());
        }
    }

    #[test]
    fn decrypt_survives_crash_at_every_barrier() {
        let vmk = Vmk::from_bytes([5; 64]);
        let pt = plaintext(DATA);
        let mut enc_io = MemIo::new(pt.clone());
        let mut ej = MemJournal::default();
        run_encrypt(&mut enc_io, &mut ej, &vmk).unwrap();
        let encrypted = enc_io.data.clone();

        for fail_at in 1..60 {
            let mut io = MemIo::new(encrypted.clone());
            let mut j = MemJournal::default();
            io.fail_after = Some(fail_at);
            let r = decrypt_in_place(
                &mut io, &mut j, &vmk, &spec(), SS, DATA as u64, [1; 16], CHUNK,
                &mut |_, _| {},
            );
            if r.is_err() {
                decrypt_in_place(
                    &mut io, &mut j, &vmk, &spec(), SS, DATA as u64, [1; 16], CHUNK,
                    &mut |_, _| {},
                )
                .unwrap_or_else(|e| panic!("resume failed at op {fail_at}: {e}"));
            }
            assert_eq!(io.data, pt, "divergence after crash at op {fail_at}");
        }
    }

    #[test]
    fn journal_is_authenticated() {
        let vmk = Vmk::from_bytes([6; 64]);
        let other_vmk = Vmk::from_bytes([7; 64]);
        let j = Journal {
            version: 1,
            uuid: [1; 16],
            direction: 0,
            chunk_size: CHUNK,
            data_len: DATA as u64,
            watermark: 1234,
            mac: [0; 32],
        };
        let sealed = j.sealed(&vmk);
        assert!(Journal::open(&sealed, &vmk).is_ok());
        assert!(matches!(
            Journal::open(&sealed, &other_vmk),
            Err(Error::JournalCorrupt)
        ));
        let mut tampered = sealed.clone();
        let n = tampered.len();
        tampered[n - 40] ^= 1;
        assert!(Journal::open(&tampered, &vmk).is_err());
    }

    #[test]
    fn mismatched_journal_rejected() {
        let vmk = Vmk::from_bytes([8; 64]);
        let pt = plaintext(DATA);
        let mut io = MemIo::new(pt);
        let mut j = MemJournal::default();
        // journal from a DIFFERENT uuid
        let wrong = Journal {
            version: 1,
            uuid: [9; 16],
            direction: 0,
            chunk_size: CHUNK,
            data_len: DATA as u64,
            watermark: DATA as u64,
            mac: [0; 32],
        };
        j.save(&wrong.sealed(&vmk)).unwrap();
        io.set_len(DATA as u64 + 2 * HEADER_REGION).unwrap();
        assert!(matches!(
            run_encrypt(&mut io, &mut j, &vmk),
            Err(Error::JournalCorrupt)
        ));
    }
}
