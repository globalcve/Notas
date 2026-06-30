//! Volume headers.
//!
//! Two profiles (DECISIONS.md D-03):
//!
//! **Standard** — plaintext CBOR with a BLAKE3 checksum verified before the
//! parser runs (D-02), a multi-slot table, and a VMK-keyed MAC over the
//! canonical bytes verified after unlock. Layout on disk:
//!
//! ```text
//! magic(8) | version(2 LE) | cbor_len(4 LE) | blake3(cbor)(32) | cbor(...)
//! ```
//!
//! **Deniable** — the whole region is indistinguishable from random:
//!
//! ```text
//! salt(32) | nonce(24) | committing-sealed( cbor(inner) || zero-pad )(fixed)
//! ```
//!
//! The deniable inner header CONTAINS the VMK (single credential, VeraCrypt
//! semantics). Hidden volumes always use the deniable profile; the hidden
//! header sits at [`crate::HIDDEN_HEADER_OFFSET`] inside the header region,
//! which is fully randomized at create time, so the presence of a hidden
//! volume is undecidable without its credentials.

use minicbor::{Decode, Encode};
use subtle::ConstantTimeEq;

use crate::aeadx;
use crate::cascade::CascadeSpec;
use crate::error::{Error, Result};
use crate::kdf::{self, KdfParams};
use crate::keyfile::KEYFILE_DIGEST_LEN;
use crate::keyslot::{open_slot, Credential, KeySlot, MAX_SLOTS};
use crate::kmac;
use crate::registry::{AeadId, HashId};
use crate::secret::{Vmk, VMK_LEN};
use crate::sign::SigBundle;
use crate::EntropySource;
use crate::{DENIABLE_BLOB_LEN, HEADER_REGION, HIDDEN_HEADER_OFFSET};

pub const MAGIC: [u8; 8] = *b"TESSERA\x01";
pub const FORMAT_VERSION: u16 = 1;
/// Hard cap on the CBOR payload, enforced before parsing.
pub const MAX_HEADER_CBOR: usize = 192 * 1024;
const FIXED_PREFIX: usize = 8 + 2 + 4 + 32;

// Volume flags.
pub const FLAG_DYNAMIC: u32 = 1 << 0;
pub const FLAG_ATTESTED: u32 = 1 << 1;
pub const FLAG_REQUIRE_PQC: u32 = 1 << 2;
pub const FLAG_EXPERIMENTAL_OK: u32 = 1 << 3;
/// In-place conversion in progress; refuse normal mounts.
pub const FLAG_CONVERTING: u32 = 1 << 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub struct Geometry {
    #[n(0)]
    pub sector_size: u32,
    /// Absolute byte offset of the data area.
    #[n(1)]
    pub data_offset: u64,
    /// Length of the data area in bytes.
    #[n(2)]
    pub data_len: u64,
    /// Total container length in bytes.
    #[n(3)]
    pub total_len: u64,
}

impl Geometry {
    /// Standard layout: header region, data, backup header region.
    pub fn standard(total_len: u64, sector_size: u32) -> Result<Self> {
        let g = Geometry {
            sector_size,
            data_offset: HEADER_REGION,
            data_len: total_len.saturating_sub(2 * HEADER_REGION),
            total_len,
        };
        g.validate()?;
        Ok(g)
    }

    pub fn validate(&self) -> Result<()> {
        if !(512..=65536).contains(&self.sector_size) || !self.sector_size.is_power_of_two() {
            return Err(Error::Geometry("bad sector size"));
        }
        if self.data_len == 0 || self.data_len % self.sector_size as u64 != 0 {
            return Err(Error::Geometry("data length not sector-aligned"));
        }
        if self.data_offset < HEADER_REGION {
            return Err(Error::Geometry("data overlaps header region"));
        }
        let end = self
            .data_offset
            .checked_add(self.data_len)
            .ok_or(Error::Geometry("overflow"))?;
        if end > self.total_len.saturating_sub(HEADER_REGION) {
            return Err(Error::Geometry("data overlaps backup header region"));
        }
        Ok(())
    }

    pub fn sector_count(&self) -> u64 {
        self.data_len / self.sector_size as u64
    }

    /// Offset of the backup header region.
    pub fn backup_offset(&self) -> u64 {
        self.total_len - HEADER_REGION
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct VolumeHeader {
    #[n(0)]
    pub version: u16,
    #[cbor(n(1), with = "minicbor::bytes")]
    pub uuid: [u8; 16],
    #[n(2)]
    pub label: String,
    #[n(3)]
    pub created_at: u64,
    #[n(4)]
    pub geometry: Geometry,
    #[n(5)]
    pub cascade: CascadeSpec,
    #[n(6)]
    pub hash: u16,
    #[n(7)]
    pub flags: u32,
    #[n(8)]
    pub slots: Vec<KeySlot>,
    /// KMAC256(VMK, "tsr/header-mac") over canonical bytes (this field
    /// zeroed). Verified after unlock; prevents cascade/geometry swaps.
    #[cbor(n(9), with = "minicbor::bytes")]
    pub header_mac: [u8; 32],
    /// Attestation signatures over the canonical bytes (mac zeroed).
    #[n(10)]
    pub attest: Vec<SigBundle>,
    #[n(11)]
    pub attest_require_all: bool,
}

impl VolumeHeader {
    pub fn hash_id(&self) -> Result<HashId> {
        HashId::from_u16(self.hash)
    }

    pub fn flag(&self, f: u32) -> bool {
        self.flags & f != 0
    }

    /// Digest binding the immutable identity of this volume; used as the
    /// keyslot AAD so slots can't be replayed onto altered headers.
    pub fn essentials_digest(&self) -> [u8; 32] {
        #[derive(Encode)]
        struct Essentials<'a> {
            #[n(0)]
            version: u16,
            #[cbor(n(1), with = "minicbor::bytes")]
            uuid: &'a [u8; 16],
            #[n(2)]
            geometry: &'a Geometry,
            #[n(3)]
            cascade: &'a CascadeSpec,
            #[n(4)]
            hash: u16,
            #[n(5)]
            flags: u32,
        }
        let bytes = minicbor::to_vec(Essentials {
            version: self.version,
            uuid: &self.uuid,
            geometry: &self.geometry,
            cascade: &self.cascade,
            hash: self.hash,
            flags: self.flags & !FLAG_CONVERTING, // conversion completes without rebinding slots
        })
        .expect("infallible encode");
        *blake3::hash(&bytes).as_bytes()
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut c = self.clone();
        c.header_mac = [0u8; 32];
        minicbor::to_vec(&c).expect("infallible encode")
    }

    /// (Re)compute the VMK-keyed MAC. Call after any header mutation.
    pub fn update_mac(&mut self, vmk: &Vmk) {
        let canonical = self.canonical_bytes();
        let mut mac = [0u8; 32];
        kmac::kmac256(vmk.as_bytes(), kmac::L_HEADER_MAC, &canonical, &mut mac);
        self.header_mac = mac;
    }

    pub fn verify_mac(&self, vmk: &Vmk) -> Result<()> {
        let canonical = self.canonical_bytes();
        let mut mac = [0u8; 32];
        kmac::kmac256(vmk.as_bytes(), kmac::L_HEADER_MAC, &canonical, &mut mac);
        if bool::from(mac.ct_eq(&self.header_mac)) {
            Ok(())
        } else {
            Err(Error::UnlockFailed)
        }
    }

    /// Bytes signed in attested mode (canonical, MAC zeroed, attest empty).
    pub fn attest_message(&self) -> Vec<u8> {
        let mut c = self.clone();
        c.header_mac = [0u8; 32];
        c.attest = Vec::new();
        minicbor::to_vec(&c).expect("infallible encode")
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion(self.version));
        }
        self.geometry.validate()?;
        self.cascade
            .validate(self.flag(FLAG_EXPERIMENTAL_OK))?;
        self.hash_id()?;
        if self.slots.is_empty() || self.slots.len() > MAX_SLOTS {
            return Err(Error::MalformedHeader("slot count"));
        }
        let mut seen = [false; 256];
        for s in &self.slots {
            if seen[s.id as usize] {
                return Err(Error::MalformedHeader("duplicate slot id"));
            }
            seen[s.id as usize] = true;
            s.validate()?;
        }
        if self.label.len() > 256 {
            return Err(Error::MalformedHeader("label too long"));
        }
        if self.flag(FLAG_REQUIRE_PQC)
            && !self
                .slots
                .iter()
                .any(|s| matches!(s.kind, crate::keyslot::SlotKind::HybridPqc { .. }))
        {
            return Err(Error::MalformedHeader("REQUIRE_PQC without a hybrid slot"));
        }
        if self.flag(FLAG_ATTESTED) && self.attest.is_empty() {
            return Err(Error::MalformedHeader("attested without signatures"));
        }
        if self.attest.len() > 4 {
            return Err(Error::MalformedHeader("too many signatures"));
        }
        Ok(())
    }

    /// Serialize: magic | version | len | checksum | cbor.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let cbor = minicbor::to_vec(self)?;
        if cbor.len() > MAX_HEADER_CBOR {
            return Err(Error::MalformedHeader("header too large"));
        }
        let mut out = Vec::with_capacity(FIXED_PREFIX + cbor.len());
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&(cbor.len() as u32).to_le_bytes());
        out.extend_from_slice(blake3::hash(&cbor).as_bytes());
        out.extend_from_slice(&cbor);
        Ok(out)
    }

    /// Parse with verify-before-parse: magic, version, length bounds, and
    /// the BLAKE3 checksum are all checked before the CBOR decoder sees a
    /// single byte.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < FIXED_PREFIX {
            return Err(Error::BadMagic);
        }
        if bytes[..8] != MAGIC {
            return Err(Error::BadMagic);
        }
        let version = u16::from_le_bytes([bytes[8], bytes[9]]);
        if version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        let len = u32::from_le_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]) as usize;
        if len > MAX_HEADER_CBOR || bytes.len() < FIXED_PREFIX + len {
            return Err(Error::MalformedHeader("length"));
        }
        let checksum = &bytes[14..46];
        let cbor = &bytes[FIXED_PREFIX..FIXED_PREFIX + len];
        // verify BEFORE parse
        if !bool::from(blake3::hash(cbor).as_bytes().ct_eq(checksum)) {
            return Err(Error::HeaderIntegrity);
        }
        let header: VolumeHeader = minicbor::decode(cbor)?;
        header.validate()?;
        Ok(header)
    }

    /// Try every slot compatible with the credential; on success verify the
    /// VMK-keyed MAC. Returns (vmk, slot id). Generic error on any failure.
    pub fn unlock(&self, cred: &Credential<'_>) -> Result<(Vmk, u8)> {
        let binding = self.essentials_digest();
        for slot in &self.slots {
            if let Ok(vmk) = open_slot(slot, cred, &binding) {
                self.verify_mac(&vmk)?;
                return Ok((vmk, slot.id));
            }
        }
        Err(Error::UnlockFailed)
    }

    pub fn next_slot_id(&self) -> Result<u8> {
        if self.slots.len() >= MAX_SLOTS {
            return Err(Error::SlotsFull);
        }
        (0..=u8::MAX)
            .find(|id| self.slots.iter().all(|s| s.id != *id))
            .ok_or(Error::SlotsFull)
    }

    pub fn remove_slot(&mut self, id: u8) -> Result<()> {
        let before = self.slots.len();
        self.slots.retain(|s| s.id != id);
        if self.slots.len() == before {
            return Err(Error::NoSuchSlot(id));
        }
        if self.slots.is_empty() {
            return Err(Error::MalformedHeader("cannot remove the last slot"));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Deniable profile
// ---------------------------------------------------------------------------

const DENIABLE_SALT_LEN: usize = 32;
const DENIABLE_NONCE_LEN: usize = 24;
const DENIABLE_SEALED_LEN: usize =
    DENIABLE_BLOB_LEN - DENIABLE_SALT_LEN - DENIABLE_NONCE_LEN;
/// Fixed plaintext size inside the sealed blob (CBOR + zero pad).
const DENIABLE_PT_LEN: usize = DENIABLE_SEALED_LEN - aeadx::COMMITMENT_LEN - 16;
const DENIABLE_AAD: &[u8] = b"tesseract-deniable-v1";

/// Inner (sealed) deniable header. Contains the VMK directly.
#[derive(Clone, Encode, Decode)]
pub struct DeniableInner {
    #[n(0)]
    pub version: u16,
    #[cbor(n(1), with = "minicbor::bytes")]
    pub uuid: [u8; 16],
    #[cbor(n(2), with = "minicbor::bytes")]
    pub vmk: [u8; VMK_LEN],
    #[n(3)]
    pub geometry: Geometry,
    #[n(4)]
    pub cascade: CascadeSpec,
    #[n(5)]
    pub hash: u16,
    #[n(6)]
    pub flags: u32,
    /// True if this is the hidden volume's header.
    #[n(7)]
    pub is_hidden: bool,
}

impl Drop for DeniableInner {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.vmk.zeroize();
    }
}

impl core::fmt::Debug for DeniableInner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("DeniableInner([REDACTED])")
    }
}

impl DeniableInner {
    pub fn validate(&self) -> Result<()> {
        if self.version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion(self.version));
        }
        self.geometry.validate()?;
        self.cascade.validate(self.flags & FLAG_EXPERIMENTAL_OK != 0)?;
        HashId::from_u16(self.hash)?;
        Ok(())
    }
}

/// Seal a deniable header blob (fixed [`DENIABLE_BLOB_LEN`] bytes,
/// indistinguishable from random).
pub fn seal_deniable(
    rng: &mut dyn EntropySource,
    inner: &DeniableInner,
    passphrase: &[u8],
    keyfiles: &[[u8; KEYFILE_DIGEST_LEN]],
    pim: u32,
) -> Result<Vec<u8>> {
    inner.validate()?;
    let cbor = minicbor::to_vec(inner)?;
    if cbor.len() > DENIABLE_PT_LEN {
        return Err(Error::MalformedHeader("deniable header too large"));
    }
    let mut pt = zeroize::Zeroizing::new(vec![0u8; DENIABLE_PT_LEN]);
    pt[..cbor.len()].copy_from_slice(&cbor);

    let mut salt = [0u8; DENIABLE_SALT_LEN];
    let mut nonce = [0u8; DENIABLE_NONCE_LEN];
    rng.fill(&mut salt);
    rng.fill(&mut nonce);

    let secret = crate::keyfile::mix_secret(passphrase, keyfiles);
    let params = KdfParams::deniable(salt, pim);
    let kek = kdf::derive_kek(&params, secret.as_slice())?;
    let sealed = aeadx::seal(
        AeadId::XChaCha20Poly1305,
        kek.as_ref(),
        &nonce,
        DENIABLE_AAD,
        &pt,
    )?;
    debug_assert_eq!(sealed.len(), DENIABLE_SEALED_LEN);

    let mut out = Vec::with_capacity(DENIABLE_BLOB_LEN);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Try to open a deniable blob. Generic failure: wrong credentials, not a
/// deniable header, and random bytes are indistinguishable outcomes.
pub fn open_deniable(
    blob: &[u8],
    passphrase: &[u8],
    keyfiles: &[[u8; KEYFILE_DIGEST_LEN]],
    pim: u32,
) -> Result<DeniableInner> {
    if blob.len() != DENIABLE_BLOB_LEN {
        return Err(Error::UnlockFailed);
    }
    let salt: [u8; DENIABLE_SALT_LEN] = blob[..DENIABLE_SALT_LEN].try_into().unwrap();
    let nonce = &blob[DENIABLE_SALT_LEN..DENIABLE_SALT_LEN + DENIABLE_NONCE_LEN];
    let sealed = &blob[DENIABLE_SALT_LEN + DENIABLE_NONCE_LEN..];

    let secret = crate::keyfile::mix_secret(passphrase, keyfiles);
    let params = KdfParams::deniable(salt, pim);
    let kek = kdf::derive_kek(&params, secret.as_slice())?;
    let pt = aeadx::open(
        AeadId::XChaCha20Poly1305,
        kek.as_ref(),
        nonce,
        DENIABLE_AAD,
        sealed,
    )?;
    let inner: DeniableInner = minicbor::decode(pt.as_slice()).map_err(|_| Error::UnlockFailed)?;
    inner.validate().map_err(|_| Error::UnlockFailed)?;
    Ok(inner)
}

/// Compose a full header-region image (HEADER_REGION bytes).
pub fn compose_standard_region(header_bytes: &[u8]) -> Result<Vec<u8>> {
    if header_bytes.len() > HEADER_REGION as usize {
        return Err(Error::MalformedHeader("header exceeds region"));
    }
    let mut region = vec![0u8; HEADER_REGION as usize];
    region[..header_bytes.len()].copy_from_slice(header_bytes);
    Ok(region)
}

/// Compose a deniable header-region image: outer blob at 0, hidden blob (or
/// random) at HIDDEN_HEADER_OFFSET, random everywhere else.
pub fn compose_deniable_region(
    rng: &mut dyn EntropySource,
    outer_blob: &[u8],
    hidden_blob: Option<&[u8]>,
) -> Result<Vec<u8>> {
    if outer_blob.len() != DENIABLE_BLOB_LEN {
        return Err(Error::MalformedHeader("outer blob size"));
    }
    let mut region = vec![0u8; HEADER_REGION as usize];
    rng.fill(&mut region);
    region[..DENIABLE_BLOB_LEN].copy_from_slice(outer_blob);
    if let Some(h) = hidden_blob {
        if h.len() != DENIABLE_BLOB_LEN {
            return Err(Error::MalformedHeader("hidden blob size"));
        }
        let off = HIDDEN_HEADER_OFFSET as usize;
        region[off..off + DENIABLE_BLOB_LEN].copy_from_slice(h);
    }
    Ok(region)
}

/// Hidden volume geometry: a hidden data area of `hidden_len` bytes placed at
/// the END of the outer volume's data area (VeraCrypt convention).
pub fn hidden_geometry(outer: &Geometry, hidden_len: u64) -> Result<Geometry> {
    if hidden_len == 0 || hidden_len % outer.sector_size as u64 != 0 {
        return Err(Error::Geometry("hidden length not sector-aligned"));
    }
    if hidden_len > outer.data_len / 2 {
        return Err(Error::Geometry("hidden volume too large for outer"));
    }
    let g = Geometry {
        sector_size: outer.sector_size,
        data_offset: outer.data_offset + outer.data_len - hidden_len,
        data_len: hidden_len,
        total_len: outer.total_len,
    };
    Ok(g)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem::test_rng;
    use crate::keyslot::{seal_slot, NewSlot, SlotSetup};
    use crate::registry::CipherId;

    fn small_kdf(salt: u8) -> KdfParams {
        KdfParams::Argon2id {
            m_kib: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
            salt: [salt; 32],
        }
    }

    fn make_header(rng: &mut dyn crate::EntropySource, vmk: &Vmk) -> VolumeHeader {
        let geometry = Geometry::standard(64 * 1024 * 1024, 4096).unwrap();
        let cascade = CascadeSpec::new(&[CipherId::Aes256, CipherId::Serpent256]).unwrap();
        let mut h = VolumeHeader {
            version: FORMAT_VERSION,
            uuid: [7; 16],
            label: "test volume".into(),
            created_at: 1750000000,
            geometry,
            cascade,
            hash: HashId::Blake3.as_u16(),
            flags: 0,
            slots: vec![],
            header_mac: [0; 32],
            attest: vec![],
            attest_require_all: false,
        };
        let binding = h.essentials_digest();
        let slot = seal_slot(
            rng,
            vmk,
            NewSlot {
                id: 0,
                aead: AeadId::XChaCha20Poly1305,
                label: "main".into(),
                created_at: 0,
                kdf: Some(small_kdf(1)),
                setup: SlotSetup::Passphrase {
                    passphrase: b"open sesame",
                    keyfiles: &[],
                },
            },
            &binding,
        )
        .unwrap();
        h.slots.push(slot);
        h.update_mac(vmk);
        h
    }

    #[test]
    fn standard_header_roundtrip_and_unlock() {
        let mut rng = test_rng(30);
        let vmk = Vmk::generate(&mut rng);
        let h = make_header(&mut rng, &vmk);
        let bytes = h.to_bytes().unwrap();
        let parsed = VolumeHeader::from_bytes(&bytes).unwrap();
        assert_eq!(h, parsed);

        let (got, slot_id) = parsed
            .unlock(&Credential::Passphrase {
                passphrase: b"open sesame",
                keyfiles: &[],
            })
            .unwrap();
        assert_eq!(got.as_bytes(), vmk.as_bytes());
        assert_eq!(slot_id, 0);

        assert!(parsed
            .unlock(&Credential::Passphrase {
                passphrase: b"wrong",
                keyfiles: &[],
            })
            .is_err());
    }

    #[test]
    fn checksum_verified_before_parse() {
        let mut rng = test_rng(31);
        let vmk = Vmk::generate(&mut rng);
        let h = make_header(&mut rng, &vmk);
        let mut bytes = h.to_bytes().unwrap();
        // flip a byte inside the CBOR payload
        let n = bytes.len();
        bytes[n - 1] ^= 1;
        assert!(matches!(
            VolumeHeader::from_bytes(&bytes),
            Err(Error::HeaderIntegrity)
        ));
        // bad magic
        let mut bytes2 = h.to_bytes().unwrap();
        bytes2[0] = b'X';
        assert!(matches!(
            VolumeHeader::from_bytes(&bytes2),
            Err(Error::BadMagic)
        ));
        // absurd length is rejected before any parsing
        let mut bytes3 = h.to_bytes().unwrap();
        bytes3[10..14].copy_from_slice(&(u32::MAX).to_le_bytes());
        assert!(VolumeHeader::from_bytes(&bytes3).is_err());
    }

    /// A header whose cascade spec was swapped (and re-checksummed) must fail
    /// at unlock: the slot AAD binds the essentials digest AND the VMK MAC
    /// covers the cascade.
    #[test]
    fn cascade_swap_breaks_unlock() {
        let mut rng = test_rng(32);
        let vmk = Vmk::generate(&mut rng);
        let h = make_header(&mut rng, &vmk);
        let mut tampered = h.clone();
        tampered.cascade =
            CascadeSpec::new(&[CipherId::Serpent256, CipherId::Aes256]).unwrap();
        // attacker can re-serialize with a fresh checksum…
        let bytes = tampered.to_bytes().unwrap();
        let parsed = VolumeHeader::from_bytes(&bytes).unwrap();
        // …but unlock fails because the slot AAD no longer matches.
        assert!(parsed
            .unlock(&Credential::Passphrase {
                passphrase: b"open sesame",
                keyfiles: &[],
            })
            .is_err());
    }

    #[test]
    fn mac_detects_slot_table_tamper() {
        let mut rng = test_rng(33);
        let vmk = Vmk::generate(&mut rng);
        let mut h = make_header(&mut rng, &vmk);
        // attacker adds a slot with their own passphrase but can't fix the MAC
        let binding = h.essentials_digest();
        let attacker_vmk = Vmk::generate(&mut rng); // attacker doesn't know the real VMK
        let evil = seal_slot(
            &mut rng,
            &attacker_vmk,
            NewSlot {
                id: 1,
                aead: AeadId::XChaCha20Poly1305,
                label: "evil".into(),
                created_at: 0,
                kdf: Some(small_kdf(2)),
                setup: SlotSetup::Passphrase {
                    passphrase: b"evil",
                    keyfiles: &[],
                },
            },
            &binding,
        )
        .unwrap();
        h.slots.push(evil);
        // legit slot still opens its VMK, but the header MAC now fails
        let bytes = h.to_bytes().unwrap();
        let parsed = VolumeHeader::from_bytes(&bytes).unwrap();
        assert!(parsed
            .unlock(&Credential::Passphrase {
                passphrase: b"open sesame",
                keyfiles: &[],
            })
            .is_err());
    }

    #[test]
    fn deniable_roundtrip_and_uniformity() {
        let mut rng = test_rng(34);
        let mut vmk_bytes = [0u8; VMK_LEN];
        rng.fill(&mut vmk_bytes);
        let geometry = Geometry::standard(32 * 1024 * 1024, 4096).unwrap();
        let inner = DeniableInner {
            version: FORMAT_VERSION,
            uuid: [9; 16],
            vmk: vmk_bytes,
            geometry,
            cascade: CascadeSpec::new(&[CipherId::Aes256]).unwrap(),
            hash: HashId::Blake3.as_u16(),
            flags: 0,
            is_hidden: false,
        };
        // PIM 0 with the fixed deniable params is heavy; tests accept it once.
        let blob = seal_deniable(&mut rng, &inner, b"pw", &[], 0).unwrap();
        assert_eq!(blob.len(), DENIABLE_BLOB_LEN);

        let opened = open_deniable(&blob, b"pw", &[], 0).unwrap();
        assert_eq!(opened.uuid, inner.uuid);
        assert_eq!(opened.vmk, inner.vmk);

        // wrong passphrase and wrong PIM both fail generically
        assert!(open_deniable(&blob, b"nope", &[], 0).is_err());
        assert!(open_deniable(&blob, b"pw", &[], 1).is_err());

        // random bytes fail the same way
        let mut random = vec![0u8; DENIABLE_BLOB_LEN];
        rng.fill(&mut random);
        assert!(matches!(
            open_deniable(&random, b"pw", &[], 0),
            Err(Error::UnlockFailed)
        ));
    }

    #[test]
    fn hidden_geometry_constraints() {
        let outer = Geometry::standard(256 * 1024 * 1024, 4096).unwrap();
        let h = hidden_geometry(&outer, 16 * 1024 * 1024).unwrap();
        assert_eq!(h.data_offset + h.data_len, outer.data_offset + outer.data_len);
        assert!(hidden_geometry(&outer, outer.data_len).is_err());
        assert!(hidden_geometry(&outer, 1234).is_err()); // unaligned
    }

    #[test]
    fn geometry_validation() {
        assert!(Geometry::standard(4 * 1024 * 1024, 4096).is_ok());
        assert!(Geometry::standard(100, 4096).is_err());
        assert!(Geometry {
            sector_size: 1000, // not a power of two
            data_offset: HEADER_REGION,
            data_len: 4096,
            total_len: 10 * 1024 * 1024,
        }
        .validate()
        .is_err());
    }

    #[test]
    fn slot_management() {
        let mut rng = test_rng(35);
        let vmk = Vmk::generate(&mut rng);
        let mut h = make_header(&mut rng, &vmk);
        assert_eq!(h.next_slot_id().unwrap(), 1);
        assert!(h.remove_slot(99).is_err());
        // can't remove the last slot
        assert!(h.remove_slot(0).is_err());
    }
}
