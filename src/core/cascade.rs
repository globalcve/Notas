//! Cascade vault encryption backed by `tesseract-core`'s file mode.
//!
//! The whole serialized note vault (one bincode blob) is sealed with a
//! password-derived KEK that wraps a random content key (CEK); the body is then
//! run through a 3-layer AEAD cascade — AES-256-GCM, then ChaCha20-Poly1305,
//! then AES-256-GCM-SIV — each layer keyed independently (KMAC over the CEK).
//! This is the quantum-resistant mode the user opts into for their notes.
//!
//! On disk the blob is tesseract's `TSRF\x01` format, which is self-describing
//! (KDF params + layer list live in the header), so unlocking only needs the
//! passphrase. Legacy single-AES-GCM vaults (no magic) are handled by
//! [`super::crypto`]; [`is_cascade`] distinguishes the two.

use aes_gcm::aead::{rand_core::RngCore, OsRng};
use anyhow::{anyhow, Result};

use tesseract_core::{
    filemode::{FileDecryptor, FileEncryptor, FileHeader, Openers, DEFAULT_CHUNK_SIZE, FILE_MAGIC},
    hpke,
    kdf::KdfParams,
    registry::AeadId,
    EntropySource,
};

use super::data::Argon2Params;

/// Body cascade, innermost layer first: AES-256-GCM -> ChaCha20-Poly1305 ->
/// AES-256-GCM-SIV. Encryption applies them in order; decryption reverses.
const CASCADE_LAYERS: [AeadId; 3] = [
    AeadId::Aes256Gcm,
    AeadId::ChaCha20Poly1305,
    AeadId::Aes256GcmSiv,
];

/// HPKE AEAD id stored in the header. Password-only vaults have no recipients,
/// but the header still validates the HPKE suite, so a valid id is required.
const HEADER_HPKE_AEAD: u16 = hpke::AEAD_AES256GCM;

/// Random source for tesseract-core, backed by the OS CSPRNG.
struct OsEntropy;

impl EntropySource for OsEntropy {
    fn fill(&mut self, buf: &mut [u8]) {
        OsRng.fill_bytes(buf);
    }
}

/// True if `bytes` is a tesseract cascade vault (vs. a legacy AES-GCM vault).
pub fn is_cascade(bytes: &[u8]) -> bool {
    bytes.len() >= FILE_MAGIC.len() && bytes[..FILE_MAGIC.len()] == FILE_MAGIC
}

/// Build cascade KDF params (Argon2id) from Notas' settings, with a fresh salt.
fn kdf_params(params: &Argon2Params) -> KdfParams {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    KdfParams::Argon2id {
        m_kib: params.memory_cost,
        t_cost: params.time_cost,
        p_cost: params.parallelism,
        salt,
    }
}

/// Encrypt the serialized vault blob with the password-gated 3-layer cascade.
pub fn encrypt_vault(passphrase: &[u8], plaintext: &[u8], params: &Argon2Params) -> Result<Vec<u8>> {
    let mut rng = OsEntropy;
    let chunk = DEFAULT_CHUNK_SIZE;
    let mut enc = FileEncryptor::with_openers(
        &mut rng,
        Openers {
            password: Some((passphrase, kdf_params(params))),
            recipients: &[],
        },
        &CASCADE_LAYERS,
        HEADER_HPKE_AEAD,
        chunk,
        plaintext.len() as u64,
        false, // detached signature: not used for the local vault
        false, // archive: plaintext is a single blob, not a directory tar
    )
    .map_err(|e| anyhow!("cascade init failed: {e}"))?;

    let mut out = enc.header_bytes().to_vec();
    if plaintext.is_empty() {
        // total_chunks is at least 1: emit one empty final chunk.
        out.extend(
            enc.encrypt_chunk(&[])
                .map_err(|e| anyhow!("cascade seal failed: {e}"))?,
        );
    } else {
        for chunk_pt in plaintext.chunks(chunk as usize) {
            out.extend(
                enc.encrypt_chunk(chunk_pt)
                    .map_err(|e| anyhow!("cascade seal failed: {e}"))?,
            );
        }
    }
    debug_assert!(enc.is_complete());
    Ok(out)
}

/// Decrypt a cascade vault blob with the passphrase.
pub fn decrypt_vault(passphrase: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
    let (header, header_len) =
        FileHeader::from_bytes(blob).map_err(|e| anyhow!("invalid cascade header: {e}"))?;

    // Capture geometry before the header is moved into the decryptor.
    let chunk = header.chunk_size as usize;
    let overhead = header.chunk_overhead();
    let total_chunks = header.total_chunks;
    let plaintext_len = header.plaintext_len as usize;

    let mut dec = FileDecryptor::with_password(header, passphrase)
        .map_err(|_| anyhow!("Invalid password or corrupted data."))?;

    // The encryptor always emits at least one (possibly empty) final chunk, so a
    // header claiming zero would skip the loop — and every authentication check
    // with it. Reject it before trusting any other geometry field.
    if total_chunks == 0 {
        return Err(anyhow!("invalid cascade geometry"));
    }

    let ct = &blob[header_len..];
    // L3: `plaintext_len` is read from the not-yet-authenticated header, so a
    // crafted file could claim a huge size and OOM us before any chunk is
    // verified. Plaintext is always <= ciphertext length, so clamp the capacity
    // hint to what's actually on disk. The Vec still grows if ever needed, so
    // this only bounds the up-front allocation; it can't truncate real output.
    let mut out = Vec::with_capacity(plaintext_len.min(ct.len()));
    // All arithmetic on header geometry is checked: the fields aren't
    // authenticated yet, and a crafted total_chunks/plaintext_len pair that
    // doesn't add up must become a clean error, not an underflow panic.
    let mut pos = 0usize;
    for i in 0..total_chunks {
        let is_final = i == total_chunks - 1;
        let pt_len = if is_final {
            (total_chunks as usize)
                .checked_sub(1)
                .and_then(|n| n.checked_mul(chunk))
                .and_then(|body| plaintext_len.checked_sub(body))
                .ok_or_else(|| anyhow!("invalid cascade geometry"))?
        } else {
            chunk
        };
        let clen = pt_len
            .checked_add(overhead)
            .ok_or_else(|| anyhow!("invalid cascade geometry"))?;
        let end = pos
            .checked_add(clen)
            .ok_or_else(|| anyhow!("truncated cascade ciphertext"))?;
        let piece = ct
            .get(pos..end)
            .ok_or_else(|| anyhow!("truncated cascade ciphertext"))?;
        let pt = dec
            .decrypt_chunk(piece)
            .map_err(|_| anyhow!("Invalid password or corrupted data."))?;
        out.extend_from_slice(&pt);
        pos += clen;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> Argon2Params {
        // Light params keep the round-trip tests fast.
        Argon2Params {
            memory_cost: 8 * 1024,
            time_cost: 1,
            parallelism: 1,
        }
    }

    #[test]
    fn roundtrip_small() {
        let pw = b"correct horse battery staple";
        let pt = b"a short secret note";
        let blob = encrypt_vault(pw, pt, &params()).unwrap();
        assert!(is_cascade(&blob));
        let got = decrypt_vault(pw, &blob).unwrap();
        assert_eq!(got, pt);
    }

    #[test]
    fn roundtrip_empty() {
        let pw = b"pw";
        let blob = encrypt_vault(pw, b"", &params()).unwrap();
        assert_eq!(decrypt_vault(pw, &blob).unwrap(), b"");
    }

    #[test]
    fn roundtrip_multichunk() {
        let pw = b"pw";
        // Larger than DEFAULT_CHUNK_SIZE to exercise chunk boundaries.
        let pt: Vec<u8> = (0..(DEFAULT_CHUNK_SIZE as usize * 2 + 123))
            .map(|i| i as u8)
            .collect();
        let blob = encrypt_vault(pw, &pt, &params()).unwrap();
        assert_eq!(decrypt_vault(pw, &blob).unwrap(), pt);
    }

    #[test]
    fn wrong_password_fails() {
        let blob = encrypt_vault(b"right", b"data", &params()).unwrap();
        assert!(decrypt_vault(b"wrong", &blob).is_err());
    }

    #[test]
    fn legacy_blob_not_cascade() {
        // A legacy vault begins with a 16-byte salt, not TSRF magic.
        assert!(!is_cascade(&[0u8; 64]));
    }
}
