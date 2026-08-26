//! Committing AEAD for keyslot sealing.
//!
//! Neither AES-256-GCM-SIV nor (X)ChaCha20-Poly1305 is key-committing on its
//! own (polynomial MACs admit multi-key ciphertexts). Tesseract therefore never
//! seals a keyslot with the raw AEAD: from the slot KEK we derive an
//! encryption key and a commitment value with domain-separated KMAC256, store
//! the commitment next to the ciphertext, and verify it in constant time on
//! open. A wrong KEK fails the commitment; it cannot authenticate, and it can
//! never yield a wrong VMK. See DECISIONS.md D-01.

use aes_gcm_siv::Aes256GcmSiv;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::kmac;
use crate::registry::AeadId;
use crate::secret::SecretBytes;

pub const COMMITMENT_LEN: usize = 32;

/// Nonce length for a slot AEAD.
pub fn nonce_len(aead: AeadId) -> Result<usize> {
    match aead {
        AeadId::XChaCha20Poly1305 => Ok(24),
        AeadId::Aes256GcmSiv => Ok(12),
        _ => Err(Error::InvalidParameter("AEAD not allowed for keyslots")),
    }
}

fn derive_subkeys(kek: &[u8]) -> (Zeroizing<[u8; 32]>, [u8; 32]) {
    let mut k_enc = Zeroizing::new([0u8; 32]);
    kmac::kmac256(kek, kmac::L_SLOT_ENC, &[], k_enc.as_mut());
    let k_com = kmac::kmac256_32(kek, kmac::L_SLOT_COM, &[]);
    (k_enc, k_com)
}

/// Seal `plaintext` under `kek`. Output: `commitment(32) || aead_ciphertext`.
pub fn seal(
    aead: AeadId,
    kek: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    if nonce.len() != nonce_len(aead)? {
        return Err(Error::InvalidParameter("nonce length"));
    }
    let (k_enc, k_com) = derive_subkeys(kek);
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    let ct = match aead {
        AeadId::XChaCha20Poly1305 => XChaCha20Poly1305::new(k_enc.as_ref().into())
            .encrypt(nonce.into(), payload)
            .map_err(|_| Error::InvalidParameter("seal failed"))?,
        AeadId::Aes256GcmSiv => Aes256GcmSiv::new(k_enc.as_ref().into())
            .encrypt(nonce.into(), payload)
            .map_err(|_| Error::InvalidParameter("seal failed"))?,
        _ => unreachable!("nonce_len gated"),
    };
    let mut out = Vec::with_capacity(COMMITMENT_LEN + ct.len());
    out.extend_from_slice(&k_com);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a sealed blob. Timing-flat on failure: the commitment check and the
/// AEAD decryption both always run; their results are merged at the end.
pub fn open(
    aead: AeadId,
    kek: &[u8],
    nonce: &[u8],
    aad: &[u8],
    sealed: &[u8],
) -> Result<SecretBytes> {
    if nonce.len() != nonce_len(aead)? || sealed.len() < COMMITMENT_LEN + 16 {
        return Err(Error::UnlockFailed);
    }
    let (k_enc, k_com) = derive_subkeys(kek);
    let (stored_com, ct) = sealed.split_at(COMMITMENT_LEN);
    let com_ok: bool = stored_com.ct_eq(&k_com).into();

    let payload = Payload { msg: ct, aad };
    let pt = match aead {
        AeadId::XChaCha20Poly1305 => {
            XChaCha20Poly1305::new(k_enc.as_ref().into()).decrypt(nonce.into(), payload)
        }
        AeadId::Aes256GcmSiv => {
            Aes256GcmSiv::new(k_enc.as_ref().into()).decrypt(nonce.into(), payload)
        }
        _ => unreachable!("nonce_len gated"),
    };

    match (com_ok, pt) {
        (true, Ok(pt)) => Ok(SecretBytes::new(pt)),
        _ => Err(Error::UnlockFailed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_both_aeads() {
        for aead in [AeadId::XChaCha20Poly1305, AeadId::Aes256GcmSiv] {
            let kek = [3u8; 32];
            let nonce = vec![9u8; nonce_len(aead).unwrap()];
            let sealed = seal(aead, &kek, &nonce, b"aad", b"the vmk bytes").unwrap();
            let pt = open(aead, &kek, &nonce, b"aad", &sealed).unwrap();
            assert_eq!(pt.as_slice(), b"the vmk bytes");
        }
    }

    #[test]
    fn wrong_key_fails_commitment() {
        let aead = AeadId::XChaCha20Poly1305;
        let nonce = vec![0u8; 24];
        let sealed = seal(aead, &[1u8; 32], &nonce, b"", b"secret").unwrap();
        assert!(matches!(
            open(aead, &[2u8; 32], &nonce, b"", &sealed),
            Err(Error::UnlockFailed)
        ));
    }

    #[test]
    fn wrong_aad_fails() {
        let aead = AeadId::Aes256GcmSiv;
        let nonce = vec![0u8; 12];
        let sealed = seal(aead, &[1u8; 32], &nonce, b"header-a", b"secret").unwrap();
        assert!(open(aead, &[1u8; 32], &nonce, b"header-b", &sealed).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let aead = AeadId::XChaCha20Poly1305;
        let nonce = vec![0u8; 24];
        let mut sealed = seal(aead, &[1u8; 32], &nonce, b"", b"secret").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(open(aead, &[1u8; 32], &nonce, b"", &sealed).is_err());
        // tampered commitment too
        let mut sealed2 = seal(aead, &[1u8; 32], &nonce, b"", b"secret").unwrap();
        sealed2[0] ^= 1;
        assert!(open(aead, &[1u8; 32], &nonce, b"", &sealed2).is_err());
    }
}
