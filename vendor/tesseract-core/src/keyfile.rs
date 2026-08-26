//! Keyfiles: digestion, mixing into the passphrase secret, and generation.
//!
//! A keyfile is digested with the volume's hash (whole contents — there is no
//! VeraCrypt-style 1 MiB cap; the caller streams the file through
//! [`KeyfileDigest`]). Digests are mixed with the passphrase through a
//! BLAKE3 keyed derivation with length-prefixed framing, so no concatenation
//! ambiguity exists between passphrase and keyfiles or between two keyfiles.

use crate::error::Result;
use crate::registry::HashId;
use crate::secret::SecretBytes;
// blake2 is still on digest 0.10; everything else is digest 0.11.
use blake2::Digest as Blake2Digest;
use digest::Digest;

pub const KEYFILE_DIGEST_LEN: usize = 64;

/// Incremental keyfile digestion (the agent feeds file chunks; core never
/// touches the filesystem).
pub struct KeyfileDigest {
    inner: DigestImpl,
}

enum DigestImpl {
    Sha512(sha2::Sha512),
    Sha256(sha2::Sha256),
    Blake3(Box<blake3::Hasher>),
    Blake2b(blake2::Blake2b512),
    #[cfg(feature = "experimental")]
    Whirlpool(whirlpool::Whirlpool),
    #[cfg(feature = "experimental")]
    Streebog(streebog::Streebog512),
}

impl core::fmt::Debug for KeyfileDigest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KeyfileDigest")
    }
}

impl KeyfileDigest {
    pub fn new(hash: HashId) -> Result<Self> {
        let inner = match hash {
            HashId::Sha512 => DigestImpl::Sha512(sha2::Sha512::new()),
            HashId::Sha256 => DigestImpl::Sha256(sha2::Sha256::new()),
            HashId::Blake3 => DigestImpl::Blake3(Box::new(blake3::Hasher::new())),
            HashId::Blake2b => DigestImpl::Blake2b(<blake2::Blake2b512 as Blake2Digest>::new()),
            #[cfg(feature = "experimental")]
            HashId::Whirlpool => DigestImpl::Whirlpool(whirlpool::Whirlpool::new()),
            #[cfg(feature = "experimental")]
            HashId::Streebog512 => DigestImpl::Streebog(streebog::Streebog512::new()),
            #[cfg(not(feature = "experimental"))]
            _ => return Err(crate::Error::ExperimentalGated(hash.label())),
        };
        Ok(Self { inner })
    }

    pub fn update(&mut self, data: &[u8]) {
        match &mut self.inner {
            DigestImpl::Sha512(h) => h.update(data),
            DigestImpl::Sha256(h) => h.update(data),
            DigestImpl::Blake3(h) => {
                h.update(data);
            }
            DigestImpl::Blake2b(h) => Blake2Digest::update(h, data),
            #[cfg(feature = "experimental")]
            DigestImpl::Whirlpool(h) => Digest::update(h, data),
            #[cfg(feature = "experimental")]
            DigestImpl::Streebog(h) => Digest::update(h, data),
        }
    }

    /// 64-byte digest (shorter hashes are length-extended with BLAKE3 XOF to
    /// keep a uniform mixing format).
    pub fn finalize(self) -> [u8; KEYFILE_DIGEST_LEN] {
        let mut out = [0u8; KEYFILE_DIGEST_LEN];
        match self.inner {
            DigestImpl::Sha512(h) => out.copy_from_slice(&h.finalize()),
            DigestImpl::Sha256(h) => {
                let d = h.finalize();
                let mut x = blake3::Hasher::new();
                x.update(&d);
                x.finalize_xof().fill(&mut out);
            }
            DigestImpl::Blake3(h) => h.finalize_xof().fill(&mut out),
            DigestImpl::Blake2b(h) => out.copy_from_slice(&Blake2Digest::finalize(h)),
            #[cfg(feature = "experimental")]
            DigestImpl::Whirlpool(h) => out.copy_from_slice(&Digest::finalize(h)),
            #[cfg(feature = "experimental")]
            DigestImpl::Streebog(h) => out.copy_from_slice(&Digest::finalize(h)),
        }
        out
    }
}

/// Combine passphrase and keyfile digests into the effective KDF input.
/// With no keyfiles this is the passphrase itself (so plain-passphrase
/// volumes don't depend on this function's framing).
pub fn mix_secret(passphrase: &[u8], keyfile_digests: &[[u8; KEYFILE_DIGEST_LEN]]) -> SecretBytes {
    if keyfile_digests.is_empty() {
        return SecretBytes::from_slice(passphrase);
    }
    let mut h = blake3::Hasher::new_derive_key("tesseract v1 keyfile mix");
    h.update(&(passphrase.len() as u64).to_le_bytes());
    h.update(passphrase);
    h.update(&(keyfile_digests.len() as u64).to_le_bytes());
    for d in keyfile_digests {
        h.update(d);
    }
    let mut out = SecretBytes::zeroed(64);
    h.finalize_xof().fill(out.as_mut_slice());
    out
}

/// Generate keyfile contents: `len` bytes of caller-supplied entropy
/// (OS CSPRNG mixed with the user pool by the agent).
pub fn generate_keyfile(rng: &mut dyn crate::EntropySource, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    rng.fill(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_all_hashes() {
        for &h in HashId::ALL {
            if !h.is_available() {
                continue;
            }
            let mut d = KeyfileDigest::new(h).unwrap();
            d.update(b"hello ");
            d.update(b"world");
            let a = d.finalize();
            let mut d2 = KeyfileDigest::new(h).unwrap();
            d2.update(b"hello world");
            assert_eq!(a, d2.finalize(), "{:?} streaming mismatch", h);
        }
    }

    #[test]
    fn sha512_kat() {
        let mut d = KeyfileDigest::new(HashId::Sha512).unwrap();
        d.update(b"abc");
        assert_eq!(
            hex::encode(d.finalize()),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn mixing_no_keyfiles_is_passphrase() {
        let m = mix_secret(b"pass", &[]);
        assert_eq!(m.as_slice(), b"pass");
    }

    #[test]
    fn mixing_order_and_count_matter() {
        let a = [1u8; 64];
        let b = [2u8; 64];
        let m1 = mix_secret(b"pass", &[a, b]);
        let m2 = mix_secret(b"pass", &[b, a]);
        let m3 = mix_secret(b"pass", &[a]);
        assert_ne!(m1.as_slice(), m2.as_slice());
        assert_ne!(m1.as_slice(), m3.as_slice());
    }
}
