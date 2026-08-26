//! Hybrid post-quantum KEM: X25519 + ML-KEM-1024.
//!
//! Both component KEMs run independently; the shared secrets are combined
//! with SHA3-256 over the full transcript (both shared secrets, both
//! ciphertexts, both public keys, and a domain-separation label) — the QSF
//! combiner shape from draft-irtf-cfrg-hybrid-kems / X-Wing, hashing the
//! complete transcript. An attacker must break BOTH X25519 and ML-KEM-1024
//! to recover the shared secret. See DECISIONS.md D-05.
//!
//! Identity files (recipient/unlock keys) are CBOR, optionally sealed under a
//! passphrase with the same committing AEAD used for keyslots.

use minicbor::{Decode, Encode};
use ml_kem::kem::Decapsulate;
use ml_kem::{ml_kem_1024, KeyExport, MlKem1024};
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

use crate::aeadx;
use crate::error::{Error, Result};
use crate::kdf::{self, KdfParams};
use crate::registry::{AeadId, KemId};
use crate::secret::Key32;
use crate::EntropySource;

pub const X25519_PK_LEN: usize = 32;
pub const ML_KEM_1024_EK_LEN: usize = 1568;
pub const ML_KEM_1024_CT_LEN: usize = 1568;
pub const HYBRID_CT_LEN: usize = ML_KEM_1024_CT_LEN + X25519_PK_LEN;

const COMBINER_LABEL: &[u8] = b"tesseract-hybrid-v1";

/// Public half of a hybrid identity (safe to store/share).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct HybridRecipient {
    #[cbor(n(0), with = "minicbor::bytes")]
    pub x_pk: [u8; X25519_PK_LEN],
    #[cbor(n(1), with = "minicbor::bytes")]
    pub ml_ek: Vec<u8>,
}

impl HybridRecipient {
    pub fn validate(&self) -> Result<()> {
        if self.ml_ek.len() != ML_KEM_1024_EK_LEN {
            return Err(Error::InvalidParameter("ML-KEM-1024 public key length"));
        }
        Ok(())
    }

    /// Short fingerprint for display: BLAKE3 of the CBOR encoding, 16 bytes.
    pub fn fingerprint(&self) -> [u8; 16] {
        let bytes = minicbor::to_vec(self).expect("infallible encode");
        let mut out = [0u8; 16];
        out.copy_from_slice(&blake3::hash(&bytes).as_bytes()[..16]);
        out
    }
}

/// Private half of a hybrid identity. Holds only seeds; full keys are
/// re-expanded on use and zeroized after.
pub struct HybridIdentity {
    x_sk: Zeroizing<[u8; 32]>,
    ml_seed: Zeroizing<[u8; 64]>,
}

impl core::fmt::Debug for HybridIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HybridIdentity([REDACTED])")
    }
}

impl HybridIdentity {
    pub fn generate(rng: &mut dyn EntropySource) -> Self {
        let mut x_sk = Zeroizing::new([0u8; 32]);
        let mut ml_seed = Zeroizing::new([0u8; 64]);
        rng.fill(x_sk.as_mut());
        rng.fill(ml_seed.as_mut());
        Self { x_sk, ml_seed }
    }

    pub fn from_parts(x_sk: [u8; 32], ml_seed: [u8; 64]) -> Self {
        Self {
            x_sk: Zeroizing::new(x_sk),
            ml_seed: Zeroizing::new(ml_seed),
        }
    }

    pub fn parts(&self) -> (&[u8; 32], &[u8; 64]) {
        (&self.x_sk, &self.ml_seed)
    }

    pub fn public(&self) -> HybridRecipient {
        let x_secret = x25519_dalek::StaticSecret::from(*self.x_sk);
        let x_pk = x25519_dalek::PublicKey::from(&x_secret);
        let dk = ml_kem_1024::DecapsulationKey::from_seed((*self.ml_seed).into());
        let ml_ek = dk.encapsulation_key().to_bytes();
        HybridRecipient {
            x_pk: x_pk.to_bytes(),
            ml_ek: ml_ek.to_vec(),
        }
    }

    /// Decapsulate `ct = ct_ml || ct_x` into the 32-byte shared secret.
    pub fn decapsulate(&self, ct: &[u8]) -> Result<Key32> {
        if ct.len() != HYBRID_CT_LEN {
            return Err(Error::UnlockFailed);
        }
        let (ct_ml_bytes, ct_x_bytes) = ct.split_at(ML_KEM_1024_CT_LEN);

        let dk = ml_kem_1024::DecapsulationKey::from_seed((*self.ml_seed).into());
        let ct_ml: ml_kem::Ciphertext<MlKem1024> = ml_kem::Ciphertext::<MlKem1024>::try_from(
            ct_ml_bytes,
        )
        .map_err(|_| Error::UnlockFailed)?;
        let ss_ml = dk.decapsulate(&ct_ml);

        let x_secret = x25519_dalek::StaticSecret::from(*self.x_sk);
        let mut ct_x = [0u8; 32];
        ct_x.copy_from_slice(ct_x_bytes);
        let eph_pk = x25519_dalek::PublicKey::from(ct_x);
        let ss_x = x_secret.diffie_hellman(&eph_pk);
        if !ss_x.was_contributory() {
            return Err(Error::UnlockFailed);
        }

        let pk = self.public();
        Ok(combine(
            ss_ml.as_slice(),
            ss_x.as_bytes(),
            ct_ml_bytes,
            ct_x_bytes,
            &pk.ml_ek,
            &pk.x_pk,
        ))
    }
}

/// Encapsulate to a recipient: returns `(ct_ml || ct_x, shared_secret)`.
pub fn encapsulate(
    rng: &mut dyn EntropySource,
    recipient: &HybridRecipient,
) -> Result<(Vec<u8>, Key32)> {
    recipient.validate()?;

    // ML-KEM-1024 with fresh uniform randomness m (the standard encap path,
    // expressed deterministically so core never needs a rand_core version).
    let ek_arr = ml_kem::Key::<ml_kem_1024::EncapsulationKey>::try_from(recipient.ml_ek.as_slice())
        .map_err(|_| Error::InvalidParameter("ML-KEM ek"))?;
    let ek = ml_kem_1024::EncapsulationKey::new(&ek_arr)
        .map_err(|_| Error::InvalidParameter("ML-KEM ek invalid"))?;
    let mut m = Zeroizing::new([0u8; 32]);
    rng.fill(m.as_mut());
    let (ct_ml, ss_ml) = ek.encapsulate_deterministic(&(*m).into());

    // X25519 with an ephemeral key.
    let mut eph = Zeroizing::new([0u8; 32]);
    rng.fill(eph.as_mut());
    let eph_secret = x25519_dalek::StaticSecret::from(*eph);
    let ct_x = x25519_dalek::PublicKey::from(&eph_secret);
    let their_pk = x25519_dalek::PublicKey::from(recipient.x_pk);
    let ss_x = eph_secret.diffie_hellman(&their_pk);
    if !ss_x.was_contributory() {
        return Err(Error::InvalidParameter("non-contributory X25519 key"));
    }

    let mut ct = Vec::with_capacity(HYBRID_CT_LEN);
    ct.extend_from_slice(ct_ml.as_slice());
    ct.extend_from_slice(ct_x.as_bytes());

    let ss = combine(
        ss_ml.as_slice(),
        ss_x.as_bytes(),
        ct_ml.as_slice(),
        ct_x.as_bytes(),
        &recipient.ml_ek,
        &recipient.x_pk,
    );
    Ok((ct, ss))
}

fn combine(
    ss_ml: &[u8],
    ss_x: &[u8],
    ct_ml: &[u8],
    ct_x: &[u8],
    ek_ml: &[u8],
    pk_x: &[u8],
) -> Key32 {
    let mut h = Sha3_256::new();
    h.update(COMBINER_LABEL);
    h.update(ss_ml);
    h.update(ss_x);
    h.update(ct_ml);
    h.update(ct_x);
    h.update(ek_ml);
    h.update(pk_x);
    let out = h.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    Key32::from_bytes(key)
}

// ---------------------------------------------------------------------------
// Identity files
// ---------------------------------------------------------------------------

const IDENTITY_MAGIC: &[u8; 8] = b"TSRID\x01\x00\x00";

#[derive(Debug, Encode, Decode)]
struct IdentityFileCbor {
    #[n(0)]
    kem_id: u16,
    #[n(1)]
    public: HybridRecipient,
    /// None => `blob` is the plain CBOR secret; Some => sealed.
    #[n(2)]
    kdf: Option<KdfParams>,
    #[cbor(n(3), with = "minicbor::bytes")]
    nonce: Vec<u8>,
    #[cbor(n(4), with = "minicbor::bytes")]
    blob: Vec<u8>,
}

#[derive(Encode, Decode)]
struct IdentitySecretCbor {
    #[cbor(n(0), with = "minicbor::bytes")]
    x_sk: [u8; 32],
    #[cbor(n(1), with = "minicbor::bytes")]
    ml_seed: [u8; 64],
}

impl Drop for IdentitySecretCbor {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.x_sk.zeroize();
        self.ml_seed.zeroize();
    }
}

/// Serialize an identity, optionally sealed under a passphrase
/// (Argon2id + committing XChaCha20-Poly1305).
pub fn seal_identity(
    identity: &HybridIdentity,
    passphrase: Option<&[u8]>,
    rng: &mut dyn EntropySource,
) -> Result<Vec<u8>> {
    let secret = IdentitySecretCbor {
        x_sk: *identity.x_sk,
        ml_seed: *identity.ml_seed,
    };
    let secret_bytes = Zeroizing::new(minicbor::to_vec(&secret)?);

    let (kdf, nonce, blob) = match passphrase {
        None => (None, Vec::new(), secret_bytes.to_vec()),
        Some(pw) => {
            let mut salt = [0u8; kdf::SALT_LEN];
            rng.fill(&mut salt);
            let params = KdfParams::argon2_default(salt);
            let kek = kdf::derive_kek(&params, pw)?;
            let mut nonce = vec![0u8; aeadx::nonce_len(AeadId::XChaCha20Poly1305)?];
            rng.fill(&mut nonce);
            let blob = aeadx::seal(
                AeadId::XChaCha20Poly1305,
                kek.as_ref(),
                &nonce,
                IDENTITY_MAGIC,
                &secret_bytes,
            )?;
            (Some(params), nonce, blob)
        }
    };

    let file = IdentityFileCbor {
        kem_id: KemId::HybridX25519MlKem1024.as_u16(),
        public: identity.public(),
        kdf,
        nonce,
        blob,
    };
    let mut out = Vec::new();
    out.extend_from_slice(IDENTITY_MAGIC);
    out.extend_from_slice(&minicbor::to_vec(&file)?);
    Ok(out)
}

/// Parse the public half without any passphrase.
pub fn identity_public(bytes: &[u8]) -> Result<HybridRecipient> {
    let file = parse_identity(bytes)?;
    file.public.validate()?;
    Ok(file.public)
}

/// True if the identity file needs a passphrase to open.
pub fn identity_is_sealed(bytes: &[u8]) -> Result<bool> {
    Ok(parse_identity(bytes)?.kdf.is_some())
}

fn parse_identity(bytes: &[u8]) -> Result<IdentityFileCbor> {
    if bytes.len() < 8 + 8 || &bytes[..8] != IDENTITY_MAGIC {
        return Err(Error::BadMagic);
    }
    if bytes.len() > 64 * 1024 {
        return Err(Error::MalformedHeader("identity file too large"));
    }
    Ok(minicbor::decode(&bytes[8..])?)
}

/// Open an identity file (with passphrase if sealed).
pub fn open_identity(bytes: &[u8], passphrase: Option<&[u8]>) -> Result<HybridIdentity> {
    let file = parse_identity(bytes)?;
    if KemId::from_u16(file.kem_id)? != KemId::HybridX25519MlKem1024 {
        return Err(Error::UnknownAlgorithm(file.kem_id));
    }
    let secret_bytes = match (&file.kdf, passphrase) {
        (None, _) => Zeroizing::new(file.blob.clone()),
        (Some(params), Some(pw)) => {
            let kek = kdf::derive_kek(params, pw)?;
            let pt = aeadx::open(
                AeadId::XChaCha20Poly1305,
                kek.as_ref(),
                &file.nonce,
                IDENTITY_MAGIC,
                &file.blob,
            )?;
            Zeroizing::new(pt.as_slice().to_vec())
        }
        (Some(_), None) => return Err(Error::UnlockFailed),
    };
    let secret: IdentitySecretCbor = minicbor::decode(&secret_bytes)?;
    let id = HybridIdentity::from_parts(secret.x_sk, secret.ml_seed);
    // sanity: stored public must match the secret
    if id.public() != file.public {
        return Err(Error::UnlockFailed);
    }
    Ok(id)
}

#[cfg(test)]
pub(crate) fn test_rng(seed: u8) -> impl FnMut(&mut [u8]) {
    let mut h = blake3::Hasher::new();
    h.update(&[seed]);
    let mut xof = h.finalize_xof();
    move |buf: &mut [u8]| {
        use std::io::Read;
        xof.read_exact(buf).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_roundtrip() {
        let mut rng = test_rng(1);
        let id = HybridIdentity::generate(&mut rng);
        let pk = id.public();
        let (ct, ss_enc) = encapsulate(&mut rng, &pk).unwrap();
        assert_eq!(ct.len(), HYBRID_CT_LEN);
        let ss_dec = id.decapsulate(&ct).unwrap();
        assert_eq!(ss_enc.as_bytes(), ss_dec.as_bytes());
    }

    #[test]
    fn wrong_identity_fails_or_differs() {
        let mut rng = test_rng(2);
        let id1 = HybridIdentity::generate(&mut rng);
        let id2 = HybridIdentity::generate(&mut rng);
        let (ct, ss) = encapsulate(&mut rng, &id1.public()).unwrap();
        // ML-KEM implicit rejection: decap with the wrong key yields a
        // different secret, never the right one.
        let ss2 = id2.decapsulate(&ct).unwrap();
        assert_ne!(ss.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn tampered_ct_changes_secret() {
        let mut rng = test_rng(3);
        let id = HybridIdentity::generate(&mut rng);
        let (mut ct, ss) = encapsulate(&mut rng, &id.public()).unwrap();
        ct[0] ^= 1;
        let ss2 = id.decapsulate(&ct).unwrap();
        assert_ne!(ss.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn identity_file_plain_roundtrip() {
        let mut rng = test_rng(4);
        let id = HybridIdentity::generate(&mut rng);
        let bytes = seal_identity(&id, None, &mut rng).unwrap();
        assert!(!identity_is_sealed(&bytes).unwrap());
        let id2 = open_identity(&bytes, None).unwrap();
        assert_eq!(id.public(), id2.public());
    }

    #[test]
    fn identity_file_sealed_roundtrip() {
        let mut rng = test_rng(5);
        let id = HybridIdentity::generate(&mut rng);
        let bytes = seal_identity(&id, Some(b"hunter2"), &mut rng).unwrap();
        assert!(identity_is_sealed(&bytes).unwrap());
        // public extractable without passphrase
        assert_eq!(identity_public(&bytes).unwrap(), id.public());
        // wrong passphrase fails
        assert!(open_identity(&bytes, Some(b"wrong")).is_err());
        assert!(open_identity(&bytes, None).is_err());
        let id2 = open_identity(&bytes, Some(b"hunter2")).unwrap();
        assert_eq!(id.public(), id2.public());
    }
}
