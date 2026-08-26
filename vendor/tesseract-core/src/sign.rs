//! Signatures for attested volumes and file-mode authenticity.
//!
//! Classical (Ed25519) and post-quantum (ML-DSA-44/65/87) schemes, plus a
//! "joint" mode where BOTH a classical and a PQ signature must verify
//! (attested volumes can require classical + PQC jointly per the brief).

use ed25519_dalek::Signer as _;
use minicbor::{Decode, Encode};
use ml_dsa::signature::{Signer as MlSigner, Verifier as MlVerifier};
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::registry::SigId;
use crate::EntropySource;

/// A detached signature bundle: scheme, public key, signature bytes.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct SigBundle {
    #[n(0)]
    pub sig_id: u16,
    #[cbor(n(1), with = "minicbor::bytes")]
    pub public_key: Vec<u8>,
    #[cbor(n(2), with = "minicbor::bytes")]
    pub signature: Vec<u8>,
}

/// Signing identity: 32-byte seeds for each scheme (expanded on use).
pub struct SignerIdentity {
    sig_id: SigId,
    seed: Zeroizing<[u8; 32]>,
}

impl core::fmt::Debug for SignerIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SignerIdentity({:?}, [REDACTED])", self.sig_id)
    }
}

impl SignerIdentity {
    pub fn generate(sig_id: SigId, rng: &mut dyn EntropySource) -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        rng.fill(seed.as_mut());
        Self { sig_id, seed }
    }

    pub fn from_seed(sig_id: SigId, seed: [u8; 32]) -> Self {
        Self {
            sig_id,
            seed: Zeroizing::new(seed),
        }
    }

    pub fn sig_id(&self) -> SigId {
        self.sig_id
    }

    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    pub fn public_key(&self) -> Vec<u8> {
        match self.sig_id {
            SigId::Ed25519 => {
                let sk = ed25519_dalek::SigningKey::from_bytes(&self.seed);
                sk.verifying_key().to_bytes().to_vec()
            }
            SigId::MlDsa44 => {
                let kp = SigningKey::<MlDsa44>::from_seed((&*self.seed).into());
                let vk: &VerifyingKey<MlDsa44> = kp.as_ref();
                vk.encode().to_vec()
            }
            SigId::MlDsa65 => {
                let kp = SigningKey::<MlDsa65>::from_seed((&*self.seed).into());
                let vk: &VerifyingKey<MlDsa65> = kp.as_ref();
                vk.encode().to_vec()
            }
            SigId::MlDsa87 => {
                let kp = SigningKey::<MlDsa87>::from_seed((&*self.seed).into());
                let vk: &VerifyingKey<MlDsa87> = kp.as_ref();
                vk.encode().to_vec()
            }
        }
    }

    /// Detached signature over `msg`.
    pub fn sign(&self, msg: &[u8]) -> SigBundle {
        let signature = match self.sig_id {
            SigId::Ed25519 => {
                let sk = ed25519_dalek::SigningKey::from_bytes(&self.seed);
                sk.sign(msg).to_bytes().to_vec()
            }
            SigId::MlDsa44 => {
                let kp = SigningKey::<MlDsa44>::from_seed((&*self.seed).into());
                kp.sign(msg).encode().to_vec()
            }
            SigId::MlDsa65 => {
                let kp = SigningKey::<MlDsa65>::from_seed((&*self.seed).into());
                kp.sign(msg).encode().to_vec()
            }
            SigId::MlDsa87 => {
                let kp = SigningKey::<MlDsa87>::from_seed((&*self.seed).into());
                kp.sign(msg).encode().to_vec()
            }
        };
        SigBundle {
            sig_id: self.sig_id.as_u16(),
            public_key: self.public_key(),
            signature,
        }
    }
}

/// Verify one bundle over `msg`.
pub fn verify(bundle: &SigBundle, msg: &[u8]) -> Result<()> {
    let sig_id = SigId::from_u16(bundle.sig_id)?;
    let ok = match sig_id {
        SigId::Ed25519 => {
            let pk: [u8; 32] = bundle
                .public_key
                .as_slice()
                .try_into()
                .map_err(|_| Error::BadSignature)?;
            let vk =
                ed25519_dalek::VerifyingKey::from_bytes(&pk).map_err(|_| Error::BadSignature)?;
            let sig_bytes: [u8; 64] = bundle
                .signature
                .as_slice()
                .try_into()
                .map_err(|_| Error::BadSignature)?;
            let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
            vk.verify_strict(msg, &sig).is_ok()
        }
        SigId::MlDsa44 => verify_mldsa::<MlDsa44>(bundle, msg)?,
        SigId::MlDsa65 => verify_mldsa::<MlDsa65>(bundle, msg)?,
        SigId::MlDsa87 => verify_mldsa::<MlDsa87>(bundle, msg)?,
    };
    if ok {
        Ok(())
    } else {
        Err(Error::BadSignature)
    }
}

fn verify_mldsa<P: ml_dsa::MlDsaParams>(bundle: &SigBundle, msg: &[u8]) -> Result<bool> {
    let enc = ml_dsa::EncodedVerifyingKey::<P>::try_from(bundle.public_key.as_slice())
        .map_err(|_| Error::BadSignature)?;
    let vk = VerifyingKey::<P>::decode(&enc);
    let sig_enc = ml_dsa::EncodedSignature::<P>::try_from(bundle.signature.as_slice())
        .map_err(|_| Error::BadSignature)?;
    let sig = ml_dsa::Signature::<P>::decode(&sig_enc).ok_or(Error::BadSignature)?;
    Ok(vk.verify(msg, &sig).is_ok())
}

/// Verify a set of bundles; `require_all` = joint classical+PQ mode.
/// With `require_all = false`, one valid bundle suffices.
pub fn verify_set(bundles: &[SigBundle], msg: &[u8], require_all: bool) -> Result<()> {
    if bundles.is_empty() {
        return Err(Error::BadSignature);
    }
    if require_all {
        for b in bundles {
            verify(b, msg)?;
        }
        Ok(())
    } else {
        for b in bundles {
            if verify(b, msg).is_ok() {
                return Ok(());
            }
        }
        Err(Error::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem::test_rng;

    #[test]
    fn sign_verify_all_schemes() {
        let mut rng = test_rng(10);
        for sig_id in [SigId::Ed25519, SigId::MlDsa44, SigId::MlDsa65, SigId::MlDsa87] {
            let signer = SignerIdentity::generate(sig_id, &mut rng);
            let bundle = signer.sign(b"attest this header");
            verify(&bundle, b"attest this header").unwrap();
            assert!(verify(&bundle, b"attest other data").is_err(), "{:?}", sig_id);
            let mut bad = bundle.clone();
            bad.signature[0] ^= 1;
            assert!(verify(&bad, b"attest this header").is_err());
        }
    }

    #[test]
    fn joint_mode_requires_both() {
        let mut rng = test_rng(11);
        let ed = SignerIdentity::generate(SigId::Ed25519, &mut rng);
        let pq = SignerIdentity::generate(SigId::MlDsa87, &mut rng);
        let msg = b"volume header";
        let b1 = ed.sign(msg);
        let mut b2 = pq.sign(msg);
        verify_set(&[b1.clone(), b2.clone()], msg, true).unwrap();
        b2.signature[10] ^= 0xFF;
        assert!(verify_set(&[b1.clone(), b2.clone()], msg, true).is_err());
        // any-of mode still passes with one good signature
        verify_set(&[b1, b2], msg, false).unwrap();
    }

    /// Ed25519 RFC 8032 test vector 1 (empty message).
    #[test]
    fn ed25519_rfc8032_kat() {
        let seed: [u8; 32] = hex::decode(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        )
        .unwrap()
        .try_into()
        .unwrap();
        let signer = SignerIdentity::from_seed(SigId::Ed25519, seed);
        assert_eq!(
            hex::encode(signer.public_key()),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let bundle = signer.sign(b"");
        assert_eq!(
            hex::encode(&bundle.signature),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
    }
}
