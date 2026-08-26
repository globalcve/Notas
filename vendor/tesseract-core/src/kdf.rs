//! Passphrase KDFs. Argon2id is the default; scrypt and PBKDF2-HMAC are
//! offered for compatibility-minded users; Balloon is experimental and gated.
//!
//! Parameters are benchmarked at create time (by the agent — core has no
//! clock) and stored per keyslot. The PIM-equivalent "cost knob" maps onto
//! Argon2id time cost; for deniable headers, where nothing can be stored in
//! plaintext, the parameters are fixed constants plus the user's PIM.

use minicbor::{Decode, Encode};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::registry::{HashId, KdfId};

pub const KEK_LEN: usize = 32;
pub const SALT_LEN: usize = 32;

/// Per-slot KDF parameters, stored in the header (standard profile) or fixed
/// by convention + PIM (deniable profile).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum KdfParams {
    #[n(0)]
    Argon2id {
        /// memory in KiB
        #[n(0)]
        m_kib: u32,
        #[n(1)]
        t_cost: u32,
        #[n(2)]
        p_cost: u32,
        #[cbor(n(3), with = "minicbor::bytes")]
        salt: [u8; SALT_LEN],
    },
    #[n(1)]
    Scrypt {
        #[n(0)]
        log_n: u8,
        #[n(1)]
        r: u32,
        #[n(2)]
        p: u32,
        #[cbor(n(3), with = "minicbor::bytes")]
        salt: [u8; SALT_LEN],
    },
    #[n(2)]
    Pbkdf2 {
        #[n(0)]
        iters: u32,
        /// PRF hash: SHA-512 (default) or SHA-256.
        #[n(1)]
        hash: u16,
        #[cbor(n(3), with = "minicbor::bytes")]
        salt: [u8; SALT_LEN],
    },
    #[n(3)]
    Balloon {
        #[n(0)]
        s_cost: u32,
        #[n(1)]
        t_cost: u32,
        #[cbor(n(3), with = "minicbor::bytes")]
        salt: [u8; SALT_LEN],
    },
}

impl KdfParams {
    pub fn id(&self) -> KdfId {
        match self {
            KdfParams::Argon2id { .. } => KdfId::Argon2id,
            KdfParams::Scrypt { .. } => KdfId::Scrypt,
            KdfParams::Pbkdf2 { .. } => KdfId::Pbkdf2,
            KdfParams::Balloon { .. } => KdfId::Balloon,
        }
    }

    pub fn salt(&self) -> &[u8; SALT_LEN] {
        match self {
            KdfParams::Argon2id { salt, .. }
            | KdfParams::Scrypt { salt, .. }
            | KdfParams::Pbkdf2 { salt, .. }
            | KdfParams::Balloon { salt, .. } => salt,
        }
    }

    /// Default Argon2id parameters before benchmarking: 512 MiB, t=4, p=4.
    pub fn argon2_default(salt: [u8; SALT_LEN]) -> Self {
        KdfParams::Argon2id {
            m_kib: 512 * 1024,
            t_cost: 4,
            p_cost: 4,
            salt,
        }
    }

    /// Fixed parameters for deniable headers (nothing stored in plaintext):
    /// Argon2id 512 MiB, t = 4 + PIM, p = 4. The same PIM must be supplied at
    /// every unlock, exactly like VeraCrypt's PIM.
    pub fn deniable(salt: [u8; SALT_LEN], pim: u32) -> Self {
        KdfParams::Argon2id {
            m_kib: 512 * 1024,
            t_cost: 4 + pim,
            p_cost: 4,
            salt,
        }
    }

    /// Low-cost parameters for keyfile-only slots (the keyfile already has
    /// full entropy; the KDF only adds domain separation and a salt).
    pub fn keyfile_slot(salt: [u8; SALT_LEN]) -> Self {
        KdfParams::Argon2id {
            m_kib: 64 * 1024,
            t_cost: 1,
            p_cost: 4,
            salt,
        }
    }

    /// Apply the user cost knob (PIM-equivalent, 0 = leave as benchmarked):
    /// each step adds one Argon2id pass.
    pub fn with_pim(self, pim: u32) -> Self {
        match self {
            KdfParams::Argon2id {
                m_kib,
                t_cost,
                p_cost,
                salt,
            } => KdfParams::Argon2id {
                m_kib,
                t_cost: t_cost + pim,
                p_cost,
                salt,
            },
            other => other,
        }
    }

    pub fn validate(&self) -> Result<()> {
        match *self {
            KdfParams::Argon2id {
                m_kib,
                t_cost,
                p_cost,
                ..
            } => {
                if !(8 * 1024..=8 * 1024 * 1024).contains(&m_kib)
                    || !(1..=64).contains(&t_cost)
                    || !(1..=64).contains(&p_cost)
                {
                    return Err(Error::InvalidParameter("argon2 cost out of range"));
                }
            }
            KdfParams::Scrypt { log_n, r, p, .. } => {
                if !(10..=24).contains(&log_n) || !(1..=32).contains(&r) || !(1..=16).contains(&p)
                {
                    return Err(Error::InvalidParameter("scrypt cost out of range"));
                }
            }
            KdfParams::Pbkdf2 { iters, hash, .. } => {
                let h = HashId::from_u16(hash)?;
                if !matches!(h, HashId::Sha512 | HashId::Sha256) {
                    return Err(Error::InvalidParameter(
                        "pbkdf2 PRF must be SHA-512/SHA-256",
                    ));
                }
                if !(100_000..=100_000_000).contains(&iters) {
                    return Err(Error::InvalidParameter("pbkdf2 iterations out of range"));
                }
            }
            KdfParams::Balloon { s_cost, t_cost, .. } => {
                if !cfg!(feature = "experimental") {
                    return Err(Error::ExperimentalGated("Balloon"));
                }
                if !(1024..=4 * 1024 * 1024).contains(&s_cost) || !(1..=64).contains(&t_cost) {
                    return Err(Error::InvalidParameter("balloon cost out of range"));
                }
            }
        }
        Ok(())
    }
}

/// Run the KDF, producing a 32-byte KEK.
pub fn derive_kek(params: &KdfParams, secret: &[u8]) -> Result<Zeroizing<[u8; KEK_LEN]>> {
    params.validate()?;
    let mut out = Zeroizing::new([0u8; KEK_LEN]);
    match params {
        KdfParams::Argon2id {
            m_kib,
            t_cost,
            p_cost,
            salt,
        } => {
            let p = argon2::Params::new(*m_kib, *t_cost, *p_cost, Some(KEK_LEN))
                .map_err(|_| Error::InvalidParameter("argon2 params"))?;
            let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, p);
            a.hash_password_into(secret, salt, out.as_mut())
                .map_err(|_| Error::InvalidParameter("argon2 failed"))?;
        }
        KdfParams::Scrypt { log_n, r, p, salt } => {
            let params = scrypt::Params::new(*log_n, *r, *p)
                .map_err(|_| Error::InvalidParameter("scrypt params"))?;
            scrypt::scrypt(secret, salt, &params, out.as_mut())
                .map_err(|_| Error::InvalidParameter("scrypt failed"))?;
        }
        KdfParams::Pbkdf2 { iters, hash, salt } => match HashId::from_u16(*hash)? {
            HashId::Sha512 => {
                pbkdf2::pbkdf2_hmac::<sha2::Sha512>(secret, salt, *iters, out.as_mut())
            }
            HashId::Sha256 => {
                pbkdf2::pbkdf2_hmac::<sha2::Sha256>(secret, salt, *iters, out.as_mut())
            }
            _ => return Err(Error::InvalidParameter("pbkdf2 PRF")),
        },
        #[cfg(feature = "experimental")]
        KdfParams::Balloon {
            s_cost,
            t_cost,
            salt,
        } => {
            let params = balloon_hash::Params::new(*s_cost, *t_cost, 1)
                .map_err(|_| Error::InvalidParameter("balloon params"))?;
            let b = balloon_hash::Balloon::<sha2_010::Sha256>::new(
                balloon_hash::Algorithm::Balloon,
                params,
                None,
            );
            let h = b
                .hash(secret, salt)
                .map_err(|_| Error::InvalidParameter("balloon failed"))?;
            out.copy_from_slice(h.as_slice());
        }
        #[cfg(not(feature = "experimental"))]
        KdfParams::Balloon { .. } => return Err(Error::ExperimentalGated("Balloon")),
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Argon2id reference vector (phc-winner-argon2 README):
    /// `argon2id, t=2, m=2^16 KiB, p=1, pwd="password", salt="somesalt"`.
    #[test]
    fn argon2id_kat() {
        let p = argon2::Params::new(65536, 2, 1, Some(32)).unwrap();
        let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, p);
        let mut out = [0u8; 32];
        a.hash_password_into(b"password", b"somesalt", &mut out)
            .unwrap();
        assert_eq!(
            hex::encode(out),
            "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7"
        );
    }

    /// scrypt KAT from RFC 7914 §12: N=1024, r=8, p=16, P="password", S="NaCl".
    #[test]
    fn scrypt_kat() {
        let params = scrypt::Params::new(10, 8, 16).unwrap();
        let mut out = [0u8; 64];
        scrypt::scrypt(b"password", b"NaCl", &params, &mut out).unwrap();
        assert_eq!(
            hex::encode(out),
            "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"
        );
    }

    /// PBKDF2-HMAC-SHA512, 1 iteration, P="password", S="salt" (public KAT).
    #[test]
    fn pbkdf2_sha512_kat() {
        let mut out = [0u8; 64];
        pbkdf2::pbkdf2_hmac::<sha2::Sha512>(b"password", b"salt", 1, &mut out);
        assert_eq!(
            hex::encode(out),
            "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce"
        );
    }

    #[test]
    fn params_validation() {
        assert!(KdfParams::argon2_default([0; 32]).validate().is_ok());
        assert!(KdfParams::Argon2id {
            m_kib: 1,
            t_cost: 1,
            p_cost: 1,
            salt: [0; 32]
        }
        .validate()
        .is_err());
        let p = KdfParams::argon2_default([0; 32]).with_pim(7);
        assert!(matches!(p, KdfParams::Argon2id { t_cost: 11, .. }));
    }

    #[test]
    fn derive_kek_deterministic() {
        let params = KdfParams::Argon2id {
            m_kib: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
            salt: [7; 32],
        };
        let a = derive_kek(&params, b"pw").unwrap();
        let b = derive_kek(&params, b"pw").unwrap();
        assert_eq!(a.as_ref(), b.as_ref());
        let c = derive_kek(&params, b"pw2").unwrap();
        assert_ne!(a.as_ref(), c.as_ref());
    }

    #[test]
    fn cbor_roundtrip() {
        let p = KdfParams::argon2_default([9; 32]);
        let bytes = minicbor::to_vec(&p).unwrap();
        let q: KdfParams = minicbor::decode(&bytes).unwrap();
        assert_eq!(p, q);
    }
}
