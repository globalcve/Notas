//! Keyslots: LUKS2-style independent AEAD-sealed copies of the VMK.
//!
//! Every slot type produces a 32-byte KEK; the VMK is sealed under that KEK
//! with the committing AEAD (see `aeadx`). Adding/rotating slots never
//! re-encrypts data. The slot AAD binds the volume's "header essentials"
//! digest (uuid, geometry, cascade, flags), so a slot cannot be transplanted
//! onto a tampered header.

use minicbor::{Decode, Encode};

use crate::aeadx;
use crate::error::{Error, Result};
use crate::kdf::{self, KdfParams};
use crate::kem::{self, HybridIdentity, HybridRecipient};
use crate::keyfile::{mix_secret, KEYFILE_DIGEST_LEN};
use crate::kmac;
use crate::registry::AeadId;
use crate::secret::{Vmk, VMK_LEN};
use crate::EntropySource;

pub const MAX_SLOTS: usize = 16;

/// FIDO2 hmac-secret slot metadata. The agent performs CTAP2; core only
/// derives the KEK from the authenticator's hmac-secret output.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct Fido2Meta {
    #[cbor(n(0), with = "minicbor::bytes")]
    pub credential_id: Vec<u8>,
    #[n(1)]
    pub rp_id: String,
    /// Salt handed to hmac-secret (public, fixed per slot).
    #[cbor(n(2), with = "minicbor::bytes")]
    pub hmac_salt: [u8; 32],
    /// Require a PIN/UV during assertion.
    #[n(3)]
    pub require_uv: bool,
}

/// What credential opens this slot.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum SlotKind {
    /// Passphrase (+ optional keyfiles mixed in by the caller).
    #[n(0)]
    Passphrase,
    /// Hybrid PQC: X25519 + ML-KEM-1024 encapsulation stored in the slot.
    #[n(1)]
    HybridPqc {
        #[cbor(n(0), with = "minicbor::bytes")]
        kem_ct: Vec<u8>,
        /// Fingerprint of the recipient identity (display only).
        #[cbor(n(1), with = "minicbor::bytes")]
        recipient_fp: [u8; 16],
    },
    /// Keyfile(s) only, no passphrase.
    #[n(2)]
    Keyfile,
    /// FIDO2 hmac-secret.
    #[n(3)]
    Fido2(#[n(0)] Fido2Meta),
}

/// One sealed copy of the VMK.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct KeySlot {
    #[n(0)]
    pub id: u8,
    #[n(1)]
    pub kind: SlotKind,
    /// KDF over the credential secret (absent for HybridPqc: the KEM shared
    /// secret already has full entropy and is passed through KMAC instead).
    #[n(2)]
    pub kdf: Option<KdfParams>,
    #[n(3)]
    pub aead: u16,
    #[cbor(n(4), with = "minicbor::bytes")]
    pub nonce: Vec<u8>,
    /// `commitment(32) || AEAD(vmk)`.
    #[cbor(n(5), with = "minicbor::bytes")]
    pub sealed_vmk: Vec<u8>,
    #[n(6)]
    pub label: String,
    /// Unix seconds (set by the agent; core has no clock).
    #[n(7)]
    pub created_at: u64,
}

impl KeySlot {
    pub fn aead_id(&self) -> Result<AeadId> {
        AeadId::from_u16(self.aead)
    }

    pub fn kind_label(&self) -> &'static str {
        match self.kind {
            SlotKind::Passphrase => "passphrase",
            SlotKind::HybridPqc { .. } => "hybrid PQC",
            SlotKind::Keyfile => "keyfile",
            SlotKind::Fido2(_) => "FIDO2",
        }
    }

    pub fn validate(&self) -> Result<()> {
        let aead = self.aead_id()?;
        if self.nonce.len() != aeadx::nonce_len(aead)? {
            return Err(Error::MalformedHeader("slot nonce length"));
        }
        if self.sealed_vmk.len() != aeadx::COMMITMENT_LEN + VMK_LEN + 16 {
            return Err(Error::MalformedHeader("slot sealed length"));
        }
        if self.label.len() > 128 {
            return Err(Error::MalformedHeader("slot label too long"));
        }
        if let Some(k) = &self.kdf {
            k.validate()?;
        }
        match &self.kind {
            SlotKind::HybridPqc { kem_ct, .. } => {
                if kem_ct.len() != kem::HYBRID_CT_LEN {
                    return Err(Error::MalformedHeader("slot kem ct length"));
                }
                if self.kdf.is_some() {
                    return Err(Error::MalformedHeader("hybrid slot must not carry a KDF"));
                }
            }
            SlotKind::Passphrase | SlotKind::Keyfile => {
                if self.kdf.is_none() {
                    return Err(Error::MalformedHeader("slot missing KDF"));
                }
            }
            SlotKind::Fido2(meta) => {
                if self.kdf.is_none() {
                    return Err(Error::MalformedHeader("slot missing KDF"));
                }
                if meta.credential_id.len() > 1024 || meta.rp_id.len() > 256 {
                    return Err(Error::MalformedHeader("fido2 metadata too large"));
                }
            }
        }
        Ok(())
    }
}

/// The opened credential for a slot, produced by the caller (agent).
pub enum Credential<'a> {
    /// Passphrase plus already-digested keyfiles.
    Passphrase {
        passphrase: &'a [u8],
        keyfiles: &'a [[u8; KEYFILE_DIGEST_LEN]],
    },
    /// Keyfiles only.
    Keyfiles(&'a [[u8; KEYFILE_DIGEST_LEN]]),
    /// Hybrid identity (private key).
    Hybrid(&'a HybridIdentity),
    /// The authenticator's hmac-secret output for this slot's salt,
    /// optionally mixed with a passphrase.
    Fido2 {
        hmac_output: &'a [u8; 32],
        passphrase: Option<&'a [u8]>,
    },
}

impl core::fmt::Debug for Credential<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Credential([REDACTED])")
    }
}

fn fido2_secret(hmac_output: &[u8; 32], passphrase: Option<&[u8]>) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(hmac_output);
    if let Some(pw) = passphrase {
        buf.extend_from_slice(&kmac::kmac256_32(hmac_output, b"tsr/fido2-pw", pw));
    }
    buf
}

/// Derive the KEK for (slot, credential). For KDF slots this runs the KDF;
/// for hybrid slots it decapsulates and KMAC-finalizes.
fn derive_kek(slot: &KeySlot, cred: &Credential<'_>) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    match (&slot.kind, cred) {
        (SlotKind::Passphrase, Credential::Passphrase { passphrase, keyfiles }) => {
            let secret = mix_secret(passphrase, keyfiles);
            let params = slot.kdf.as_ref().ok_or(Error::UnlockFailed)?;
            kdf::derive_kek(params, secret.as_slice())
        }
        (SlotKind::Keyfile, Credential::Keyfiles(keyfiles)) => {
            if keyfiles.is_empty() {
                return Err(Error::UnlockFailed);
            }
            let secret = mix_secret(b"", keyfiles);
            let params = slot.kdf.as_ref().ok_or(Error::UnlockFailed)?;
            kdf::derive_kek(params, secret.as_slice())
        }
        (SlotKind::HybridPqc { kem_ct, .. }, Credential::Hybrid(identity)) => {
            let ss = identity.decapsulate(kem_ct)?;
            let mut kek = zeroize::Zeroizing::new([0u8; 32]);
            kmac::kmac256(ss.as_bytes(), kmac::L_HYBRID_KEM, b"slot-kek", kek.as_mut());
            Ok(kek)
        }
        (SlotKind::Fido2(_), Credential::Fido2 { hmac_output, passphrase }) => {
            let secret = fido2_secret(hmac_output, *passphrase);
            let params = slot.kdf.as_ref().ok_or(Error::UnlockFailed)?;
            kdf::derive_kek(params, &secret)
        }
        _ => Err(Error::UnlockFailed),
    }
}

/// Parameters for creating a slot.
#[derive(Debug)]
pub struct NewSlot<'a> {
    pub id: u8,
    pub aead: AeadId,
    pub label: String,
    pub created_at: u64,
    /// For KDF-based kinds. Ignored for hybrid.
    pub kdf: Option<KdfParams>,
    pub setup: SlotSetup<'a>,
}

/// Creation-time credential material.
pub enum SlotSetup<'a> {
    Passphrase {
        passphrase: &'a [u8],
        keyfiles: &'a [[u8; KEYFILE_DIGEST_LEN]],
    },
    Keyfiles(&'a [[u8; KEYFILE_DIGEST_LEN]]),
    Hybrid(&'a HybridRecipient),
    Fido2 {
        meta: Fido2Meta,
        hmac_output: &'a [u8; 32],
        passphrase: Option<&'a [u8]>,
    },
}

impl core::fmt::Debug for SlotSetup<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SlotSetup([REDACTED])")
    }
}

/// Seal the VMK into a new slot. `header_binding` is the essentials digest
/// of the owning header (AAD).
pub fn seal_slot(
    rng: &mut dyn EntropySource,
    vmk: &Vmk,
    new: NewSlot<'_>,
    header_binding: &[u8; 32],
) -> Result<KeySlot> {
    let mut nonce = vec![0u8; aeadx::nonce_len(new.aead)?];
    rng.fill(&mut nonce);

    let (kind, kdf_params, kek) = match new.setup {
        SlotSetup::Passphrase { passphrase, keyfiles } => {
            let params = new.kdf.ok_or(Error::InvalidParameter("KDF required"))?;
            let secret = mix_secret(passphrase, keyfiles);
            let kek = kdf::derive_kek(&params, secret.as_slice())?;
            (SlotKind::Passphrase, Some(params), kek)
        }
        SlotSetup::Keyfiles(keyfiles) => {
            if keyfiles.is_empty() {
                return Err(Error::InvalidParameter("at least one keyfile required"));
            }
            let params = new.kdf.ok_or(Error::InvalidParameter("KDF required"))?;
            let secret = mix_secret(b"", keyfiles);
            let kek = kdf::derive_kek(&params, secret.as_slice())?;
            (SlotKind::Keyfile, Some(params), kek)
        }
        SlotSetup::Hybrid(recipient) => {
            let (kem_ct, ss) = kem::encapsulate(rng, recipient)?;
            let mut kek = zeroize::Zeroizing::new([0u8; 32]);
            kmac::kmac256(ss.as_bytes(), kmac::L_HYBRID_KEM, b"slot-kek", kek.as_mut());
            (
                SlotKind::HybridPqc {
                    kem_ct,
                    recipient_fp: recipient.fingerprint(),
                },
                None,
                kek,
            )
        }
        SlotSetup::Fido2 { meta, hmac_output, passphrase } => {
            let params = new.kdf.ok_or(Error::InvalidParameter("KDF required"))?;
            let secret = fido2_secret(hmac_output, passphrase);
            let kek = kdf::derive_kek(&params, &secret)?;
            (SlotKind::Fido2(meta), Some(params), kek)
        }
    };

    let sealed_vmk = aeadx::seal(new.aead, kek.as_ref(), &nonce, header_binding, vmk.as_bytes())?;

    let slot = KeySlot {
        id: new.id,
        kind,
        kdf: kdf_params,
        aead: new.aead.as_u16(),
        nonce,
        sealed_vmk,
        label: new.label,
        created_at: new.created_at,
    };
    slot.validate()?;
    Ok(slot)
}

/// Try to open a slot with a credential. Returns the VMK or the generic
/// timing-flat unlock failure.
pub fn open_slot(
    slot: &KeySlot,
    cred: &Credential<'_>,
    header_binding: &[u8; 32],
) -> Result<Vmk> {
    slot.validate().map_err(|_| Error::UnlockFailed)?;
    let kek = derive_kek(slot, cred)?;
    let aead = slot.aead_id().map_err(|_| Error::UnlockFailed)?;
    let pt = aeadx::open(aead, kek.as_ref(), &slot.nonce, header_binding, &slot.sealed_vmk)?;
    let bytes: [u8; VMK_LEN] = pt.as_slice().try_into().map_err(|_| Error::UnlockFailed)?;
    Ok(Vmk::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem::test_rng;

    fn small_kdf() -> KdfParams {
        KdfParams::Argon2id {
            m_kib: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
            salt: [5; 32],
        }
    }

    fn binding() -> [u8; 32] {
        [0xBB; 32]
    }

    #[test]
    fn passphrase_slot_roundtrip() {
        let mut rng = test_rng(20);
        let vmk = Vmk::generate(&mut rng);
        let slot = seal_slot(
            &mut rng,
            &vmk,
            NewSlot {
                id: 0,
                aead: AeadId::XChaCha20Poly1305,
                label: "main".into(),
                created_at: 0,
                kdf: Some(small_kdf()),
                setup: SlotSetup::Passphrase {
                    passphrase: b"correct horse",
                    keyfiles: &[],
                },
            },
            &binding(),
        )
        .unwrap();

        let got = open_slot(
            &slot,
            &Credential::Passphrase {
                passphrase: b"correct horse",
                keyfiles: &[],
            },
            &binding(),
        )
        .unwrap();
        assert_eq!(got.as_bytes(), vmk.as_bytes());

        // wrong passphrase
        assert!(open_slot(
            &slot,
            &Credential::Passphrase {
                passphrase: b"wrong",
                keyfiles: &[],
            },
            &binding(),
        )
        .is_err());

        // wrong header binding (tampered header)
        assert!(open_slot(
            &slot,
            &Credential::Passphrase {
                passphrase: b"correct horse",
                keyfiles: &[],
            },
            &[0xCC; 32],
        )
        .is_err());
    }

    #[test]
    fn keyfile_changes_kek() {
        let mut rng = test_rng(21);
        let vmk = Vmk::generate(&mut rng);
        let kf = [[7u8; 64]];
        let slot = seal_slot(
            &mut rng,
            &vmk,
            NewSlot {
                id: 1,
                aead: AeadId::Aes256GcmSiv,
                label: String::new(),
                created_at: 0,
                kdf: Some(small_kdf()),
                setup: SlotSetup::Passphrase {
                    passphrase: b"pw",
                    keyfiles: &kf,
                },
            },
            &binding(),
        )
        .unwrap();
        // passphrase without keyfile fails
        assert!(open_slot(
            &slot,
            &Credential::Passphrase {
                passphrase: b"pw",
                keyfiles: &[],
            },
            &binding(),
        )
        .is_err());
        // with the keyfile succeeds
        open_slot(
            &slot,
            &Credential::Passphrase {
                passphrase: b"pw",
                keyfiles: &kf,
            },
            &binding(),
        )
        .unwrap();
    }

    #[test]
    fn hybrid_slot_roundtrip() {
        let mut rng = test_rng(22);
        let vmk = Vmk::generate(&mut rng);
        let identity = HybridIdentity::generate(&mut rng);
        let other = HybridIdentity::generate(&mut rng);
        let slot = seal_slot(
            &mut rng,
            &vmk,
            NewSlot {
                id: 2,
                aead: AeadId::XChaCha20Poly1305,
                label: "yubilike".into(),
                created_at: 0,
                kdf: None,
                setup: SlotSetup::Hybrid(&identity.public()),
            },
            &binding(),
        )
        .unwrap();

        let got = open_slot(&slot, &Credential::Hybrid(&identity), &binding()).unwrap();
        assert_eq!(got.as_bytes(), vmk.as_bytes());
        // wrong identity: implicit rejection => commitment failure
        assert!(open_slot(&slot, &Credential::Hybrid(&other), &binding()).is_err());
    }

    #[test]
    fn fido2_slot_roundtrip() {
        let mut rng = test_rng(23);
        let vmk = Vmk::generate(&mut rng);
        let meta = Fido2Meta {
            credential_id: vec![1, 2, 3],
            rp_id: "Tesseract.local".into(),
            hmac_salt: [9; 32],
            require_uv: true,
        };
        let hmac_out = [0x44; 32];
        let slot = seal_slot(
            &mut rng,
            &vmk,
            NewSlot {
                id: 3,
                aead: AeadId::XChaCha20Poly1305,
                label: "security key".into(),
                created_at: 0,
                kdf: Some(small_kdf()),
                setup: SlotSetup::Fido2 {
                    meta,
                    hmac_output: &hmac_out,
                    passphrase: Some(b"pin-extra"),
                },
            },
            &binding(),
        )
        .unwrap();
        let got = open_slot(
            &slot,
            &Credential::Fido2 {
                hmac_output: &hmac_out,
                passphrase: Some(b"pin-extra"),
            },
            &binding(),
        )
        .unwrap();
        assert_eq!(got.as_bytes(), vmk.as_bytes());
        assert!(open_slot(
            &slot,
            &Credential::Fido2 {
                hmac_output: &[0x45; 32],
                passphrase: Some(b"pin-extra"),
            },
            &binding(),
        )
        .is_err());
    }

    #[test]
    fn slot_cbor_roundtrip() {
        let mut rng = test_rng(24);
        let vmk = Vmk::generate(&mut rng);
        let slot = seal_slot(
            &mut rng,
            &vmk,
            NewSlot {
                id: 0,
                aead: AeadId::XChaCha20Poly1305,
                label: "x".into(),
                created_at: 1234,
                kdf: Some(small_kdf()),
                setup: SlotSetup::Passphrase {
                    passphrase: b"pw",
                    keyfiles: &[],
                },
            },
            &binding(),
        )
        .unwrap();
        let bytes = minicbor::to_vec(&slot).unwrap();
        let slot2: KeySlot = minicbor::decode(&bytes).unwrap();
        assert_eq!(slot, slot2);
    }
}
