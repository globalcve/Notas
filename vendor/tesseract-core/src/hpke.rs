//! HPKE (RFC 9180), base mode, implemented in-tree so the hybrid
//! X25519+ML-KEM-1024 KEM can plug in (no released crate offers one — see
//! DECISIONS.md D-05). Validated against the official RFC 9180 test vectors
//! (DHKEM(X25519)+HKDF-SHA256 with AES-128-GCM and ChaCha20Poly1305).
//!
//! KEM ids: 0x0020 = DHKEM(X25519, HKDF-SHA256) (RFC 9180);
//!          0x647A = X25519+ML-KEM-1024 hybrid (private use, QSF combiner).
//! KDF ids: 0x0001 = HKDF-SHA256, 0x0003 = HKDF-SHA512.
//! AEAD ids: 0x0001 = AES-128-GCM (KAT only), 0x0002 = AES-256-GCM,
//!           0x0003 = ChaCha20Poly1305.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::kem::{self, HybridIdentity, HybridRecipient};
use crate::EntropySource;

pub const KEM_X25519: u16 = 0x0020;
pub const KEM_HYBRID_X25519_MLKEM1024: u16 = 0x647A;
pub const KDF_HKDF_SHA256: u16 = 0x0001;
pub const KDF_HKDF_SHA512: u16 = 0x0003;
pub const AEAD_AES128GCM: u16 = 0x0001;
pub const AEAD_AES256GCM: u16 = 0x0002;
pub const AEAD_CHACHA20POLY1305: u16 = 0x0003;

const VERSION_LABEL: &[u8] = b"HPKE-v1";
const MODE_BASE: u8 = 0x00;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Suite {
    pub kem: u16,
    pub kdf: u16,
    pub aead: u16,
}

impl Suite {
    /// Tesseract's default file-mode suite.
    pub fn tesseract_default() -> Self {
        Suite {
            kem: KEM_HYBRID_X25519_MLKEM1024,
            kdf: KDF_HKDF_SHA512,
            aead: AEAD_CHACHA20POLY1305,
        }
    }

    fn nk(&self) -> usize {
        match self.aead {
            AEAD_AES128GCM => 16,
            AEAD_AES256GCM | AEAD_CHACHA20POLY1305 => 32,
            _ => 0,
        }
    }

    fn nh(&self) -> usize {
        match self.kdf {
            KDF_HKDF_SHA256 => 32,
            KDF_HKDF_SHA512 => 64,
            _ => 0,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if !matches!(self.kem, KEM_X25519 | KEM_HYBRID_X25519_MLKEM1024) {
            return Err(Error::UnknownAlgorithm(self.kem));
        }
        if !matches!(self.kdf, KDF_HKDF_SHA256 | KDF_HKDF_SHA512) {
            return Err(Error::UnknownAlgorithm(self.kdf));
        }
        if !matches!(
            self.aead,
            AEAD_AES128GCM | AEAD_AES256GCM | AEAD_CHACHA20POLY1305
        ) {
            return Err(Error::UnknownAlgorithm(self.aead));
        }
        Ok(())
    }

    fn hpke_suite_id(&self) -> [u8; 10] {
        let mut id = [0u8; 10];
        id[..4].copy_from_slice(b"HPKE");
        id[4..6].copy_from_slice(&self.kem.to_be_bytes());
        id[6..8].copy_from_slice(&self.kdf.to_be_bytes());
        id[8..10].copy_from_slice(&self.aead.to_be_bytes());
        id
    }
}

fn hkdf_extract(kdf: u16, salt: &[u8], ikm: &[u8]) -> Zeroizing<Vec<u8>> {
    match kdf {
        KDF_HKDF_SHA256 => {
            let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
            Zeroizing::new(prk.to_vec())
        }
        _ => {
            let (prk, _) = Hkdf::<Sha512>::extract(Some(salt), ikm);
            Zeroizing::new(prk.to_vec())
        }
    }
}

fn hkdf_expand(kdf: u16, prk: &[u8], info: &[u8], len: usize) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(vec![0u8; len]);
    match kdf {
        KDF_HKDF_SHA256 => Hkdf::<Sha256>::from_prk(prk)
            .expect("prk length")
            .expand(info, &mut out)
            .expect("expand length"),
        _ => Hkdf::<Sha512>::from_prk(prk)
            .expect("prk length")
            .expand(info, &mut out)
            .expect("expand length"),
    }
    out
}

fn labeled_extract(
    kdf: u16,
    suite_id: &[u8],
    salt: &[u8],
    label: &[u8],
    ikm: &[u8],
) -> Zeroizing<Vec<u8>> {
    let mut labeled = Zeroizing::new(Vec::with_capacity(
        VERSION_LABEL.len() + suite_id.len() + label.len() + ikm.len(),
    ));
    labeled.extend_from_slice(VERSION_LABEL);
    labeled.extend_from_slice(suite_id);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(ikm);
    hkdf_extract(kdf, salt, &labeled)
}

fn labeled_expand(
    kdf: u16,
    suite_id: &[u8],
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    len: usize,
) -> Zeroizing<Vec<u8>> {
    let mut labeled = Zeroizing::new(Vec::with_capacity(
        2 + VERSION_LABEL.len() + suite_id.len() + label.len() + info.len(),
    ));
    labeled.extend_from_slice(&(len as u16).to_be_bytes());
    labeled.extend_from_slice(VERSION_LABEL);
    labeled.extend_from_slice(suite_id);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(info);
    hkdf_expand(kdf, prk, &labeled, len)
}

// ---------------------------------------------------------------------------
// KEMs
// ---------------------------------------------------------------------------

/// Recipient public key for HPKE.
#[derive(Debug, Clone)]
pub enum RecipientPk {
    X25519([u8; 32]),
    Hybrid(HybridRecipient),
}

/// Recipient private key for HPKE.
pub enum RecipientSk<'a> {
    X25519(&'a [u8; 32]),
    Hybrid(&'a HybridIdentity),
}

impl core::fmt::Debug for RecipientSk<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecipientSk([REDACTED])")
    }
}

/// DHKEM(X25519, HKDF-SHA256) — always HKDF-SHA256 per RFC 9180 §4.1
/// regardless of the suite KDF.
fn x25519_kem_suite_id() -> [u8; 5] {
    let mut id = [0u8; 5];
    id[..3].copy_from_slice(b"KEM");
    id[3..].copy_from_slice(&KEM_X25519.to_be_bytes());
    id
}

fn dhkem_extract_and_expand(dh: &[u8], kem_context: &[u8]) -> Zeroizing<Vec<u8>> {
    let sid = x25519_kem_suite_id();
    let eae_prk = labeled_extract(KDF_HKDF_SHA256, &sid, b"", b"eae_prk", dh);
    labeled_expand(
        KDF_HKDF_SHA256,
        &sid,
        &eae_prk,
        b"shared_secret",
        kem_context,
        32,
    )
}

fn x25519_encap_det(pk_r: &[u8; 32], sk_e: &[u8; 32]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    let sk = x25519_dalek::StaticSecret::from(*sk_e);
    let pk_e = x25519_dalek::PublicKey::from(&sk);
    let their = x25519_dalek::PublicKey::from(*pk_r);
    let dh = sk.diffie_hellman(&their);
    if !dh.was_contributory() {
        return Err(Error::InvalidParameter("non-contributory X25519"));
    }
    let mut kem_context = Vec::with_capacity(64);
    kem_context.extend_from_slice(pk_e.as_bytes());
    kem_context.extend_from_slice(pk_r);
    let ss = dhkem_extract_and_expand(dh.as_bytes(), &kem_context);
    Ok((pk_e.as_bytes().to_vec(), ss))
}

fn x25519_decap(enc: &[u8], sk_r: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>> {
    let pk_e: [u8; 32] = enc.try_into().map_err(|_| Error::UnlockFailed)?;
    let sk = x25519_dalek::StaticSecret::from(*sk_r);
    let pk_r = x25519_dalek::PublicKey::from(&sk);
    let dh = sk.diffie_hellman(&x25519_dalek::PublicKey::from(pk_e));
    if !dh.was_contributory() {
        return Err(Error::UnlockFailed);
    }
    let mut kem_context = Vec::with_capacity(64);
    kem_context.extend_from_slice(&pk_e);
    kem_context.extend_from_slice(pk_r.as_bytes());
    Ok(dhkem_extract_and_expand(dh.as_bytes(), &kem_context))
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

/// An established HPKE context (sender or recipient side).
pub struct Context {
    suite: Suite,
    key: Zeroizing<Vec<u8>>,
    base_nonce: [u8; 12],
    exporter_secret: Zeroizing<Vec<u8>>,
    seq: u64,
}

impl core::fmt::Debug for Context {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "hpke::Context(suite={:?}, seq={})", self.suite, self.seq)
    }
}

fn key_schedule(suite: &Suite, shared_secret: &[u8], info: &[u8]) -> Context {
    let sid = suite.hpke_suite_id();
    let psk_id_hash = labeled_extract(suite.kdf, &sid, b"", b"psk_id_hash", b"");
    let info_hash = labeled_extract(suite.kdf, &sid, b"", b"info_hash", info);
    let mut ksc = Vec::with_capacity(1 + psk_id_hash.len() + info_hash.len());
    ksc.push(MODE_BASE);
    ksc.extend_from_slice(&psk_id_hash);
    ksc.extend_from_slice(&info_hash);

    let secret = labeled_extract(suite.kdf, &sid, shared_secret, b"secret", b"");
    let key = labeled_expand(suite.kdf, &sid, &secret, b"key", &ksc, suite.nk());
    let nonce_v = labeled_expand(suite.kdf, &sid, &secret, b"base_nonce", &ksc, 12);
    let exporter_secret = labeled_expand(suite.kdf, &sid, &secret, b"exp", &ksc, suite.nh());

    let mut base_nonce = [0u8; 12];
    base_nonce.copy_from_slice(&nonce_v);
    Context {
        suite: *suite,
        key,
        base_nonce,
        exporter_secret,
        seq: 0,
    }
}

impl Context {
    fn nonce(&self, seq: u64) -> [u8; 12] {
        let mut n = self.base_nonce;
        let seq_bytes = seq.to_be_bytes();
        for (i, b) in seq_bytes.iter().enumerate() {
            n[4 + i] ^= b;
        }
        n
    }

    /// Seal the next message in sequence.
    pub fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.nonce(self.seq);
        let ct = self.aead_encrypt(&nonce, aad, pt)?;
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or(Error::InvalidParameter("seq overflow"))?;
        Ok(ct)
    }

    /// Open the next message in sequence.
    pub fn open(&mut self, aad: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let nonce = self.nonce(self.seq);
        let pt = self.aead_decrypt(&nonce, aad, ct)?;
        self.seq = self.seq.checked_add(1).ok_or(Error::UnlockFailed)?;
        Ok(pt)
    }

    /// RFC 9180 §5.3 secret export.
    pub fn export(&self, exporter_context: &[u8], len: usize) -> Zeroizing<Vec<u8>> {
        let sid = self.suite.hpke_suite_id();
        labeled_expand(
            self.suite.kdf,
            &sid,
            &self.exporter_secret,
            b"sec",
            exporter_context,
            len,
        )
    }

    fn aead_encrypt(&self, nonce: &[u8; 12], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
        let payload = Payload { msg: pt, aad };
        let r = match self.suite.aead {
            AEAD_AES128GCM => Aes128Gcm::new_from_slice(&self.key)
                .map_err(|_| Error::InvalidParameter("key"))?
                .encrypt(nonce.into(), payload),
            AEAD_AES256GCM => Aes256Gcm::new_from_slice(&self.key)
                .map_err(|_| Error::InvalidParameter("key"))?
                .encrypt(nonce.into(), payload),
            AEAD_CHACHA20POLY1305 => ChaCha20Poly1305::new_from_slice(&self.key)
                .map_err(|_| Error::InvalidParameter("key"))?
                .encrypt(nonce.into(), payload),
            _ => return Err(Error::UnknownAlgorithm(self.suite.aead)),
        };
        r.map_err(|_| Error::InvalidParameter("seal"))
    }

    fn aead_decrypt(&self, nonce: &[u8; 12], aad: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let payload = Payload { msg: ct, aad };
        let r = match self.suite.aead {
            AEAD_AES128GCM => Aes128Gcm::new_from_slice(&self.key)
                .map_err(|_| Error::UnlockFailed)?
                .decrypt(nonce.into(), payload),
            AEAD_AES256GCM => Aes256Gcm::new_from_slice(&self.key)
                .map_err(|_| Error::UnlockFailed)?
                .decrypt(nonce.into(), payload),
            AEAD_CHACHA20POLY1305 => ChaCha20Poly1305::new_from_slice(&self.key)
                .map_err(|_| Error::UnlockFailed)?
                .decrypt(nonce.into(), payload),
            _ => return Err(Error::UnknownAlgorithm(self.suite.aead)),
        };
        r.map(Zeroizing::new).map_err(|_| Error::UnlockFailed)
    }
}

/// Sender side: returns (enc, context).
pub fn setup_base_s(
    rng: &mut dyn EntropySource,
    suite: &Suite,
    pk_r: &RecipientPk,
    info: &[u8],
) -> Result<(Vec<u8>, Context)> {
    suite.validate()?;
    let (enc, ss) = match (suite.kem, pk_r) {
        (KEM_X25519, RecipientPk::X25519(pk)) => {
            let mut sk_e = Zeroizing::new([0u8; 32]);
            rng.fill(sk_e.as_mut());
            x25519_encap_det(pk, &sk_e)?
        }
        (KEM_HYBRID_X25519_MLKEM1024, RecipientPk::Hybrid(pk)) => {
            let (ct, key) = kem::encapsulate(rng, pk)?;
            (ct, Zeroizing::new(key.as_bytes().to_vec()))
        }
        _ => return Err(Error::InvalidParameter("KEM/key mismatch")),
    };
    Ok((enc, key_schedule(suite, &ss, info)))
}

/// Recipient side.
pub fn setup_base_r(
    suite: &Suite,
    enc: &[u8],
    sk_r: &RecipientSk<'_>,
    info: &[u8],
) -> Result<Context> {
    suite.validate()?;
    let ss = match (suite.kem, sk_r) {
        (KEM_X25519, RecipientSk::X25519(sk)) => x25519_decap(enc, sk)?,
        (KEM_HYBRID_X25519_MLKEM1024, RecipientSk::Hybrid(id)) => {
            let key = id.decapsulate(enc)?;
            Zeroizing::new(key.as_bytes().to_vec())
        }
        _ => return Err(Error::UnlockFailed),
    };
    Ok(key_schedule(suite, &ss, info))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem::test_rng;

    /// RFC 9180 A.1: DHKEM(X25519)+HKDF-SHA256+AES-128-GCM, mode_base.
    #[test]
    fn rfc9180_a1_kat() {
        let suite = Suite {
            kem: KEM_X25519,
            kdf: KDF_HKDF_SHA256,
            aead: AEAD_AES128GCM,
        };
        let info = hex::decode("4f6465206f6e2061204772656369616e2055726e").unwrap();
        let sk_e: [u8; 32] =
            hex::decode("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736")
                .unwrap()
                .try_into()
                .unwrap();
        let pk_r: [u8; 32] =
            hex::decode("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d")
                .unwrap()
                .try_into()
                .unwrap();
        let sk_r: [u8; 32] =
            hex::decode("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8")
                .unwrap()
                .try_into()
                .unwrap();

        // sender with the vector's ephemeral key
        let (enc, ss) = x25519_encap_det(&pk_r, &sk_e).unwrap();
        assert_eq!(
            hex::encode(&enc),
            "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"
        );
        assert_eq!(
            hex::encode(ss.as_slice()),
            "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc"
        );
        let mut ctx_s = key_schedule(&suite, &ss, &info);
        assert_eq!(hex::encode(&*ctx_s.key), "4531685d41d65f03dc48f6b8302c05b0");
        assert_eq!(hex::encode(ctx_s.base_nonce), "56d890e5accaaf011cff4b7d");
        assert_eq!(
            hex::encode(ctx_s.exporter_secret.as_slice()),
            "45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8"
        );

        // first encryption
        let pt = hex::decode("4265617574792069732074727574682c20747275746820626561757479")
            .unwrap();
        let aad = hex::decode("436f756e742d30").unwrap();
        let ct = ctx_s.seal(&aad, &pt).unwrap();
        assert_eq!(
            hex::encode(&ct),
            "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a"
        );

        // recipient opens
        let mut ctx_r = setup_base_r(&suite, &enc, &RecipientSk::X25519(&sk_r), &info).unwrap();
        let got = ctx_r.open(&aad, &ct).unwrap();
        assert_eq!(got.as_slice(), pt.as_slice());

        // export KAT (exporter_context = "", L = 32)
        assert_eq!(
            hex::encode(ctx_r.export(b"", 32).as_slice()),
            "3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee"
        );
    }

    /// RFC 9180 A.2: DHKEM(X25519)+HKDF-SHA256+ChaCha20Poly1305, mode_base.
    #[test]
    fn rfc9180_a2_kat() {
        let suite = Suite {
            kem: KEM_X25519,
            kdf: KDF_HKDF_SHA256,
            aead: AEAD_CHACHA20POLY1305,
        };
        let info = hex::decode("4f6465206f6e2061204772656369616e2055726e").unwrap();
        let sk_e: [u8; 32] =
            hex::decode("f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600")
                .unwrap()
                .try_into()
                .unwrap();
        let pk_r: [u8; 32] =
            hex::decode("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a")
                .unwrap()
                .try_into()
                .unwrap();
        let (enc, ss) = x25519_encap_det(&pk_r, &sk_e).unwrap();
        assert_eq!(
            hex::encode(&enc),
            "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a"
        );
        assert_eq!(
            hex::encode(ss.as_slice()),
            "0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7"
        );
        let mut ctx = key_schedule(&suite, &ss, &info);
        assert_eq!(
            hex::encode(&*ctx.key),
            "ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91"
        );
        assert_eq!(hex::encode(ctx.base_nonce), "5c4d98150661b848853b547f");
        let pt = hex::decode("4265617574792069732074727574682c20747275746820626561757479")
            .unwrap();
        let aad = hex::decode("436f756e742d30").unwrap();
        let ct = ctx.seal(&aad, &pt).unwrap();
        assert_eq!(
            hex::encode(&ct),
            "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28"
        );
        assert_eq!(
            hex::encode(ctx.export(b"", 32).as_slice()),
            "4bbd6243b8bb54cec311fac9df81841b6fd61f56538a775e7c80a9f40160606e"
        );
    }

    #[test]
    fn hybrid_suite_roundtrip() {
        let mut rng = test_rng(40);
        let id = HybridIdentity::generate(&mut rng);
        let suite = Suite::tesseract_default();
        let (enc, mut ctx_s) = setup_base_s(
            &mut rng,
            &suite,
            &RecipientPk::Hybrid(id.public()),
            b"test info",
        )
        .unwrap();
        let ct1 = ctx_s.seal(b"aad1", b"first message").unwrap();
        let ct2 = ctx_s.seal(b"aad2", b"second message").unwrap();

        let mut ctx_r =
            setup_base_r(&suite, &enc, &RecipientSk::Hybrid(&id), b"test info").unwrap();
        assert_eq!(
            ctx_r.open(b"aad1", &ct1).unwrap().as_slice(),
            b"first message"
        );
        assert_eq!(
            ctx_r.open(b"aad2", &ct2).unwrap().as_slice(),
            b"second message"
        );

        // sequence violation: out-of-order open fails
        let mut ctx_r2 =
            setup_base_r(&suite, &enc, &RecipientSk::Hybrid(&id), b"test info").unwrap();
        assert!(ctx_r2.open(b"aad2", &ct2).is_err());

        // exports agree between the two sides
        assert_eq!(
            ctx_s.export(b"ctx", 48).as_slice(),
            ctx_r.export(b"ctx", 48).as_slice()
        );

        // wrong info breaks decryption
        let mut ctx_bad =
            setup_base_r(&suite, &enc, &RecipientSk::Hybrid(&id), b"other info").unwrap();
        assert!(ctx_bad.open(b"aad1", &ct1).is_err());
    }
}
