//! Standalone file encryption (age-style, built on HPKE — RFC 9180).
//!
//! Format `TSRF\x01`:
//!
//! ```text
//! magic(5) | cbor_len(4 LE) | blake3(cbor)(32) | cbor(FileHeader) | chunks...
//! ```
//!
//! A random 32-byte content key (CEK) encrypts the body; for each recipient
//! the CEK is sealed with one HPKE encapsulation (multi-recipient). The body
//! is chunked; each chunk passes through an AEAD cascade (1..=3 layers, each
//! with an independent KMAC-derived key), innermost layer first, decrypted in
//! reverse order with per-chunk, per-layer tag verification. Chunk index and
//! final flag are bound into the AAD, so chunks cannot be reordered,
//! truncated, or spliced. An optional ML-DSA-87/Ed25519 detached signature
//! covers the entire ciphertext stream.

use minicbor::{Decode, Encode};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::hpke;
use crate::kdf::{self, KdfParams};
use crate::kem::{HybridIdentity, HybridRecipient};
use crate::kmac;
use crate::registry::AeadId;
use crate::sign::SigBundle;
use crate::{aeadx, EntropySource};

pub const FILE_MAGIC: [u8; 5] = *b"TSRF\x01";
pub const DEFAULT_CHUNK_SIZE: u32 = 256 * 1024;
pub const MAX_CHUNK_SIZE: u32 = 16 * 1024 * 1024;
pub const MAX_AEAD_LAYERS: usize = 3;
pub const MAX_RECIPIENTS: usize = 64;
const MAX_FILE_HEADER_CBOR: usize = 1024 * 1024;
const CEK_LEN: usize = 32;
const FIXED_PREFIX: usize = 5 + 4 + 32;
const HPKE_INFO: &[u8] = b"tesseract file v1";

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct RecipientStanza {
    /// HPKE encapsulated key.
    #[cbor(n(0), with = "minicbor::bytes")]
    pub enc: Vec<u8>,
    /// HPKE-sealed CEK.
    #[cbor(n(1), with = "minicbor::bytes")]
    pub sealed_cek: Vec<u8>,
    /// Recipient hint (public-key fingerprint), display only.
    #[cbor(n(2), with = "minicbor::bytes")]
    pub recipient_fp: [u8; 16],
}

/// Password-based recipient: the CEK sealed under a passphrase-derived KEK
/// with the committing AEAD. This is the simple "encrypt with a password"
/// mode — anyone with the passphrase can open the file, no keypair needed.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct PasswordStanza {
    #[n(0)]
    pub kdf: KdfParams,
    #[cbor(n(1), with = "minicbor::bytes")]
    pub nonce: Vec<u8>,
    /// `commitment(32) || AEAD(cek)`.
    #[cbor(n(2), with = "minicbor::bytes")]
    pub sealed_cek: Vec<u8>,
}

const PASSWORD_AAD: &[u8] = b"tesseract-file-password-v1";

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct FileHeader {
    #[n(0)]
    pub version: u16,
    /// HPKE suite identifiers (kem, kdf, aead) — agility per the brief.
    #[n(1)]
    pub kem_id: u16,
    #[n(2)]
    pub kdf_id: u16,
    #[n(3)]
    pub hpke_aead_id: u16,
    /// Body AEAD cascade (registry AeadIds), innermost first.
    #[n(4)]
    pub body_layers: Vec<u16>,
    #[n(5)]
    pub chunk_size: u32,
    #[n(6)]
    pub total_chunks: u64,
    #[n(7)]
    pub plaintext_len: u64,
    #[n(8)]
    pub recipients: Vec<RecipientStanza>,
    /// True if a detached signature is expected alongside.
    #[n(9)]
    pub signed: bool,
    /// Password-based opener (simple mode). May coexist with recipients.
    #[n(10)]
    pub password: Option<PasswordStanza>,
    /// The plaintext is a tar archive of a directory (decrypt extracts it
    /// rather than writing a single file). Set by the client; default false.
    #[n(11)]
    pub archive: bool,
}

impl FileHeader {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(Error::UnsupportedVersion(self.version));
        }
        hpke::Suite {
            kem: self.kem_id,
            kdf: self.kdf_id,
            aead: self.hpke_aead_id,
        }
        .validate()?;
        if self.body_layers.is_empty() || self.body_layers.len() > MAX_AEAD_LAYERS {
            return Err(Error::FileFormat("body layer count"));
        }
        for l in &self.body_layers {
            let id = AeadId::from_u16(*l)?;
            if !matches!(
                id,
                AeadId::XChaCha20Poly1305 | AeadId::Aes256GcmSiv | AeadId::Aes256Gcm | AeadId::ChaCha20Poly1305
            ) {
                return Err(Error::FileFormat("body layer aead"));
            }
        }
        if self.chunk_size == 0 || self.chunk_size > MAX_CHUNK_SIZE {
            return Err(Error::FileFormat("chunk size"));
        }
        if self.recipients.len() > MAX_RECIPIENTS {
            return Err(Error::FileFormat("recipient count"));
        }
        // At least one way to open the file: a password, recipients, or both.
        if self.recipients.is_empty() && self.password.is_none() {
            return Err(Error::FileFormat("file has no openers"));
        }
        if let Some(p) = &self.password {
            p.kdf.validate()?;
        }
        let expect_chunks = self.plaintext_len.div_ceil(self.chunk_size as u64).max(1);
        if self.total_chunks != expect_chunks {
            return Err(Error::FileFormat("chunk count mismatch"));
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let cbor = minicbor::to_vec(self)?;
        if cbor.len() > MAX_FILE_HEADER_CBOR {
            return Err(Error::FileFormat("header too large"));
        }
        let mut out = Vec::with_capacity(FIXED_PREFIX + cbor.len());
        out.extend_from_slice(&FILE_MAGIC);
        out.extend_from_slice(&(cbor.len() as u32).to_le_bytes());
        out.extend_from_slice(blake3::hash(&cbor).as_bytes());
        out.extend_from_slice(&cbor);
        Ok(out)
    }

    /// Verify-before-parse. Returns (header, total header length in bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize)> {
        use subtle::ConstantTimeEq;
        if bytes.len() < FIXED_PREFIX {
            return Err(Error::BadMagic);
        }
        if bytes[..5] != FILE_MAGIC {
            return Err(Error::BadMagic);
        }
        let len = u32::from_le_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]) as usize;
        if len > MAX_FILE_HEADER_CBOR || bytes.len() < FIXED_PREFIX + len {
            return Err(Error::FileFormat("length"));
        }
        let checksum = &bytes[9..41];
        let cbor = &bytes[FIXED_PREFIX..FIXED_PREFIX + len];
        if !bool::from(blake3::hash(cbor).as_bytes().ct_eq(checksum)) {
            return Err(Error::HeaderIntegrity);
        }
        let header: FileHeader = minicbor::decode(cbor)?;
        header.validate()?;
        Ok((header, FIXED_PREFIX + len))
    }

    /// Digest binding the header into every chunk AAD.
    fn binding(&self) -> Result<[u8; 32]> {
        let cbor = minicbor::to_vec(self)?;
        Ok(*blake3::hash(&cbor).as_bytes())
    }

    /// True if the plaintext is a directory tar archive.
    pub fn is_archive(&self) -> bool {
        self.archive
    }

    /// Ciphertext overhead per chunk (one tag per layer).
    pub fn chunk_overhead(&self) -> usize {
        self.body_layers.len() * 16
    }
}

fn layer_key(cek: &[u8; CEK_LEN], layer: u8) -> Zeroizing<[u8; 32]> {
    let mut k = Zeroizing::new([0u8; 32]);
    kmac::kmac256(cek, kmac::L_FILE_CHUNK, &[layer], k.as_mut());
    k
}

fn chunk_nonce(aead: AeadId, chunk_index: u64, layer: u8) -> Vec<u8> {
    // Deterministic counter nonce: unique per (CEK, layer, chunk).
    let len = match aead {
        AeadId::XChaCha20Poly1305 => 24,
        _ => 12,
    };
    let mut n = vec![0u8; len];
    n[..8].copy_from_slice(&chunk_index.to_le_bytes());
    n[8] = layer;
    n
}

fn chunk_aad(binding: &[u8; 32], chunk_index: u64, is_final: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(41);
    aad.extend_from_slice(binding);
    aad.extend_from_slice(&chunk_index.to_le_bytes());
    aad.push(is_final as u8);
    aad
}

fn aead_seal(aead: AeadId, key: &[u8; 32], nonce: &[u8], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    let payload = Payload { msg: pt, aad };
    let r = match aead {
        AeadId::XChaCha20Poly1305 => {
            chacha20poly1305::XChaCha20Poly1305::new(key.into()).encrypt(nonce.into(), payload)
        }
        AeadId::ChaCha20Poly1305 => {
            chacha20poly1305::ChaCha20Poly1305::new(key.into()).encrypt(nonce.into(), payload)
        }
        AeadId::Aes256GcmSiv => {
            aes_gcm_siv::Aes256GcmSiv::new(key.into()).encrypt(nonce.into(), payload)
        }
        AeadId::Aes256Gcm => aes_gcm::Aes256Gcm::new(key.into()).encrypt(nonce.into(), payload),
    };
    r.map_err(|_| Error::FileFormat("seal"))
}

fn aead_open(
    aead: AeadId,
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    let payload = Payload { msg: ct, aad };
    let r = match aead {
        AeadId::XChaCha20Poly1305 => {
            chacha20poly1305::XChaCha20Poly1305::new(key.into()).decrypt(nonce.into(), payload)
        }
        AeadId::ChaCha20Poly1305 => {
            chacha20poly1305::ChaCha20Poly1305::new(key.into()).decrypt(nonce.into(), payload)
        }
        AeadId::Aes256GcmSiv => {
            aes_gcm_siv::Aes256GcmSiv::new(key.into()).decrypt(nonce.into(), payload)
        }
        AeadId::Aes256Gcm => aes_gcm::Aes256Gcm::new(key.into()).decrypt(nonce.into(), payload),
    };
    r.map_err(|_| Error::UnlockFailed)
}

/// Streaming encryptor. The caller (agent/CLI) feeds plaintext chunks in
/// order and writes out `header_bytes()` then each returned ciphertext chunk.
pub struct FileEncryptor {
    header: FileHeader,
    header_bytes: Vec<u8>,
    binding: [u8; 32],
    cek: Zeroizing<[u8; CEK_LEN]>,
    next_chunk: u64,
}

impl core::fmt::Debug for FileEncryptor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "FileEncryptor(chunk={}/{})", self.next_chunk, self.header.total_chunks)
    }
}

/// How a file may be opened. At least one opener is required.
pub struct Openers<'a> {
    /// Passphrase + KDF parameters for the simple password mode.
    pub password: Option<(&'a [u8], KdfParams)>,
    /// Public-key recipients (hybrid PQ) for the advanced mode.
    pub recipients: &'a [HybridRecipient],
}

impl core::fmt::Debug for Openers<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Openers(password={}, recipients={})",
            self.password.is_some(),
            self.recipients.len()
        )
    }
}

impl FileEncryptor {
    /// Recipient-only convenience constructor (kept for existing callers).
    pub fn new(
        rng: &mut dyn EntropySource,
        recipients: &[HybridRecipient],
        body_layers: &[AeadId],
        hpke_aead: u16,
        chunk_size: u32,
        plaintext_len: u64,
        signed: bool,
    ) -> Result<Self> {
        Self::with_openers(
            rng,
            Openers {
                password: None,
                recipients,
            },
            body_layers,
            hpke_aead,
            chunk_size,
            plaintext_len,
            signed,
            false,
        )
    }

    /// Full constructor: password and/or recipients. `archive` marks the
    /// plaintext as a directory tar (the decryptor extracts it).
    #[allow(clippy::too_many_arguments)]
    pub fn with_openers(
        rng: &mut dyn EntropySource,
        openers: Openers<'_>,
        body_layers: &[AeadId],
        hpke_aead: u16,
        chunk_size: u32,
        plaintext_len: u64,
        signed: bool,
        archive: bool,
    ) -> Result<Self> {
        if openers.recipients.len() > MAX_RECIPIENTS {
            return Err(Error::InvalidParameter("recipient count"));
        }
        if openers.password.is_none() && openers.recipients.is_empty() {
            return Err(Error::InvalidParameter("need a password or a recipient"));
        }
        let mut cek = Zeroizing::new([0u8; CEK_LEN]);
        rng.fill(cek.as_mut());

        let suite = hpke::Suite {
            kem: hpke::KEM_HYBRID_X25519_MLKEM1024,
            kdf: hpke::KDF_HKDF_SHA512,
            aead: hpke_aead,
        };
        let mut stanzas = Vec::with_capacity(openers.recipients.len());
        for r in openers.recipients {
            let (enc, mut ctx) =
                hpke::setup_base_s(rng, &suite, &hpke::RecipientPk::Hybrid(r.clone()), HPKE_INFO)?;
            let sealed_cek = ctx.seal(b"cek", cek.as_ref())?;
            stanzas.push(RecipientStanza {
                enc,
                sealed_cek,
                recipient_fp: r.fingerprint(),
            });
        }

        let password = match openers.password {
            Some((pw, params)) => {
                params.validate()?;
                let kek = kdf::derive_kek(&params, pw)?;
                let mut nonce = vec![0u8; aeadx::nonce_len(crate::registry::AeadId::XChaCha20Poly1305)?];
                rng.fill(&mut nonce);
                let sealed_cek = aeadx::seal(
                    crate::registry::AeadId::XChaCha20Poly1305,
                    kek.as_ref(),
                    &nonce,
                    PASSWORD_AAD,
                    cek.as_ref(),
                )?;
                Some(PasswordStanza {
                    kdf: params,
                    nonce,
                    sealed_cek,
                })
            }
            None => None,
        };

        let header = FileHeader {
            version: 1,
            kem_id: suite.kem,
            kdf_id: suite.kdf,
            hpke_aead_id: suite.aead,
            body_layers: body_layers.iter().map(|a| a.as_u16()).collect(),
            chunk_size,
            total_chunks: plaintext_len.div_ceil(chunk_size as u64).max(1),
            plaintext_len,
            recipients: stanzas,
            signed,
            password,
            archive,
        };
        header.validate()?;
        let header_bytes = header.to_bytes()?;
        let binding = header.binding()?;
        Ok(Self {
            header,
            header_bytes,
            binding,
            cek,
            next_chunk: 0,
        })
    }

    pub fn header_bytes(&self) -> &[u8] {
        &self.header_bytes
    }

    pub fn header(&self) -> &FileHeader {
        &self.header
    }

    /// Encrypt the next chunk. `pt` must be `chunk_size` bytes except the
    /// final chunk.
    pub fn encrypt_chunk(&mut self, pt: &[u8]) -> Result<Vec<u8>> {
        if self.next_chunk >= self.header.total_chunks {
            return Err(Error::FileFormat("too many chunks"));
        }
        let is_final = self.next_chunk == self.header.total_chunks - 1;
        if !is_final && pt.len() != self.header.chunk_size as usize {
            return Err(Error::FileFormat("non-final chunk must be full"));
        }
        let aad = chunk_aad(&self.binding, self.next_chunk, is_final);
        let mut buf = pt.to_vec();
        for (i, layer) in self.header.body_layers.iter().enumerate() {
            let aead = AeadId::from_u16(*layer)?;
            let key = layer_key(&self.cek, i as u8);
            let nonce = chunk_nonce(aead, self.next_chunk, i as u8);
            buf = aead_seal(aead, &key, &nonce, &aad, &buf)?;
        }
        self.next_chunk += 1;
        Ok(buf)
    }

    pub fn is_complete(&self) -> bool {
        self.next_chunk == self.header.total_chunks
    }
}

/// Streaming decryptor.
pub struct FileDecryptor {
    header: FileHeader,
    binding: [u8; 32],
    cek: Zeroizing<[u8; CEK_LEN]>,
    next_chunk: u64,
}

impl core::fmt::Debug for FileDecryptor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "FileDecryptor(chunk={}/{})", self.next_chunk, self.header.total_chunks)
    }
}

impl FileDecryptor {
    /// Open the file for `identity`. Tries every recipient stanza.
    pub fn new(header: FileHeader, identity: &HybridIdentity) -> Result<Self> {
        header.validate()?;
        let suite = hpke::Suite {
            kem: header.kem_id,
            kdf: header.kdf_id,
            aead: header.hpke_aead_id,
        };
        let binding = header.binding()?;
        let mut cek_opt = None;
        for stanza in &header.recipients {
            let Ok(mut ctx) =
                hpke::setup_base_r(&suite, &stanza.enc, &hpke::RecipientSk::Hybrid(identity), HPKE_INFO)
            else {
                continue;
            };
            if let Ok(cek) = ctx.open(b"cek", &stanza.sealed_cek) {
                if cek.len() == CEK_LEN {
                    let mut k = Zeroizing::new([0u8; CEK_LEN]);
                    k.copy_from_slice(&cek);
                    cek_opt = Some(k);
                    break;
                }
            }
        }
        let cek = cek_opt.ok_or(Error::NotARecipient)?;
        Ok(Self {
            header,
            binding,
            cek,
            next_chunk: 0,
        })
    }

    /// Open the file with a passphrase (simple password mode).
    pub fn with_password(header: FileHeader, passphrase: &[u8]) -> Result<Self> {
        header.validate()?;
        let binding = header.binding()?;
        let stanza = header.password.as_ref().ok_or(Error::UnlockFailed)?;
        let kek = kdf::derive_kek(&stanza.kdf, passphrase)?;
        let pt = aeadx::open(
            crate::registry::AeadId::XChaCha20Poly1305,
            kek.as_ref(),
            &stanza.nonce,
            PASSWORD_AAD,
            &stanza.sealed_cek,
        )?;
        if pt.len() != CEK_LEN {
            return Err(Error::UnlockFailed);
        }
        let mut cek = Zeroizing::new([0u8; CEK_LEN]);
        cek.copy_from_slice(pt.as_slice());
        Ok(Self {
            header,
            binding,
            cek,
            next_chunk: 0,
        })
    }

    /// True if the file carries a password opener.
    pub fn has_password(header: &FileHeader) -> bool {
        header.password.is_some()
    }

    pub fn header(&self) -> &FileHeader {
        &self.header
    }

    /// Decrypt the next chunk (reverse layer order, every tag verified).
    pub fn decrypt_chunk(&mut self, ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if self.next_chunk >= self.header.total_chunks {
            return Err(Error::FileFormat("trailing data"));
        }
        let is_final = self.next_chunk == self.header.total_chunks - 1;
        let aad = chunk_aad(&self.binding, self.next_chunk, is_final);
        let mut buf = ct.to_vec();
        for (i, layer) in self.header.body_layers.iter().enumerate().rev() {
            let aead = AeadId::from_u16(*layer)?;
            let key = layer_key(&self.cek, i as u8);
            let nonce = chunk_nonce(aead, self.next_chunk, i as u8);
            buf = aead_open(aead, &key, &nonce, &aad, &buf)?;
        }
        self.next_chunk += 1;
        Ok(Zeroizing::new(buf))
    }

    pub fn is_complete(&self) -> bool {
        self.next_chunk == self.header.total_chunks
    }
}

/// Sign the complete ciphertext (header bytes + all chunks), detached.
pub fn sign_file(signer: &crate::sign::SignerIdentity, ciphertext_digest: &[u8; 32]) -> SigBundle {
    signer.sign(ciphertext_digest)
}

/// Verify a detached signature bundle over the ciphertext digest.
pub fn verify_file(bundle: &SigBundle, ciphertext_digest: &[u8; 32]) -> Result<()> {
    crate::sign::verify(bundle, ciphertext_digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem::test_rng;

    fn encrypt_all(
        rng: &mut dyn EntropySource,
        recipients: &[HybridRecipient],
        layers: &[AeadId],
        chunk_size: u32,
        data: &[u8],
    ) -> Vec<u8> {
        let mut enc = FileEncryptor::new(
            rng,
            recipients,
            layers,
            hpke::AEAD_CHACHA20POLY1305,
            chunk_size,
            data.len() as u64,
            false,
        )
        .unwrap();
        let mut out = enc.header_bytes().to_vec();
        if data.is_empty() {
            out.extend_from_slice(&enc.encrypt_chunk(b"").unwrap());
        } else {
            for chunk in data.chunks(chunk_size as usize) {
                out.extend_from_slice(&enc.encrypt_chunk(chunk).unwrap());
            }
        }
        assert!(enc.is_complete());
        out
    }

    fn decrypt_all(file: &[u8], identity: &HybridIdentity) -> Result<Vec<u8>> {
        let (header, hlen) = FileHeader::from_bytes(file)?;
        let chunk_ct_len = header.chunk_size as usize + header.chunk_overhead();
        let mut dec = FileDecryptor::new(header, identity)?;
        let mut out = Vec::new();
        let mut pos = hlen;
        while !dec.is_complete() {
            let remaining = file.len() - pos;
            let take = remaining.min(chunk_ct_len);
            let pt = dec.decrypt_chunk(&file[pos..pos + take])?;
            out.extend_from_slice(&pt);
            pos += take;
        }
        if pos != file.len() {
            return Err(Error::FileFormat("trailing data"));
        }
        Ok(out)
    }

    #[test]
    fn roundtrip_multi_chunk_multi_layer() {
        let mut rng = test_rng(50);
        let id = HybridIdentity::generate(&mut rng);
        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        // chunk boundary coverage: 4096 → 2 full chunks + partial final
        let file = encrypt_all(
            &mut rng,
            &[id.public()],
            &[AeadId::XChaCha20Poly1305, AeadId::Aes256Gcm],
            4096,
            &data,
        );
        let got = decrypt_all(&file, &id).unwrap();
        assert_eq!(got, data);
    }

    #[test]
    fn empty_file_roundtrips() {
        let mut rng = test_rng(51);
        let id = HybridIdentity::generate(&mut rng);
        let file = encrypt_all(&mut rng, &[id.public()], &[AeadId::ChaCha20Poly1305], 4096, b"");
        let got = decrypt_all(&file, &id).unwrap();
        assert!(got.is_empty());
    }

    #[test]
    fn exact_chunk_multiple_roundtrips() {
        let mut rng = test_rng(52);
        let id = HybridIdentity::generate(&mut rng);
        let data = vec![7u8; 8192]; // exactly 2 chunks of 4096
        let file = encrypt_all(&mut rng, &[id.public()], &[AeadId::Aes256GcmSiv], 4096, &data);
        assert_eq!(decrypt_all(&file, &id).unwrap(), data);
    }

    fn small_kdf() -> KdfParams {
        KdfParams::Argon2id {
            m_kib: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
            salt: [42; 32],
        }
    }

    fn encrypt_pw(
        rng: &mut dyn EntropySource,
        password: &[u8],
        recipients: &[HybridRecipient],
        layers: &[AeadId],
        chunk_size: u32,
        data: &[u8],
    ) -> Vec<u8> {
        let mut enc = FileEncryptor::with_openers(
            rng,
            Openers {
                password: Some((password, small_kdf())),
                recipients,
            },
            layers,
            hpke::AEAD_CHACHA20POLY1305,
            chunk_size,
            data.len() as u64,
            false,
            false,
        )
        .unwrap();
        let mut out = enc.header_bytes().to_vec();
        if data.is_empty() {
            out.extend_from_slice(&enc.encrypt_chunk(b"").unwrap());
        } else {
            for chunk in data.chunks(chunk_size as usize) {
                out.extend_from_slice(&enc.encrypt_chunk(chunk).unwrap());
            }
        }
        out
    }

    fn decrypt_pw(file: &[u8], password: &[u8]) -> Result<Vec<u8>> {
        let (header, hlen) = FileHeader::from_bytes(file)?;
        let chunk_ct_len = header.chunk_size as usize + header.chunk_overhead();
        let mut dec = FileDecryptor::with_password(header, password)?;
        let mut out = Vec::new();
        let mut pos = hlen;
        while !dec.is_complete() {
            let take = (file.len() - pos).min(chunk_ct_len);
            let pt = dec.decrypt_chunk(&file[pos..pos + take])?;
            out.extend_from_slice(&pt);
            pos += take;
        }
        Ok(out)
    }

    #[test]
    fn password_mode_roundtrip() {
        let mut rng = test_rng(60);
        let data: Vec<u8> = (0..9000u32).map(|i| (i % 251) as u8).collect();
        let file = encrypt_pw(&mut rng, b"correct horse battery", &[], &[AeadId::XChaCha20Poly1305], 4096, &data);
        // right password opens
        assert_eq!(decrypt_pw(&file, b"correct horse battery").unwrap(), data);
        // wrong password fails (committing AEAD)
        assert!(decrypt_pw(&file, b"wrong").is_err());
        // empty file with password
        let ef = encrypt_pw(&mut rng, b"pw", &[], &[AeadId::ChaCha20Poly1305], 4096, b"");
        assert!(decrypt_pw(&ef, b"pw").unwrap().is_empty());
    }

    #[test]
    fn password_and_recipient_both_open() {
        let mut rng = test_rng(61);
        let id = HybridIdentity::generate(&mut rng);
        let data = b"openable two ways".to_vec();
        let file = encrypt_pw(&mut rng, b"shared-pw", &[id.public()], &[AeadId::Aes256Gcm], 4096, &data);
        // password opens
        assert_eq!(decrypt_pw(&file, b"shared-pw").unwrap(), data);
        // and the recipient's key opens
        assert_eq!(decrypt_all(&file, &id).unwrap(), data);
    }

    #[test]
    fn multi_recipient() {
        let mut rng = test_rng(53);
        let alice = HybridIdentity::generate(&mut rng);
        let bob = HybridIdentity::generate(&mut rng);
        let mallory = HybridIdentity::generate(&mut rng);
        let data = b"for alice and bob only".to_vec();
        let file = encrypt_all(
            &mut rng,
            &[alice.public(), bob.public()],
            &[AeadId::XChaCha20Poly1305],
            4096,
            &data,
        );
        assert_eq!(decrypt_all(&file, &alice).unwrap(), data);
        assert_eq!(decrypt_all(&file, &bob).unwrap(), data);
        assert!(matches!(
            decrypt_all(&file, &mallory),
            Err(Error::NotARecipient)
        ));
    }

    #[test]
    fn truncation_and_reorder_rejected() {
        let mut rng = test_rng(54);
        let id = HybridIdentity::generate(&mut rng);
        let data = vec![1u8; 12288]; // 3 chunks of 4096
        let file = encrypt_all(&mut rng, &[id.public()], &[AeadId::ChaCha20Poly1305], 4096, &data);

        let (header, hlen) = FileHeader::from_bytes(&file).unwrap();
        let clen = 4096 + header.chunk_overhead();

        // truncated: missing last chunk → decryptor's final-chunk AAD check fails
        let mut dec = FileDecryptor::new(header.clone(), &id).unwrap();
        dec.decrypt_chunk(&file[hlen..hlen + clen]).unwrap();
        dec.decrypt_chunk(&file[hlen + clen..hlen + 2 * clen]).unwrap();
        // feeding chunk 1's ciphertext as the final chunk must fail
        assert!(dec.decrypt_chunk(&file[hlen + clen..hlen + 2 * clen]).is_err());

        // reorder: chunk 2 fed first must fail
        let mut dec2 = FileDecryptor::new(header, &id).unwrap();
        assert!(dec2.decrypt_chunk(&file[hlen + clen..hlen + 2 * clen]).is_err());
    }

    #[test]
    fn tampered_chunk_rejected() {
        let mut rng = test_rng(55);
        let id = HybridIdentity::generate(&mut rng);
        let data = vec![9u8; 100];
        let mut file = encrypt_all(&mut rng, &[id.public()], &[AeadId::XChaCha20Poly1305], 4096, &data);
        let n = file.len();
        file[n - 1] ^= 1;
        assert!(decrypt_all(&file, &id).is_err());
    }

    #[test]
    fn signature_over_ciphertext() {
        let mut rng = test_rng(56);
        let id = HybridIdentity::generate(&mut rng);
        let signer = crate::sign::SignerIdentity::generate(crate::registry::SigId::MlDsa87, &mut rng);
        let file = encrypt_all(&mut rng, &[id.public()], &[AeadId::ChaCha20Poly1305], 4096, b"x");
        let digest = *blake3::hash(&file).as_bytes();
        let bundle = sign_file(&signer, &digest);
        verify_file(&bundle, &digest).unwrap();
        let bad = *blake3::hash(b"other").as_bytes();
        assert!(verify_file(&bundle, &bad).is_err());
    }

    #[test]
    fn header_caps_enforced() {
        let mut rng = test_rng(57);
        let id = HybridIdentity::generate(&mut rng);
        // zero recipients rejected at construction
        assert!(FileEncryptor::new(
            &mut rng,
            &[],
            &[AeadId::ChaCha20Poly1305],
            hpke::AEAD_CHACHA20POLY1305,
            4096,
            10,
            false,
        )
        .is_err());
        // too many layers rejected
        assert!(FileEncryptor::new(
            &mut rng,
            &[id.public()],
            &[AeadId::ChaCha20Poly1305; 4],
            hpke::AEAD_CHACHA20POLY1305,
            4096,
            10,
            false,
        )
        .is_err());
    }
}
