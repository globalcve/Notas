//! tesseract-core — the cryptographic heart of Tesseract.
//!
//! Pure Rust, no OS calls, `#![forbid(unsafe_code)]`. Everything here is
//! deterministic given its inputs: randomness enters only through the
//! [`EntropySource`] trait supplied by the caller (the agent), and IO enters
//! only through the [`inplace::BlockIo`] trait. This keeps the crate fully
//! unit-testable and keeps the OS surface in `tesseract-agent` where it is
//! audited and sandboxed.
//!
//! Layout:
//! - [`registry`] — algorithm identifiers and capability metadata
//! - [`cascade`] — the XTS/stream cascade engine over [`cipher_layer`] layers
//! - [`keyslot`] — VMK wrapping: committing AEAD seal/open per slot type
//! - [`header`] — volume headers (standard + deniable), verify-before-parse
//! - [`hpke`] — RFC 9180 HPKE with the hybrid X25519+ML-KEM-1024 KEM
//! - [`filemode`] — standalone encrypt-to-recipient file format
//! - [`statemachine`] — the volume lifecycle state machine
//! - [`inplace`] — resumable, crash-safe in-place encryption/decryption

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
#![warn(clippy::all)]

pub mod aeadx;
pub mod cascade;
pub mod cipher_layer;
pub mod entropy;
pub mod error;
pub mod filemode;
pub mod header;
pub mod hpke;
pub mod inplace;
pub mod kdf;
pub mod kem;
pub mod keyfile;
pub mod keyslot;
pub mod kmac;
pub mod registry;
pub mod secret;
pub mod sign;
pub mod statemachine;

pub use error::{Error, Result};
pub use secret::{SecretBytes, Vmk};

/// Bytes reserved for the primary header region at the start of a volume and
/// mirrored as the backup header region at the end.
pub const HEADER_REGION: u64 = 256 * 1024;

/// Offset of the hidden-volume header inside the (deniable) header region.
pub const HIDDEN_HEADER_OFFSET: u64 = 128 * 1024;

/// Size of one deniable header blob (salt + sealed header + padding).
pub const DENIABLE_BLOB_LEN: usize = 16 * 1024;

/// Source of randomness. Implemented by the agent over the OS CSPRNG mixed
/// with collected user entropy; implemented deterministically in tests.
pub trait EntropySource {
    fn fill(&mut self, buf: &mut [u8]);

    fn bytes<const N: usize>(&mut self) -> [u8; N]
    where
        Self: Sized,
    {
        let mut out = [0u8; N];
        self.fill(&mut out);
        out
    }
}

impl<F: FnMut(&mut [u8])> EntropySource for F {
    fn fill(&mut self, buf: &mut [u8]) {
        self(buf)
    }
}
