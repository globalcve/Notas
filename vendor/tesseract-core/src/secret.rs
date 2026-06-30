//! Zeroize-on-drop secret containers.
//!
//! In `tesseract-core` these guarantee zeroization; the *locked, non-dumpable*
//! property is layered on by the agent, which allocates the backing storage
//! of long-lived secrets (the VMK, cached KEKs) inside its guard-page arenas
//! and only lends slices into this crate.

use zeroize::{Zeroize, Zeroizing};

/// Volume Master Key: 512 bits. Per-layer data/tweak subkeys are derived from
/// it with KMAC256, so the VMK size is independent of cascade depth.
pub const VMK_LEN: usize = 64;

/// Heap-backed secret byte string, zeroized on drop.
#[derive(Clone, Default)]
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    pub fn new(v: Vec<u8>) -> Self {
        Self(Zeroizing::new(v))
    }

    pub fn zeroed(len: usize) -> Self {
        Self(Zeroizing::new(vec![0u8; len]))
    }

    pub fn from_slice(s: &[u8]) -> Self {
        Self(Zeroizing::new(s.to_vec()))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl core::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecretBytes(len={}, [REDACTED])", self.0.len())
    }
}

impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// The Volume Master Key.
#[derive(Clone)]
pub struct Vmk(Zeroizing<[u8; VMK_LEN]>);

impl Vmk {
    pub fn from_bytes(b: [u8; VMK_LEN]) -> Self {
        Self(Zeroizing::new(b))
    }

    pub fn generate(rng: &mut dyn crate::EntropySource) -> Self {
        let mut b = [0u8; VMK_LEN];
        rng.fill(&mut b);
        Self(Zeroizing::new(b))
    }

    pub fn as_bytes(&self) -> &[u8; VMK_LEN] {
        &self.0
    }

    /// Explicit wipe (drop also wipes; this is for "wipe now" paths).
    pub fn wipe(&mut self) {
        self.0.zeroize();
    }
}

impl core::fmt::Debug for Vmk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Vmk([REDACTED; 64])")
    }
}

/// A 32-byte derived key (KEK, layer subkey, MAC key...), zeroized on drop.
#[derive(Clone)]
pub struct Key32(Zeroizing<[u8; 32]>);

impl Key32 {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(Zeroizing::new(b))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for Key32 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Key32([REDACTED; 32])")
    }
}
