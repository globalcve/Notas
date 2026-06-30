//! KMAC256 (NIST SP 800-185) — the single key-derivation/MAC workhorse for
//! everything keyed by the VMK or a KEK. Domain separation comes from the
//! KMAC customization string; every caller uses a distinct `pqc/...` label.

use tiny_keccak::{Hasher, Kmac};

/// `out = KMAC256(key, custom)(data)`, output length = `out.len()`.
pub fn kmac256(key: &[u8], custom: &[u8], data: &[u8], out: &mut [u8]) {
    let mut k = Kmac::v256(key, custom);
    k.update(data);
    k.finalize(out);
}

/// Convenience: fixed 32-byte output.
pub fn kmac256_32(key: &[u8], custom: &[u8], data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    kmac256(key, custom, data, &mut out);
    out
}

/// Convenience: fixed 64-byte output.
pub fn kmac256_64(key: &[u8], custom: &[u8], data: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    kmac256(key, custom, data, &mut out);
    out
}

// Domain-separation labels. Never reuse a label for a new purpose.
pub const L_LAYER: &[u8] = b"pqc/layer"; // per-cascade-layer subkeys
pub const L_HEADER_MAC: &[u8] = b"pqc/header-mac"; // VMK-keyed header MAC
pub const L_SLOT_ENC: &[u8] = b"pqc/slot-enc"; // keyslot AEAD key
pub const L_SLOT_COM: &[u8] = b"pqc/slot-com"; // keyslot commitment
pub const L_CHACHA_IV: &[u8] = b"pqc/chacha-iv"; // sector nonce for stream layers
pub const L_HYBRID_KEM: &[u8] = b"pqc/hybrid-kem"; // KEM combiner
pub const L_FILE_CHUNK: &[u8] = b"pqc/file-chunk"; // file-mode per-layer chunk keys
pub const L_JOURNAL: &[u8] = b"pqc/journal"; // in-place conversion journal MAC

#[cfg(test)]
mod tests {
    use super::*;

    /// KAT from NIST SP 800-185 KMAC256 sample #4 (KMAC_samples.pdf):
    /// key = 0x40..0x5F, data = 00 01 02 03, custom = "My Tagged Application",
    /// output length 64 bytes.
    #[test]
    fn kmac256_nist_sample() {
        let key: Vec<u8> = (0x40u8..=0x5F).collect();
        let data = [0x00u8, 0x01, 0x02, 0x03];
        let custom = b"My Tagged Application";
        let mut out = [0u8; 64];
        kmac256(&key, custom, &data, &mut out);
        let expect = hex::decode(
            "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7\
             f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd",
        )
        .unwrap();
        assert_eq!(out.as_slice(), expect.as_slice());
    }
}
