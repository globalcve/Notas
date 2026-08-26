//! The cascade engine.
//!
//! A `CascadeSpec` is an ordered list of cipher layers, depth 1..=5. The
//! convention (this is Tesseract's own, see the brief): **layer 0 is applied
//! first to the plaintext**; the highest index is the outermost layer an
//! attacker sees. Decryption MUST reverse the order. Each layer derives its
//! own independent (data, tweak) subkeys from the VMK via
//! `KMAC256(VMK, "tsr/layer" || index || role)`, so identical ciphers at
//! different depths never share keys.

use minicbor::{Decode, Encode};

use crate::cipher_layer::{build_layer, SectorLayer};
use crate::error::{Error, Result};
use crate::registry::CipherId;
use crate::secret::Vmk;

pub const MAX_DEPTH: usize = 5;

/// Ordered cascade specification (stored in the header, covered by the
/// header MAC and the keyslot AAD binding).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[cbor(transparent)]
pub struct CascadeSpec(#[n(0)] Vec<u16>);

impl CascadeSpec {
    pub fn new(layers: &[CipherId]) -> Result<Self> {
        if layers.is_empty() || layers.len() > MAX_DEPTH {
            return Err(Error::InvalidCascade("depth must be 1..=5"));
        }
        Ok(Self(layers.iter().map(|c| c.as_u16()).collect()))
    }

    pub fn layers(&self) -> Result<Vec<CipherId>> {
        self.0.iter().map(|&v| CipherId::from_u16(v)).collect()
    }

    pub fn depth(&self) -> usize {
        self.0.len()
    }

    /// Validate ids, availability, and the experimental opt-in.
    pub fn validate(&self, experimental_ok: bool) -> Result<()> {
        if self.0.is_empty() || self.0.len() > MAX_DEPTH {
            return Err(Error::InvalidCascade("depth must be 1..=5"));
        }
        for id in self.layers()? {
            if !id.is_available() {
                return Err(Error::ExperimentalGated(id.label()));
            }
            crate::registry::gate_experimental(id.is_experimental(), id.label(), experimental_ok)?;
        }
        Ok(())
    }

    /// Display string, e.g. "AES-256 → Serpent-256" (innermost first).
    pub fn display(&self) -> String {
        self.layers()
            .map(|v| {
                v.iter()
                    .map(|c| c.label())
                    .collect::<Vec<_>>()
                    .join(" → ")
            })
            .unwrap_or_else(|_| "<invalid>".into())
    }
}

/// A ready-to-run cascade: all layers built, subkeys derived.
pub struct CascadeEngine {
    layers: Vec<Box<dyn SectorLayer>>,
    sector_size: usize,
}

impl core::fmt::Debug for CascadeEngine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "CascadeEngine(depth={}, sector={})",
            self.layers.len(),
            self.sector_size
        )
    }
}

impl CascadeEngine {
    pub fn new(vmk: &Vmk, spec: &CascadeSpec, sector_size: usize) -> Result<Self> {
        if !(sector_size >= 512 && sector_size.is_power_of_two() && sector_size <= 65536) {
            return Err(Error::Geometry("sector size must be a power of two in 512..=65536"));
        }
        let ids = spec.layers()?;
        if ids.is_empty() || ids.len() > MAX_DEPTH {
            return Err(Error::InvalidCascade("depth must be 1..=5"));
        }
        let mut layers = Vec::with_capacity(ids.len());
        for (i, id) in ids.iter().enumerate() {
            layers.push(build_layer(*id, i as u8, vmk)?);
        }
        Ok(Self {
            layers,
            sector_size,
        })
    }

    pub fn sector_size(&self) -> usize {
        self.sector_size
    }

    /// Encrypt one sector in place: layer 0 first, then up the stack.
    pub fn encrypt_sector(&self, sector_index: u64, buf: &mut [u8]) -> Result<()> {
        self.check_len(buf)?;
        for layer in &self.layers {
            layer.encrypt_sector(sector_index, buf);
        }
        Ok(())
    }

    /// Decrypt one sector in place: outermost layer first (reverse order),
    /// each cipher's inverse with the same sector tweak.
    pub fn decrypt_sector(&self, sector_index: u64, buf: &mut [u8]) -> Result<()> {
        self.check_len(buf)?;
        for layer in self.layers.iter().rev() {
            layer.decrypt_sector(sector_index, buf);
        }
        Ok(())
    }

    /// Encrypt a run of consecutive sectors starting at `first_sector`.
    /// `buf.len()` must be a multiple of the sector size.
    pub fn encrypt_range(&self, first_sector: u64, buf: &mut [u8]) -> Result<()> {
        self.check_range(buf)?;
        for (i, sector) in buf.chunks_exact_mut(self.sector_size).enumerate() {
            for layer in &self.layers {
                layer.encrypt_sector(first_sector + i as u64, sector);
            }
        }
        Ok(())
    }

    pub fn decrypt_range(&self, first_sector: u64, buf: &mut [u8]) -> Result<()> {
        self.check_range(buf)?;
        for (i, sector) in buf.chunks_exact_mut(self.sector_size).enumerate() {
            for layer in self.layers.iter().rev() {
                layer.decrypt_sector(first_sector + i as u64, sector);
            }
        }
        Ok(())
    }

    fn check_len(&self, buf: &[u8]) -> Result<()> {
        if buf.len() != self.sector_size {
            return Err(Error::Length {
                want: self.sector_size,
                got: buf.len(),
            });
        }
        Ok(())
    }

    fn check_range(&self, buf: &[u8]) -> Result<()> {
        if buf.is_empty() || buf.len() % self.sector_size != 0 {
            return Err(Error::Length {
                want: self.sector_size,
                got: buf.len(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vmk() -> Vmk {
        Vmk::from_bytes([0x42; 64])
    }

    fn sample_sector(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 % 251) as u8).collect()
    }

    fn available() -> Vec<CipherId> {
        CipherId::ALL
            .iter()
            .copied()
            .filter(|c| c.is_available())
            .collect()
    }

    #[test]
    fn every_single_cipher_roundtrips() {
        for id in available() {
            let spec = CascadeSpec::new(&[id]).unwrap();
            let eng = CascadeEngine::new(&vmk(), &spec, 4096).unwrap();
            let orig = sample_sector(4096);
            let mut buf = orig.clone();
            eng.encrypt_sector(7, &mut buf).unwrap();
            assert_ne!(buf, orig);
            eng.decrypt_sector(7, &mut buf).unwrap();
            assert_eq!(buf, orig, "{:?}", id);
        }
    }

    #[test]
    fn every_pair_ordering_roundtrips() {
        let avail = available();
        for &a in &avail {
            for &b in &avail {
                let spec = CascadeSpec::new(&[a, b]).unwrap();
                let eng = CascadeEngine::new(&vmk(), &spec, 512).unwrap();
                let orig = sample_sector(512);
                let mut buf = orig.clone();
                eng.encrypt_sector(123456, &mut buf).unwrap();
                eng.decrypt_sector(123456, &mut buf).unwrap();
                assert_eq!(buf, orig, "{:?}+{:?}", a, b);
            }
        }
    }

    #[test]
    fn deep_cascades_roundtrip_across_sector_sizes() {
        use CipherId::*;
        let specs: Vec<Vec<CipherId>> = vec![
            vec![Aes256, Serpent256, Twofish256],
            vec![Twofish256, Aes256, Serpent256],
            vec![Camellia256, XChaCha20, Aes256, Serpent256, Twofish256],
            vec![Aes256, Aes256], // duplicate ciphers get independent subkeys
        ];
        for layers in specs {
            let spec = CascadeSpec::new(&layers).unwrap();
            for sector_size in [512usize, 4096] {
                let eng = CascadeEngine::new(&vmk(), &spec, sector_size).unwrap();
                // multi-sector range crossing sector boundaries
                let orig = sample_sector(sector_size * 3);
                let mut buf = orig.clone();
                eng.encrypt_range(99, &mut buf).unwrap();
                eng.decrypt_range(99, &mut buf).unwrap();
                assert_eq!(buf, orig);
            }
        }
    }

    /// Layer-order regression: decrypting with the same layers applied in
    /// FORWARD order must NOT return the plaintext. If this test ever fails,
    /// someone broke the reverse-order convention.
    #[test]
    fn decryption_must_reverse_layer_order() {
        use CipherId::*;
        let spec = CascadeSpec::new(&[Aes256, Serpent256, Twofish256]).unwrap();
        let eng = CascadeEngine::new(&vmk(), &spec, 512).unwrap();
        let orig = sample_sector(512);
        let mut buf = orig.clone();
        eng.encrypt_sector(5, &mut buf).unwrap();

        // simulate a buggy forward-order decryption using single-layer engines
        let mut wrong = buf.clone();
        for (i, &id) in [Aes256, Serpent256, Twofish256].iter().enumerate() {
            // build layer i alone and apply its inverse in forward order
            let layer = crate::cipher_layer::build_layer(id, i as u8, &vmk()).unwrap();
            layer.decrypt_sector(5, &mut wrong);
        }
        assert_ne!(wrong, orig, "forward-order decryption must not work");

        eng.decrypt_sector(5, &mut buf).unwrap();
        assert_eq!(buf, orig);
    }

    /// A volume encrypted with one spec must not decrypt with another
    /// (different ordering of the same ciphers).
    #[test]
    fn different_spec_cannot_decrypt() {
        use CipherId::*;
        let e1 = CascadeEngine::new(
            &vmk(),
            &CascadeSpec::new(&[Aes256, Serpent256]).unwrap(),
            512,
        )
        .unwrap();
        let e2 = CascadeEngine::new(
            &vmk(),
            &CascadeSpec::new(&[Serpent256, Aes256]).unwrap(),
            512,
        )
        .unwrap();
        let orig = sample_sector(512);
        let mut buf = orig.clone();
        e1.encrypt_sector(0, &mut buf).unwrap();
        e2.decrypt_sector(0, &mut buf).unwrap();
        assert_ne!(buf, orig);
    }

    /// Golden vector pinning the cascade convention. If the subkey
    /// derivation, tweak convention, or layer order ever drifts, this fails.
    #[test]
    fn cascade_golden_vector() {
        use CipherId::*;
        let vmk = Vmk::from_bytes([1; 64]);
        let spec = CascadeSpec::new(&[Aes256, Serpent256]).unwrap();
        let eng = CascadeEngine::new(&vmk, &spec, 512).unwrap();
        let mut buf = vec![0u8; 512];
        eng.encrypt_sector(0, &mut buf).unwrap();
        // Pinned at first implementation (2026-06): regenerate ONLY for a
        // deliberate, versioned format change.
        let expected_prefix = compute_golden();
        assert_eq!(&buf[..16], &expected_prefix[..]);
    }

    fn compute_golden() -> [u8; 16] {
        // Derived once from the implementation under test; stored as the
        // literal below after first run. The assert in cascade_golden_vector
        // is against this constant.
        hex_literal()
    }

    fn hex_literal() -> [u8; 16] {
        let mut out = [0u8; 16];
        out.copy_from_slice(&hex::decode(GOLDEN_PREFIX_HEX).unwrap());
        out
    }

    // Placeholder updated by the build process below (see test output).
    const GOLDEN_PREFIX_HEX: &str = "285d2912798b2d020fcd5a6158bef60f"; // pinned 2026-06-11, v1 format

    #[test]
    fn spec_validation() {
        assert!(CascadeSpec::new(&[]).is_err());
        assert!(CascadeSpec::new(&[CipherId::Aes256; 6]).is_err());
        let s = CascadeSpec::new(&[CipherId::Aes256]).unwrap();
        assert!(s.validate(false).is_ok());
        #[cfg(feature = "experimental")]
        {
            let e = CascadeSpec::new(&[CipherId::Threefish512]).unwrap();
            assert!(e.validate(false).is_err(), "experimental needs opt-in");
            assert!(e.validate(true).is_ok());
        }
    }

    #[test]
    fn cbor_roundtrip() {
        let s = CascadeSpec::new(&[CipherId::Aes256, CipherId::Serpent256]).unwrap();
        let b = minicbor::to_vec(&s).unwrap();
        let s2: CascadeSpec = minicbor::decode(&b).unwrap();
        assert_eq!(s, s2);
    }
}
