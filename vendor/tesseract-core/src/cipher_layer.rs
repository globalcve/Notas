//! One cascade layer: a length-preserving, tweakable sector transform.
//!
//! Block ciphers with 128-bit blocks run in XTS. Threefish-512 uses its
//! native 128-bit tweak (it is already a tweakable block cipher; XTS would
//! only emulate what it does natively). Adiantum is a wide-block mode and
//! consumes the whole sector at once. ChaCha20/XChaCha20 are stream layers
//! with a KMAC-derived per-sector nonce (see DECISIONS.md D-04 for the
//! rewrite caveat).

use cipher::{KeyInit, KeyIvInit, StreamCipher};
use xts_mode::{get_tweak_default, Xts128};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::kmac;
use crate::registry::CipherId;

/// A sector-granular, length-preserving cipher layer.
pub trait SectorLayer: Send + Sync {
    /// Encrypt one sector in place. `buf.len()` must be the volume sector size
    /// (a multiple of 16, >= 64).
    fn encrypt_sector(&self, sector_index: u64, buf: &mut [u8]);
    /// Decrypt one sector in place.
    fn decrypt_sector(&self, sector_index: u64, buf: &mut [u8]);
}

/// Derive the (data, tweak) subkeys for layer `index` of a cascade, per the
/// brief: `KMAC256(VMK, "pqc/layer" || index || role)`.
/// role 0 = data key, role 1 = tweak/nonce key.
pub fn derive_layer_keys(
    vmk: &crate::Vmk,
    index: u8,
    key_len: usize,
) -> (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>) {
    let mut data_key = Zeroizing::new(vec![0u8; key_len]);
    let mut tweak_key = Zeroizing::new(vec![0u8; key_len]);
    kmac::kmac256(
        vmk.as_bytes(),
        kmac::L_LAYER,
        &[index, 0],
        &mut data_key,
    );
    kmac::kmac256(
        vmk.as_bytes(),
        kmac::L_LAYER,
        &[index, 1],
        &mut tweak_key,
    );
    (data_key, tweak_key)
}

/// XTS over any 128-bit block cipher.
struct XtsLayer<C: cipher::BlockCipherEncrypt + cipher::BlockCipherDecrypt> {
    xts: Xts128<C>,
}

impl<C> SectorLayer for XtsLayer<C>
where
    C: cipher::BlockCipherEncrypt
        + cipher::BlockCipherDecrypt
        + cipher::BlockSizeUser<BlockSize = cipher::consts::U16>
        + Send
        + Sync,
{
    fn encrypt_sector(&self, sector_index: u64, buf: &mut [u8]) {
        let tweak = get_tweak_default(sector_index as u128);
        self.xts.encrypt_sector(buf, tweak);
    }

    fn decrypt_sector(&self, sector_index: u64, buf: &mut [u8]) {
        let tweak = get_tweak_default(sector_index as u128);
        self.xts.decrypt_sector(buf, tweak);
    }
}

fn xts_layer<C>(data_key: &[u8], tweak_key: &[u8]) -> Result<Box<dyn SectorLayer>>
where
    C: cipher::BlockCipherEncrypt
        + cipher::BlockCipherDecrypt
        + cipher::BlockSizeUser<BlockSize = cipher::consts::U16>
        + KeyInit
        + Send
        + Sync
        + 'static,
{
    let c1 = C::new_from_slice(data_key).map_err(|_| Error::InvalidParameter("key length"))?;
    let c2 = C::new_from_slice(tweak_key).map_err(|_| Error::InvalidParameter("key length"))?;
    Ok(Box::new(XtsLayer { xts: Xts128::new(c1, c2) }))
}

/// ChaCha20/XChaCha20 stream layer. Per-sector nonce derived from the tweak
/// key: `KMAC256(tweak_key, "pqc/chacha-iv", sector_le)`.
struct StreamLayer {
    xchacha: bool,
    data_key: Zeroizing<[u8; 32]>,
    tweak_key: Zeroizing<[u8; 32]>,
}

impl StreamLayer {
    fn apply(&self, sector_index: u64, buf: &mut [u8]) {
        if self.xchacha {
            let mut nonce = [0u8; 24];
            kmac::kmac256(
                &*self.tweak_key,
                kmac::L_CHACHA_IV,
                &sector_index.to_le_bytes(),
                &mut nonce,
            );
            let mut c = chacha20::XChaCha20::new((&*self.data_key).into(), (&nonce).into());
            c.apply_keystream(buf);
        } else {
            let mut nonce = [0u8; 12];
            kmac::kmac256(
                &*self.tweak_key,
                kmac::L_CHACHA_IV,
                &sector_index.to_le_bytes(),
                &mut nonce,
            );
            let mut c = chacha20::ChaCha20::new((&*self.data_key).into(), (&nonce).into());
            c.apply_keystream(buf);
        }
    }
}

impl SectorLayer for StreamLayer {
    fn encrypt_sector(&self, sector_index: u64, buf: &mut [u8]) {
        self.apply(sector_index, buf);
    }
    fn decrypt_sector(&self, sector_index: u64, buf: &mut [u8]) {
        self.apply(sector_index, buf);
    }
}

#[cfg(feature = "experimental")]
mod experimental {
    use super::*;

    /// Threefish-512 with its native tweak: tweak = (sector_index, block_no).
    pub struct Threefish512Layer {
        pub data_key: Zeroizing<[u8; 64]>,
    }

    impl SectorLayer for Threefish512Layer {
        fn encrypt_sector(&self, sector_index: u64, buf: &mut [u8]) {
            use cipher::BlockCipherEncrypt;
            for (i, block) in buf.chunks_exact_mut(64).enumerate() {
                let tf = threefish::Threefish512::new_with_tweak(
                    &self.data_key,
                    &tweak_bytes(sector_index, i as u64),
                );
                let block: &mut [u8; 64] = block.try_into().expect("chunks_exact(64)");
                tf.encrypt_block(block.into());
            }
        }

        fn decrypt_sector(&self, sector_index: u64, buf: &mut [u8]) {
            use cipher::BlockCipherDecrypt;
            for (i, block) in buf.chunks_exact_mut(64).enumerate() {
                let tf = threefish::Threefish512::new_with_tweak(
                    &self.data_key,
                    &tweak_bytes(sector_index, i as u64),
                );
                let block: &mut [u8; 64] = block.try_into().expect("chunks_exact(64)");
                tf.decrypt_block(block.into());
            }
        }
    }

    fn tweak_bytes(sector: u64, block: u64) -> [u8; 16] {
        let mut t = [0u8; 16];
        t[..8].copy_from_slice(&sector.to_le_bytes());
        t[8..].copy_from_slice(&block.to_le_bytes());
        t
    }

    /// Adiantum (XChaCha12 + AES-256 as in the paper and the kernel): a true
    /// wide-block tweakable mode; the whole sector is one block, tweak =
    /// sector index.
    pub struct AdiantumLayer {
        pub cipher: adiantum::Cipher<chacha20::XChaCha12, aes::Aes256>,
    }

    impl SectorLayer for AdiantumLayer {
        fn encrypt_sector(&self, sector_index: u64, buf: &mut [u8]) {
            let tweak = sector_index.to_le_bytes();
            self.cipher.encrypt(buf, &tweak);
        }
        fn decrypt_sector(&self, sector_index: u64, buf: &mut [u8]) {
            let tweak = sector_index.to_le_bytes();
            self.cipher.decrypt(buf, &tweak);
        }
    }
}

/// Build one cascade layer for `id` at cascade position `index`, deriving its
/// subkeys from the VMK.
pub fn build_layer(id: CipherId, index: u8, vmk: &crate::Vmk) -> Result<Box<dyn SectorLayer>> {
    if !id.is_available() {
        return Err(Error::ExperimentalGated(id.label()));
    }
    let (dk, tk) = derive_layer_keys(vmk, index, id.key_len());
    match id {
        CipherId::Aes256 => xts_layer::<aes::Aes256>(&dk, &tk),
        CipherId::Serpent256 => xts_layer::<serpent::Serpent>(&dk, &tk),
        CipherId::Twofish256 => xts_layer::<twofish::Twofish>(&dk, &tk),
        CipherId::Camellia256 => xts_layer::<camellia::Camellia256>(&dk, &tk),
        CipherId::ChaCha20 | CipherId::XChaCha20 => {
            let mut data_key = Zeroizing::new([0u8; 32]);
            let mut tweak_key = Zeroizing::new([0u8; 32]);
            data_key.copy_from_slice(&dk);
            tweak_key.copy_from_slice(&tk);
            Ok(Box::new(StreamLayer {
                xchacha: id == CipherId::XChaCha20,
                data_key,
                tweak_key,
            }))
        }
        #[cfg(feature = "experimental")]
        CipherId::Kuznyechik => xts_layer::<kuznyechik::Kuznyechik>(&dk, &tk),
        #[cfg(feature = "experimental")]
        CipherId::Sm4 => {
            // SM4 keys are 128-bit; use the first 16 bytes of each subkey.
            xts_layer::<sm4::Sm4>(&dk[..16], &tk[..16])
        }
        #[cfg(feature = "experimental")]
        CipherId::Aria256 => xts_layer::<aria::Aria256>(&dk, &tk),
        #[cfg(feature = "experimental")]
        CipherId::Threefish512 => {
            let mut data_key = Zeroizing::new([0u8; 64]);
            data_key.copy_from_slice(&dk);
            Ok(Box::new(experimental::Threefish512Layer { data_key }))
        }
        #[cfg(feature = "experimental")]
        CipherId::Adiantum => {
            let cipher = adiantum::Cipher::<chacha20::XChaCha12, aes::Aes256>::new_from_slice(&dk)
                .map_err(|_| Error::InvalidParameter("key length"))?;
            Ok(Box::new(experimental::AdiantumLayer { cipher }))
        }
        #[cfg(not(feature = "experimental"))]
        _ => Err(Error::ExperimentalGated(id.label())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Vmk;

    fn vmk() -> Vmk {
        Vmk::from_bytes([7u8; 64])
    }

    #[test]
    fn every_available_cipher_roundtrips() {
        for &id in CipherId::ALL {
            if !id.is_available() {
                continue;
            }
            let layer = build_layer(id, 0, &vmk()).unwrap();
            let mut sector = vec![0u8; 4096];
            for (i, b) in sector.iter_mut().enumerate() {
                *b = (i % 251) as u8;
            }
            let orig = sector.clone();
            layer.encrypt_sector(42, &mut sector);
            assert_ne!(sector, orig, "{:?} did not change the data", id);
            layer.decrypt_sector(42, &mut sector);
            assert_eq!(sector, orig, "{:?} did not round-trip", id);
        }
    }

    #[test]
    fn sector_index_matters() {
        let layer = build_layer(CipherId::Aes256, 0, &vmk()).unwrap();
        let mut a = vec![0xABu8; 512];
        let mut b = vec![0xABu8; 512];
        layer.encrypt_sector(1, &mut a);
        layer.encrypt_sector(2, &mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn layer_index_changes_subkeys() {
        let l0 = build_layer(CipherId::Aes256, 0, &vmk()).unwrap();
        let l1 = build_layer(CipherId::Aes256, 1, &vmk()).unwrap();
        let mut a = vec![0u8; 512];
        let mut b = vec![0u8; 512];
        l0.encrypt_sector(0, &mut a);
        l1.encrypt_sector(0, &mut b);
        assert_ne!(a, b);
    }

    /// IEEE 1619 XTS-AES-256 known-answer vector (Vector 10 of the standard's
    /// test set: 512-byte data unit, sequential plaintext).
    #[test]
    fn xts_aes256_kat() {
        use cipher::KeyInit;
        let key1 = hex::decode(
            "2718281828459045235360287471352662497757247093699959574966967627",
        )
        .unwrap();
        let key2 = hex::decode(
            "3141592653589793238462643383279502884197169399375105820974944592",
        )
        .unwrap();
        let mut pt = [0u8; 512];
        for (i, b) in pt.iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }
        let c1 = aes::Aes256::new_from_slice(&key1).unwrap();
        let c2 = aes::Aes256::new_from_slice(&key2).unwrap();
        let xts = Xts128::new(c1, c2);
        let mut buf = pt;
        xts.encrypt_sector(&mut buf, get_tweak_default(0xff));
        let head =
            hex::decode("1c3b3a102f770386e4836c99e370cf9bea00803f5e482357a4ae12d414a3e63b")
                .unwrap();
        assert_eq!(&buf[..32], head.as_slice());
        // and the inverse returns the plaintext
        let mut back = buf;
        xts.decrypt_sector(&mut back, get_tweak_default(0xff));
        assert_eq!(back, pt);
    }
}
