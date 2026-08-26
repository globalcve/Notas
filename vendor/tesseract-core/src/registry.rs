//! Algorithm registry: stable on-disk identifiers and capability metadata.
//!
//! IDs are u16 and permanently stable — never renumber. IDs >= 100 are the
//! experimental range: compiled only with the `experimental` cargo feature
//! and additionally per-volume opt-in, labeled non-standard in the GUI.

use crate::error::{Error, Result};

pub const EXPERIMENTAL_ID_BASE: u16 = 100;

macro_rules! id_enum {
    ($(#[$m:meta])* $name:ident { $($(#[$vm:meta])* $variant:ident = $val:expr => $label:expr),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        #[repr(u16)]
        pub enum $name {
            $($(#[$vm])* $variant = $val),+
        }

        impl $name {
            pub const ALL: &'static [$name] = &[$($name::$variant),+];

            pub fn from_u16(v: u16) -> Result<Self> {
                match v {
                    $($val => Ok($name::$variant),)+
                    other => Err(Error::UnknownAlgorithm(other)),
                }
            }

            pub fn as_u16(self) -> u16 {
                self as u16
            }

            /// Human-readable display name.
            pub fn label(self) -> &'static str {
                match self {
                    $($name::$variant => $label),+
                }
            }

            /// True if this id sits in the experimental (gated) range.
            pub fn is_experimental(self) -> bool {
                self.as_u16() >= EXPERIMENTAL_ID_BASE
            }
        }
    };
}

id_enum! {
    /// Cascade-eligible symmetric ciphers (sector layers and file-mode layers).
    CipherId {
        Aes256 = 1 => "AES-256",
        Serpent256 = 2 => "Serpent-256",
        Twofish256 = 3 => "Twofish-256",
        Camellia256 = 4 => "Camellia-256",
        ChaCha20 = 5 => "ChaCha20",
        XChaCha20 = 6 => "XChaCha20",
        Threefish512 = 100 => "Threefish-512",
        Kuznyechik = 101 => "Kuznyechik (GOST R 34.12-2015)",
        Sm4 = 102 => "SM4",
        Aria256 = 103 => "ARIA-256",
        Adiantum = 104 => "Adiantum",
    }
}

id_enum! {
    /// Hashes (keyfile digestion, PBKDF2 PRF selection).
    HashId {
        Sha512 = 1 => "SHA-512",
        Sha256 = 2 => "SHA-256",
        Blake3 = 3 => "BLAKE3",
        Blake2b = 4 => "BLAKE2b-512",
        Whirlpool = 100 => "Whirlpool",
        Streebog512 = 101 => "Streebog-512",
    }
}

id_enum! {
    /// Password-hashing KDFs for passphrase keyslots.
    KdfId {
        Argon2id = 1 => "Argon2id",
        Scrypt = 2 => "scrypt",
        Pbkdf2 = 3 => "PBKDF2-HMAC",
        Balloon = 100 => "Balloon (experimental)",
    }
}

id_enum! {
    /// KEMs for asymmetric keyslots and file mode.
    KemId {
        X25519 = 1 => "X25519",
        MlKem512 = 2 => "ML-KEM-512",
        MlKem768 = 3 => "ML-KEM-768",
        MlKem1024 = 4 => "ML-KEM-1024",
        HybridX25519MlKem1024 = 5 => "Hybrid X25519 + ML-KEM-1024",
        // Reserved (not implemented): ClassicMcEliece=100, FrodoKem=101,
        // Hqc=102, Bike=103, Sntrup761=104. Kept out of the enum so they can
        // never be constructed; from_u16 reports them as unknown.
    }
}

id_enum! {
    /// Signature schemes for attested volumes and file-mode signing.
    SigId {
        Ed25519 = 1 => "Ed25519",
        MlDsa44 = 2 => "ML-DSA-44",
        MlDsa65 = 3 => "ML-DSA-65",
        MlDsa87 = 4 => "ML-DSA-87",
        // Reserved: Falcon=100, SphincsPlus=101.
    }
}

id_enum! {
    /// AEADs for keyslot sealing (always wrapped in the committing
    /// construction, see `aeadx`) and file-mode body layers.
    AeadId {
        XChaCha20Poly1305 = 1 => "XChaCha20-Poly1305",
        Aes256GcmSiv = 2 => "AES-256-GCM-SIV",
        Aes256Gcm = 3 => "AES-256-GCM",
        ChaCha20Poly1305 = 4 => "ChaCha20-Poly1305",
    }
}

impl CipherId {
    /// Key length in bytes for ONE role (data or tweak); each layer derives
    /// two independent keys of this size.
    pub fn key_len(self) -> usize {
        match self {
            CipherId::Threefish512 => 64,
            _ => 32,
        }
    }

    /// True if the layer is a tweakable block-cipher construction (XTS or a
    /// natively tweakable cipher) rather than a stream cipher. Stream layers
    /// carry the sector-rewrite caveat (DECISIONS.md D-04).
    pub fn is_block_mode(self) -> bool {
        !matches!(self, CipherId::ChaCha20 | CipherId::XChaCha20)
    }

    /// Compiled into this build?
    pub fn is_available(self) -> bool {
        if !self.is_experimental() {
            return true;
        }
        cfg!(feature = "experimental")
    }
}

impl HashId {
    pub fn is_available(self) -> bool {
        !self.is_experimental() || cfg!(feature = "experimental")
    }

    pub fn digest_len(self) -> usize {
        match self {
            HashId::Sha256 => 32,
            HashId::Blake3 => 32,
            _ => 64,
        }
    }
}

impl KdfId {
    pub fn is_available(self) -> bool {
        !self.is_experimental() || cfg!(feature = "experimental")
    }
}

/// Reject experimental algorithms unless the caller opted in. Volumes record
/// the opt-in; the GUI exposes it as the "experimental algorithms" toggle.
pub fn gate_experimental(id_is_experimental: bool, label: &'static str, opted_in: bool) -> Result<()> {
    if id_is_experimental {
        if !cfg!(feature = "experimental") || !opted_in {
            return Err(Error::ExperimentalGated(label));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_ids() {
        for c in CipherId::ALL {
            assert_eq!(CipherId::from_u16(c.as_u16()).unwrap(), *c);
        }
        assert!(CipherId::from_u16(9999).is_err());
        assert!(CipherId::Aes256.is_block_mode());
        assert!(!CipherId::XChaCha20.is_block_mode());
        assert!(CipherId::Threefish512.is_experimental());
        assert!(!CipherId::Serpent256.is_experimental());
        assert_eq!(CipherId::Threefish512.key_len(), 64);
    }
}
