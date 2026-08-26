use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    /// Generic, timing-flat credential failure. Deliberately does not say
    /// which step failed (KDF, commitment, AEAD tag, KEM decap, header MAC).
    #[error("unlock failed: wrong credentials or corrupted volume")]
    UnlockFailed,

    #[error("header integrity check failed")]
    HeaderIntegrity,

    #[error("not a Tesseract volume (bad magic)")]
    BadMagic,

    #[error("unsupported format version {0}")]
    UnsupportedVersion(u16),

    #[error("malformed header: {0}")]
    MalformedHeader(&'static str),

    #[error("algorithm {0:#06x} unknown or not enabled in this build")]
    UnknownAlgorithm(u16),

    #[error("experimental algorithm {0} requires the experimental feature/opt-in")]
    ExperimentalGated(&'static str),

    #[error("invalid cascade: {0}")]
    InvalidCascade(&'static str),

    #[error("invalid parameter: {0}")]
    InvalidParameter(&'static str),

    #[error("keyslot table full")]
    SlotsFull,

    #[error("no such keyslot {0}")]
    NoSuchSlot(u8),

    #[error("buffer length {got} invalid, expected {want}")]
    Length { want: usize, got: usize },

    #[error("volume geometry invalid: {0}")]
    Geometry(&'static str),

    #[error("state machine: cannot {action} from {state}")]
    BadTransition {
        state: &'static str,
        action: &'static str,
    },

    #[error("in-place conversion journal corrupt or mismatched")]
    JournalCorrupt,

    #[error("io: {0}")]
    Io(&'static str),

    #[error("file format: {0}")]
    FileFormat(&'static str),

    #[error("signature verification failed")]
    BadSignature,

    #[error("recipient cannot open this file")]
    NotARecipient,

    #[error("hidden volume protection triggered: write into hidden region refused")]
    HiddenProtection,

    #[error("cbor: {0}")]
    Cbor(&'static str),
}

impl From<minicbor::decode::Error> for Error {
    fn from(_: minicbor::decode::Error) -> Self {
        Error::Cbor("decode")
    }
}

impl<T> From<minicbor::encode::Error<T>> for Error {
    fn from(_: minicbor::encode::Error<T>) -> Self {
        Error::Cbor("encode")
    }
}
