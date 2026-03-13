use thiserror::Error;

#[derive(Debug, Error)]
pub enum RokError {
    #[error("key derivation failed: {0}")]
    DerivationError(String),

    #[error("encryption failed: {0}")]
    EncryptionError(String),

    #[error("decryption failed: {0}")]
    DecryptionError(String),

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("invalid scope path: {0}")]
    InvalidScope(String),

    #[error("no matching access entry for key id {0}")]
    NoMatchingAccessEntry(String),

    #[error("key not found: {0}")]
    KeyNotFound(String),

    #[error("key revoked: {0}")]
    KeyRevoked(String),

    #[error("serialization error: {0}")]
    SerializationError(String),

    #[error("invalid key material")]
    InvalidKeyMaterial,

    #[error("scope mismatch: key scope '{key_scope}' cannot access data at scope '{data_scope}'")]
    ScopeMismatch {
        key_scope: String,
        data_scope: String,
    },

    #[error("encoding error: {0}")]
    EncodingError(String),

    #[error("invalid checksum")]
    InvalidChecksum,

    #[error("invalid type tag: expected {expected}, got {got}")]
    InvalidTypeTag { expected: u8, got: u8 },
}

pub type Result<T> = std::result::Result<T, RokError>;
