use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("registry error: {0}")]
    Registry(#[from] abyss_registry::RegistryError),

    #[error("key not found: {key}")]
    KeyNotFound { key: String },

    #[error("value not found: {name}")]
    ValueNotFound { name: String },

    #[error("invalid data: {detail}")]
    InvalidData { detail: String },

    #[error("decrypt error: {detail}")]
    Decrypt { detail: String },

    #[error("buffer too small: need {need}, have {have}")]
    BufferTooSmall { need: usize, have: usize },
}
