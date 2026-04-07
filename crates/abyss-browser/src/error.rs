use thiserror::Error;

#[derive(Debug, Error)]
pub enum BrowserError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("crypto error: {0}")]
    Crypto(#[from] abyss_crypto::CryptoError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("AES-GCM decrypt error")]
    AesGcm,

    #[error("invalid data: {detail}")]
    InvalidData { detail: String },
}
