use thiserror::Error;

#[derive(Debug, Error)]
pub enum AdError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid NTDS database")]
    InvalidDatabase,
    #[error("parse error: {0}")]
    Parse(String),
}
