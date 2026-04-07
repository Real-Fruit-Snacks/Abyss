use thiserror::Error;

#[derive(Debug, Error)]
pub enum NtfsError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid NTFS signature")]
    InvalidSignature,
    #[error("parse error: {0}")]
    Parse(String),
}
