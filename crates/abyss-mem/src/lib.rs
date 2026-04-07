use thiserror::Error;

#[derive(Debug, Error)]
pub enum MemError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("unsupported memory dump format: {0}")]
    UnsupportedFormat(String),
    #[error("parse error: {0}")]
    Parse(String),
}
