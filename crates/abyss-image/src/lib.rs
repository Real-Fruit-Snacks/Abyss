use thiserror::Error;

#[derive(Debug, Error)]
pub enum ImageError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("unsupported image format: {0}")]
    UnsupportedFormat(String),
    #[error("parse error: {0}")]
    Parse(String),
}
