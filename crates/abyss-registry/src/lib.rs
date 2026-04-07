use thiserror::Error;

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid registry hive signature")]
    InvalidSignature,
    #[error("parse error: {0}")]
    Parse(String),
}
