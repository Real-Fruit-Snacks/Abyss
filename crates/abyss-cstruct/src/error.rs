use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("buffer too small: need {need} bytes, have {have}")]
    BufferTooSmall { need: usize, have: usize },

    #[error("invalid magic: expected {expected:#x}, got {got:#x}")]
    InvalidMagic { expected: u64, got: u64 },

    #[error("invalid value for field '{field}': {detail}")]
    InvalidField { field: &'static str, detail: String },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
