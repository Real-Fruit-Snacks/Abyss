use thiserror::Error;

#[derive(Debug, Error)]
pub enum ContainerError {
    #[error("unsupported container format")]
    UnsupportedFormat,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("parse error: {0}")]
    Parse(#[from] abyss_cstruct::ParseError),

    #[error("invalid E01 segment: {detail}")]
    InvalidE01 { detail: String },

    #[error("invalid VMDK: {detail}")]
    InvalidVmdk { detail: String },

    #[error("decompression error: {0}")]
    Decompression(String),
}
