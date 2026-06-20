use thiserror::Error;

#[derive(Debug, Error)]
pub enum NtfsError {
    #[error("not an NTFS volume")]
    NotNtfs,

    #[error("invalid MFT record at index {index}")]
    InvalidMftRecord { index: u64 },

    #[error("attribute error: {detail}")]
    AttributeError { detail: String },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("parse error: {0}")]
    Parse(#[from] abyss_cstruct::ParseError),
}
