use thiserror::Error;

#[derive(Debug, Error)]
pub enum EseError {
    #[error("not an ESE database")]
    NotEse,

    #[error("unsupported ESE version: {version}")]
    UnsupportedVersion { version: u32 },

    #[error("table not found: {name}")]
    TableNotFound { name: String },

    #[error("column not found: {name}")]
    ColumnNotFound { name: String },

    #[error("page {page} out of range")]
    PageOutOfRange { page: u32 },

    #[error("invalid page: {detail}")]
    InvalidPage { detail: String },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("parse error: {0}")]
    Parse(#[from] abyss_cstruct::ParseError),
}
