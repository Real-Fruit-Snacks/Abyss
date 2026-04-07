use thiserror::Error;

#[derive(Debug, Error)]
pub enum MemoryError {
    #[error("not a valid memory dump")]
    NotMemoryDump,
    #[error("unsupported dump format: {format}")]
    UnsupportedFormat { format: String },
    #[error("virtual address {addr:#x} not mapped")]
    AddressNotMapped { addr: u64 },
    #[error("LSASS process not found")]
    LsassNotFound,
    #[error("pattern not found: {pattern}")]
    PatternNotFound { pattern: String },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse error: {0}")]
    Parse(#[from] abyss_cstruct::ParseError),
}
