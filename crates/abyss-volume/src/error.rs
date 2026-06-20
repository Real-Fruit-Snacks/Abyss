use thiserror::Error;

#[derive(Debug, Error)]
pub enum VolumeError {
    #[error("no partition table found")]
    NoPartitionTable,

    #[error("invalid partition table: {detail}")]
    InvalidPartitionTable { detail: String },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("parse error: {0}")]
    Parse(#[from] abyss_cstruct::ParseError),
}
