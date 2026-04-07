use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExtfsError {
    #[error("not an ext filesystem")]
    NotExtfs,

    #[error("unsupported ext feature: {feature}")]
    UnsupportedFeature { feature: String },

    #[error("invalid inode {inode}")]
    InvalidInode { inode: u64 },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("parse error: {0}")]
    Parse(#[from] abyss_cstruct::ParseError),
}
