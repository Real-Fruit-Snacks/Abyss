use thiserror::Error;

#[derive(Debug, Error)]
pub enum ContainerError {
    #[error("unsupported container format")]
    UnsupportedFormat,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("parse error: {0}")]
    Parse(#[from] abyss_cstruct::ParseError),
}
