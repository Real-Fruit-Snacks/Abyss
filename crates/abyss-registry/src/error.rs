use thiserror::Error;

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("not a registry hive (invalid magic)")]
    NotRegistryHive,

    #[error("key not found: {path}")]
    KeyNotFound { path: String },

    #[error("value not found: {name}")]
    ValueNotFound { name: String },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("parse error: {0}")]
    Parse(#[from] abyss_cstruct::ParseError),
}
