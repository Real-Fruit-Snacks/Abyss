use std::fmt;

/// Detected operating system type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OsType {
    Windows,
    Linux,
    Unknown,
}

impl fmt::Display for OsType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OsType::Windows => write!(f, "Windows"),
            OsType::Linux => write!(f, "Linux"),
            OsType::Unknown => write!(f, "Unknown"),
        }
    }
}
