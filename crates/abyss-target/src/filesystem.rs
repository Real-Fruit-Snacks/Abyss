use std::fmt;
use std::time::SystemTime;

/// Metadata for a file or directory on a target filesystem.
#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub size: u64,
    pub is_directory: bool,
    pub is_file: bool,
    pub created: Option<SystemTime>,
    pub modified: Option<SystemTime>,
    pub accessed: Option<SystemTime>,
}

/// A single directory entry from a target filesystem.
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub is_directory: bool,
    pub size: u64,
}

impl fmt::Display for DirEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_directory {
            write!(f, "{}/", self.name)
        } else {
            write!(f, "{} ({})", self.name, self.size)
        }
    }
}
