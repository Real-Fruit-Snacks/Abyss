//! abyss-ntfs: NTFS filesystem parser.
//!
//! Parses NTFS volumes: boot sector, MFT, attributes, directory indexes.

pub mod attribute;
pub mod boot;
pub mod datarun;
pub mod error;
pub mod filename;
pub mod index;
pub mod mft;
pub mod ntfs;

pub use error::NtfsError;
pub use ntfs::NtfsFilesystem;
