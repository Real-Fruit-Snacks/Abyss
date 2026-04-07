//! abyss-ntfs: NTFS filesystem parser.
//!
//! Parses NTFS volumes: boot sector, MFT, attributes, directory indexes.

pub mod error;

pub use error::NtfsError;
