//! abyss-ntfs: NTFS filesystem parser.
//!
//! Parses NTFS volumes: boot sector, MFT, attributes, directory indexes.

pub mod attribute;
pub mod boot;
pub mod error;
pub mod mft;

pub use error::NtfsError;
