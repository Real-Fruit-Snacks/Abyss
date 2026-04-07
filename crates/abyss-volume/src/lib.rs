//! abyss-volume: Partition and volume management.
//!
//! Parses GPT and MBR partition tables. Future: LVM2, VSS.

pub mod error;
pub mod gpt;
pub mod mbr;
pub mod partition;

pub use error::VolumeError;
pub use partition::Partition;
