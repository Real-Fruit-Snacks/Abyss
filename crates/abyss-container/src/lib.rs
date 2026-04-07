//! abyss-container: Disk image container parsers.
//!
//! Handles raw disk images. Future: VMDK, QCOW2, VHDX, VDI, E01.

pub mod error;
pub mod raw;
pub mod traits;

pub use error::ContainerError;
pub use traits::{BlockDevice, ContainerParser};
