//! abyss-container: Disk image container parsers.
//!
//! Handles raw, E01 (EnCase), and VMDK disk images.

pub mod detect;
pub mod e01;
pub mod error;
pub mod raw;
pub mod shared;
pub mod traits;
pub mod vmdk;

pub use detect::detect_and_open;
pub use error::ContainerError;
pub use shared::SharedBlockDevice;
pub use traits::{BlockDevice, ContainerParser};
