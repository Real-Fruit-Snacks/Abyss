use crate::ContainerError;
use abyss_cstruct::read::ReadSeek;
use std::io::{Read, Seek};

/// A virtual block device — the output of opening a container.
/// Provides seekable read access to raw disk bytes.
pub trait BlockDevice: Read + Seek + Send {
    /// Total size of the block device in bytes.
    fn size(&self) -> u64;

    /// Sector size (typically 512).
    fn sector_size(&self) -> u32 {
        512
    }
}

/// Parser for a specific container format.
pub trait ContainerParser {
    /// Check if this parser can handle the given input by inspecting magic bytes.
    fn probe(input: &mut dyn ReadSeek) -> Result<bool, ContainerError>
    where
        Self: Sized;

    /// Open the container, returning a virtual block device.
    fn open(input: Box<dyn ReadSeek>) -> Result<Box<dyn BlockDevice>, ContainerError>
    where
        Self: Sized;
}
