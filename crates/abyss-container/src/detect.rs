use crate::error::ContainerError;
use crate::traits::BlockDevice;
use abyss_cstruct::read::ReadSeek;
use crate::e01::E01Container;
use crate::vmdk::VmdkContainer;
use crate::raw::RawContainer;
use crate::traits::ContainerParser;
use std::io::SeekFrom;

/// Try to detect the container format and open it.
/// Probes E01 first (most specific magic), then VMDK, then falls back to Raw.
pub fn detect_and_open(mut input: Box<dyn ReadSeek>) -> Result<Box<dyn BlockDevice>, ContainerError> {
    // Try E01
    if E01Container::probe(input.as_mut())? {
        input.seek(SeekFrom::Start(0))?;
        return E01Container::open(input);
    }
    input.seek(SeekFrom::Start(0))?;

    // Try VMDK
    if VmdkContainer::probe(input.as_mut())? {
        input.seek(SeekFrom::Start(0))?;
        return VmdkContainer::open(input);
    }
    input.seek(SeekFrom::Start(0))?;

    // Fall back to raw
    RawContainer::open(input)
}
