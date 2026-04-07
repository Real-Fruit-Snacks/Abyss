use crate::error::ContainerError;
use crate::traits::{BlockDevice, ContainerParser};
use abyss_cstruct::read::ReadSeek;
use std::io::{Read, Seek, SeekFrom};

/// A raw disk image — passthrough to the underlying file.
pub struct RawContainer {
    inner: Box<dyn ReadSeek>,
    size: u64,
}

impl RawContainer {
    fn new(mut inner: Box<dyn ReadSeek>) -> Result<Self, ContainerError> {
        let size = inner.seek(SeekFrom::End(0))?;
        inner.seek(SeekFrom::Start(0))?;
        Ok(Self { inner, size })
    }
}

impl ContainerParser for RawContainer {
    fn probe(_input: &mut dyn ReadSeek) -> Result<bool, ContainerError> {
        // Raw container is the fallback — it accepts everything.
        Ok(true)
    }

    fn open(input: Box<dyn ReadSeek>) -> Result<Box<dyn BlockDevice>, ContainerError> {
        Ok(Box::new(RawContainer::new(input)?))
    }
}

impl Read for RawContainer {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Seek for RawContainer {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(pos)
    }
}

impl BlockDevice for RawContainer {
    fn size(&self) -> u64 {
        self.size
    }
}
