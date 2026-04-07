//! NtfsFilesystem — top-level handle for an NTFS volume.
//!
//! Provides volume probing, boot sector access, raw byte reading, and MFT
//! record retrieval.

use std::io::SeekFrom;

use abyss_cstruct::read::{FromBytes, ReadSeek};

use crate::boot::NtfsBootSector;
use crate::error::NtfsError;

/// Read `n` bytes from a `dyn ReadSeek` at the given offset.
fn read_at_dyn(reader: &mut dyn ReadSeek, offset: u64, n: usize) -> std::io::Result<Vec<u8>> {
    reader.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; n];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

/// Handle to an open NTFS volume.
pub struct NtfsFilesystem {
    /// Parsed boot sector.
    boot: NtfsBootSector,
    /// Underlying reader (disk image, block device, etc.).
    reader: Box<dyn ReadSeek>,
    /// Total volume size in bytes.
    volume_size: u64,
}

impl NtfsFilesystem {
    /// Returns `true` if `reader` looks like an NTFS volume.
    ///
    /// Reads the first 512 bytes and attempts to parse them as an
    /// [`NtfsBootSector`]. Any parse failure is treated as a non-NTFS volume.
    pub fn probe(reader: &mut Box<dyn ReadSeek>) -> bool {
        let buf = match read_at_dyn(reader.as_mut(), 0, 512) {
            Ok(b) => b,
            Err(_) => return false,
        };
        NtfsBootSector::from_bytes(&buf).is_ok()
    }

    /// Open an NTFS volume.
    ///
    /// Reads and validates the boot sector, then stores the reader for future
    /// operations.
    pub fn open(mut reader: Box<dyn ReadSeek>) -> Result<Self, NtfsError> {
        let buf = read_at_dyn(reader.as_mut(), 0, 512)?;
        let boot = NtfsBootSector::from_bytes(&buf)?;
        let volume_size = (boot.total_sectors + 1) * boot.bytes_per_sector as u64;
        Ok(Self {
            boot,
            reader,
            volume_size,
        })
    }

    /// Returns a reference to the parsed boot sector.
    pub fn boot_sector(&self) -> &NtfsBootSector {
        &self.boot
    }

    /// Total volume size in bytes.
    pub fn volume_size(&self) -> u64 {
        self.volume_size
    }

    /// Read `len` raw bytes from the volume starting at `offset`.
    pub fn read_at(&mut self, offset: u64, len: usize) -> Result<Vec<u8>, NtfsError> {
        let buf = read_at_dyn(self.reader.as_mut(), offset, len)?;
        Ok(buf)
    }

    /// Read and validate the MFT record at `index`.
    ///
    /// Returns the raw bytes of the record. Returns
    /// [`NtfsError::InvalidMftRecord`] if the record does not start with the
    /// `FILE` magic.
    pub fn read_mft_record(&mut self, index: u64) -> Result<Vec<u8>, NtfsError> {
        let record_size = self.boot.mft_record_size();
        let offset = self.boot.mft_offset() + index * record_size;
        let buf = read_at_dyn(self.reader.as_mut(), offset, record_size as usize)?;

        // Validate FILE magic.
        if buf.len() < 4 || &buf[0..4] != b"FILE" {
            return Err(NtfsError::InvalidMftRecord { index });
        }

        Ok(buf)
    }
}
