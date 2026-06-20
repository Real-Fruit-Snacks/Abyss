//! NTFS Boot Sector parser.
//!
//! Parses the NTFS BPB (BIOS Parameter Block) from the first sector of an NTFS volume.

use abyss_cstruct::read::{read_u16_le, read_u64_le, FromBytes};
use abyss_cstruct::ParseError;

/// NTFS OEM ID string, at offset 3 in the boot sector.
const NTFS_OEM_ID: &[u8; 8] = b"NTFS    ";

/// Parsed NTFS boot sector (BPB).
#[derive(Debug, Clone)]
pub struct NtfsBootSector {
    /// OEM ID string (should be "NTFS    ").
    pub oem_id: [u8; 8],
    /// Bytes per logical sector.
    pub bytes_per_sector: u16,
    /// Sectors per cluster.
    pub sectors_per_cluster: u8,
    /// Total number of sectors on the volume.
    pub total_sectors: u64,
    /// LCN (Logical Cluster Number) of the MFT.
    pub mft_cluster: u64,
    /// LCN of the MFT mirror.
    pub mft_mirror_cluster: u64,
    /// Clusters per MFT record (encoded: positive = clusters, negative = power of 2 bytes).
    pub clusters_per_mft_record: i8,
}

impl NtfsBootSector {
    /// Bytes per cluster.
    pub fn bytes_per_cluster(&self) -> u64 {
        self.bytes_per_sector as u64 * self.sectors_per_cluster as u64
    }

    /// Size of one MFT record in bytes.
    ///
    /// If `clusters_per_mft_record` is positive, it is a cluster count.
    /// If negative, the record size is `2^(-clusters_per_mft_record)`.
    pub fn mft_record_size(&self) -> u64 {
        if self.clusters_per_mft_record > 0 {
            self.bytes_per_cluster() * self.clusters_per_mft_record as u64
        } else {
            1u64 << (-(self.clusters_per_mft_record as i32)) as u32
        }
    }

    /// Byte offset of the MFT on the volume.
    pub fn mft_offset(&self) -> u64 {
        self.mft_cluster * self.bytes_per_cluster()
    }
}

impl FromBytes for NtfsBootSector {
    fn from_bytes(buf: &[u8]) -> Result<Self, ParseError> {
        // Minimum size: we need at least 88 bytes to cover all fields.
        if buf.len() < 88 {
            return Err(ParseError::BufferTooSmall {
                need: 88,
                have: buf.len(),
            });
        }

        // Validate OEM ID at offset 3.
        let mut oem_id = [0u8; 8];
        oem_id.copy_from_slice(&buf[3..11]);
        if &oem_id != NTFS_OEM_ID {
            return Err(ParseError::InvalidField {
                field: "oem_id",
                detail: format!("expected \"NTFS    \", got {:?}", &oem_id),
            });
        }

        let bytes_per_sector = read_u16_le(buf, 11)?;
        let sectors_per_cluster = buf[13];
        let total_sectors = read_u64_le(buf, 40)?;
        let mft_cluster = read_u64_le(buf, 48)?;
        let mft_mirror_cluster = read_u64_le(buf, 56)?;
        let clusters_per_mft_record = buf[64] as i8;

        Ok(NtfsBootSector {
            oem_id,
            bytes_per_sector,
            sectors_per_cluster,
            total_sectors,
            mft_cluster,
            mft_mirror_cluster,
            clusters_per_mft_record,
        })
    }

    fn fixed_size() -> Option<usize> {
        Some(512)
    }
}
