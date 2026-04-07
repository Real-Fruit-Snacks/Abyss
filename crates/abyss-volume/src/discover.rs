//! Partition auto-discovery: tries GPT first, falls back to MBR.

use abyss_cstruct::read::ReadSeek;

use crate::error::VolumeError;
use crate::gpt;
use crate::mbr;
use crate::partition::Partition;

/// Auto-detect partition table type and parse all partitions.
/// Tries GPT first (since GPT disks also have a protective MBR).
/// Falls back to MBR. Returns error if neither is found.
pub fn discover_partitions<R: ReadSeek>(
    reader: &mut R,
    sector_size: u64,
) -> Result<Vec<Partition>, VolumeError> {
    // Try GPT first
    if gpt::is_gpt(reader, sector_size) {
        match gpt::parse_gpt(reader, sector_size) {
            Ok(parts) if !parts.is_empty() => return Ok(parts),
            Ok(_) => {} // empty GPT, try MBR
            Err(e) => log::debug!("GPT parse failed: {}, trying MBR", e),
        }
    }

    // Try MBR
    if mbr::is_mbr(reader) {
        match mbr::parse_mbr(reader, sector_size) {
            Ok(parts) => return Ok(parts),
            Err(e) => log::debug!("MBR parse failed: {}", e),
        }
    }

    Err(VolumeError::NoPartitionTable)
}
