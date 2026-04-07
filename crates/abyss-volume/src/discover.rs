//! Partition auto-discovery: tries GPT first, falls back to MBR.

use abyss_cstruct::read::ReadSeek;

use crate::error::VolumeError;
use crate::mbr::{is_mbr, parse_mbr};
use crate::partition::Partition;

/// Discover partitions on a disk image.
///
/// Tries GPT first (since GPT disks have a protective MBR at sector 0).
/// Falls back to MBR if GPT is not present or not yet implemented.
pub fn discover_partitions<R: ReadSeek>(
    reader: &mut R,
    sector_size: u64,
) -> Result<Vec<Partition>, VolumeError> {
    // TODO: Try GPT first when gpt module is implemented.
    // For now, fall back to MBR detection.

    if is_mbr(reader) {
        return parse_mbr(reader, sector_size);
    }

    Err(VolumeError::NoPartitionTable)
}
