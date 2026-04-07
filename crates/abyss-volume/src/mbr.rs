//! MBR partition table parser.

use abyss_cstruct::read::{read_bytes_at, read_u32_le};
use abyss_cstruct::read::ReadSeek;

use crate::error::VolumeError;
use crate::partition::{Partition, PartitionScheme};

/// MBR boot signature offset and value.
const MBR_SIGNATURE_OFFSET: usize = 510;
const MBR_SIGNATURE: [u8; 2] = [0x55, 0xAA];

/// Offset of first partition entry in MBR.
const MBR_PARTITION_TABLE_OFFSET: usize = 446;
/// Size of each partition entry.
const MBR_ENTRY_SIZE: usize = 16;
/// Number of primary partition entries.
const MBR_PARTITION_COUNT: usize = 4;

/// Parse the MBR partition table from a reader.
///
/// Reads the MBR at offset 0, validates the 0x55AA boot signature, and
/// returns all non-empty partition entries as `Partition` values.
pub fn parse_mbr<R: ReadSeek>(
    reader: &mut R,
    sector_size: u64,
) -> Result<Vec<Partition>, VolumeError> {
    let mbr = read_bytes_at(reader, 0, 512)?;

    // Validate boot signature.
    if mbr[MBR_SIGNATURE_OFFSET] != MBR_SIGNATURE[0]
        || mbr[MBR_SIGNATURE_OFFSET + 1] != MBR_SIGNATURE[1]
    {
        return Err(VolumeError::InvalidPartitionTable {
            detail: "missing MBR boot signature 0x55AA".into(),
        });
    }

    let mut partitions = Vec::new();

    for i in 0..MBR_PARTITION_COUNT {
        let entry_offset = MBR_PARTITION_TABLE_OFFSET + i * MBR_ENTRY_SIZE;
        let type_byte = mbr[entry_offset + 4];

        // Skip empty entries.
        if type_byte == 0x00 {
            continue;
        }

        let lba_start = read_u32_le(&mbr, entry_offset + 8)?;
        let lba_count = read_u32_le(&mbr, entry_offset + 12)?;

        if lba_count == 0 {
            continue;
        }

        let offset = lba_start as u64 * sector_size;
        let size = lba_count as u64 * sector_size;
        let type_name = mbr_type_name(type_byte).to_string();
        let partition_type = format!("{:#04x}", type_byte);

        partitions.push(Partition {
            index: i,
            offset,
            size,
            partition_type,
            type_name,
            label: None,
            scheme: PartitionScheme::Mbr,
        });
    }

    Ok(partitions)
}

/// Quick check: does this reader contain a valid MBR boot signature?
pub fn is_mbr<R: ReadSeek>(reader: &mut R) -> bool {
    match read_bytes_at(reader, 0, 512) {
        Ok(buf) => buf[MBR_SIGNATURE_OFFSET] == MBR_SIGNATURE[0]
            && buf[MBR_SIGNATURE_OFFSET + 1] == MBR_SIGNATURE[1],
        Err(_) => false,
    }
}

/// Map an MBR partition type byte to a human-readable name.
pub fn mbr_type_name(type_byte: u8) -> &'static str {
    match type_byte {
        0x00 => "Empty",
        0x01 => "FAT12",
        0x04 => "FAT16 <32M",
        0x05 => "Extended",
        0x06 => "FAT16",
        0x07 => "NTFS",
        0x0B => "FAT32",
        0x0C => "FAT32 (LBA)",
        0x0E => "FAT16 (LBA)",
        0x0F => "Extended (LBA)",
        0x11 => "Hidden FAT12",
        0x14 => "Hidden FAT16 <32M",
        0x16 => "Hidden FAT16",
        0x17 => "Hidden NTFS",
        0x1B => "Hidden FAT32",
        0x1C => "Hidden FAT32 (LBA)",
        0x1E => "Hidden FAT16 (LBA)",
        0x27 => "Windows Recovery",
        0x42 => "Windows Dynamic",
        0x82 => "Linux Swap",
        0x83 => "Linux",
        0x84 => "Hibernation",
        0x85 => "Linux Extended",
        0x86 => "Linux RAID",
        0x87 => "NTFS Volume Set",
        0x8E => "Linux LVM",
        0xA5 => "FreeBSD",
        0xA6 => "OpenBSD",
        0xA8 => "macOS",
        0xA9 => "NetBSD",
        0xAB => "macOS Boot",
        0xAF => "macOS HFS+",
        0xBE => "Solaris Boot",
        0xBF => "Solaris",
        0xEB => "BeOS",
        0xEE => "GPT Protective",
        0xEF => "EFI System",
        0xFB => "VMware VMFS",
        0xFC => "VMware Swap",
        0xFD => "Linux RAID Auto",
        _ => "Unknown",
    }
}
