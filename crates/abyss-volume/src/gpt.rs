//! GPT partition table parser.

use crate::error::VolumeError;
use crate::partition::{Partition, PartitionScheme};
use abyss_cstruct::read::{read_bytes_at, read_u32_le, read_u64_le, read_utf16le, ReadSeek};

const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";

/// Well-known GPT partition type GUIDs (lowercase, no braces).
pub mod gpt_types {
    pub const MICROSOFT_BASIC_DATA: &str = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7";
    pub const EFI_SYSTEM: &str = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b";
    pub const MICROSOFT_RESERVED: &str = "e3c9e316-0b5c-4db8-817d-f92df00215ae";
    pub const LINUX_FILESYSTEM: &str = "0fc63daf-8483-4772-8e79-3d69d8477de4";
    pub const LINUX_SWAP: &str = "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f";
    pub const LINUX_LVM: &str = "e6d6d379-f507-44c2-a23c-238f2a3df928";

    pub fn name_for_guid(guid: &str) -> &'static str {
        match guid {
            MICROSOFT_BASIC_DATA => "Microsoft Basic Data",
            EFI_SYSTEM => "EFI System",
            MICROSOFT_RESERVED => "Microsoft Reserved",
            LINUX_FILESYSTEM => "Linux Filesystem",
            LINUX_SWAP => "Linux Swap",
            LINUX_LVM => "Linux LVM",
            _ => "Unknown",
        }
    }
}

/// Parse GPT partition table from a seekable disk stream.
pub fn parse_gpt<R: ReadSeek>(
    reader: &mut R,
    sector_size: u64,
) -> Result<Vec<Partition>, VolumeError> {
    // Read GPT header at LBA 1
    let header_buf = read_bytes_at(reader, sector_size, 92)?;

    // Validate signature
    if &header_buf[0..8] != GPT_SIGNATURE {
        return Err(VolumeError::InvalidPartitionTable {
            detail: "GPT signature not found at LBA 1".into(),
        });
    }

    let entry_start_lba = read_u64_le(&header_buf, 72)?;
    let num_entries = read_u32_le(&header_buf, 80)? as usize;
    let entry_size = read_u32_le(&header_buf, 84)? as usize;

    if entry_size < 128 {
        return Err(VolumeError::InvalidPartitionTable {
            detail: format!("GPT entry size {} too small", entry_size),
        });
    }

    // Read all partition entries
    let entries_offset = entry_start_lba * sector_size;
    let entries_total_size = num_entries * entry_size;
    let entries_buf = read_bytes_at(reader, entries_offset, entries_total_size)?;

    let mut partitions = Vec::new();
    let empty_guid = [0u8; 16];

    for i in 0..num_entries {
        let base = i * entry_size;
        let type_guid_bytes = &entries_buf[base..base + 16];

        if type_guid_bytes == &empty_guid {
            continue;
        }

        let start_lba = read_u64_le(&entries_buf, base + 32)?;
        let end_lba = read_u64_le(&entries_buf, base + 40)?;

        let type_guid = decode_mixed_endian_guid(type_guid_bytes);

        // Decode name (UTF-16LE, up to 72 bytes = 36 chars)
        let name_byte_len = (entry_size - 56).min(72);
        let name_raw = read_utf16le(&entries_buf, base + 56, name_byte_len).unwrap_or_default();
        let name = name_raw.trim_end_matches('\0').to_string();
        let label = if name.is_empty() { None } else { Some(name) };

        let type_name = gpt_types::name_for_guid(&type_guid).to_string();

        partitions.push(Partition {
            index: partitions.len(),
            offset: start_lba * sector_size,
            size: (end_lba - start_lba + 1) * sector_size,
            partition_type: type_guid,
            type_name,
            label,
            scheme: PartitionScheme::Gpt,
        });
    }

    Ok(partitions)
}

/// Check if a disk has a GPT partition table.
pub fn is_gpt<R: ReadSeek>(reader: &mut R, sector_size: u64) -> bool {
    if let Ok(buf) = read_bytes_at(reader, sector_size, 8) {
        &buf[0..8] == GPT_SIGNATURE
    } else {
        false
    }
}

/// Decode a mixed-endian GUID from 16 bytes into a lowercase string.
fn decode_mixed_endian_guid(bytes: &[u8]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[3], bytes[2], bytes[1], bytes[0],
        bytes[5], bytes[4],
        bytes[7], bytes[6],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}
