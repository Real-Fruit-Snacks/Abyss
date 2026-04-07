/// Integration tests for discover_partitions, mbr_type_name, is_gpt, and
/// multi-entry scenarios not covered by mbr_test.rs / gpt_test.rs.
use abyss_volume::discover::discover_partitions;
use abyss_volume::gpt::{is_gpt, parse_gpt};
use abyss_volume::mbr::{mbr_type_name, parse_mbr};
use abyss_volume::partition::PartitionScheme;
use std::io::Cursor;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a valid 512-byte MBR disk with up to four non-empty partition
/// entries.  Each entry in `entries` is (type_byte, lba_start, lba_count).
fn build_mbr_disk(entries: &[(u8, u32, u32)]) -> Cursor<Vec<u8>> {
    let mut disk = vec![0u8; 512];
    disk[510] = 0x55;
    disk[511] = 0xAA;

    for (i, &(type_byte, lba_start, lba_count)) in entries.iter().enumerate().take(4) {
        let off = 446 + i * 16;
        disk[off + 4] = type_byte;
        disk[off + 8..off + 12].copy_from_slice(&lba_start.to_le_bytes());
        disk[off + 12..off + 16].copy_from_slice(&lba_count.to_le_bytes());
    }

    Cursor::new(disk)
}

/// Build a minimal valid GPT disk (1 MiB, 2048 sectors of 512 bytes) with
/// one Microsoft Basic Data partition entry.
fn build_gpt_disk() -> Vec<u8> {
    let sector_size: usize = 512;
    let total_sectors: usize = 2048;
    let mut disk = vec![0u8; total_sectors * sector_size];

    // Protective MBR
    disk[510] = 0x55;
    disk[511] = 0xAA;
    disk[446 + 4] = 0xEE;

    // GPT header at LBA 1
    let hdr = sector_size;
    disk[hdr..hdr + 8].copy_from_slice(b"EFI PART");
    disk[hdr + 8..hdr + 12].copy_from_slice(&0x00010000u32.to_le_bytes());
    disk[hdr + 12..hdr + 16].copy_from_slice(&92u32.to_le_bytes());
    disk[hdr + 24..hdr + 32].copy_from_slice(&1u64.to_le_bytes());
    disk[hdr + 32..hdr + 40].copy_from_slice(&((total_sectors - 1) as u64).to_le_bytes());
    disk[hdr + 40..hdr + 48].copy_from_slice(&34u64.to_le_bytes());
    disk[hdr + 48..hdr + 56].copy_from_slice(&((total_sectors - 34) as u64).to_le_bytes());
    disk[hdr + 56..hdr + 72].copy_from_slice(&[0x01; 16]);
    disk[hdr + 72..hdr + 80].copy_from_slice(&2u64.to_le_bytes()); // entry start LBA
    disk[hdr + 80..hdr + 84].copy_from_slice(&1u32.to_le_bytes()); // num entries
    disk[hdr + 84..hdr + 88].copy_from_slice(&128u32.to_le_bytes()); // entry size

    // Partition entry at LBA 2
    let ent = 2 * sector_size;
    // Microsoft Basic Data GUID (mixed-endian)
    let type_guid: [u8; 16] = [
        0xa2, 0xa0, 0xd0, 0xeb, 0xe5, 0xb9, 0x33, 0x44, 0x87, 0xc0, 0x68, 0xb6, 0xb7, 0x26,
        0x99, 0xc7,
    ];
    disk[ent..ent + 16].copy_from_slice(&type_guid);
    disk[ent + 16..ent + 32].copy_from_slice(&[0x02; 16]);
    disk[ent + 32..ent + 40].copy_from_slice(&34u64.to_le_bytes());
    disk[ent + 40..ent + 48].copy_from_slice(&2013u64.to_le_bytes());

    disk
}

// ---------------------------------------------------------------------------
// mbr_type_name
// ---------------------------------------------------------------------------

#[test]
fn test_mbr_type_name_known_types() {
    assert_eq!(mbr_type_name(0x07), "NTFS");
    assert_eq!(mbr_type_name(0x0B), "FAT32");
    assert_eq!(mbr_type_name(0x83), "Linux");
    assert_eq!(mbr_type_name(0x82), "Linux Swap");
    assert_eq!(mbr_type_name(0xEE), "GPT Protective");
    assert_eq!(mbr_type_name(0xEF), "EFI System");
    assert_eq!(mbr_type_name(0x8E), "Linux LVM");
}

#[test]
fn test_mbr_type_name_empty_is_empty() {
    assert_eq!(mbr_type_name(0x00), "Empty");
}

#[test]
fn test_mbr_type_name_unknown_returns_unknown() {
    assert_eq!(mbr_type_name(0xCC), "Unknown");
    assert_eq!(mbr_type_name(0xFF), "Unknown");
}

// ---------------------------------------------------------------------------
// parse_mbr – multiple partitions
// ---------------------------------------------------------------------------

#[test]
fn test_parse_mbr_multiple_partitions() {
    // Three entries: NTFS, FAT32, Linux.
    let mut cursor = build_mbr_disk(&[
        (0x07, 2048, 204800),
        (0x0B, 206848, 102400),
        (0x83, 309248, 409600),
    ]);
    let parts = parse_mbr(&mut cursor, 512).expect("parse_mbr should succeed");
    assert_eq!(parts.len(), 3);

    assert_eq!(parts[0].partition_type, "0x07");
    assert_eq!(parts[0].type_name, "NTFS");
    assert_eq!(parts[0].offset, 2048 * 512);
    assert_eq!(parts[0].size, 204800 * 512);
    assert_eq!(parts[0].scheme, PartitionScheme::Mbr);

    assert_eq!(parts[1].partition_type, "0x0b");
    assert_eq!(parts[1].type_name, "FAT32");

    assert_eq!(parts[2].partition_type, "0x83");
    assert_eq!(parts[2].type_name, "Linux");
}

#[test]
fn test_parse_mbr_all_zeros_empty_table() {
    // MBR with signature but all-zero partition entries.
    let mut disk = vec![0u8; 512];
    disk[510] = 0x55;
    disk[511] = 0xAA;
    let mut cursor = Cursor::new(disk);
    let parts = parse_mbr(&mut cursor, 512).expect("parse_mbr should succeed");
    assert!(parts.is_empty(), "all-zero entries should yield no partitions");
}

#[test]
fn test_parse_mbr_skips_zero_lba_count_entry() {
    // type_byte is non-zero but lba_count is 0 — should be skipped.
    let mut cursor = build_mbr_disk(&[(0x07, 2048, 0)]);
    let parts = parse_mbr(&mut cursor, 512).expect("parse_mbr should succeed");
    assert!(
        parts.is_empty(),
        "entry with lba_count=0 should be skipped"
    );
}

#[test]
fn test_parse_mbr_partition_index_matches_slot() {
    // Put a partition in slot 2 (index 2).
    let mut cursor = build_mbr_disk(&[(0x00, 0, 0), (0x00, 0, 0), (0x83, 4096, 8192)]);
    let parts = parse_mbr(&mut cursor, 512).unwrap();
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].index, 2);
}

// ---------------------------------------------------------------------------
// is_gpt
// ---------------------------------------------------------------------------

#[test]
fn test_is_gpt_returns_true_for_valid_gpt_disk() {
    let disk = build_gpt_disk();
    let mut cursor = Cursor::new(disk);
    assert!(is_gpt(&mut cursor, 512));
}

#[test]
fn test_is_gpt_returns_false_for_zeroed_disk() {
    let disk = vec![0u8; 4096];
    let mut cursor = Cursor::new(disk);
    assert!(!is_gpt(&mut cursor, 512));
}

#[test]
fn test_is_gpt_returns_false_for_mbr_only_disk() {
    // Valid MBR signature but no GPT header.
    let mut disk = vec![0u8; 1024];
    disk[510] = 0x55;
    disk[511] = 0xAA;
    let mut cursor = Cursor::new(disk);
    assert!(!is_gpt(&mut cursor, 512));
}

// ---------------------------------------------------------------------------
// parse_gpt – label handling
// ---------------------------------------------------------------------------

#[test]
fn test_parse_gpt_partition_has_no_label_when_name_empty() {
    // Build a GPT disk with an entry whose name field is all zeros.
    let disk = build_gpt_disk();
    // The helper above doesn't write a name, so label should be None.
    let mut cursor = Cursor::new(disk);
    let parts = parse_gpt(&mut cursor, 512).unwrap();
    assert_eq!(parts.len(), 1);
    // Name bytes are all zero → label should be None.
    assert!(
        parts[0].label.is_none(),
        "empty name should yield None label"
    );
}

#[test]
fn test_parse_gpt_offset_and_size_calculation() {
    let disk = build_gpt_disk();
    let mut cursor = Cursor::new(disk);
    let parts = parse_gpt(&mut cursor, 512).unwrap();
    // start_lba=34, end_lba=2013, sector_size=512
    assert_eq!(parts[0].offset, 34 * 512);
    assert_eq!(parts[0].size, (2013 - 34 + 1) * 512);
}

// ---------------------------------------------------------------------------
// discover_partitions – GPT-first then MBR fallback
// ---------------------------------------------------------------------------

#[test]
fn test_discover_partitions_detects_gpt() {
    let disk = build_gpt_disk();
    let mut cursor = Cursor::new(disk);
    let parts = discover_partitions(&mut cursor, 512).expect("should discover GPT partitions");
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].scheme, PartitionScheme::Gpt);
}

#[test]
fn test_discover_partitions_falls_back_to_mbr() {
    // A plain MBR disk (no GPT header at LBA 1).
    let mut cursor = build_mbr_disk(&[(0x07, 2048, 204800)]);
    let parts = discover_partitions(&mut cursor, 512).expect("should discover MBR partitions");
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].scheme, PartitionScheme::Mbr);
    assert_eq!(parts[0].type_name, "NTFS");
}

#[test]
fn test_discover_partitions_errors_on_empty_disk() {
    let disk = vec![0u8; 4096];
    let mut cursor = Cursor::new(disk);
    let result = discover_partitions(&mut cursor, 512);
    assert!(
        result.is_err(),
        "should error when no GPT or MBR is present"
    );
}

#[test]
fn test_discover_partitions_prefers_gpt_over_protective_mbr() {
    // A GPT disk has a protective MBR (type 0xEE). discover_partitions should
    // return GPT partitions, not the protective MBR entry.
    let disk = build_gpt_disk();
    let mut cursor = Cursor::new(disk);
    let parts = discover_partitions(&mut cursor, 512).unwrap();
    // GPT partition is Microsoft Basic Data, not "GPT Protective".
    assert!(parts.iter().all(|p| p.type_name != "GPT Protective"));
    assert_eq!(parts[0].scheme, PartitionScheme::Gpt);
}
