use abyss_volume::mbr::{is_mbr, parse_mbr};

/// Build a minimal 512-byte MBR disk image with one active partition.
fn build_test_mbr_disk() -> std::io::Cursor<Vec<u8>> {
    let mut disk = vec![0u8; 512];

    // Write boot signature.
    disk[510] = 0x55;
    disk[511] = 0xAA;

    // First partition entry at offset 446.
    // Status (bootable): 0x80
    disk[446] = 0x80;
    // Type: 0x07 (NTFS)
    disk[446 + 4] = 0x07;
    // LBA start (little-endian u32): 2048
    let lba_start: u32 = 2048;
    disk[446 + 8..446 + 12].copy_from_slice(&lba_start.to_le_bytes());
    // LBA count (little-endian u32): 204800
    let lba_count: u32 = 204800;
    disk[446 + 12..446 + 16].copy_from_slice(&lba_count.to_le_bytes());

    std::io::Cursor::new(disk)
}

#[test]
fn test_parse_mbr_finds_one_partition() {
    let mut cursor = build_test_mbr_disk();
    let partitions = parse_mbr(&mut cursor, 512).expect("parse_mbr should succeed");

    assert_eq!(partitions.len(), 1);
    let p = &partitions[0];
    assert_eq!(p.index, 0);
    assert_eq!(p.offset, 2048 * 512);
    assert_eq!(p.size, 204800 * 512);
    assert_eq!(p.partition_type, "0x07");
    assert_eq!(p.type_name, "NTFS");
}

#[test]
fn test_parse_mbr_skips_empty_entries() {
    let mut cursor = build_test_mbr_disk();
    let partitions = parse_mbr(&mut cursor, 512).expect("parse_mbr should succeed");

    // Only one non-empty entry was written; the other three should be skipped.
    assert_eq!(partitions.len(), 1);
}

#[test]
fn test_parse_mbr_rejects_no_signature() {
    // Disk with no boot signature.
    let disk = vec![0u8; 512];
    let mut cursor = std::io::Cursor::new(disk);

    let result = parse_mbr(&mut cursor, 512);
    assert!(result.is_err(), "should reject disk without 0x55AA signature");
}

#[test]
fn test_is_mbr_true_for_valid_mbr() {
    let mut cursor = build_test_mbr_disk();
    assert!(is_mbr(&mut cursor));
}

#[test]
fn test_is_mbr_false_for_no_signature() {
    let disk = vec![0u8; 512];
    let mut cursor = std::io::Cursor::new(disk);
    assert!(!is_mbr(&mut cursor));
}
