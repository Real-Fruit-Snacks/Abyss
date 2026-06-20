use abyss_ntfs::boot::NtfsBootSector;
use abyss_cstruct::read::FromBytes;

/// Build a minimal 512-byte buffer that looks like a valid NTFS boot sector.
fn build_ntfs_boot() -> Vec<u8> {
    let mut buf = vec![0u8; 512];

    // OEM ID at offset 3: "NTFS    "
    buf[3..11].copy_from_slice(b"NTFS    ");

    // Bytes per sector at offset 11: 512 (little-endian u16)
    buf[11..13].copy_from_slice(&512u16.to_le_bytes());

    // Sectors per cluster at offset 13: 8
    buf[13] = 8;

    // Total sectors at offset 40: 2097151 (u64 LE)
    buf[40..48].copy_from_slice(&2097151u64.to_le_bytes());

    // MFT cluster at offset 48: 786432 (u64 LE)
    buf[48..56].copy_from_slice(&786432u64.to_le_bytes());

    // MFT mirror cluster at offset 56: 2 (u64 LE)
    buf[56..64].copy_from_slice(&2u64.to_le_bytes());

    // Clusters per MFT record at offset 64: -10 (i8, means 2^10 = 1024 bytes)
    buf[64] = (-10i8) as u8;

    buf
}

#[test]
fn test_parse_ntfs_boot_sector() {
    let buf = build_ntfs_boot();
    let boot = NtfsBootSector::from_bytes(&buf).expect("should parse valid boot sector");

    assert_eq!(&boot.oem_id, b"NTFS    ");
    assert_eq!(boot.bytes_per_sector, 512);
    assert_eq!(boot.sectors_per_cluster, 8);
    assert_eq!(boot.total_sectors, 2097151);
    assert_eq!(boot.mft_cluster, 786432);
    assert_eq!(boot.mft_mirror_cluster, 2);
    assert_eq!(boot.clusters_per_mft_record, -10);
}

#[test]
fn test_bytes_per_cluster() {
    let buf = build_ntfs_boot();
    let boot = NtfsBootSector::from_bytes(&buf).unwrap();
    // 512 * 8 = 4096
    assert_eq!(boot.bytes_per_cluster(), 4096);
}

#[test]
fn test_mft_record_size_negative_exponent() {
    let buf = build_ntfs_boot();
    let boot = NtfsBootSector::from_bytes(&buf).unwrap();
    // clusters_per_mft_record = -10 => 2^10 = 1024
    assert_eq!(boot.mft_record_size(), 1024);
}

#[test]
fn test_mft_record_size_positive() {
    let mut buf = build_ntfs_boot();
    // Set clusters_per_mft_record = 1 (positive)
    buf[64] = 1u8;
    let boot = NtfsBootSector::from_bytes(&buf).unwrap();
    // 1 cluster = 4096 bytes
    assert_eq!(boot.mft_record_size(), 4096);
}

#[test]
fn test_mft_offset() {
    let buf = build_ntfs_boot();
    let boot = NtfsBootSector::from_bytes(&buf).unwrap();
    // 786432 * 4096 = 3221225472
    assert_eq!(boot.mft_offset(), 786432 * 4096);
}

#[test]
fn test_rejects_invalid_oem_id() {
    let mut buf = build_ntfs_boot();
    // Overwrite OEM ID with garbage
    buf[3..11].copy_from_slice(b"FAT32   ");
    let result = NtfsBootSector::from_bytes(&buf);
    assert!(result.is_err(), "should reject non-NTFS OEM ID");
}

#[test]
fn test_rejects_too_small_buffer() {
    let buf = vec![0u8; 80];
    let result = NtfsBootSector::from_bytes(&buf);
    assert!(result.is_err(), "should reject buffer smaller than 88 bytes");
}
