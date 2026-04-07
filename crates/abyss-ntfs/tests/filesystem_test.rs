use std::io::Cursor;
use abyss_ntfs::NtfsFilesystem;

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
fn test_ntfs_probe_detects_ntfs_volume() {
    let boot = build_ntfs_boot();
    let mut reader: Box<dyn abyss_cstruct::read::ReadSeek> = Box::new(Cursor::new(boot));
    assert!(NtfsFilesystem::probe(&mut reader), "probe should return true for a valid NTFS boot sector");
}

#[test]
fn test_ntfs_probe_rejects_non_ntfs() {
    let buf = vec![0u8; 512];
    let mut reader: Box<dyn abyss_cstruct::read::ReadSeek> = Box::new(Cursor::new(buf));
    assert!(!NtfsFilesystem::probe(&mut reader), "probe should return false for a zeroed buffer");
}
