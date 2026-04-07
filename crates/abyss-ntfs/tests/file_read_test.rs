/// Basic API existence tests for the file-reading methods on NtfsFilesystem.
///
/// These tests verify that the methods compile and return appropriate errors
/// when given invalid/empty input, without requiring a real NTFS disk image.
use std::io::{self, Cursor, Read, Seek, SeekFrom};

use abyss_cstruct::read::ReadSeek;
use abyss_ntfs::NtfsFilesystem;

/// A reader backed by an empty byte slice — any read will fail with an I/O error.
struct EmptyReader;

impl Read for EmptyReader {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::UnexpectedEof, "empty reader"))
    }
}

impl Seek for EmptyReader {
    fn seek(&mut self, _pos: SeekFrom) -> io::Result<u64> {
        Ok(0)
    }
}


/// Build a tiny reader containing just a valid NTFS boot sector so that
/// `NtfsFilesystem::open` succeeds, but MFT reads will fail.
fn make_boot_sector_reader() -> Box<dyn ReadSeek> {
    let mut buf = vec![0u8; 512];

    // Jump instruction
    buf[0] = 0xEB;
    buf[1] = 0x52;
    buf[2] = 0x90;

    // OEM ID: "NTFS    "
    buf[3..11].copy_from_slice(b"NTFS    ");

    // bytes_per_sector: 512
    buf[11..13].copy_from_slice(&512u16.to_le_bytes());

    // sectors_per_cluster: 8
    buf[13] = 8;

    // total_sectors (offset 40): 1000
    buf[40..48].copy_from_slice(&1000u64.to_le_bytes());

    // mft_cluster (offset 48): 4
    buf[48..56].copy_from_slice(&4u64.to_le_bytes());

    // mft_mirror_cluster (offset 56): 500
    buf[56..64].copy_from_slice(&500u64.to_le_bytes());

    // clusters_per_mft_record (offset 64): -10 (=> 2^10 = 1024 bytes)
    buf[64] = (-10i8) as u8;

    Box::new(Cursor::new(buf))
}

#[test]
fn test_ntfs_filesystem_open_succeeds_with_valid_boot_sector() {
    let reader = make_boot_sector_reader();
    let fs = NtfsFilesystem::open(reader);
    assert!(fs.is_ok(), "open should succeed with valid boot sector");
}

#[test]
fn test_read_file_by_index_fails_on_invalid_mft() {
    let reader = make_boot_sector_reader();
    let mut fs = NtfsFilesystem::open(reader).unwrap();
    // MFT record 99 won't be present in our tiny reader.
    let result = fs.read_file_by_index(99);
    assert!(result.is_err(), "should fail when MFT record is not readable");
}

#[test]
fn test_find_file_fails_on_invalid_mft() {
    let reader = make_boot_sector_reader();
    let mut fs = NtfsFilesystem::open(reader).unwrap();
    let result = fs.find_file("Windows/System32/ntoskrnl.exe");
    assert!(result.is_err(), "should fail when MFT is not readable");
}

#[test]
fn test_read_file_fails_on_invalid_mft() {
    let reader = make_boot_sector_reader();
    let mut fs = NtfsFilesystem::open(reader).unwrap();
    let result = fs.read_file("somefile.txt");
    assert!(result.is_err(), "read_file should fail on unreadable MFT");
}

#[test]
fn test_list_directory_returns_empty_on_unreadable_mft() {
    let reader = make_boot_sector_reader();
    let mut fs = NtfsFilesystem::open(reader).unwrap();
    // total_mft_records will fall back to 1024; all reads will fail gracefully.
    let result = fs.list_directory(5);
    assert!(result.is_ok(), "list_directory should not panic");
    assert!(
        result.unwrap().is_empty(),
        "no entries expected when MFT is unreadable"
    );
}
