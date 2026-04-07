/// Integration tests for SharedBlockDevice.
///
/// All test data is constructed inline using `std::io::Cursor<Vec<u8>>`.
use abyss_container::{detect_and_open, SharedBlockDevice};
use std::io::{Cursor, Read, Seek, SeekFrom};

// ─────────────────────────────────────────────────────────────
// Helper
// ─────────────────────────────────────────────────────────────

/// Build a 4096-byte SharedBlockDevice whose content is the repeating
/// sequence 0, 1, 2, … 255, 0, 1, …
fn make_shared() -> (SharedBlockDevice, Vec<u8>) {
    let data: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
    let cursor: Box<dyn abyss_cstruct::read::ReadSeek> = Box::new(Cursor::new(data.clone()));
    let container = detect_and_open(cursor).expect("detect_and_open must succeed for raw data");
    let shared = SharedBlockDevice::new(container);
    (shared, data)
}

// ─────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────

/// Cloning two readers: reading from one must not advance the other.
#[test]
fn shared_clone_readers_are_independent() {
    let (shared, _data) = make_shared();
    let mut reader1 = shared.clone_reader();
    let mut reader2 = shared.clone_reader();

    // Consume 64 bytes from reader1.
    let mut buf1 = vec![0u8; 64];
    reader1.read_exact(&mut buf1).unwrap();

    // reader2 should still be at position 0.
    let mut buf2 = [0u8; 1];
    reader2.read_exact(&mut buf2).unwrap();
    assert_eq!(buf2[0], 0, "reader2 must still be at position 0 after reader1 advanced");
}

/// size() must equal the length of the underlying data.
#[test]
fn shared_size_matches_original() {
    let (shared, data) = make_shared();
    assert_eq!(shared.size(), data.len() as u64);
}

/// SeekFrom::End(-10) then read 10 bytes must return the last 10 bytes.
#[test]
fn shared_seek_from_end() {
    let (shared, data) = make_shared();
    let mut reader = shared.clone_reader();

    reader.seek(SeekFrom::End(-10)).unwrap();
    let mut buf = [0u8; 10];
    reader.read_exact(&mut buf).unwrap();

    let expected = &data[data.len() - 10..];
    assert_eq!(&buf, expected);
}

/// Reading the first 10 bytes from two independent clones must return the same bytes.
#[test]
fn shared_sequential_reads_across_clones() {
    let (shared, data) = make_shared();
    let mut clone1 = shared.clone_reader();
    let mut clone2 = shared.clone_reader();

    let mut buf1 = [0u8; 10];
    let mut buf2 = [0u8; 10];
    clone1.read_exact(&mut buf1).unwrap();
    clone2.read_exact(&mut buf2).unwrap();

    assert_eq!(buf1, buf2, "independent clones at position 0 must read the same bytes");
    assert_eq!(&buf1, &data[..10]);
}

/// Seek to the middle of the data and verify the correct bytes are returned.
#[test]
fn shared_read_after_seek() {
    let (shared, data) = make_shared();
    let mut reader = shared.clone_reader();
    let offset: usize = 1000;

    reader.seek(SeekFrom::Start(offset as u64)).unwrap();
    let mut buf = [0u8; 16];
    reader.read_exact(&mut buf).unwrap();

    assert_eq!(&buf, &data[offset..offset + 16]);
}

/// Simulate the SliceReader pattern used by Target::open():
/// seek to a partition offset in one clone, read N bytes, and verify they
/// match the expected slice of the original data.
#[test]
fn slice_reader_basic() {
    let (shared, data) = make_shared();
    let partition_offset: usize = 512;
    let read_len: usize = 64;

    let mut reader = shared.clone_reader();
    reader.seek(SeekFrom::Start(partition_offset as u64)).unwrap();

    let mut buf = vec![0u8; read_len];
    reader.read_exact(&mut buf).unwrap();

    assert_eq!(
        &buf,
        &data[partition_offset..partition_offset + read_len],
        "slice reader must return bytes at the partition offset"
    );
}
