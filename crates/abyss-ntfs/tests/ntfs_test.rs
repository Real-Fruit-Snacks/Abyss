/// Integration tests for AttributeHeader (resident and non-resident) and
/// data run edge cases beyond the inline unit tests in datarun.rs.
use abyss_cstruct::read::FromBytes;
use abyss_ntfs::attribute::{AttributeHeader, AttributeType};
use abyss_ntfs::datarun::{decode_data_runs, DataRun};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a minimal resident attribute buffer at offset 0.
///
/// Layout (24-byte resident header + value_len bytes of value):
///   0..4   type_code (u32 LE)
///   4..8   total length (u32 LE)  = 24 + value_len, rounded to 8
///   8      non_resident = 0
///   9      name_length = 0
///  10..12  name_offset (u16 LE) = 24
///  12..14  flags (u16 LE) = 0
///  14..16  instance (u16 LE)
///  16..20  value_length (u32 LE) = value_len
///  20..22  value_offset (u16 LE) = 24
///  24..    value bytes
fn build_resident_attr(type_code: u32, instance: u16, value: &[u8]) -> Vec<u8> {
    let value_len = value.len() as u32;
    // Round total length to 8-byte alignment.
    let total = ((24 + value.len() + 7) & !7) as u32;
    let mut buf = vec![0u8; total as usize];

    buf[0..4].copy_from_slice(&type_code.to_le_bytes());
    buf[4..8].copy_from_slice(&total.to_le_bytes());
    buf[8] = 0; // resident
    buf[9] = 0; // name_length
    buf[10..12].copy_from_slice(&24u16.to_le_bytes()); // name_offset
    buf[12..14].copy_from_slice(&0u16.to_le_bytes()); // flags
    buf[14..16].copy_from_slice(&instance.to_le_bytes());
    buf[16..20].copy_from_slice(&value_len.to_le_bytes()); // value_length
    buf[20..22].copy_from_slice(&24u16.to_le_bytes()); // value_offset
    buf[24..24 + value.len()].copy_from_slice(value);

    buf
}

/// Build a minimal non-resident attribute buffer at offset 0.
///
/// The non-resident header occupies 64 bytes before any data-run stream.
fn build_nonresident_attr(
    type_code: u32,
    instance: u16,
    start_vcn: u64,
    last_vcn: u64,
    allocated_size: u64,
    data_size: u64,
) -> Vec<u8> {
    let total: u32 = 64;
    let mut buf = vec![0u8; total as usize];

    buf[0..4].copy_from_slice(&type_code.to_le_bytes());
    buf[4..8].copy_from_slice(&total.to_le_bytes());
    buf[8] = 1; // non_resident
    buf[9] = 0; // name_length
    buf[10..12].copy_from_slice(&64u16.to_le_bytes()); // name_offset (unused)
    buf[12..14].copy_from_slice(&0u16.to_le_bytes()); // flags
    buf[14..16].copy_from_slice(&instance.to_le_bytes());
    buf[16..24].copy_from_slice(&start_vcn.to_le_bytes());
    buf[24..32].copy_from_slice(&last_vcn.to_le_bytes());
    buf[32..34].copy_from_slice(&64u16.to_le_bytes()); // data_runs_offset
    // compression unit size + padding at 34..40 left as zeros
    buf[40..48].copy_from_slice(&allocated_size.to_le_bytes());
    buf[48..56].copy_from_slice(&data_size.to_le_bytes());

    buf
}

// ---------------------------------------------------------------------------
// AttributeHeader – FromBytes (resident)
// ---------------------------------------------------------------------------

#[test]
fn test_attribute_header_from_bytes_resident_standard_information() {
    let value = [0xAA, 0xBB, 0xCC, 0xDD];
    let buf = build_resident_attr(0x10, 0, &value);

    let hdr = AttributeHeader::from_bytes(&buf).expect("should parse resident $STANDARD_INFORMATION");
    assert_eq!(hdr.attr_type, AttributeType::StandardInformation);
    assert!(!hdr.non_resident);
    assert_eq!(hdr.name_length, 0);
    assert_eq!(hdr.instance, 0);
    assert_eq!(hdr.value_length, Some(4));
    assert_eq!(hdr.value_offset, Some(24));
    // Non-resident fields must be absent.
    assert!(hdr.start_vcn.is_none());
    assert!(hdr.last_vcn.is_none());
    assert!(hdr.data_runs_offset.is_none());
    assert!(hdr.allocated_size.is_none());
    assert!(hdr.data_size.is_none());
}

#[test]
fn test_attribute_header_resident_filename_type() {
    let value = vec![0u8; 8];
    let buf = build_resident_attr(0x30, 1, &value);

    let hdr = AttributeHeader::from_bytes(&buf).unwrap();
    assert_eq!(hdr.attr_type, AttributeType::FileName);
    assert_eq!(hdr.instance, 1);
    assert!(!hdr.non_resident);
}

#[test]
fn test_attribute_header_resident_data_type() {
    let value = b"hello";
    let buf = build_resident_attr(0x80, 2, value);

    let hdr = AttributeHeader::from_bytes(&buf).unwrap();
    assert_eq!(hdr.attr_type, AttributeType::Data);
    assert_eq!(hdr.value_length, Some(5));
}

#[test]
fn test_attribute_header_resident_value_extraction() {
    let value = [0x11, 0x22, 0x33, 0x44, 0x55];
    let buf = build_resident_attr(0x10, 0, &value);
    let hdr = AttributeHeader::from_bytes(&buf).unwrap();

    let extracted = hdr.resident_value(&buf, 0).expect("should return value slice");
    assert_eq!(extracted, &[0x11, 0x22, 0x33, 0x44, 0x55]);
}

#[test]
fn test_attribute_header_end_of_attributes_marker() {
    // A buffer starting with 0xFFFFFFFF should parse as None via from_bytes_at,
    // and from_bytes should return an error (not a valid header).
    let buf = [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00];
    let result = AttributeHeader::from_bytes(&buf);
    assert!(result.is_err(), "0xFFFFFFFF should be rejected by from_bytes");
}

#[test]
fn test_attribute_header_unknown_type_code() {
    let value = [0u8; 4];
    let buf = build_resident_attr(0xDEAD, 0, &value);
    let hdr = AttributeHeader::from_bytes(&buf).unwrap();
    assert_eq!(hdr.attr_type, AttributeType::Unknown(0xDEAD));
}

#[test]
fn test_attribute_header_too_small_buffer_returns_error() {
    // Only 10 bytes — not enough for even the common header (needs 16).
    let buf = vec![0x10, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00];
    let result = AttributeHeader::from_bytes(&buf);
    assert!(result.is_err(), "should error on buffer too small for header");
}

// ---------------------------------------------------------------------------
// AttributeHeader – non-resident
// ---------------------------------------------------------------------------

#[test]
fn test_attribute_header_nonresident_data() {
    let buf = build_nonresident_attr(0x80, 3, 0, 9, 40960, 38912);

    let hdr = AttributeHeader::from_bytes(&buf).expect("should parse non-resident $DATA");
    assert_eq!(hdr.attr_type, AttributeType::Data);
    assert!(hdr.non_resident);
    assert_eq!(hdr.start_vcn, Some(0));
    assert_eq!(hdr.last_vcn, Some(9));
    assert_eq!(hdr.allocated_size, Some(40960));
    assert_eq!(hdr.data_size, Some(38912));
    assert_eq!(hdr.data_runs_offset, Some(64));
    // Resident-only fields must be absent.
    assert!(hdr.value_length.is_none());
    assert!(hdr.value_offset.is_none());
}

#[test]
fn test_attribute_header_nonresident_resident_value_returns_none() {
    let buf = build_nonresident_attr(0x80, 0, 0, 4, 20480, 16384);
    let hdr = AttributeHeader::from_bytes(&buf).unwrap();
    assert!(
        hdr.resident_value(&buf, 0).is_none(),
        "non-resident attribute should not return a resident value"
    );
}

#[test]
fn test_attribute_header_nonresident_too_small_buffer() {
    // non_resident=1 requires at least 64 bytes from the attribute start.
    let mut buf = vec![0u8; 50];
    buf[0..4].copy_from_slice(&0x80u32.to_le_bytes()); // type = $DATA
    buf[4..8].copy_from_slice(&64u32.to_le_bytes()); // declared length
    buf[8] = 1; // non_resident
    let result = AttributeHeader::from_bytes(&buf);
    assert!(
        result.is_err(),
        "should error when buffer is too small for non-resident header"
    );
}

// ---------------------------------------------------------------------------
// AttributeHeader::from_bytes_at – offset variants
// ---------------------------------------------------------------------------

#[test]
fn test_from_bytes_at_reads_attribute_at_nonzero_offset() {
    // Build two back-to-back resident attributes and parse the second one.
    let attr1 = build_resident_attr(0x10, 0, &[0u8; 4]); // $STANDARD_INFORMATION
    let attr2 = build_resident_attr(0x30, 1, &[0u8; 8]); // $FILE_NAME

    let offset = attr1.len();
    let mut buf = attr1.clone();
    buf.extend_from_slice(&attr2);

    let hdr = AttributeHeader::from_bytes_at(&buf, offset)
        .expect("from_bytes_at should not error")
        .expect("should find attribute at offset");
    assert_eq!(hdr.attr_type, AttributeType::FileName);
    assert_eq!(hdr.instance, 1);
}

#[test]
fn test_from_bytes_at_end_marker_returns_none() {
    let mut buf = vec![0u8; 8];
    buf[0..4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    let result = AttributeHeader::from_bytes_at(&buf, 0).unwrap();
    assert!(result.is_none(), "end marker should produce None");
}

#[test]
fn test_from_bytes_at_offset_past_end_returns_none() {
    let buf = vec![0u8; 8];
    let result = AttributeHeader::from_bytes_at(&buf, 10).unwrap();
    assert!(result.is_none(), "offset past end should produce None");
}

// ---------------------------------------------------------------------------
// decode_data_runs – edge cases beyond the inline tests
// ---------------------------------------------------------------------------

#[test]
fn test_decode_data_runs_empty_buf_returns_empty() {
    // An empty buffer (no terminator) is treated as an empty run list.
    let runs = decode_data_runs(&[]).unwrap();
    assert!(runs.is_empty());
}

#[test]
fn test_decode_data_runs_immediate_terminator() {
    let runs = decode_data_runs(&[0x00]).unwrap();
    assert!(runs.is_empty());
}

#[test]
fn test_decode_data_runs_two_byte_length_field() {
    // Header 0x21: length_size=1, offset_size=2
    // Length = 0x80 (128 clusters)
    // Offset = 0x0100 (256, little-endian 2 bytes)
    let buf = [0x21, 0x80, 0x00, 0x01, 0x00];
    let runs = decode_data_runs(&buf).unwrap();
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].length, 0x80);
    assert_eq!(runs[0].cluster, Some(0x0100));
}

#[test]
fn test_decode_data_runs_negative_relative_offset() {
    // Run 1: header=0x11, length=10, offset=+20  -> cluster 20
    // Run 2: header=0x11, length=5,  offset=-5   -> cluster 15 (20 + (-5))
    // signed byte -5 = 0xFB
    let buf = [0x11, 0x0A, 0x14, 0x11, 0x05, 0xFB, 0x00];
    let runs = decode_data_runs(&buf).unwrap();
    assert_eq!(runs.len(), 2);
    assert_eq!(runs[0].cluster, Some(20));
    assert_eq!(runs[1].cluster, Some(15));
    assert_eq!(runs[1].length, 5);
}

#[test]
fn test_decode_data_runs_three_runs_with_cumulative_offsets() {
    // Run 1: offset=+10 -> cluster 10
    // Run 2: offset=+5  -> cluster 15
    // Run 3: offset=+3  -> cluster 18
    let buf = [
        0x11, 0x04, 0x0A, // run 1: len=4, off=+10
        0x11, 0x02, 0x05, // run 2: len=2, off=+5
        0x11, 0x07, 0x03, // run 3: len=7, off=+3
        0x00,
    ];
    let runs = decode_data_runs(&buf).unwrap();
    assert_eq!(runs.len(), 3);
    assert_eq!(runs[0].cluster, Some(10));
    assert_eq!(runs[1].cluster, Some(15));
    assert_eq!(runs[2].cluster, Some(18));
    assert_eq!(runs[2].length, 7);
}

#[test]
fn test_decode_data_runs_sparse_run_does_not_advance_cluster_counter() {
    // Sparse run (offset_size=0) followed by a normal run.
    // Run 1 (sparse): header=0x01, length=8           -> cluster=None
    // Run 2 (normal): header=0x11, length=4, offset=5 -> cluster=5
    let buf = [0x01, 0x08, 0x11, 0x04, 0x05, 0x00];
    let runs = decode_data_runs(&buf).unwrap();
    assert_eq!(runs.len(), 2);
    assert_eq!(runs[0], DataRun { cluster: None, length: 8 });
    // After a sparse run prev_cluster stays 0, so next absolute = 0+5 = 5.
    assert_eq!(runs[1].cluster, Some(5));
}

#[test]
fn test_decode_data_runs_invalid_zero_length_size_errors() {
    // Header 0x10: length_size=0 (invalid), offset_size=1
    let buf = [0x10, 0x05, 0x00];
    let result = decode_data_runs(&buf);
    assert!(result.is_err(), "length_size=0 should return an error");
}

#[test]
fn test_decode_data_runs_truncated_length_field_errors() {
    // Header 0x21: length_size=1, offset_size=2 — but the buffer ends before
    // the length field can be read.
    let buf = [0x21]; // only the header byte, no data
    let result = decode_data_runs(&buf);
    assert!(result.is_err(), "truncated length field should return an error");
}

#[test]
fn test_decode_data_runs_truncated_offset_field_errors() {
    // Header 0x11: length_size=1, offset_size=1
    // Length byte present, but offset byte missing.
    let buf = [0x11, 0x05]; // header + length only
    let result = decode_data_runs(&buf);
    assert!(result.is_err(), "truncated offset field should return an error");
}
