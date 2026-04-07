use abyss_cstruct::read::{
    read_bytes, read_bytes_at, read_u16_le, read_u32_le, read_u64_le, read_utf16le, FromBytes,
};
use abyss_cstruct::ParseError;
use std::io::Cursor;

// ---------------------------------------------------------------------------
// read_u16_le
// ---------------------------------------------------------------------------

#[test]
fn read_u16_le_valid() {
    let buf = [0x34, 0x12, 0xFF, 0xFF];
    assert_eq!(read_u16_le(&buf, 0).unwrap(), 0x1234);
    assert_eq!(read_u16_le(&buf, 2).unwrap(), 0xFFFF);
}

#[test]
fn read_u16_le_offset_valid() {
    // Read at an interior offset.
    let buf = [0x00, 0x78, 0x56];
    assert_eq!(read_u16_le(&buf, 1).unwrap(), 0x5678);
}

#[test]
fn read_u16_le_buffer_too_small_exact() {
    // Buffer has 1 byte; need 2.
    let buf = [0xAB];
    match read_u16_le(&buf, 0) {
        Err(ParseError::BufferTooSmall { need, have }) => {
            assert_eq!(need, 2);
            assert_eq!(have, 1);
        }
        other => panic!("expected BufferTooSmall, got {:?}", other),
    }
}

#[test]
fn read_u16_le_buffer_too_small_with_offset() {
    // Buffer length 3 but offset 2 requires bytes [2..4].
    let buf = [0x01, 0x02, 0x03];
    match read_u16_le(&buf, 2) {
        Err(ParseError::BufferTooSmall { need, have }) => {
            assert_eq!(need, 4);
            assert_eq!(have, 3);
        }
        other => panic!("expected BufferTooSmall, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// read_u32_le
// ---------------------------------------------------------------------------

#[test]
fn read_u32_le_valid() {
    let buf = [0x78, 0x56, 0x34, 0x12];
    assert_eq!(read_u32_le(&buf, 0).unwrap(), 0x1234_5678);
}

#[test]
fn read_u32_le_offset_valid() {
    let buf = [0x00, 0xEF, 0xCD, 0xAB, 0x89];
    assert_eq!(read_u32_le(&buf, 1).unwrap(), 0x89AB_CDEF);
}

#[test]
fn read_u32_le_buffer_too_small_exact() {
    let buf = [0x01, 0x02, 0x03]; // only 3 bytes
    match read_u32_le(&buf, 0) {
        Err(ParseError::BufferTooSmall { need, have }) => {
            assert_eq!(need, 4);
            assert_eq!(have, 3);
        }
        other => panic!("expected BufferTooSmall, got {:?}", other),
    }
}

#[test]
fn read_u32_le_buffer_too_small_with_offset() {
    // offset 2 in a 4-byte buffer: needs bytes [2..6].
    let buf = [0x01, 0x02, 0x03, 0x04];
    match read_u32_le(&buf, 2) {
        Err(ParseError::BufferTooSmall { need, have }) => {
            assert_eq!(need, 6);
            assert_eq!(have, 4);
        }
        other => panic!("expected BufferTooSmall, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// read_u64_le
// ---------------------------------------------------------------------------

#[test]
fn read_u64_le_valid() {
    let buf = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    assert_eq!(
        read_u64_le(&buf, 0).unwrap(),
        0x0807_0605_0403_0201u64
    );
}

#[test]
fn read_u64_le_offset_valid() {
    // prefix byte + 8 payload bytes
    let buf = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];
    // offset 1: bytes [1..9] are all 0xFF
    assert_eq!(
        read_u64_le(&buf, 1).unwrap(),
        0xFFFF_FFFF_FFFF_FFFFu64
    );
}

#[test]
fn read_u64_le_buffer_too_small_exact() {
    let buf = [0u8; 7]; // only 7 bytes
    match read_u64_le(&buf, 0) {
        Err(ParseError::BufferTooSmall { need, have }) => {
            assert_eq!(need, 8);
            assert_eq!(have, 7);
        }
        other => panic!("expected BufferTooSmall, got {:?}", other),
    }
}

#[test]
fn read_u64_le_buffer_too_small_with_offset() {
    let buf = [0u8; 8]; // offset 2 needs bytes [2..10]
    match read_u64_le(&buf, 2) {
        Err(ParseError::BufferTooSmall { need, have }) => {
            assert_eq!(need, 10);
            assert_eq!(have, 8);
        }
        other => panic!("expected BufferTooSmall, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// read_utf16le
// ---------------------------------------------------------------------------

fn utf16le_bytes(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect()
}

#[test]
fn read_utf16le_valid_ascii() {
    let encoded = utf16le_bytes("Hello");
    let result = read_utf16le(&encoded, 0, encoded.len()).unwrap();
    assert_eq!(result, "Hello");
}

#[test]
fn read_utf16le_valid_unicode() {
    // U+00E9 LATIN SMALL LETTER E WITH ACUTE, U+4E2D CJK UNIFIED IDEOGRAPH
    let s = "caf\u{00E9}\u{4E2D}";
    let encoded = utf16le_bytes(s);
    let result = read_utf16le(&encoded, 0, encoded.len()).unwrap();
    assert_eq!(result, s);
}

#[test]
fn read_utf16le_with_offset() {
    // Prefix two bytes then the actual string.
    let prefix = [0xAA, 0xBB];
    let payload = utf16le_bytes("AB");
    let mut buf = Vec::new();
    buf.extend_from_slice(&prefix);
    buf.extend_from_slice(&payload);
    let result = read_utf16le(&buf, 2, payload.len()).unwrap();
    assert_eq!(result, "AB");
}

#[test]
fn read_utf16le_buffer_too_small() {
    let encoded = utf16le_bytes("Hi"); // 4 bytes
    // Ask for 6 bytes from a 4-byte buffer.
    match read_utf16le(&encoded, 0, 6) {
        Err(ParseError::BufferTooSmall { need, have }) => {
            assert_eq!(need, 6);
            assert_eq!(have, 4);
        }
        other => panic!("expected BufferTooSmall, got {:?}", other),
    }
}

#[test]
fn read_utf16le_buffer_too_small_with_offset() {
    // offset 2 in a 4-byte buffer, requesting 4 bytes -> needs offset+byte_len = 6
    let encoded = utf16le_bytes("Hi"); // 4 bytes
    match read_utf16le(&encoded, 2, 4) {
        Err(ParseError::BufferTooSmall { need, have }) => {
            assert_eq!(need, 6);
            assert_eq!(have, 4);
        }
        other => panic!("expected BufferTooSmall, got {:?}", other),
    }
}

#[test]
fn read_utf16le_invalid_utf16() {
    // 0xD800 is a lone high surrogate — invalid UTF-16.
    let buf = [0x00, 0xD8]; // lone high surrogate in LE
    match read_utf16le(&buf, 0, 2) {
        Err(ParseError::InvalidField { field, detail }) => {
            assert_eq!(field, "utf16le_string");
            assert!(detail.contains("invalid UTF-16LE"));
        }
        other => panic!("expected InvalidField, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// read_bytes
// ---------------------------------------------------------------------------

#[test]
fn read_bytes_exact_size() {
    let data = vec![0x10, 0x20, 0x30, 0x40];
    let mut cursor = Cursor::new(data.clone());
    let result = read_bytes(&mut cursor, 4).unwrap();
    assert_eq!(result, data);
}

#[test]
fn read_bytes_partial() {
    let data = vec![0xAA, 0xBB, 0xCC, 0xDD];
    let mut cursor = Cursor::new(data);
    let result = read_bytes(&mut cursor, 2).unwrap();
    assert_eq!(result, [0xAA, 0xBB]);
}

#[test]
fn read_bytes_too_few_available() {
    // Only 2 bytes in the cursor, but we request 4.
    let data = vec![0x01, 0x02];
    let mut cursor = Cursor::new(data);
    match read_bytes(&mut cursor, 4) {
        Err(ParseError::Io(_)) => {}
        other => panic!("expected Io error, got {:?}", other),
    }
}

#[test]
fn read_bytes_sequential_reads() {
    let data = vec![0x01, 0x02, 0x03, 0x04];
    let mut cursor = Cursor::new(data);
    let first = read_bytes(&mut cursor, 2).unwrap();
    let second = read_bytes(&mut cursor, 2).unwrap();
    assert_eq!(first, [0x01, 0x02]);
    assert_eq!(second, [0x03, 0x04]);
}

// ---------------------------------------------------------------------------
// read_bytes_at
// ---------------------------------------------------------------------------

#[test]
fn read_bytes_at_start() {
    let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let mut cursor = Cursor::new(data.clone());
    let result = read_bytes_at(&mut cursor, 0, 4).unwrap();
    assert_eq!(result, data);
}

#[test]
fn read_bytes_at_offset() {
    let data = vec![0x00, 0x00, 0xCA, 0xFE, 0xBA, 0xBE];
    let mut cursor = Cursor::new(data);
    let result = read_bytes_at(&mut cursor, 2, 4).unwrap();
    assert_eq!(result, [0xCA, 0xFE, 0xBA, 0xBE]);
}

#[test]
fn read_bytes_at_advances_then_reads_from_offset() {
    // Pre-advance the cursor; read_bytes_at should still seek to the right place.
    let data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
    let mut cursor = Cursor::new(data);
    // Consume the first 3 bytes so cursor position is 3.
    read_bytes(&mut cursor, 3).unwrap();
    // Now read from offset 1, independent of current position.
    let result = read_bytes_at(&mut cursor, 1, 2).unwrap();
    assert_eq!(result, [0x02, 0x03]);
}

#[test]
fn read_bytes_at_too_few_available() {
    let data = vec![0x01, 0x02];
    let mut cursor = Cursor::new(data);
    match read_bytes_at(&mut cursor, 0, 4) {
        Err(ParseError::Io(_)) => {}
        other => panic!("expected Io error, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// ParseError display formatting
// ---------------------------------------------------------------------------

#[test]
fn parse_error_display_buffer_too_small() {
    let e = ParseError::BufferTooSmall { need: 8, have: 3 };
    assert_eq!(e.to_string(), "buffer too small: need 8 bytes, have 3");
}

#[test]
fn parse_error_display_invalid_magic() {
    let e = ParseError::InvalidMagic {
        expected: 0x4D5A,
        got: 0x0000,
    };
    let s = e.to_string();
    assert!(s.contains("0x4d5a") || s.contains("0x4D5A"), "got: {}", s);
    assert!(s.contains("0x0") || s.contains("0x0000"), "got: {}", s);
}

#[test]
fn parse_error_display_invalid_field() {
    let e = ParseError::InvalidField {
        field: "magic",
        detail: "bad value".into(),
    };
    assert_eq!(
        e.to_string(),
        "invalid value for field 'magic': bad value"
    );
}

#[test]
fn parse_error_display_io() {
    let io_err = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof");
    let e = ParseError::Io(io_err);
    let s = e.to_string();
    assert!(s.starts_with("io error:"), "got: {}", s);
}

// ---------------------------------------------------------------------------
// FromBytes trait — basic implementation smoke test
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
struct TwoU16 {
    a: u16,
    b: u16,
}

impl FromBytes for TwoU16 {
    fn from_bytes(buf: &[u8]) -> Result<Self, ParseError> {
        Ok(TwoU16 {
            a: read_u16_le(buf, 0)?,
            b: read_u16_le(buf, 2)?,
        })
    }

    fn fixed_size() -> Option<usize> {
        Some(4)
    }
}

#[test]
fn from_bytes_custom_struct() {
    let buf = [0x01, 0x00, 0x02, 0x00];
    let v = TwoU16::from_bytes(&buf).unwrap();
    assert_eq!(v, TwoU16 { a: 1, b: 2 });
}

#[test]
fn from_bytes_fixed_size() {
    assert_eq!(TwoU16::fixed_size(), Some(4));
}

#[test]
fn from_bytes_buffer_too_small_propagates() {
    let buf = [0x01, 0x02]; // only 2 bytes, need 4
    match TwoU16::from_bytes(&buf) {
        Err(ParseError::BufferTooSmall { .. }) => {}
        other => panic!("expected BufferTooSmall, got {:?}", other),
    }
}
