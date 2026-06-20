use abyss_ntfs::filename::FileName;

/// Build a minimal $FILE_NAME attribute value.
///
/// Layout (bytes):
///   0..8   parent MFT reference (u64 LE)
///  64      name_length (in UTF-16 code units)
///  65      namespace
///  66..    name as UTF-16LE
fn build_filename_bytes(parent_ref: u64, namespace: u8, name: &str) -> Vec<u8> {
    // Minimum 66 bytes before the name starts.
    let utf16: Vec<u16> = name.encode_utf16().collect();
    let name_len = utf16.len() as u8;
    let total = 66 + utf16.len() * 2;
    let mut buf = vec![0u8; total];

    buf[0..8].copy_from_slice(&parent_ref.to_le_bytes());
    buf[64] = name_len;
    buf[65] = namespace;

    for (i, &unit) in utf16.iter().enumerate() {
        let off = 66 + i * 2;
        buf[off..off + 2].copy_from_slice(&unit.to_le_bytes());
    }

    buf
}

#[test]
fn test_filename_basic_parse() {
    let data = build_filename_bytes(5, 1, "Documents");
    let fname = FileName::from_bytes(&data).expect("should parse");
    assert_eq!(fname.parent_ref, 5);
    assert_eq!(fname.namespace, 1);
    assert_eq!(fname.name, "Documents");
}

#[test]
fn test_filename_parent_ref_masked_to_48_bits() {
    // Set sequence number in upper 16 bits (bits 48–63).
    let raw_ref: u64 = (7u64 << 48) | 42;
    let data = build_filename_bytes(raw_ref, 3, "foo.txt");
    let fname = FileName::from_bytes(&data).expect("should parse");
    // Only the lower 48 bits should be kept.
    assert_eq!(fname.parent_ref, 42);
}

#[test]
fn test_filename_is_win32_name_namespace_1() {
    let data = build_filename_bytes(5, 1, "test");
    let fname = FileName::from_bytes(&data).unwrap();
    assert!(fname.is_win32_name());
}

#[test]
fn test_filename_is_win32_name_namespace_3() {
    let data = build_filename_bytes(5, 3, "test");
    let fname = FileName::from_bytes(&data).unwrap();
    assert!(fname.is_win32_name());
}

#[test]
fn test_filename_is_not_win32_name_namespace_0() {
    let data = build_filename_bytes(5, 0, "test");
    let fname = FileName::from_bytes(&data).unwrap();
    assert!(!fname.is_win32_name());
}

#[test]
fn test_filename_is_not_win32_name_namespace_2() {
    let data = build_filename_bytes(5, 2, "test");
    let fname = FileName::from_bytes(&data).unwrap();
    assert!(!fname.is_win32_name());
}

#[test]
fn test_filename_rejects_too_small_buffer() {
    let buf = vec![0u8; 30];
    assert!(FileName::from_bytes(&buf).is_err());
}

#[test]
fn test_filename_unicode_name() {
    let data = build_filename_bytes(5, 1, "日本語");
    let fname = FileName::from_bytes(&data).expect("should parse unicode");
    assert_eq!(fname.name, "日本語");
}
