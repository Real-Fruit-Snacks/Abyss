use abyss_ntfs::mft::MftRecord;
use abyss_ntfs::attribute::AttributeType;
use abyss_cstruct::read::FromBytes;

/// Build a minimal 1024-byte MFT record buffer with one resident $STANDARD_INFORMATION attribute.
fn build_mft_record(in_use: bool, is_dir: bool) -> Vec<u8> {
    let mut buf = vec![0u8; 1024];

    // Magic: "FILE"
    buf[0..4].copy_from_slice(b"FILE");

    // Update sequence offset: 48 (just past the header)
    buf[4..6].copy_from_slice(&48u16.to_le_bytes());
    // Update sequence count: 3
    buf[6..8].copy_from_slice(&3u16.to_le_bytes());

    // Log file sequence number: 12345 (u64 LE)
    buf[8..16].copy_from_slice(&12345u64.to_le_bytes());

    // Sequence number: 1
    buf[16..18].copy_from_slice(&1u16.to_le_bytes());

    // Hard link count: 1
    buf[18..20].copy_from_slice(&1u16.to_le_bytes());

    // First attribute offset: 56 (after header + fixup array)
    buf[20..22].copy_from_slice(&56u16.to_le_bytes());

    // Flags
    let mut flags: u16 = 0;
    if in_use { flags |= 0x0001; }
    if is_dir  { flags |= 0x0002; }
    buf[22..24].copy_from_slice(&flags.to_le_bytes());

    // Used size: 128
    buf[24..28].copy_from_slice(&128u32.to_le_bytes());

    // Allocated size: 1024
    buf[28..32].copy_from_slice(&1024u32.to_le_bytes());

    // Base record ref: 0
    buf[32..40].copy_from_slice(&0u64.to_le_bytes());

    // --- Write a resident $STANDARD_INFORMATION attribute at offset 56 ---
    let attr_off = 56usize;

    // Type: 0x10 ($STANDARD_INFORMATION)
    buf[attr_off..attr_off+4].copy_from_slice(&0x10u32.to_le_bytes());

    // Length: 28 (24-byte resident header + 4 bytes of value data, rounded to 8-byte alignment)
    let attr_len: u32 = 28;
    buf[attr_off+4..attr_off+8].copy_from_slice(&attr_len.to_le_bytes());

    // Non-resident flag: 0 (resident)
    buf[attr_off+8] = 0;

    // Name length: 0
    buf[attr_off+9] = 0;

    // Name offset: 24 (unused since no name)
    buf[attr_off+10..attr_off+12].copy_from_slice(&24u16.to_le_bytes());

    // Flags: 0
    buf[attr_off+12..attr_off+14].copy_from_slice(&0u16.to_le_bytes());

    // Instance: 0
    buf[attr_off+14..attr_off+16].copy_from_slice(&0u16.to_le_bytes());

    // Value length: 4 (resident)
    buf[attr_off+16..attr_off+20].copy_from_slice(&4u32.to_le_bytes());

    // Value offset: 24 (from start of attribute — past the 24-byte resident header)
    buf[attr_off+20..attr_off+22].copy_from_slice(&24u16.to_le_bytes());

    // Value data at attr_off+24: [0xDE, 0xAD, 0xBE, 0xEF]
    buf[attr_off+24..attr_off+28].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

    // --- End marker at offset 56 + 24 = 80 ---
    let end_off = attr_off + attr_len as usize;
    buf[end_off..end_off+4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

    buf
}

#[test]
fn test_parse_mft_record_basic() {
    let buf = build_mft_record(true, false);
    let rec = MftRecord::from_bytes(&buf).expect("should parse FILE record");

    assert_eq!(rec.sequence_number, 1);
    assert_eq!(rec.hard_link_count, 1);
    assert_eq!(rec.first_attribute_offset, 56);
    assert_eq!(rec.logfile_seq_number, 12345);
    assert_eq!(rec.used_size, 128);
    assert_eq!(rec.allocated_size, 1024);
    assert_eq!(rec.base_record_ref, 0);
}

#[test]
fn test_mft_is_in_use() {
    let buf_live = build_mft_record(true, false);
    let buf_dead = build_mft_record(false, false);

    let live = MftRecord::from_bytes(&buf_live).unwrap();
    let dead = MftRecord::from_bytes(&buf_dead).unwrap();

    assert!(live.is_in_use());
    assert!(!dead.is_in_use());
}

#[test]
fn test_mft_is_directory() {
    let buf_dir  = build_mft_record(true, true);
    let buf_file = build_mft_record(true, false);

    let dir  = MftRecord::from_bytes(&buf_dir).unwrap();
    let file = MftRecord::from_bytes(&buf_file).unwrap();

    assert!(dir.is_directory());
    assert!(!file.is_directory());
}

#[test]
fn test_mft_attribute_iterator_finds_standard_information() {
    let buf = build_mft_record(true, false);
    let rec = MftRecord::from_bytes(&buf).unwrap();

    let attrs: Vec<_> = rec.attributes(&buf).collect();
    assert_eq!(attrs.len(), 1, "should find exactly one attribute");

    let (_, ref hdr) = attrs[0];
    assert_eq!(hdr.attr_type, AttributeType::StandardInformation);
    assert!(!hdr.non_resident);
}

#[test]
fn test_resident_value_extraction() {
    let buf = build_mft_record(true, false);
    let rec = MftRecord::from_bytes(&buf).unwrap();

    let attrs: Vec<_> = rec.attributes(&buf).collect();
    let (attr_off, ref hdr) = attrs[0];

    let value = hdr.resident_value(&buf, attr_off).expect("should have resident value");
    assert_eq!(value, &[0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn test_mft_rejects_invalid_magic() {
    let mut buf = build_mft_record(true, false);
    buf[0..4].copy_from_slice(b"BAAD");
    let result = MftRecord::from_bytes(&buf);
    assert!(result.is_err(), "should reject non-FILE magic");
}

#[test]
fn test_mft_rejects_too_small_buffer() {
    let buf = vec![0u8; 40];
    let result = MftRecord::from_bytes(&buf);
    assert!(result.is_err(), "should reject buffer smaller than 48 bytes");
}
