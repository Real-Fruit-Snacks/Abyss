use abyss_ese::EseDatabase;
use abyss_ese::header::EseHeader;
use abyss_ese::page::{PageFlags, PageHeader, PAGE_HEADER_SIZE, parse_page_tags, get_tag_data};
use abyss_cstruct::read::FromBytes;
use std::io::Cursor;

/// Build a minimal valid 4096-byte header buffer.
fn make_header_buf(magic: u32, page_size: u32) -> Vec<u8> {
    let mut buf = vec![0u8; 4096];
    // checksum at 0
    buf[0..4].copy_from_slice(&0u32.to_le_bytes());
    // magic at 4
    buf[4..8].copy_from_slice(&magic.to_le_bytes());
    // format_version at 8
    buf[8..12].copy_from_slice(&0x620u32.to_le_bytes());
    // file_type at 12
    buf[12..16].copy_from_slice(&0u32.to_le_bytes());
    // db_state at 52
    buf[52..56].copy_from_slice(&1u32.to_le_bytes());
    // page_size at 236
    buf[236..240].copy_from_slice(&page_size.to_le_bytes());
    buf
}

/// Build a minimal ESE file (header page + one data page).
fn make_ese_file(page_size: u32) -> Vec<u8> {
    let header_buf = make_header_buf(0x89ABCDEF, page_size);
    let mut file = header_buf;
    // Append a blank data page
    file.extend(vec![0u8; page_size as usize]);
    file
}

// --- Header tests ---

#[test]
fn header_valid_parse() {
    let buf = make_header_buf(0x89ABCDEF, 4096);
    let hdr = EseHeader::from_bytes(&buf).expect("should parse valid header");
    assert_eq!(hdr.magic, 0x89ABCDEF);
    assert_eq!(hdr.page_size, 4096);
    assert_eq!(hdr.format_version, 0x620);
    assert_eq!(hdr.db_state, 1);
}

#[test]
fn header_invalid_magic() {
    let buf = make_header_buf(0xDEADBEEF, 4096);
    let result = EseHeader::from_bytes(&buf);
    assert!(result.is_err());
    match result.unwrap_err() {
        abyss_cstruct::ParseError::InvalidMagic { expected, got } => {
            assert_eq!(expected, 0x89ABCDEF);
            assert_eq!(got, 0xDEADBEEF);
        }
        e => panic!("unexpected error: {:?}", e),
    }
}

#[test]
fn header_buffer_too_small() {
    let buf = vec![0u8; 100];
    let result = EseHeader::from_bytes(&buf);
    assert!(result.is_err());
    match result.unwrap_err() {
        abyss_cstruct::ParseError::BufferTooSmall { need, have } => {
            assert_eq!(need, 668);
            assert_eq!(have, 100);
        }
        e => panic!("unexpected error: {:?}", e),
    }
}

#[test]
fn header_invalid_page_size() {
    // page_size = 5000 (not a power of 2)
    let buf = make_header_buf(0x89ABCDEF, 5000);
    let result = EseHeader::from_bytes(&buf);
    assert!(result.is_err());
    match result.unwrap_err() {
        abyss_cstruct::ParseError::InvalidField { field, .. } => {
            assert_eq!(field, "page_size");
        }
        e => panic!("unexpected error: {:?}", e),
    }
}

// --- PageFlags tests ---

#[test]
fn page_flags_checks() {
    let root_and_leaf = PageFlags(0x03);
    assert!(root_and_leaf.is_root());
    assert!(root_and_leaf.is_leaf());
    assert!(!root_and_leaf.is_branch());
    assert!(!root_and_leaf.is_empty());
    assert!(!root_and_leaf.is_space_tree());
    assert!(!root_and_leaf.is_index());
    assert!(!root_and_leaf.is_long_value());

    let index_page = PageFlags(0x40);
    assert!(!index_page.is_root());
    assert!(index_page.is_index());

    let long_value = PageFlags(0x80);
    assert!(long_value.is_long_value());

    let branch = PageFlags(0x04);
    assert!(branch.is_branch());

    let space_tree = PageFlags(0x20);
    assert!(space_tree.is_space_tree());
}

// --- PageHeader tests ---

#[test]
fn page_header_parse() {
    let mut page = vec![0u8; PAGE_HEADER_SIZE + 8];
    // Write flags = 0x03 (root | leaf) at offset 32
    page[32..36].copy_from_slice(&0x03u32.to_le_bytes());
    let hdr = PageHeader::from_page(&page).expect("should parse page header");
    assert!(hdr.page_flags.is_root());
    assert!(hdr.page_flags.is_leaf());
    assert!(!hdr.page_flags.is_branch());
}

// --- Tag data extraction tests ---

#[test]
fn page_tag_data_extraction() {
    let page_size = 4096usize;
    let mut page = vec![0u8; page_size];

    // Write known data at offset 0 within data area (i.e., page[40..45])
    let payload = b"HELLO";
    page[PAGE_HEADER_SIZE..PAGE_HEADER_SIZE + 5].copy_from_slice(payload);

    // Write a tag at the end of the page: offset=0, size=5
    // Tag 0 is at page_size - 4
    let tag_pos = page_size - 4;
    let offset_raw: u16 = 0u16; // offset within data area = 0
    let size: u16 = 5;
    page[tag_pos..tag_pos + 2].copy_from_slice(&offset_raw.to_le_bytes());
    page[tag_pos + 2..tag_pos + 4].copy_from_slice(&size.to_le_bytes());

    let tags = parse_page_tags(&page, false);
    assert!(!tags.is_empty(), "should find at least one tag");
    assert_eq!(tags[0].offset, 0);
    assert_eq!(tags[0].size, 5);

    let data = get_tag_data(&page, &tags[0]).expect("should get tag data");
    assert_eq!(data, payload);
}

// --- EseDatabase tests ---

#[test]
fn database_open_valid() {
    let file_data = make_ese_file(4096);
    let cursor = Cursor::new(file_data);
    let db = EseDatabase::open(Box::new(cursor)).expect("should open valid ESE database");
    assert_eq!(db.page_size, 4096);
    assert!(db.new_format);
    assert_eq!(db.header.magic, 0x89ABCDEF);
}

#[test]
fn database_open_invalid() {
    // Just random bytes — no ESE magic
    let file_data = vec![0xAAu8; 4096];
    let cursor = Cursor::new(file_data);
    let result = EseDatabase::open(Box::new(cursor));
    assert!(result.is_err());
}
