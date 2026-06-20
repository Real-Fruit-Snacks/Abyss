/// Comprehensive tests for abyss-registry: hive header, nk/vk cells, open() with synthetic hive.
use abyss_registry::{RegistryHive, RegistryError};
use abyss_registry::value::RegType;
use std::io::Cursor;

// ---------------------------------------------------------------------------
// Helpers to build synthetic hives
// ---------------------------------------------------------------------------

/// Write a little-endian u16 into a buffer at `offset`.
fn put_u16(buf: &mut [u8], offset: usize, val: u16) {
    buf[offset..offset + 2].copy_from_slice(&val.to_le_bytes());
}

/// Write a little-endian u32 into a buffer at `offset`.
fn put_u32(buf: &mut [u8], offset: usize, val: u32) {
    buf[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
}

/// Build the base block (4096 bytes) with "regf" magic, root_cell_offset and
/// hive_bins_size set.  The rest of the bytes are zero.
fn build_base_block(root_cell_offset: u32, hive_bins_size: u32) -> Vec<u8> {
    let mut block = vec![0u8; 4096];
    block[0..4].copy_from_slice(b"regf");
    put_u32(&mut block, 36, root_cell_offset);
    put_u32(&mut block, 40, hive_bins_size);
    block
}

/// Build a minimal hive with a single root "nk" cell and no values or subkeys.
///
/// Layout of hive bins data (relative to hive bins data base = file offset 4096):
///   offset 32: nk cell  (4-byte cell size + cell data)
///
/// The nk cell data layout mirrors what `read_key_node` expects:
///   [0..2]   "nk"
///   [2..4]   flags u16
///   [4..16]  last_written (8 bytes) + access_bits (4 bytes) — zeros
///   [16..20] parent_offset u32
///   [20..24] num_subkeys u32
///   [24..28] num_volatile_subkeys u32
///   [28..32] subkeys_list_offset u32
///   [32..36] volatile_subkeys_list_offset u32
///   [36..40] num_values u32
///   [40..44] values_list_offset u32
///   [44..72] security_offset, class_offset, … (zeros)
///   [72..74] name_length u16
///   [74..76] name_flags u16  (1 = ASCII)
///   [76..]   name bytes
fn build_minimal_hive(name: &[u8], flags: u16) -> Vec<u8> {
    // root_cell_offset = 32, one hbin = 4096 bytes
    let mut buf = build_base_block(32, 4096);
    buf.resize(8192, 0u8);

    let hbin_start = 4096usize;
    buf[hbin_start..hbin_start + 4].copy_from_slice(b"hbin");
    put_u32(&mut buf, hbin_start + 4, 0);
    put_u32(&mut buf, hbin_start + 8, 4096);

    let cell_start = hbin_start + 32;
    let name_len = name.len() as u32;
    let cell_size: i32 = -((80 + name_len) as i32);
    buf[cell_start..cell_start + 4].copy_from_slice(&cell_size.to_le_bytes());

    let nk = cell_start + 4;
    buf[nk..nk + 2].copy_from_slice(b"nk");
    put_u16(&mut buf, nk + 2, flags);
    put_u32(&mut buf, nk + 16, 0xFFFF_FFFF); // parent_offset
    put_u32(&mut buf, nk + 20, 0);           // num_subkeys
    put_u32(&mut buf, nk + 24, 0);           // num_volatile_subkeys
    put_u32(&mut buf, nk + 28, 0xFFFF_FFFF); // subkeys_list_offset
    put_u32(&mut buf, nk + 32, 0xFFFF_FFFF); // volatile_subkeys_list_offset
    put_u32(&mut buf, nk + 36, 0);           // num_values
    put_u32(&mut buf, nk + 40, 0xFFFF_FFFF); // values_list_offset
    put_u32(&mut buf, nk + 44, 0xFFFF_FFFF); // security_offset
    put_u32(&mut buf, nk + 48, 0xFFFF_FFFF); // class_offset  (class_length stays 0)
    put_u16(&mut buf, nk + 72, name_len as u16); // name_length
    put_u16(&mut buf, nk + 74, 1);               // name_flags: ASCII
    buf[nk + 76..nk + 76 + name.len()].copy_from_slice(name);

    buf
}

// ---------------------------------------------------------------------------
// 1. Hive header: "regf" magic + root_cell_offset is read correctly
// ---------------------------------------------------------------------------

#[test]
fn hive_header_regf_magic_accepted() {
    let data = build_minimal_hive(b"SYSTEM", 0x0020);
    let cursor = Cursor::new(data);
    let hive = RegistryHive::open(Box::new(cursor)).expect("valid regf hive must open");
    assert_eq!(hive.root_key_name(), Some("SYSTEM"));
}

#[test]
fn hive_header_root_key_name_is_cached() {
    let data = build_minimal_hive(b"SAM", 0x0020);
    let cursor = Cursor::new(data);
    let hive = RegistryHive::open(Box::new(cursor)).unwrap();
    // Called twice — must return the same cached value both times.
    assert_eq!(hive.root_key_name(), Some("SAM"));
    assert_eq!(hive.root_key_name(), Some("SAM"));
}

// ---------------------------------------------------------------------------
// 2. Invalid hive magic should error
// ---------------------------------------------------------------------------

#[test]
fn invalid_magic_returns_not_registry_hive() {
    let data = vec![0u8; 8192];
    let cursor = Cursor::new(data);
    let result = RegistryHive::open(Box::new(cursor));
    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(
        matches!(err, RegistryError::NotRegistryHive),
        "expected NotRegistryHive"
    );
}

#[test]
fn wrong_magic_bytes_rejected() {
    let mut data = vec![0u8; 8192];
    data[0..4].copy_from_slice(b"REGF"); // upper-case — invalid
    let cursor = Cursor::new(data);
    assert!(RegistryHive::open(Box::new(cursor)).is_err());
}

#[test]
fn truncated_buffer_rejected() {
    // Less than 512 bytes — read_bytes_at will fail.
    let data = vec![0u8; 256];
    let cursor = Cursor::new(data);
    assert!(RegistryHive::open(Box::new(cursor)).is_err());
}

// ---------------------------------------------------------------------------
// 3. Named key (nk record): parse via root_key()
// ---------------------------------------------------------------------------

#[test]
fn nk_cell_name_parsed_ascii() {
    let data = build_minimal_hive(b"MyKey", 0x0020);
    let cursor = Cursor::new(data);
    let mut hive = RegistryHive::open(Box::new(cursor)).unwrap();
    let key = hive.root_key().unwrap();
    assert_eq!(key.name, "MyKey");
}

#[test]
fn nk_cell_root_flag_detected() {
    // flags = 0x0020 means is_root() returns true
    let data = build_minimal_hive(b"ROOT", 0x0020);
    let cursor = Cursor::new(data);
    let mut hive = RegistryHive::open(Box::new(cursor)).unwrap();
    let key = hive.root_key().unwrap();
    assert!(key.is_root(), "root flag (0x0020) should be set");
}

#[test]
fn nk_cell_non_root_flag() {
    // flags = 0x0000 — is_root() should be false
    let data = build_minimal_hive(b"NonRoot", 0x0000);
    let cursor = Cursor::new(data);
    let mut hive = RegistryHive::open(Box::new(cursor)).unwrap();
    let key = hive.root_key().unwrap();
    assert!(!key.is_root());
}

#[test]
fn nk_cell_subkey_count_is_zero() {
    let data = build_minimal_hive(b"ROOT", 0x0020);
    let cursor = Cursor::new(data);
    let mut hive = RegistryHive::open(Box::new(cursor)).unwrap();
    let key = hive.root_key().unwrap();
    assert_eq!(key.num_subkeys, 0);
    assert_eq!(key.num_values, 0);
}

#[test]
fn nk_cell_cell_offset_matches_root_offset() {
    let data = build_minimal_hive(b"ROOT", 0x0020);
    let cursor = Cursor::new(data);
    let mut hive = RegistryHive::open(Box::new(cursor)).unwrap();
    let key = hive.root_key().unwrap();
    // root_cell_offset was set to 32 in the header
    assert_eq!(key.cell_offset, 32);
}

// ---------------------------------------------------------------------------
// 4. Value key (vk record): parse via read_values()
// ---------------------------------------------------------------------------

/// Build a hive with a root nk that has one external REG_BINARY value named "BinVal".
///
/// Layout of hive bins data:
///   offset  32: nk cell (num_values=1, values_list_offset=160)
///   offset 160: values list cell (one u32 entry -> 224)
///   offset 224: vk cell (name="BinVal", type=REG_BINARY, external data at 320)
///   offset 320: data cell (4 bytes: 0xDE, 0xAD, 0xBE, 0xEF)
fn build_hive_with_binary_value() -> Vec<u8> {
    let mut buf = vec![0u8; 8192];
    buf[0..4].copy_from_slice(b"regf");
    put_u32(&mut buf, 36, 32);   // root_cell_offset
    put_u32(&mut buf, 40, 4096); // hive_bins_size

    let hb = 4096usize; // hive bins file offset
    buf[hb..hb + 4].copy_from_slice(b"hbin");
    put_u32(&mut buf, hb + 4, 0);
    put_u32(&mut buf, hb + 8, 4096);

    // --- nk cell at offset 32 ---
    let nk_cell = hb + 32;
    let nk_size: i32 = -128;
    buf[nk_cell..nk_cell + 4].copy_from_slice(&nk_size.to_le_bytes());
    let nk = nk_cell + 4;
    buf[nk..nk + 2].copy_from_slice(b"nk");
    put_u16(&mut buf, nk + 2, 0x0020); // flags: root
    put_u32(&mut buf, nk + 16, 0xFFFF_FFFF); // parent_offset
    put_u32(&mut buf, nk + 20, 0);           // num_subkeys
    put_u32(&mut buf, nk + 28, 0xFFFF_FFFF); // subkeys_list_offset
    put_u32(&mut buf, nk + 36, 1);           // num_values = 1
    put_u32(&mut buf, nk + 40, 160);         // values_list_offset
    put_u32(&mut buf, nk + 44, 0xFFFF_FFFF); // security_offset
    put_u32(&mut buf, nk + 48, 0xFFFF_FFFF); // class_offset
    put_u16(&mut buf, nk + 72, 4);  // name_length "ROOT"
    put_u16(&mut buf, nk + 74, 1);  // name_flags: ASCII
    buf[nk + 76..nk + 80].copy_from_slice(b"ROOT");

    // --- values list cell at offset 160 ---
    let vl = hb + 160;
    let vl_size: i32 = -8;
    buf[vl..vl + 4].copy_from_slice(&vl_size.to_le_bytes());
    put_u32(&mut buf, vl + 4, 224); // vk cell offset

    // --- vk cell at offset 224 ---
    // vk layout (from cell data base = hb + 224 + 4):
    //   [0..2]   "vk"
    //   [2..4]   name_length u16  = 6 ("BinVal")
    //   [4..8]   data_length_raw u32 = 4 (external)
    //   [8..12]  data_offset u32  = 320 (hive-bins-data relative)
    //   [12..16] data_type u32    = 3 (REG_BINARY)
    //   [16..18] name_flags u16   = 1 (ASCII)
    //   [24..30] "BinVal"
    let vk_cell = hb + 224;
    let vk_size: i32 = -64;
    buf[vk_cell..vk_cell + 4].copy_from_slice(&vk_size.to_le_bytes());
    let vk = vk_cell + 4;
    buf[vk..vk + 2].copy_from_slice(b"vk");
    put_u16(&mut buf, vk + 2, 6);    // name_length
    put_u32(&mut buf, vk + 4, 4);    // data_length_raw (external, 4 bytes)
    put_u32(&mut buf, vk + 8, 320);  // data_offset
    put_u32(&mut buf, vk + 12, 3);   // data_type: REG_BINARY
    put_u16(&mut buf, vk + 16, 1);   // name_flags: ASCII
    buf[vk + 24..vk + 30].copy_from_slice(b"BinVal");

    // --- data cell at offset 320 ---
    let dc = hb + 320;
    let dc_size: i32 = -8;
    buf[dc..dc + 4].copy_from_slice(&dc_size.to_le_bytes());
    buf[dc + 4..dc + 8].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

    buf
}

#[test]
fn vk_cell_binary_value_name_and_type() {
    let data = build_hive_with_binary_value();
    let cursor = Cursor::new(data);
    let mut hive = RegistryHive::open(Box::new(cursor)).unwrap();
    let root = hive.root_key().unwrap();
    let values = hive.read_values(&root).unwrap();
    assert_eq!(values.len(), 1);
    assert_eq!(values[0].name, "BinVal");
    assert_eq!(values[0].reg_type, RegType::Binary);
}

#[test]
fn vk_cell_binary_value_data() {
    let data = build_hive_with_binary_value();
    let cursor = Cursor::new(data);
    let mut hive = RegistryHive::open(Box::new(cursor)).unwrap();
    let root = hive.root_key().unwrap();
    let values = hive.read_values(&root).unwrap();
    assert_eq!(values[0].data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn vk_cell_default_value_name_when_name_length_zero() {
    // A vk cell with name_length = 0 must produce "(Default)" as the name.
    let mut buf = vec![0u8; 8192];
    buf[0..4].copy_from_slice(b"regf");
    put_u32(&mut buf, 36, 32);
    put_u32(&mut buf, 40, 4096);

    let hb = 4096usize;
    buf[hb..hb + 4].copy_from_slice(b"hbin");
    put_u32(&mut buf, hb + 8, 4096);

    // nk cell
    let nk_cell = hb + 32;
    buf[nk_cell..nk_cell + 4].copy_from_slice(&(-128i32).to_le_bytes());
    let nk = nk_cell + 4;
    buf[nk..nk + 2].copy_from_slice(b"nk");
    put_u16(&mut buf, nk + 2, 0x0020);
    put_u32(&mut buf, nk + 16, 0xFFFF_FFFF);
    put_u32(&mut buf, nk + 28, 0xFFFF_FFFF);
    put_u32(&mut buf, nk + 36, 1);    // num_values
    put_u32(&mut buf, nk + 40, 160);  // values_list_offset
    put_u32(&mut buf, nk + 44, 0xFFFF_FFFF);
    put_u32(&mut buf, nk + 48, 0xFFFF_FFFF);
    put_u16(&mut buf, nk + 72, 4);
    put_u16(&mut buf, nk + 74, 1);
    buf[nk + 76..nk + 80].copy_from_slice(b"ROOT");

    // values list
    let vl = hb + 160;
    buf[vl..vl + 4].copy_from_slice(&(-8i32).to_le_bytes());
    put_u32(&mut buf, vl + 4, 224); // vk offset

    // vk cell with name_length = 0, inline DWORD
    let vk_cell = hb + 224;
    buf[vk_cell..vk_cell + 4].copy_from_slice(&(-32i32).to_le_bytes());
    let vk = vk_cell + 4;
    buf[vk..vk + 2].copy_from_slice(b"vk");
    put_u16(&mut buf, vk + 2, 0);             // name_length = 0 -> "(Default)"
    put_u32(&mut buf, vk + 4, 0x8000_0004);   // inline, 4 bytes
    put_u32(&mut buf, vk + 8, 42);            // inline value = 42
    put_u32(&mut buf, vk + 12, 4);            // REG_DWORD
    put_u16(&mut buf, vk + 16, 1);            // name_flags

    let cursor = Cursor::new(buf);
    let mut hive = RegistryHive::open(Box::new(cursor)).unwrap();
    let root = hive.root_key().unwrap();
    let values = hive.read_values(&root).unwrap();
    assert_eq!(values.len(), 1);
    assert_eq!(values[0].name, "(Default)");
    assert_eq!(values[0].as_u32().unwrap(), 42);
}

// ---------------------------------------------------------------------------
// 5. open() with a minimal synthetic hive — navigation and errors
// ---------------------------------------------------------------------------

#[test]
fn open_key_empty_path_returns_root() {
    let data = build_minimal_hive(b"ROOT", 0x0020);
    let cursor = Cursor::new(data);
    let mut hive = RegistryHive::open(Box::new(cursor)).unwrap();
    let key = hive.open_key("").unwrap();
    assert_eq!(key.name, "ROOT");
}

#[test]
fn open_key_root_name_returns_root() {
    let data = build_minimal_hive(b"ROOT", 0x0020);
    let cursor = Cursor::new(data);
    let mut hive = RegistryHive::open(Box::new(cursor)).unwrap();
    let key = hive.open_key("ROOT").unwrap();
    assert_eq!(key.name, "ROOT");
}

#[test]
fn open_key_missing_child_returns_key_not_found() {
    let data = build_minimal_hive(b"ROOT", 0x0020);
    let cursor = Cursor::new(data);
    let mut hive = RegistryHive::open(Box::new(cursor)).unwrap();
    let err = hive.open_key("NoSuchChild").unwrap_err();
    assert!(
        matches!(err, RegistryError::KeyNotFound { .. }),
        "expected KeyNotFound, got {err:?}"
    );
}

#[test]
fn subkey_names_returns_empty_for_leaf_key() {
    let data = build_minimal_hive(b"ROOT", 0x0020);
    let cursor = Cursor::new(data);
    let mut hive = RegistryHive::open(Box::new(cursor)).unwrap();
    let root = hive.root_key().unwrap();
    let names = hive.subkey_names(&root).unwrap();
    assert!(names.is_empty());
}

#[test]
fn read_values_returns_empty_for_no_value_key() {
    let data = build_minimal_hive(b"ROOT", 0x0020);
    let cursor = Cursor::new(data);
    let mut hive = RegistryHive::open(Box::new(cursor)).unwrap();
    let root = hive.root_key().unwrap();
    let values = hive.read_values(&root).unwrap();
    assert!(values.is_empty());
}

// ---------------------------------------------------------------------------
// RegType conversion
// ---------------------------------------------------------------------------

#[test]
fn reg_type_from_known_values() {
    assert_eq!(RegType::from(0), RegType::None);
    assert_eq!(RegType::from(1), RegType::Sz);
    assert_eq!(RegType::from(2), RegType::ExpandSz);
    assert_eq!(RegType::from(3), RegType::Binary);
    assert_eq!(RegType::from(4), RegType::Dword);
    assert_eq!(RegType::from(5), RegType::DwordBigEndian);
    assert_eq!(RegType::from(6), RegType::Link);
    assert_eq!(RegType::from(7), RegType::MultiSz);
    assert_eq!(RegType::from(11), RegType::Qword);
}

#[test]
fn reg_type_unknown_wraps_value() {
    let t = RegType::from(999u32);
    assert_eq!(t, RegType::Unknown(999));
}

// ---------------------------------------------------------------------------
// RegValue decoders
// ---------------------------------------------------------------------------

#[test]
fn reg_value_as_u64() {
    use abyss_registry::RegValue;
    let v = RegValue {
        name: "Q".to_string(),
        reg_type: RegType::Qword,
        data: 0x0102030405060708u64.to_le_bytes().to_vec(),
    };
    assert_eq!(v.as_u64().unwrap(), 0x0102030405060708u64);
}

#[test]
fn reg_value_as_u32_too_short_errors() {
    use abyss_registry::RegValue;
    let v = RegValue {
        name: "Short".to_string(),
        reg_type: RegType::Dword,
        data: vec![1, 2], // only 2 bytes
    };
    assert!(v.as_u32().is_err());
}

#[test]
fn reg_value_as_string_utf16le() {
    use abyss_registry::RegValue;
    // "Hi" encoded as UTF-16LE + NUL terminator
    let data: Vec<u8> = "Hi\0".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let v = RegValue {
        name: "Str".to_string(),
        reg_type: RegType::Sz,
        data,
    };
    assert_eq!(v.as_string().unwrap(), "Hi");
}

#[test]
fn reg_value_as_string_odd_length_errors() {
    use abyss_registry::RegValue;
    let v = RegValue {
        name: "Odd".to_string(),
        reg_type: RegType::Sz,
        data: vec![0x48, 0x00, 0x69], // 3 bytes — not a multiple of 2
    };
    assert!(v.as_string().is_err());
}
