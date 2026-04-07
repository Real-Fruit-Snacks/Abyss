use abyss_registry::RegistryHive;
use std::io::Cursor;

/// Build a minimal hive with a root "ROOT" key that has one inline DWORD value:
///   name = "MyValue", type = REG_DWORD (4), value = 0x12345678
///
/// Hive bins data layout (all offsets relative to hive bins data start = file offset 4096):
///   offset  32: nk cell for root key (num_values=1, values_list_offset=128)
///   offset 128: values list cell (one 4-byte entry pointing to offset 192)
///   offset 192: vk cell ("MyValue", inline DWORD 0x12345678)
fn build_hive_with_value() -> Vec<u8> {
    let mut buf = vec![0u8; 8192];

    // --- Base block (4096 bytes) ---
    buf[0..4].copy_from_slice(b"regf");
    // root_cell_offset = 32
    buf[36..40].copy_from_slice(&32u32.to_le_bytes());
    // hive_bins_size = 4096
    buf[40..44].copy_from_slice(&4096u32.to_le_bytes());

    // --- hbin header at file offset 4096 ---
    let hbin_start = 4096usize;
    buf[hbin_start..hbin_start + 4].copy_from_slice(b"hbin");
    buf[hbin_start + 4..hbin_start + 8].copy_from_slice(&0u32.to_le_bytes());
    buf[hbin_start + 8..hbin_start + 12].copy_from_slice(&4096u32.to_le_bytes());

    // ---------------------------------------------------------------
    // nk cell at hive-bins-data offset 32
    // File offset = 4096 + 32 = 4128
    // Cell data (after 4-byte size field) at 4132
    // ---------------------------------------------------------------
    let nk_cell = hbin_start + 32;
    let cell_size: i32 = -128; // allocated, large enough
    buf[nk_cell..nk_cell + 4].copy_from_slice(&cell_size.to_le_bytes());
    let nk = nk_cell + 4; // cell data base

    buf[nk..nk + 2].copy_from_slice(b"nk");
    // flags: root key (0x0020)
    buf[nk + 2..nk + 4].copy_from_slice(&0x0020u16.to_le_bytes());
    // parent_offset (offset 16): 0xFFFFFFFF
    buf[nk + 16..nk + 20].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    // num_subkeys (offset 20): 0
    buf[nk + 20..nk + 24].copy_from_slice(&0u32.to_le_bytes());
    // subkeys_list_offset (offset 28): 0xFFFFFFFF
    buf[nk + 28..nk + 32].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    // num_values (offset 36): 1
    buf[nk + 36..nk + 40].copy_from_slice(&1u32.to_le_bytes());
    // values_list_offset (offset 40): 128
    buf[nk + 40..nk + 44].copy_from_slice(&128u32.to_le_bytes());
    // security_offset (offset 44): 0xFFFFFFFF
    buf[nk + 44..nk + 48].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    // class_offset (offset 48): 0xFFFFFFFF
    buf[nk + 48..nk + 52].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    // name_length (offset 72): 4 ("ROOT")
    buf[nk + 72..nk + 74].copy_from_slice(&4u16.to_le_bytes());
    // name_flags (offset 74): 1 (ASCII)
    buf[nk + 74..nk + 76].copy_from_slice(&1u16.to_le_bytes());
    // name (offset 76): "ROOT"
    buf[nk + 76..nk + 80].copy_from_slice(b"ROOT");

    // ---------------------------------------------------------------
    // Values list cell at hive-bins-data offset 128
    // File offset = 4096 + 128 = 4224
    // Contains one u32 entry: vk cell offset = 192
    // ---------------------------------------------------------------
    let vl_cell = hbin_start + 128;
    let vl_size: i32 = -8;
    buf[vl_cell..vl_cell + 4].copy_from_slice(&vl_size.to_le_bytes());
    // Single vk offset = 192
    buf[vl_cell + 4..vl_cell + 8].copy_from_slice(&192u32.to_le_bytes());

    // ---------------------------------------------------------------
    // vk cell at hive-bins-data offset 192
    // File offset = 4096 + 192 = 4288
    // Cell data at 4292
    // vk layout (relative to cell data):
    //   [0..2]   "vk" signature
    //   [2..4]   name_length u16 = 7 ("MyValue")
    //   [4..8]   data_length_raw u32 = 0x80000004 (inline, 4 bytes)
    //   [8..12]  data_offset u32 = 0x12345678 (inline value)
    //   [12..16] data_type u32 = 4 (REG_DWORD)
    //   [16..18] name_flags u16 = 1 (ASCII)
    //   [18..24] padding
    //   [24..31] "MyValue"
    // ---------------------------------------------------------------
    let vk_cell = hbin_start + 192;
    let vk_size: i32 = -64;
    buf[vk_cell..vk_cell + 4].copy_from_slice(&vk_size.to_le_bytes());
    let vk = vk_cell + 4;

    buf[vk..vk + 2].copy_from_slice(b"vk");
    // name_length = 7
    buf[vk + 2..vk + 4].copy_from_slice(&7u16.to_le_bytes());
    // data_length_raw = 0x80000004 (inline, 4 bytes)
    buf[vk + 4..vk + 8].copy_from_slice(&0x8000_0004u32.to_le_bytes());
    // data_offset = inline value 0x12345678
    buf[vk + 8..vk + 12].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    // data_type = 4 (REG_DWORD)
    buf[vk + 12..vk + 16].copy_from_slice(&4u32.to_le_bytes());
    // name_flags = 1 (ASCII)
    buf[vk + 16..vk + 18].copy_from_slice(&1u16.to_le_bytes());
    // name "MyValue" at offset 24
    buf[vk + 24..vk + 31].copy_from_slice(b"MyValue");

    buf
}

#[test]
fn test_read_values_returns_dword() {
    let data = build_hive_with_value();
    let cursor = Cursor::new(data);
    let mut hive = RegistryHive::open(Box::new(cursor)).expect("should open hive");
    let root = hive.root_key().expect("should get root key");
    let values = hive.read_values(&root).expect("should read values");
    assert_eq!(values.len(), 1);
    assert_eq!(values[0].name, "MyValue");
    assert_eq!(values[0].as_u32().expect("should be u32"), 0x1234_5678);
}

#[test]
fn test_read_value_by_name() {
    let data = build_hive_with_value();
    let cursor = Cursor::new(data);
    let mut hive = RegistryHive::open(Box::new(cursor)).expect("should open hive");
    let root = hive.root_key().expect("should get root key");
    let val = hive.read_value(&root, "myvalue").expect("should find value case-insensitively");
    assert_eq!(val.name, "MyValue");
    assert_eq!(val.as_u32().unwrap(), 0x1234_5678);
}

#[test]
fn test_read_value_not_found() {
    let data = build_hive_with_value();
    let cursor = Cursor::new(data);
    let mut hive = RegistryHive::open(Box::new(cursor)).expect("should open hive");
    let root = hive.root_key().expect("should get root key");
    let result = hive.read_value(&root, "NoSuchValue");
    assert!(result.is_err(), "should return error for missing value");
}
