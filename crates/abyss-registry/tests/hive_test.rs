use abyss_registry::RegistryHive;
use std::io::Cursor;

/// Build a minimal in-memory registry hive:
///   - 4096-byte base block with "regf" signature and root_cell_offset = 32
///   - 4096-byte hbin block with a root "nk" cell at offset 32 (name "ROOT")
fn build_test_hive() -> Vec<u8> {
    let mut buf = vec![0u8; 8192];

    // --- Base block (4096 bytes) ---
    // Magic "regf" at offset 0
    buf[0..4].copy_from_slice(b"regf");

    // root_cell_offset at header offset 36: value = 32
    // (The first cell sits right after the 32-byte hbin header.)
    let root_cell_offset: u32 = 32;
    buf[36..40].copy_from_slice(&root_cell_offset.to_le_bytes());

    // hive_bins_size at header offset 40: one hbin = 4096 bytes
    buf[40..44].copy_from_slice(&4096u32.to_le_bytes());

    // --- hbin block starting at file offset 4096 ---
    let hbin_start = 4096usize;

    // hbin signature at hbin_start + 0
    buf[hbin_start..hbin_start + 4].copy_from_slice(b"hbin");

    // hbin offset (relative to start of hive bins data) = 0
    buf[hbin_start + 4..hbin_start + 8].copy_from_slice(&0u32.to_le_bytes());

    // hbin size = 4096
    buf[hbin_start + 8..hbin_start + 12].copy_from_slice(&4096u32.to_le_bytes());

    // --- nk cell at hive-bins-data offset 32 ---
    // File offset = 4096 + 32 = 4128
    // Cell layout: [4-byte cell size][cell data...]
    // read_key_node reads at: HIVE_HEADER_SIZE + cell_offset + 4
    //   = 4096 + 32 + 4 = 4132
    let cell_start = hbin_start + 32; // = 4128

    // Cell size (negative = allocated): -(80 + name_len) stored as i32 LE
    // Name "ROOT" = 4 bytes ASCII
    let name = b"ROOT";
    let name_len = name.len() as u32;
    let cell_size: i32 = -((80 + name_len) as i32);
    buf[cell_start..cell_start + 4].copy_from_slice(&cell_size.to_le_bytes());

    // Cell data starts at cell_start + 4 = 4132
    let nk = cell_start + 4;

    // +0: "nk" signature
    buf[nk..nk + 2].copy_from_slice(b"nk");

    // +2: flags u16 — set root flag 0x0020
    let flags: u16 = 0x0020;
    buf[nk + 2..nk + 4].copy_from_slice(&flags.to_le_bytes());

    // +4..+16: last_written timestamp (8 bytes) — zero is fine
    // +16: parent_offset u32 — 0xFFFFFFFF (no parent for root)
    buf[nk + 16..nk + 20].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

    // +20: num_subkeys = 0
    buf[nk + 20..nk + 24].copy_from_slice(&0u32.to_le_bytes());

    // +24: num_volatile_subkeys = 0
    buf[nk + 24..nk + 28].copy_from_slice(&0u32.to_le_bytes());

    // +28: subkeys_list_offset = 0xFFFFFFFF (none)
    buf[nk + 28..nk + 32].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

    // +32: volatile_subkeys_list_offset = 0xFFFFFFFF
    buf[nk + 32..nk + 36].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

    // +36: num_values = 0
    buf[nk + 36..nk + 40].copy_from_slice(&0u32.to_le_bytes());

    // +40: values_list_offset = 0xFFFFFFFF
    buf[nk + 40..nk + 44].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

    // +44..+72: security_offset, class_name_offset, etc. — zeros

    // +72: name_length u16
    buf[nk + 72..nk + 74].copy_from_slice(&(name_len as u16).to_le_bytes());

    // +74: name_flags u16 — bit 0 set = ASCII name
    buf[nk + 74..nk + 76].copy_from_slice(&1u16.to_le_bytes());

    // +76: name bytes "ROOT"
    buf[nk + 76..nk + 76 + name.len()].copy_from_slice(name);

    buf
}

#[test]
fn test_open_registry_hive() {
    let data = build_test_hive();
    let cursor = Cursor::new(data);
    let hive = RegistryHive::open(Box::new(cursor)).expect("should open hive");
    assert_eq!(hive.root_key_name(), Some("ROOT"));
}

#[test]
fn test_rejects_non_registry() {
    let data = vec![0u8; 8192];
    let cursor = Cursor::new(data);
    let result = RegistryHive::open(Box::new(cursor));
    assert!(result.is_err(), "should reject non-registry data");
}
