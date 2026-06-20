use std::io::Cursor;

/// Build a minimal valid MDMP file in memory.
///
/// Layout:
///   [0..32]    Header
///   [32..68]   Stream directory (3 entries x 12 bytes)
///   [68..96]   SystemInfo stream (28 bytes)
///   [96..128]  Memory64List stream (16 header + 16 descriptor = 32 bytes)
///   [128..256] Module list stream (4 + 108 = 112 bytes, padded)
///   [256..260] Module name MINIDUMP_STRING (4 byte length + UTF-16LE "lsasrv.dll")
///   [280..408] Actual memory data (128 bytes at VA 0x7FF0_0000)
fn build_test_dump() -> Vec<u8> {
    let mut buf = vec![0u8; 512];

    // --- Header (32 bytes at offset 0) ---
    // Signature: "MDMP" = 0x504D444D
    buf[0..4].copy_from_slice(&0x504D_444Du32.to_le_bytes());
    // Version
    buf[4..8].copy_from_slice(&0xA793u32.to_le_bytes());
    // Stream count: 3
    buf[8..12].copy_from_slice(&3u32.to_le_bytes());
    // Stream directory RVA: 32
    buf[12..16].copy_from_slice(&32u32.to_le_bytes());
    // Checksum: 0
    buf[16..20].copy_from_slice(&0u32.to_le_bytes());
    // Timestamp
    buf[20..24].copy_from_slice(&0u32.to_le_bytes());
    // Flags (u64)
    buf[24..32].copy_from_slice(&0u64.to_le_bytes());

    // --- Stream directory (3 entries at offset 32, 12 bytes each) ---

    // Entry 0: SystemInfoStream (type=7, size=28, rva=68)
    buf[32..36].copy_from_slice(&7u32.to_le_bytes());
    buf[36..40].copy_from_slice(&28u32.to_le_bytes());
    buf[40..44].copy_from_slice(&68u32.to_le_bytes());

    // Entry 1: Memory64ListStream (type=9, size=32, rva=96)
    buf[44..48].copy_from_slice(&9u32.to_le_bytes());
    buf[48..52].copy_from_slice(&32u32.to_le_bytes());
    buf[52..56].copy_from_slice(&96u32.to_le_bytes());

    // Entry 2: ModuleListStream (type=4, size=112, rva=128)
    buf[56..60].copy_from_slice(&4u32.to_le_bytes());
    buf[60..64].copy_from_slice(&112u32.to_le_bytes());
    buf[64..68].copy_from_slice(&128u32.to_le_bytes());

    // --- SystemInfo stream (28 bytes at offset 68) ---
    // ProcessorArchitecture: AMD64 = 9
    buf[68..70].copy_from_slice(&9u16.to_le_bytes());
    // ProcessorLevel, ProcessorRevision, NumberOfProcessors, ProductType (skip)
    // MajorVersion at offset 68+16=84
    buf[84..88].copy_from_slice(&10u32.to_le_bytes());
    // MinorVersion at offset 88
    buf[88..92].copy_from_slice(&0u32.to_le_bytes());
    // BuildNumber at offset 92
    buf[92..96].copy_from_slice(&19041u32.to_le_bytes());

    // --- Memory64List stream (at offset 96) ---
    // NumberOfMemoryRanges (u64): 1
    buf[96..104].copy_from_slice(&1u64.to_le_bytes());
    // BaseRva (u64): 280 (where memory data starts in file)
    buf[104..112].copy_from_slice(&280u64.to_le_bytes());
    // Descriptor 0: StartOfMemoryRange=0x7FF00000, DataSize=128
    buf[112..120].copy_from_slice(&0x7FF0_0000u64.to_le_bytes());
    buf[120..128].copy_from_slice(&128u64.to_le_bytes());

    // --- ModuleList stream (at offset 128) ---
    // NumberOfModules (u32): 1
    buf[128..132].copy_from_slice(&1u32.to_le_bytes());
    // Module entry (108 bytes at offset 132):
    //   BaseOfImage (u64 at +0): 0x7FF00000
    buf[132..140].copy_from_slice(&0x7FF0_0000u64.to_le_bytes());
    //   SizeOfImage (u32 at +8): 128
    buf[140..144].copy_from_slice(&128u32.to_le_bytes());
    //   CheckSum (u32 at +12): 0
    //   TimeDateStamp (u32 at +16): 0
    //   ModuleNameRva (u32 at +20): 256
    buf[152..156].copy_from_slice(&256u32.to_le_bytes());

    // --- Module name MINIDUMP_STRING (at offset 256) ---
    // "lsasrv.dll" in UTF-16LE = 20 bytes
    let name_utf16: Vec<u16> = "lsasrv.dll".encode_utf16().collect();
    let name_bytes: Vec<u8> = name_utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
    let name_byte_len = name_bytes.len() as u32;
    buf[256..260].copy_from_slice(&name_byte_len.to_le_bytes());
    buf[260..260 + name_bytes.len()].copy_from_slice(&name_bytes);

    // --- Memory data (128 bytes at offset 280, VA 0x7FF00000) ---
    // Fill with a recognizable pattern
    for i in 0..128 {
        buf[280 + i] = (i & 0xFF) as u8;
    }

    buf
}

#[test]
fn test_valid_mdmp_header_parse() {
    let data = build_test_dump();
    let cursor = Cursor::new(data);
    let reader = abyss_memory::MinidumpReader::open(Box::new(cursor));
    assert!(reader.is_ok(), "should parse valid MDMP header");
    let reader = reader.unwrap();
    assert_eq!(reader.arch, abyss_memory::Architecture::X64);
    assert_eq!(reader.os_build, 19041);
}

#[test]
fn test_invalid_signature_rejected() {
    let mut data = build_test_dump();
    // Corrupt the signature
    data[0] = 0xFF;
    data[1] = 0xFF;
    let cursor = Cursor::new(data);
    let result = abyss_memory::MinidumpReader::open(Box::new(cursor));
    assert!(result.is_err(), "should reject invalid signature");
    match result {
        Err(abyss_memory::MemoryError::NotMemoryDump) => {} // expected
        Err(other) => panic!("expected NotMemoryDump, got: {:?}", other),
        Ok(_) => panic!("expected error, got Ok"),
    }
}

#[test]
fn test_memory64_list_parse() {
    let data = build_test_dump();
    let cursor = Cursor::new(data);
    let reader = abyss_memory::MinidumpReader::open(Box::new(cursor)).unwrap();
    let ranges = reader.memory_ranges();
    assert_eq!(ranges.len(), 1);
    assert_eq!(ranges[0].virtual_address, 0x7FF0_0000);
    assert_eq!(ranges[0].size, 128);
    assert_eq!(ranges[0].file_offset, 280);
}

#[test]
fn test_virtual_address_translation() {
    let data = build_test_dump();
    let cursor = Cursor::new(data);
    let mut reader = abyss_memory::MinidumpReader::open(Box::new(cursor)).unwrap();

    // Read bytes from virtual address 0x7FF00000
    let bytes = reader.read_virtual(0x7FF0_0000, 4).unwrap();
    assert_eq!(bytes, vec![0, 1, 2, 3]);

    // Read from an offset within the range
    let bytes = reader.read_virtual(0x7FF0_0010, 4).unwrap();
    assert_eq!(bytes, vec![16, 17, 18, 19]);
}

#[test]
fn test_virtual_address_unmapped() {
    let data = build_test_dump();
    let cursor = Cursor::new(data);
    let mut reader = abyss_memory::MinidumpReader::open(Box::new(cursor)).unwrap();

    // Try to read from an unmapped address
    let result = reader.read_virtual(0xDEAD_0000, 4);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        abyss_memory::MemoryError::AddressNotMapped { .. }
    ));
}

#[test]
fn test_module_list_parse() {
    let data = build_test_dump();
    let cursor = Cursor::new(data);
    let reader = abyss_memory::MinidumpReader::open(Box::new(cursor)).unwrap();
    let modules = reader.modules();
    assert_eq!(modules.len(), 1);
    assert_eq!(modules[0].name, "lsasrv.dll");
    assert_eq!(modules[0].base_address, 0x7FF0_0000);
    assert_eq!(modules[0].size, 128);
}

#[test]
fn test_find_module() {
    let data = build_test_dump();
    let cursor = Cursor::new(data);
    let reader = abyss_memory::MinidumpReader::open(Box::new(cursor)).unwrap();

    // Case-insensitive search
    let module = reader.find_module("LSASRV.DLL");
    assert!(module.is_some());
    assert_eq!(module.unwrap().name, "lsasrv.dll");

    // Partial match
    let module = reader.find_module("lsasrv");
    assert!(module.is_some());

    // Not found
    let module = reader.find_module("kernel32.dll");
    assert!(module.is_none());
}

#[test]
fn test_pattern_search_in_memory() {
    let data = build_test_dump();
    let cursor = Cursor::new(data);
    let mut reader = abyss_memory::MinidumpReader::open(Box::new(cursor)).unwrap();

    // Search for pattern [16, 17, 18, 19] which is at VA offset 0x10
    let hits = reader.search_pattern(&[16, 17, 18, 19]).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0], 0x7FF0_0010);
}

#[test]
fn test_pattern_search_in_module() {
    let data = build_test_dump();
    let cursor = Cursor::new(data);
    let mut reader = abyss_memory::MinidumpReader::open(Box::new(cursor)).unwrap();

    // Search for pattern within the module's memory
    let hits = reader
        .search_pattern_in_module("lsasrv.dll", &[0, 1, 2, 3])
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0], 0x7FF0_0000);
}

#[test]
fn test_pattern_search_not_found() {
    let data = build_test_dump();
    let cursor = Cursor::new(data);
    let mut reader = abyss_memory::MinidumpReader::open(Box::new(cursor)).unwrap();

    let hits = reader.search_pattern(&[0xFF, 0xFE, 0xFD]).unwrap();
    assert!(hits.is_empty());
}

#[test]
fn test_lsass_credential_struct() {
    let cred = abyss_memory::LsassCredential {
        provider: "msv1_0".into(),
        domain: "WORKGROUP".into(),
        username: "Administrator".into(),
        password: None,
        nt_hash: Some(vec![
            0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0,
            0x89, 0xc0,
        ]),
    };
    assert_eq!(cred.provider, "msv1_0");
    assert_eq!(cred.username, "Administrator");
    assert!(cred.password.is_none());
    assert_eq!(cred.nt_hash.as_ref().unwrap().len(), 16);
}

#[test]
fn test_x86_architecture_detection() {
    let mut data = build_test_dump();
    // Change processor architecture to x86 (0)
    data[68..70].copy_from_slice(&0u16.to_le_bytes());

    let cursor = Cursor::new(data);
    let reader = abyss_memory::MinidumpReader::open(Box::new(cursor)).unwrap();
    assert_eq!(reader.arch, abyss_memory::Architecture::X86);
}

#[test]
fn test_read_virtual_u32_u64() {
    let data = build_test_dump();
    let cursor = Cursor::new(data);
    let mut reader = abyss_memory::MinidumpReader::open(Box::new(cursor)).unwrap();

    let val = reader.read_virtual_u32(0x7FF0_0000).unwrap();
    assert_eq!(val, u32::from_le_bytes([0, 1, 2, 3]));

    let val = reader.read_virtual_u64(0x7FF0_0000).unwrap();
    assert_eq!(val, u64::from_le_bytes([0, 1, 2, 3, 4, 5, 6, 7]));
}
