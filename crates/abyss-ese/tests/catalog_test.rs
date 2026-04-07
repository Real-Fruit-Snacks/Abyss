use abyss_ese::catalog::{ColumnDef, TableDef, fixed_column_size, build_table_defs};
use abyss_ese::record::EseRecord;

// --- ColumnDef tests ---

#[test]
fn column_def_fixed_classification() {
    let col = ColumnDef {
        id: 1,
        name: "TestCol".to_string(),
        col_type: 4,
        size: 4,
        flags: 0,
        is_fixed: true,
        is_variable: false,
        is_tagged: false,
    };
    assert!(col.is_fixed);
    assert!(!col.is_variable);
    assert!(!col.is_tagged);
    assert_eq!(col.id, 1);
    assert_eq!(col.col_type, 4);
    assert_eq!(col.size, 4);
}

#[test]
fn column_def_variable_classification() {
    let col = ColumnDef {
        id: 128,
        name: "VarCol".to_string(),
        col_type: 10, // text
        size: 0,
        flags: 0,
        is_fixed: false,
        is_variable: true,
        is_tagged: false,
    };
    assert!(!col.is_fixed);
    assert!(col.is_variable);
    assert!(!col.is_tagged);
}

#[test]
fn column_def_tagged_classification() {
    let col = ColumnDef {
        id: 256,
        name: "TaggedCol".to_string(),
        col_type: 9, // binary
        size: 0,
        flags: 0,
        is_fixed: false,
        is_variable: false,
        is_tagged: true,
    };
    assert!(!col.is_fixed);
    assert!(!col.is_variable);
    assert!(col.is_tagged);
}

// --- TableDef tests ---

#[test]
fn table_def_creation() {
    let table = TableDef {
        name: "datatable".to_string(),
        obj_id: 2,
        root_page: 100,
        columns: vec![
            ColumnDef {
                id: 1,
                name: "Col1".to_string(),
                col_type: 4,
                size: 4,
                flags: 0,
                is_fixed: true,
                is_variable: false,
                is_tagged: false,
            },
            ColumnDef {
                id: 128,
                name: "Col2".to_string(),
                col_type: 10,
                size: 0,
                flags: 0,
                is_fixed: false,
                is_variable: true,
                is_tagged: false,
            },
        ],
    };
    assert_eq!(table.name, "datatable");
    assert_eq!(table.obj_id, 2);
    assert_eq!(table.root_page, 100);
    assert_eq!(table.columns.len(), 2);
    assert_eq!(table.columns[0].name, "Col1");
    assert_eq!(table.columns[1].name, "Col2");
}

// --- fixed_column_size tests ---

#[test]
fn fixed_column_sizes() {
    assert_eq!(fixed_column_size(0), 0);   // nil
    assert_eq!(fixed_column_size(1), 1);   // bit
    assert_eq!(fixed_column_size(2), 1);   // unsigned byte
    assert_eq!(fixed_column_size(3), 2);   // short
    assert_eq!(fixed_column_size(4), 4);   // long
    assert_eq!(fixed_column_size(5), 8);   // currency
    assert_eq!(fixed_column_size(6), 4);   // float
    assert_eq!(fixed_column_size(7), 8);   // double
    assert_eq!(fixed_column_size(8), 8);   // date_time
    assert_eq!(fixed_column_size(9), 0);   // binary (variable)
    assert_eq!(fixed_column_size(10), 0);  // text (variable)
    assert_eq!(fixed_column_size(11), 0);  // long_binary
    assert_eq!(fixed_column_size(12), 0);  // long_text
    assert_eq!(fixed_column_size(14), 4);  // unsigned long
    assert_eq!(fixed_column_size(15), 8);  // long_long
    assert_eq!(fixed_column_size(16), 16); // guid
    assert_eq!(fixed_column_size(17), 2);  // unsigned short
    assert_eq!(fixed_column_size(99), 0);  // unknown
}

// --- EseRecord tests ---

#[test]
fn record_get_u32() {
    let mut rec = EseRecord::new();
    rec.values.insert(1, vec![0x78, 0x56, 0x34, 0x12]);
    assert_eq!(rec.get_u32(1), Some(0x12345678));
    assert_eq!(rec.get_u32(2), None);
}

#[test]
fn record_get_u16() {
    let mut rec = EseRecord::new();
    rec.values.insert(3, vec![0xCD, 0xAB]);
    assert_eq!(rec.get_u16(3), Some(0xABCD));
    assert_eq!(rec.get_u16(4), None);
}

#[test]
fn record_get_u32_too_short() {
    let mut rec = EseRecord::new();
    rec.values.insert(1, vec![0x01, 0x02]);
    assert_eq!(rec.get_u32(1), None);
}

#[test]
fn record_get_u16_too_short() {
    let mut rec = EseRecord::new();
    rec.values.insert(1, vec![0x01]);
    assert_eq!(rec.get_u16(1), None);
}

#[test]
fn record_get_raw_bytes() {
    let mut rec = EseRecord::new();
    rec.values.insert(5, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    let bytes = rec.get(5).unwrap();
    assert_eq!(bytes, &[0xDE, 0xAD, 0xBE, 0xEF]);
    assert!(rec.get(6).is_none());
}

#[test]
fn record_get_ascii() {
    let mut rec = EseRecord::new();
    rec.values.insert(128, b"hello\0".to_vec());
    assert_eq!(rec.get_ascii(128), Some("hello".to_string()));

    // Without null terminator
    rec.values.insert(129, b"world".to_vec());
    assert_eq!(rec.get_ascii(129), Some("world".to_string()));
}

#[test]
fn record_get_string_utf16le() {
    let mut rec = EseRecord::new();
    // "AB" in UTF-16LE: 0x41,0x00, 0x42,0x00
    rec.values.insert(200, vec![0x41, 0x00, 0x42, 0x00]);
    assert_eq!(rec.get_string(200), Some("AB".to_string()));
}

#[test]
fn record_get_string_empty() {
    let mut rec = EseRecord::new();
    rec.values.insert(201, vec![0x01]);
    // Too short for a UTF-16LE pair
    assert_eq!(rec.get_string(201), None);
}

#[test]
fn record_default() {
    let rec = EseRecord::default();
    assert!(rec.values.is_empty());
}

// --- Record parsing from raw bytes ---

#[test]
fn parse_record_fixed_columns() {
    use abyss_ese::record::parse_record;

    // Build column definitions: two fixed columns
    let columns = vec![
        ColumnDef {
            id: 1,
            name: "ColA".to_string(),
            col_type: 4, // long (4 bytes)
            size: 4,
            flags: 0,
            is_fixed: true,
            is_variable: false,
            is_tagged: false,
        },
        ColumnDef {
            id: 2,
            name: "ColB".to_string(),
            col_type: 3, // short (2 bytes)
            size: 2,
            flags: 0,
            is_fixed: true,
            is_variable: false,
            is_tagged: false,
        },
    ];

    // Build raw record:
    // [last_fixed_col_id=2][last_var_col_id=0][var_offset=10(=4+4+2)][ColA:4bytes][ColB:2bytes]
    let mut data = Vec::new();
    data.push(2u8);     // last_fixed_col_id
    data.push(0u8);     // last_variable_col_id (none)
    data.extend_from_slice(&10u16.to_le_bytes()); // var_offset_array_offset = 4 + 4 + 2
    data.extend_from_slice(&0x11223344u32.to_le_bytes()); // ColA value
    data.extend_from_slice(&0x5566u16.to_le_bytes());     // ColB value

    let rec = parse_record(&data, &columns, 0).expect("should parse");
    assert_eq!(rec.get_u32(1), Some(0x11223344));
    assert_eq!(rec.get_u16(2), Some(0x5566));
}

#[test]
fn parse_record_with_key_prefix() {
    use abyss_ese::record::parse_record;

    let columns = vec![
        ColumnDef {
            id: 1,
            name: "ColA".to_string(),
            col_type: 4,
            size: 4,
            flags: 0,
            is_fixed: true,
            is_variable: false,
            is_tagged: false,
        },
    ];

    // 4-byte key prefix + record
    let mut data = vec![0xAA, 0xBB, 0xCC, 0xDD]; // key prefix
    data.push(1u8);     // last_fixed_col_id
    data.push(0u8);     // last_variable_col_id
    data.extend_from_slice(&8u16.to_le_bytes()); // var_offset = 4 + 4
    data.extend_from_slice(&0xDEADBEEFu32.to_le_bytes());

    let rec = parse_record(&data, &columns, 4).expect("should parse with prefix");
    assert_eq!(rec.get_u32(1), Some(0xDEADBEEF));
}

#[test]
fn parse_record_with_variable_columns() {
    use abyss_ese::record::parse_record;

    let columns = vec![
        ColumnDef {
            id: 1,
            name: "FixedCol".to_string(),
            col_type: 4,
            size: 4,
            flags: 0,
            is_fixed: true,
            is_variable: false,
            is_tagged: false,
        },
        ColumnDef {
            id: 128,
            name: "VarCol".to_string(),
            col_type: 10, // text
            size: 0,
            flags: 0,
            is_fixed: false,
            is_variable: true,
            is_tagged: false,
        },
    ];

    // Record layout:
    // [last_fixed=1][last_var=128][var_offset=8(=4+4)][fixed_data:4bytes]
    // [var_offset_array: 1 entry (u16)][var_data: "test"]
    let mut data = Vec::new();
    data.push(1u8);     // last_fixed_col_id
    data.push(128u8);   // last_variable_col_id
    data.extend_from_slice(&8u16.to_le_bytes()); // var_offset_array_offset = 4 + 4
    data.extend_from_slice(&0x42u32.to_le_bytes()); // fixed col value

    // Variable offset array: 1 entry, end offset = 4 (length of "test")
    data.extend_from_slice(&4u16.to_le_bytes());

    // Variable data
    data.extend_from_slice(b"test");

    let rec = parse_record(&data, &columns, 0).expect("should parse");
    assert_eq!(rec.get_u32(1), Some(0x42));
    assert_eq!(rec.get_ascii(128), Some("test".to_string()));
}

// --- build_table_defs tests ---

#[test]
fn build_table_defs_basic() {
    let records = vec![
        // Table entry: obj_id_table=2, type=1(table), id=2, pgno=100, flags=0, name="datatable"
        (2u32, 1u16, 2u32, 100u32, 0u32, "datatable".to_string()),
        // Column entry: obj_id_table=2, type=2(column), id=1, coltyp=4(long), flags=0, name="Col1"
        (2u32, 2u16, 1u32, 4u32, 0u32, "Col1".to_string()),
        // Column entry: obj_id_table=2, type=2(column), id=128, coltyp=10(text), flags=0, name="Col2"
        (2u32, 2u16, 128u32, 10u32, 0u32, "Col2".to_string()),
    ];

    let tables = build_table_defs(&records);
    assert_eq!(tables.len(), 1);
    assert_eq!(tables[0].name, "datatable");
    assert_eq!(tables[0].obj_id, 2);
    assert_eq!(tables[0].root_page, 100);
    assert_eq!(tables[0].columns.len(), 2);

    let col1 = &tables[0].columns[0];
    assert_eq!(col1.id, 1);
    assert_eq!(col1.name, "Col1");
    assert_eq!(col1.col_type, 4);
    assert_eq!(col1.size, 4);
    assert!(col1.is_fixed);
    assert!(!col1.is_variable);

    let col2 = &tables[0].columns[1];
    assert_eq!(col2.id, 128);
    assert_eq!(col2.name, "Col2");
    assert_eq!(col2.col_type, 10);
    assert_eq!(col2.size, 0);
    assert!(!col2.is_fixed);
    assert!(col2.is_variable);
}

#[test]
fn build_table_defs_multiple_tables() {
    let records = vec![
        (1u32, 1u16, 1u32, 50u32, 0u32, "alpha".to_string()),
        (2u32, 1u16, 2u32, 60u32, 0u32, "beta".to_string()),
        (1u32, 2u16, 1u32, 4u32, 0u32, "ACol".to_string()),
        (2u32, 2u16, 1u32, 3u32, 0u32, "BCol".to_string()),
    ];

    let tables = build_table_defs(&records);
    assert_eq!(tables.len(), 2);
    // Sorted alphabetically
    assert_eq!(tables[0].name, "alpha");
    assert_eq!(tables[1].name, "beta");
    assert_eq!(tables[0].columns.len(), 1);
    assert_eq!(tables[1].columns.len(), 1);
}

#[test]
fn build_table_defs_ignores_index_entries() {
    let records = vec![
        (1u32, 1u16, 1u32, 50u32, 0u32, "tbl".to_string()),
        (1u32, 3u16, 10u32, 0u32, 0u32, "idx1".to_string()), // type=3 (index)
        (1u32, 2u16, 1u32, 4u32, 0u32, "col".to_string()),
    ];

    let tables = build_table_defs(&records);
    assert_eq!(tables.len(), 1);
    assert_eq!(tables[0].columns.len(), 1);
    assert_eq!(tables[0].columns[0].name, "col");
}
