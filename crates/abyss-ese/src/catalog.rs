/// ESE catalog (MSysObjects) parsing.
///
/// The catalog describes all tables and columns in the database.
/// It is stored in the B+ tree rooted at page 4.

/// A column definition from the catalog.
#[derive(Debug, Clone)]
pub struct ColumnDef {
    pub id: u32,
    pub name: String,
    /// ESE column type (0=nil, 1=bit, 2=ubyte, 3=short, 4=long, etc.)
    pub col_type: u16,
    /// Fixed size for fixed-width types, 0 for variable.
    pub size: u32,
    pub flags: u32,
    /// Column ID 1-127.
    pub is_fixed: bool,
    /// Column ID 128-255.
    pub is_variable: bool,
    /// Column ID > 255.
    pub is_tagged: bool,
}

/// A table definition from the catalog.
#[derive(Debug, Clone)]
pub struct TableDef {
    pub name: String,
    pub obj_id: u32,
    /// Root page of the data B+ tree for this table.
    pub root_page: u32,
    pub columns: Vec<ColumnDef>,
}

/// Catalog entry type values.
const CATALOG_TYPE_TABLE: u16 = 1;
const CATALOG_TYPE_COLUMN: u16 = 2;

/// The root page of the MSysObjects catalog B+ tree.
pub const CATALOG_ROOT_PAGE: u32 = 4;

/// Fixed size of the catalog record's fixed columns (after the 4-byte record header).
/// Fields: ObjidTable(4) + Type(2) + Id(4) + ColtypOrPgnoFDP(4) + SpaceUsage(4) + Flags(4) + PagesOrLocale(4) = 26 bytes.
pub const CATALOG_FIXED_SIZE: usize = 26;

/// Fixed column size by ESE column type.
pub fn fixed_column_size(col_type: u16) -> u32 {
    match col_type {
        0 => 0,          // nil
        1 => 1,          // bit
        2 => 1,          // unsigned byte
        3 => 2,          // short
        4 => 4,          // long
        5 => 8,          // currency
        6 => 4,          // float
        7 => 8,          // double
        8 => 8,          // date_time
        9 => 0,          // binary (variable)
        10 => 0,         // text (variable)
        11 => 0,         // long_binary (variable)
        12 => 0,         // long_text (variable)
        13 => 0,         // SLV (deprecated)
        14 => 4,         // unsigned long
        15 => 8,         // long_long
        16 => 16,        // guid
        17 => 2,         // unsigned short
        _ => 0,
    }
}

/// Parse a single catalog record from raw leaf tag data.
///
/// Returns `(obj_id_table, entry_type, id, coltyp_or_pgno, flags, name)`.
pub fn parse_catalog_record(data: &[u8]) -> Option<(u32, u16, u32, u32, u32, String)> {
    // The catalog key is ObjidTable(4) + Type(2) + Id(4) = 10 bytes prefix,
    // but in leaf records the key prefix length varies. The record header
    // starts after the key. In practice, the MSysObjects leaf tag layout is:
    //
    //   [key_prefix...][last_fixed_col_id:u8][last_var_col_id:u8][var_offset:u16][fixed_data...][var_offsets...][var_data...]
    //
    // For the catalog, the key is typically the first few bytes that encode
    // (ObjidTable, Type, Id). We need to find the record header.
    //
    // ESE catalog leaf records have a prefix byte count. In the tag data:
    //   byte 0-3: depends on tag flags. In new-format databases, tag data
    //             may have a 4-byte prefix (common key prefix + suffix) or
    //             the tag flags indicate how to interpret it.
    //
    // For simplicity and robustness, we scan for the record structure.
    // The MSysObjects fixed columns have IDs 1-7. So last_fixed_col_id
    // should be 7 (0x07). We search for this pattern.

    if data.len() < 4 {
        return None;
    }

    // In ESE leaf pages for the catalog, after the page-level key prefix handling,
    // each tag's data has:
    //   - A key suffix (variable length)
    //   - The record data
    //
    // The record data always starts with:
    //   last_fixed_column_id (u8) -- should be 7 for catalog
    //   last_variable_column_id (u8) -- typically 128 or higher
    //   variable_offset_array_offset (u16 LE)
    //
    // We try different key prefix lengths. The catalog key is 10 bytes
    // (ObjidTable=4 + Type=2 + Id=4), but tag 0 may have no key prefix (it's
    // the first entry), and subsequent tags have varying common prefix compression.
    //
    // Strategy: look for last_fixed_col_id == 7 at various offsets.

    let mut record_start = None;
    for prefix_len in 0..data.len().saturating_sub(4).min(32) {
        if data[prefix_len] == 7 && prefix_len + 4 <= data.len() {
            let last_var = data[prefix_len + 1];
            // Variable columns for catalog start at ID 128
            if last_var >= 127 && last_var <= 191 {
                let var_offset = u16::from_le_bytes([
                    data[prefix_len + 2],
                    data[prefix_len + 3],
                ]);
                let var_off_usize = var_offset as usize;
                // The var_offset should point somewhere reasonable within the record
                if var_off_usize >= CATALOG_FIXED_SIZE && var_off_usize < data.len().saturating_sub(prefix_len) {
                    record_start = Some(prefix_len);
                    break;
                }
            }
        }
    }

    let rs = record_start?;
    let rec = &data[rs..];
    if rec.len() < 4 + CATALOG_FIXED_SIZE {
        return None;
    }

    let _last_fixed = rec[0]; // should be 7
    let last_var = rec[1];
    let var_offset = u16::from_le_bytes([rec[2], rec[3]]) as usize;

    // Fixed columns start at offset 4 in the record
    let fixed = &rec[4..];
    if fixed.len() < CATALOG_FIXED_SIZE {
        return None;
    }

    let obj_id_table = u32::from_le_bytes([fixed[0], fixed[1], fixed[2], fixed[3]]);
    let entry_type = u16::from_le_bytes([fixed[4], fixed[5]]);
    let id = u32::from_le_bytes([fixed[6], fixed[7], fixed[8], fixed[9]]);
    let coltyp_or_pgno = u32::from_le_bytes([fixed[10], fixed[11], fixed[12], fixed[13]]);
    let _space_usage = u32::from_le_bytes([fixed[14], fixed[15], fixed[16], fixed[17]]);
    let flags = u32::from_le_bytes([fixed[18], fixed[19], fixed[20], fixed[21]]);
    let _pages_or_locale = u32::from_le_bytes([fixed[22], fixed[23], fixed[24], fixed[25]]);

    // Now extract the name from the variable columns area.
    // Variable column IDs start at 128. The name is variable column 128 (the first one).
    // The offset array is at rec[var_offset..], with one u16 per variable column
    // from 128 to last_var (inclusive).
    let num_var_cols = (last_var as usize).saturating_sub(127);
    if num_var_cols == 0 {
        return Some((obj_id_table, entry_type, id, coltyp_or_pgno, flags, String::new()));
    }

    let var_array_start = var_offset;
    let var_array_end = var_array_start + num_var_cols * 2;
    if var_array_end > rec.len() {
        // If we can't read the variable offset array, return with empty name
        return Some((obj_id_table, entry_type, id, coltyp_or_pgno, flags, String::new()));
    }

    // Read variable column offsets. Each is relative to the start of variable data.
    // The variable data starts right after the offset array.
    let mut var_offsets = Vec::with_capacity(num_var_cols);
    for i in 0..num_var_cols {
        let off_pos = var_array_start + i * 2;
        let raw = u16::from_le_bytes([rec[off_pos], rec[off_pos + 1]]);
        // High bit indicates the column is null/empty
        var_offsets.push(raw);
    }

    // Variable data starts after the offset array
    let var_data_start = var_array_end;

    // The first variable column (128 = Name) spans from 0 to var_offsets[0]
    // (or it's null if high bit is set)
    let first_end_raw = var_offsets[0];
    let is_null = first_end_raw & 0x8000 != 0;
    if is_null {
        return Some((obj_id_table, entry_type, id, coltyp_or_pgno, flags, String::new()));
    }

    let name_end = (first_end_raw & 0x7FFF) as usize;
    let name_start = var_data_start;
    let name_end_abs = var_data_start + name_end;

    if name_end_abs > rec.len() || name_end == 0 {
        return Some((obj_id_table, entry_type, id, coltyp_or_pgno, flags, String::new()));
    }

    let name_bytes = &rec[name_start..name_end_abs];
    // Catalog names are ASCII (or possibly null-terminated)
    let name = String::from_utf8_lossy(name_bytes)
        .trim_end_matches('\0')
        .to_string();

    Some((obj_id_table, entry_type, id, coltyp_or_pgno, flags, name))
}

/// Build `TableDef` entries from parsed catalog records.
pub fn build_table_defs(records: &[(u32, u16, u32, u32, u32, String)]) -> Vec<TableDef> {
    use std::collections::HashMap;

    // First pass: collect table entries
    let mut tables: HashMap<u32, TableDef> = HashMap::new();
    for &(_obj_id_table, entry_type, id, coltyp_or_pgno, _flags, ref name) in records {
        if entry_type == CATALOG_TYPE_TABLE {
            tables.entry(id).or_insert_with(|| TableDef {
                name: name.clone(),
                obj_id: id,
                root_page: coltyp_or_pgno,
                columns: Vec::new(),
            });
        }
    }

    // Second pass: collect column entries
    for &(obj_id_table, entry_type, id, coltyp_or_pgno, flags, ref name) in records {
        if entry_type == CATALOG_TYPE_COLUMN {
            if let Some(table) = tables.get_mut(&obj_id_table) {
                let col_type = coltyp_or_pgno as u16;
                let size = fixed_column_size(col_type);
                table.columns.push(ColumnDef {
                    id,
                    name: name.clone(),
                    col_type,
                    size,
                    flags,
                    is_fixed: id <= 127,
                    is_variable: id >= 128 && id <= 255,
                    is_tagged: id > 255,
                });
            }
        }
    }

    // Sort columns by ID within each table
    let mut result: Vec<TableDef> = tables.into_values().collect();
    for table in &mut result {
        table.columns.sort_by_key(|c| c.id);
    }
    result.sort_by(|a, b| a.name.cmp(&b.name));
    result
}
