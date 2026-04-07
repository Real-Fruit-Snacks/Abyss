/// ESE record parsing.
///
/// Handles extraction of column values from raw record data.

use std::collections::HashMap;

use crate::catalog::ColumnDef;

/// A single record from an ESE table.
#[derive(Debug, Clone)]
pub struct EseRecord {
    /// Column values keyed by column ID. Value is raw bytes.
    pub values: HashMap<u32, Vec<u8>>,
}

impl EseRecord {
    /// Create a new empty record.
    pub fn new() -> Self {
        Self {
            values: HashMap::new(),
        }
    }

    /// Get a column value as raw bytes.
    pub fn get(&self, column_id: u32) -> Option<&[u8]> {
        self.values.get(&column_id).map(|v| v.as_slice())
    }

    /// Get a column value as u32 (for 4-byte fixed columns).
    pub fn get_u32(&self, column_id: u32) -> Option<u32> {
        let data = self.values.get(&column_id)?;
        if data.len() >= 4 {
            Some(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
        } else {
            None
        }
    }

    /// Get a column value as u16.
    pub fn get_u16(&self, column_id: u32) -> Option<u16> {
        let data = self.values.get(&column_id)?;
        if data.len() >= 2 {
            Some(u16::from_le_bytes([data[0], data[1]]))
        } else {
            None
        }
    }

    /// Get a column value as a UTF-16LE string.
    pub fn get_string(&self, column_id: u32) -> Option<String> {
        let data = self.values.get(&column_id)?;
        if data.len() < 2 {
            return None;
        }
        // Decode UTF-16LE
        let u16s: Vec<u16> = data
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16(&u16s).ok()
            .map(|s| s.trim_end_matches('\0').to_string())
    }

    /// Get a column value as an ASCII string.
    pub fn get_ascii(&self, column_id: u32) -> Option<String> {
        let data = self.values.get(&column_id)?;
        Some(
            String::from_utf8_lossy(data)
                .trim_end_matches('\0')
                .to_string(),
        )
    }
}

impl Default for EseRecord {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a raw record blob into an `EseRecord`, using the column definitions
/// to determine fixed/variable/tagged column layout.
///
/// The record layout (after any key prefix) is:
///   - `last_fixed_column_id` (u8)
///   - `last_variable_column_id` (u8)
///   - `variable_offset_array_offset` (u16 LE)
///   - Fixed column data
///   - Variable column offset array (u16 per variable column)
///   - Variable column data
///   - Tagged column data
///
/// `key_prefix_len` is the number of bytes of key prefix to skip before the
/// record header.
pub fn parse_record(
    data: &[u8],
    columns: &[ColumnDef],
    key_prefix_len: usize,
) -> Option<EseRecord> {
    if data.len() < key_prefix_len + 4 {
        return None;
    }
    let rec = &data[key_prefix_len..];
    if rec.len() < 4 {
        return None;
    }

    let last_fixed_col = rec[0] as u32;
    let last_var_col = rec[1] as u32;
    let var_offset_array_offset = u16::from_le_bytes([rec[2], rec[3]]) as usize;

    let mut record = EseRecord::new();

    // --- Fixed columns (IDs 1 to last_fixed_col) ---
    // Extract fixed columns: accumulate offset from column sizes
    let mut offset = 4usize;
    let mut fixed_cols: Vec<&ColumnDef> = columns
        .iter()
        .filter(|c| c.is_fixed && c.id <= last_fixed_col && c.size > 0)
        .collect();
    fixed_cols.sort_by_key(|c| c.id);

    for col in &fixed_cols {
        let col_size = col.size as usize;
        let end = offset + col_size;
        if end <= rec.len() {
            record.values.insert(col.id, rec[offset..end].to_vec());
        }
        offset += col_size;
    }

    // --- Variable columns (IDs 128 to last_var_col) ---
    if last_var_col >= 128 {
        let num_var_cols = (last_var_col - 127) as usize;
        let var_array_start = var_offset_array_offset;
        let var_array_end = var_array_start + num_var_cols * 2;

        if var_array_end <= rec.len() {
            let mut var_offsets = Vec::with_capacity(num_var_cols);
            for i in 0..num_var_cols {
                let off_pos = var_array_start + i * 2;
                let raw = u16::from_le_bytes([rec[off_pos], rec[off_pos + 1]]);
                var_offsets.push(raw);
            }

            let var_data_start = var_array_end;
            let mut prev_end: usize = 0;

            for (i, &off_raw) in var_offsets.iter().enumerate() {
                let col_id = 128 + i as u32;
                let is_null = off_raw & 0x8000 != 0;
                let end = (off_raw & 0x7FFF) as usize;

                if !is_null && end > prev_end {
                    let abs_start = var_data_start + prev_end;
                    let abs_end = var_data_start + end;
                    if abs_end <= rec.len() {
                        record.values.insert(col_id, rec[abs_start..abs_end].to_vec());
                    }
                }
                prev_end = end;
            }
        }
    }

    // --- Tagged columns (IDs > 255) ---
    // Tagged data comes after variable data. We need to find where it starts.
    // It starts after all variable column data.
    if last_var_col >= 128 {
        let num_var_cols = (last_var_col - 127) as usize;
        let var_array_start = var_offset_array_offset;
        let var_array_end = var_array_start + num_var_cols * 2;

        if var_array_end <= rec.len() && num_var_cols > 0 {
            let last_off_pos = var_array_start + (num_var_cols - 1) * 2;
            let last_raw = u16::from_le_bytes([rec[last_off_pos], rec[last_off_pos + 1]]);
            let last_end = (last_raw & 0x7FFF) as usize;
            let tagged_start = var_array_end + last_end;
            parse_tagged_columns(rec, tagged_start, &mut record);
        }
    } else {
        // No variable columns; tagged data starts at var_offset_array_offset
        parse_tagged_columns(rec, var_offset_array_offset, &mut record);
    }

    Some(record)
}

/// Parse tagged column data from the record.
///
/// Tagged columns are stored as:
///   [tag_id:u16 LE][offset:u16 LE] pairs (the "tag array"), followed by data.
/// The offset values are relative to the start of the tagged data area.
fn parse_tagged_columns(rec: &[u8], tagged_start: usize, record: &mut EseRecord) {
    if tagged_start >= rec.len() {
        return;
    }

    let tagged = &rec[tagged_start..];
    if tagged.len() < 4 {
        return;
    }

    // Read the tag array. Each entry is 4 bytes (tag_id:u16 + offset:u16).
    // The first entry's offset tells us where the tag array ends and data begins.
    let first_offset = u16::from_le_bytes([tagged[2], tagged[3]]) as usize;
    if first_offset < 4 || first_offset > tagged.len() {
        return;
    }

    // Number of tag entries = first_offset / 4
    let num_tags = first_offset / 4;
    if num_tags == 0 || num_tags * 4 > tagged.len() {
        return;
    }

    let mut entries = Vec::with_capacity(num_tags);
    for i in 0..num_tags {
        let base = i * 4;
        if base + 4 > tagged.len() {
            break;
        }
        let tag_id = u16::from_le_bytes([tagged[base], tagged[base + 1]]) as u32;
        let offset = u16::from_le_bytes([tagged[base + 2], tagged[base + 3]]) as usize;
        entries.push((tag_id, offset));
    }

    // Extract data for each tagged column
    for i in 0..entries.len() {
        let (tag_id, start) = entries[i];
        let end = if i + 1 < entries.len() {
            entries[i + 1].1
        } else {
            tagged.len()
        };

        if start < tagged.len() && end <= tagged.len() && end > start {
            let tag_data = &tagged[start..end];
            // In ESE, tagged column data may have a 1-byte flag prefix
            // (bit 0 = variable length, bit 1 = compressed, etc.)
            // For simplicity, if the first byte has a known flag pattern,
            // we skip it. But for raw extraction we keep all bytes.
            record.values.insert(tag_id, tag_data.to_vec());
        }
    }
}
