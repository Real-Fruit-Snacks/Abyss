/// B+ tree walking for ESE databases.
///
/// ESE stores data in B+ trees. Branch pages contain pointers to child pages,
/// and leaf pages contain actual records.

use std::collections::HashMap;

use log::trace;

use crate::catalog::TableDef;
use crate::database::EseDatabase;
use crate::error::EseError;
use crate::page::{get_tag_data, strip_leaf_key, parse_branch_child, TAG_COMMON};
use crate::record::{parse_record, EseRecord};

impl EseDatabase {
    /// Walk a B+ tree starting at `root_page` and collect all leaf record data.
    ///
    /// Returns the raw entry data from each leaf page tag (excluding tag 0,
    /// which is the page's external header). Key prefixes are stripped from
    /// each tag's data so the returned bytes are pure record data.
    ///
    /// Space tree, index, and long-value pages are skipped automatically.
    ///
    /// The walker follows the gosecretsdump/impacket convention:
    /// - If a page is a **leaf** (and not space/index/LV), collect data from its tags.
    /// - If a page is **not a leaf**, treat it as a branch/FDP page and follow
    ///   child page pointers from its tags.
    pub fn walk_btree(&mut self, root_page: u32) -> Result<Vec<Vec<u8>>, EseError> {
        let mut results = Vec::new();
        let mut stack = vec![root_page];
        let mut visited = std::collections::HashSet::new();

        while let Some(page_num) = stack.pop() {
            // Prevent infinite loops from circular page references
            if !visited.insert(page_num) {
                continue;
            }

            let page_buf = match self.read_page(page_num) {
                Ok(buf) => buf,
                Err(e) => {
                    log::warn!("ESE: skipping corrupt page {}: {}", page_num, e);
                    continue;
                }
            };
            let header = match self.parse_page_header(&page_buf) {
                Ok(h) => h,
                Err(e) => {
                    log::warn!("ESE: skipping page {} with bad header: {}", page_num, e);
                    continue;
                }
            };

            let flags = header.page_flags;

            // Skip space tree, index, and long-value pages (not data).
            if flags.is_space_tree() || flags.is_index() || flags.is_long_value() {
                continue;
            }

            let tags = self.parse_page_tags(&page_buf, header.first_available_page_tag);

            if flags.is_leaf() {
                // Leaf page: collect record data from tags 1..N
                for tag in tags.iter().skip(1) {
                    if tag.size == 0 {
                        continue;
                    }
                    if let Some(tag_data) = get_tag_data(&page_buf, tag) {
                        if let Some(entry_data) = strip_leaf_key(tag_data, tag.flags) {
                            if !entry_data.is_empty() {
                                results.push(entry_data.to_vec());
                            }
                        }
                    }
                }

                // Follow next-page chain for multi-page leaf sequences
                if header.next_page_number > 0 {
                    stack.push(header.next_page_number);
                }
            } else {
                // Non-leaf page (branch or FDP): follow child page pointers.
                //
                // In ESE, any non-leaf page's tags contain branch entries with
                // child page numbers. This includes FDP root pages (which have
                // root flag but no branch or leaf flag) and pure branch pages.
                //
                // Tag 0 on non-leaf pages may contain space header or external
                // header data. We extract the child from the last 4 bytes.
                // Tags 1..N are standard branch entries: key + child page ptr.
                for tag in tags.iter().skip(1) {
                    if tag.size < 4 {
                        continue;
                    }
                    if let Some(tag_data) = get_tag_data(&page_buf, tag) {
                        if let Some(child) = parse_branch_child(tag_data, tag.flags) {
                            if child > 0 {
                                stack.push(child);
                            }
                        }
                    }
                }
            }
        }

        trace!("walk_btree: collected {} records from root page {}", results.len(), root_page);
        Ok(results)
    }

    /// Walk a long-value B+ tree and build a map of LV ID -> assembled data.
    ///
    /// LV tree pages have the `is_long_value()` flag set. Each leaf entry has
    /// an 8-byte key: `[LV ID: 4 BE][segment offset: 4 BE]`, followed by the
    /// segment data bytes. A single long value may span multiple segments.
    ///
    /// Key prefix compression: when the `TAG_COMMON` flag is set on a tag, the
    /// first 2 bytes of the tag data are `common_key_size` (u16 LE), indicating
    /// how many leading bytes of the key are inherited from the page's tag[0]
    /// (the common key prefix). The local key bytes fill the remainder.
    ///
    /// Each LV ID has two kinds of entries:
    /// - Header entry: segment_offset=0, data=[ref_count:4 LE][total_size:4 LE]
    /// - Data entry: segment_offset>=0, data=actual segment bytes
    /// Header entries are skipped (they have exactly 8 bytes of data).
    ///
    /// Returns a `HashMap<u32, Vec<u8>>` mapping each LV ID to its fully
    /// assembled data (segments concatenated in offset order).
    fn build_lv_map(&mut self, lv_root: u32) -> Result<HashMap<u32, Vec<u8>>, EseError> {
        let mut segments: HashMap<u32, Vec<(u32, Vec<u8>)>> = HashMap::new();
        let mut stack = vec![lv_root];
        let mut visited = std::collections::HashSet::new();

        while let Some(page_num) = stack.pop() {
            if !visited.insert(page_num) {
                continue;
            }

            let page_buf = match self.read_page(page_num) {
                Ok(buf) => buf,
                Err(e) => {
                    log::warn!("ESE LV: skipping corrupt page {}: {}", page_num, e);
                    continue;
                }
            };
            let header = match self.parse_page_header(&page_buf) {
                Ok(h) => h,
                Err(e) => {
                    log::warn!("ESE LV: skipping page {} with bad header: {}", page_num, e);
                    continue;
                }
            };

            let flags = header.page_flags;

            // Skip space tree and index pages, but NOT long-value pages
            if flags.is_space_tree() || flags.is_index() {
                continue;
            }

            let tags = self.parse_page_tags(&page_buf, header.first_available_page_tag);

            if flags.is_leaf() {
                // Read the common key prefix from tag[0]
                let common_prefix = if !tags.is_empty() {
                    get_tag_data(&page_buf, &tags[0])
                        .map(|d| d.to_vec())
                        .unwrap_or_default()
                } else {
                    Vec::new()
                };

                for tag in tags.iter().skip(1) {
                    if tag.size == 0 {
                        continue;
                    }
                    if let Some(tag_data) = get_tag_data(&page_buf, tag) {
                        if let Some((lv_id, offset, data)) =
                            Self::parse_lv_entry(tag_data, tag.flags, &common_prefix)
                        {
                            segments.entry(lv_id).or_default().push((offset, data.to_vec()));
                        }
                    }
                }

                if header.next_page_number > 0 {
                    stack.push(header.next_page_number);
                }
            } else {
                for tag in tags.iter().skip(1) {
                    if tag.size < 4 {
                        continue;
                    }
                    if let Some(tag_data) = get_tag_data(&page_buf, tag) {
                        if let Some(child) = parse_branch_child(tag_data, tag.flags) {
                            if child > 0 {
                                stack.push(child);
                            }
                        }
                    }
                }
            }
        }

        // Assemble segments: sort by offset and concatenate
        let mut result = HashMap::new();
        for (lv_id, mut segs) in segments {
            segs.sort_by_key(|(off, _)| *off);
            let mut combined = Vec::new();
            for (_, data) in segs {
                combined.extend_from_slice(&data);
            }
            result.insert(lv_id, combined);
        }

        trace!("build_lv_map: assembled {} long values from LV root page {}", result.len(), lv_root);
        Ok(result)
    }

    /// Parse a single LV tree leaf entry, reconstructing the full 8-byte key
    /// from the page's common key prefix and the tag's local key bytes.
    ///
    /// Returns `(lv_id, segment_offset, data_slice)` or `None` if invalid.
    /// Skips LV header entries (those with exactly 8 bytes of data that contain
    /// ref_count + total_size metadata rather than actual segment data).
    fn parse_lv_entry<'a>(
        tag_data: &'a [u8],
        tag_flags: u8,
        common_prefix: &[u8],
    ) -> Option<(u32, u32, &'a [u8])> {
        let mut pos: usize = 0;
        let mut common_key_size: usize = 0;

        // If TAG_COMMON flag set, read 2-byte common key size
        if tag_flags & TAG_COMMON != 0 {
            if tag_data.len() < 2 {
                return None;
            }
            common_key_size = u16::from_le_bytes([tag_data[0], tag_data[1]]) as usize;
            pos = 2;
        }

        // Read local key size
        if tag_data.len() < pos + 2 {
            return None;
        }
        let local_key_size = u16::from_le_bytes([tag_data[pos], tag_data[pos + 1]]) as usize;
        pos += 2;

        let local_key_end = pos + local_key_size;
        if local_key_end > tag_data.len() {
            return None;
        }
        let local_key = &tag_data[pos..local_key_end];
        let data = &tag_data[local_key_end..];

        // Build the full 8-byte key: [common_prefix bytes][local_key bytes]
        let total_key_size = common_key_size + local_key_size;
        if total_key_size < 8 {
            return None;
        }

        let mut full_key = [0u8; 8];
        // Copy common prefix bytes (from page's tag[0])
        let prefix_copy_len = common_key_size.min(8).min(common_prefix.len());
        full_key[..prefix_copy_len].copy_from_slice(&common_prefix[..prefix_copy_len]);
        // Copy local key bytes after the common prefix
        let local_copy_start = common_key_size.min(8);
        let local_copy_len = (8 - local_copy_start).min(local_key_size);
        full_key[local_copy_start..local_copy_start + local_copy_len]
            .copy_from_slice(&local_key[..local_copy_len]);

        let lv_id = u32::from_be_bytes([full_key[0], full_key[1], full_key[2], full_key[3]]);
        let segment_offset = u32::from_be_bytes([full_key[4], full_key[5], full_key[6], full_key[7]]);

        // Skip LV header entries: these have segment_offset==0 and exactly 8 bytes
        // of data containing [ref_count:4 LE][total_size:4 LE]. They are metadata,
        // not actual segment data.
        if data.len() == 8 && segment_offset == 0 {
            // Check if this looks like a header (ref_count is typically small)
            let ref_count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            if ref_count <= 0x10000 {
                return None;
            }
        }

        if data.is_empty() {
            return None;
        }

        Some((lv_id, segment_offset, data))
    }

    /// Read the MSysObjects catalog and return all table definitions.
    pub fn read_catalog(&mut self) -> Result<Vec<TableDef>, EseError> {
        use crate::catalog::{build_table_defs, parse_catalog_record, CATALOG_ROOT_PAGE};

        let raw_records = self.walk_btree(CATALOG_ROOT_PAGE)?;

        let mut parsed = Vec::new();
        for data in &raw_records {
            if let Some(entry) = parse_catalog_record(data) {
                parsed.push(entry);
            }
        }

        Ok(build_table_defs(&parsed))
    }

    /// Find a specific table by name in the catalog.
    pub fn find_table(&mut self, name: &str) -> Result<TableDef, EseError> {
        let tables = self.read_catalog()?;
        tables
            .into_iter()
            .find(|t| t.name.eq_ignore_ascii_case(name))
            .ok_or_else(|| EseError::TableNotFound {
                name: name.to_string(),
            })
    }

    /// Read all records from a table, parsing them according to column definitions.
    ///
    /// For each raw record from the B+ tree walk, this attempts to parse the record
    /// using the table's column definitions. Records that fail to parse are skipped.
    ///
    /// Separated long-value columns (those with the fSeparated flag in their tagged
    /// column data) are resolved automatically: the inline LV ID reference is replaced
    /// with the full data from the table's long value tree.
    pub fn read_table_records(&mut self, table: &TableDef) -> Result<Vec<EseRecord>, EseError> {
        // Build LV map once if this table has an LV tree
        let lv_map = if let Some(lv_root) = table.lv_root_page {
            match self.build_lv_map(lv_root) {
                Ok(map) => {
                    trace!("read_table_records: built LV map with {} entries for table '{}'",
                        map.len(), table.name);
                    map
                }
                Err(e) => {
                    log::warn!("ESE: failed to build LV map for table '{}': {}", table.name, e);
                    HashMap::new()
                }
            }
        } else {
            HashMap::new()
        };

        let raw_records = self.walk_btree(table.root_page)?;
        let mut records = Vec::new();

        for data in &raw_records {
            // The entry data (after key stripping) starts with the record header:
            //   last_fixed_col_id (u8)
            //   last_var_col_id (u8)
            //   var_offset (u16 LE)
            if data.len() < 4 {
                continue;
            }

            let last_fixed = data[0] as u32;
            let last_var = data[1] as u32;
            let var_offset = u16::from_le_bytes([data[2], data[3]]) as usize;

            // Basic sanity checks on the record header.
            // last_var == 0 or 127 both mean "no variable columns" (var IDs start at 128).
            if last_fixed == 0
                || (last_var > 0 && last_var < 127)
                || var_offset < 4
                || var_offset >= data.len()
            {
                continue;
            }

            if let Some(mut rec) = parse_record(data, &table.columns, 0) {
                // Resolve separated long value columns: replace inline LV ID with
                // actual data from the LV tree. Only columns flagged as fSeparated
                // during tagged column parsing are resolved -- inline values are
                // left as-is.
                if !lv_map.is_empty() && !rec.lv_columns.is_empty() {
                    for col_id in rec.lv_columns.clone() {
                        if let Some(lv_ref) = rec.values.get(&col_id) {
                            if let Some(id) = extract_lv_id(lv_ref) {
                                if let Some(full_data) = lv_map.get(&id) {
                                    rec.values.insert(col_id, full_data.clone());
                                }
                            }
                        }
                    }
                }

                if !rec.values.is_empty() {
                    records.push(rec);
                }
            }
        }

        trace!(
            "read_table_records: parsed {} records from table '{}' (root page {})",
            records.len(),
            table.name,
            table.root_page
        );
        Ok(records)
    }
}

/// Extract a long value ID from the inline tagged column data.
///
/// For separated long value columns, the tagged column data (after the flag
/// byte is stripped) contains a 4-byte LV ID (little-endian u32).
fn extract_lv_id(data: &[u8]) -> Option<u32> {
    if data.len() >= 4 {
        Some(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
    } else {
        None
    }
}
