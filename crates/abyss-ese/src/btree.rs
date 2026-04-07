/// B+ tree walking for ESE databases.
///
/// ESE stores data in B+ trees. Branch pages contain pointers to child pages,
/// and leaf pages contain actual records.

use log::trace;

use crate::catalog::TableDef;
use crate::database::EseDatabase;
use crate::error::EseError;
use crate::record::{parse_record, EseRecord};

impl EseDatabase {
    /// Walk a B+ tree starting at `root_page` and collect all leaf tag data blobs.
    ///
    /// Returns the raw bytes from each leaf page tag (excluding tag 0, which is
    /// the page's external header).
    pub fn walk_btree(&mut self, root_page: u32) -> Result<Vec<Vec<u8>>, EseError> {
        let mut results = Vec::new();
        let mut stack = vec![root_page];

        while let Some(page_num) = stack.pop() {
            let page_buf = self.read_page(page_num)?;
            let header = self.parse_page_header(&page_buf)?;
            let tags = self.parse_page_tags(&page_buf);

            // Skip empty or space-tree pages
            if header.page_flags.is_empty() || header.page_flags.is_space_tree() {
                continue;
            }

            if header.page_flags.is_leaf() {
                // Leaf page: collect data from tags 1..N (skip tag 0 = external header)
                for tag in tags.iter().skip(1) {
                    if tag.size == 0 {
                        continue;
                    }
                    if let Some(data) = self.get_tag_data(&page_buf, tag) {
                        // In new format, tag flags bit 0x01 and 0x02 may indicate
                        // prefix/suffix compression. For raw extraction, we take
                        // the data as-is.
                        results.push(data.to_vec());
                    }
                }
            } else if header.page_flags.is_branch() {
                // Branch page: extract child page numbers from tags.
                // Tag 0 on a branch page is special (external header / pointer to
                // the leftmost child). Tags 1..N contain key data + child page ptr.
                //
                // For branch pages, tag 0's data is the child page number of the
                // leftmost subtree (4 bytes LE).
                if !tags.is_empty() {
                    if let Some(data) = self.get_tag_data(&page_buf, &tags[0]) {
                        // Tag 0 on branch: just the child page number (last 4 bytes,
                        // or the only 4 bytes).
                        if data.len() >= 4 {
                            let child = u32::from_le_bytes([
                                data[data.len() - 4],
                                data[data.len() - 3],
                                data[data.len() - 2],
                                data[data.len() - 1],
                            ]);
                            if child > 0 {
                                stack.push(child);
                            }
                        }
                    }
                }
                for tag in tags.iter().skip(1) {
                    if tag.size < 4 {
                        continue;
                    }
                    if let Some(data) = self.get_tag_data(&page_buf, tag) {
                        if data.len() >= 4 {
                            let child = u32::from_le_bytes([
                                data[data.len() - 4],
                                data[data.len() - 3],
                                data[data.len() - 2],
                                data[data.len() - 1],
                            ]);
                            if child > 0 {
                                stack.push(child);
                            }
                        }
                    }
                }
            }
            // Pages that are neither leaf nor branch (e.g., root-only with both
            // flags) are treated as branch if they have branch flag, otherwise leaf.
        }

        trace!("walk_btree: collected {} records from root page {}", results.len(), root_page);
        Ok(results)
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
    pub fn read_table_records(&mut self, table: &TableDef) -> Result<Vec<EseRecord>, EseError> {
        let raw_records = self.walk_btree(table.root_page)?;
        let mut records = Vec::new();

        for data in &raw_records {
            // Try to find the record header by scanning for reasonable
            // last_fixed_col values. The key prefix length is unknown without
            // the index definition, so we probe.
            let mut parsed = None;
            for prefix_len in 0..data.len().saturating_sub(4).min(32) {
                let candidate = &data[prefix_len..];
                if candidate.len() < 4 {
                    break;
                }
                let last_fixed = candidate[0] as u32;
                let last_var = candidate[1] as u32;
                let var_offset = u16::from_le_bytes([candidate[2], candidate[3]]) as usize;

                // Validate: last_fixed should be within range of the table's fixed columns
                let max_fixed_id = table
                    .columns
                    .iter()
                    .filter(|c| c.is_fixed)
                    .map(|c| c.id)
                    .max()
                    .unwrap_or(0);

                // Accept if last_fixed is reasonable (0 to max_fixed_id+10 to allow
                // for columns not in our catalog) and var_offset is within bounds
                if last_fixed <= max_fixed_id.max(127)
                    && (last_var == 0 || (last_var >= 128 && last_var <= 255))
                    && var_offset >= 4
                    && var_offset < candidate.len()
                {
                    if let Some(rec) = parse_record(data, &table.columns, prefix_len) {
                        if !rec.values.is_empty() {
                            parsed = Some(rec);
                            break;
                        }
                    }
                }
            }

            if let Some(rec) = parsed {
                records.push(rec);
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
