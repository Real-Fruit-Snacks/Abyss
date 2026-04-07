use abyss_cstruct::read::{read_bytes_at, read_u16_le, read_u32_le, read_utf16le, ReadSeek};
use crate::error::RegistryError;
use crate::key::KeyNode;

/// Size of the base block (regf header) in bytes.
const HIVE_HEADER_SIZE: u64 = 4096;

/// A parsed Windows registry hive.
pub struct RegistryHive {
    reader: Box<dyn ReadSeek>,
    root_cell_offset: u32,
    #[allow(dead_code)]
    hive_bins_size: u32,
    root_key_name_cache: Option<String>,
}

impl RegistryHive {
    /// Open a registry hive from a `ReadSeek` source.
    ///
    /// Validates the "regf" magic signature and reads the root cell offset
    /// from header offset 36.
    pub fn open(mut reader: Box<dyn ReadSeek>) -> Result<Self, RegistryError> {
        // Read first 512 bytes of the base block.
        let header = read_bytes_at(&mut reader, 0, 512)?;

        // Validate "regf" signature.
        if &header[0..4] != b"regf" {
            return Err(RegistryError::NotRegistryHive);
        }

        // Root cell offset is at header offset 36 (relative to hive bins data).
        let root_cell_offset = read_u32_le(&header, 36)?;

        // Hive bins size at offset 40.
        let hive_bins_size = read_u32_le(&header, 40)?;

        let mut hive = Self {
            reader,
            root_cell_offset,
            hive_bins_size,
            root_key_name_cache: None,
        };

        // Pre-cache the root key name.
        let root = hive.read_key_node(root_cell_offset)?;
        hive.root_key_name_cache = Some(root.name.clone());

        Ok(hive)
    }

    /// Returns the cached root key name.
    pub fn root_key_name(&self) -> Option<&str> {
        self.root_key_name_cache.as_deref()
    }

    /// Returns the root `KeyNode`.
    pub fn root_key(&mut self) -> Result<KeyNode, RegistryError> {
        self.read_key_node(self.root_cell_offset)
    }

    /// Navigate a backslash-delimited path and return the target `KeyNode`.
    ///
    /// An empty path or a path equal to the root key name returns the root.
    pub fn open_key(&mut self, path: &str) -> Result<KeyNode, RegistryError> {
        let root = self.read_key_node(self.root_cell_offset)?;

        if path.is_empty() {
            return Ok(root);
        }

        let parts: Vec<&str> = path.split('\\').collect();
        let mut current = root;

        // If the first component matches the root key name, skip it.
        let start = if parts[0].eq_ignore_ascii_case(&current.name) {
            1
        } else {
            0
        };

        for part in &parts[start..] {
            if part.is_empty() {
                continue;
            }
            let next_offset = self.find_subkey(&current, part)?;
            current = self.read_key_node(next_offset)?;
        }

        Ok(current)
    }

    /// Read a `KeyNode` (nk cell) at the given cell offset (relative to hive bins data).
    pub fn read_key_node(&mut self, cell_offset: u32) -> Result<KeyNode, RegistryError> {
        // Absolute file offset: skip hive header + cell size field (4 bytes) before the cell data.
        let abs_offset = HIVE_HEADER_SIZE + cell_offset as u64 + 4;

        // Read enough bytes for the nk cell header (up to name_length at offset 72 + name bytes).
        // First pass: read fixed-size portion (76 bytes covers all fixed fields + name_length).
        let fixed = read_bytes_at(&mut self.reader, abs_offset, 76)?;

        // Validate "nk" signature.
        if &fixed[0..2] != b"nk" {
            return Err(RegistryError::Parse(abyss_cstruct::ParseError::InvalidField {
                field: "nk_signature",
                detail: format!("expected 'nk', got {:?}", &fixed[0..2]),
            }));
        }

        let flags = read_u16_le(&fixed, 2)?;
        let parent_offset = read_u32_le(&fixed, 16)?;
        let num_subkeys = read_u32_le(&fixed, 20)?;
        let subkeys_list_offset = read_u32_le(&fixed, 28)?;
        let num_values = read_u32_le(&fixed, 36)?;
        let values_list_offset = read_u32_le(&fixed, 40)?;
        let name_length = read_u16_le(&fixed, 72)? as usize;
        let name_flags = read_u16_le(&fixed, 74)?;

        // Read the key name bytes immediately following the fixed header.
        let name_bytes = read_bytes_at(&mut self.reader, abs_offset + 76, name_length)?;

        // If bit 0 of name_flags is set, the name is ASCII; otherwise UTF-16LE.
        let name = if name_flags & 0x0001 != 0 {
            // ASCII / Latin-1 compressed name.
            String::from_utf8_lossy(&name_bytes).into_owned()
        } else {
            read_utf16le(&name_bytes, 0, name_length)?
        };

        Ok(KeyNode {
            name,
            flags,
            parent_offset,
            num_subkeys,
            subkeys_list_offset,
            num_values,
            values_list_offset,
            cell_offset,
        })
    }

    /// Find a subkey by name within the given key node.
    ///
    /// Returns the cell offset of the matching subkey.
    fn find_subkey(&mut self, key: &KeyNode, name: &str) -> Result<u32, RegistryError> {
        if key.num_subkeys == 0 || key.subkeys_list_offset == 0xFFFF_FFFF {
            return Err(RegistryError::KeyNotFound { path: name.to_string() });
        }

        let list_abs = HIVE_HEADER_SIZE + key.subkeys_list_offset as u64 + 4;
        // Read 4 bytes for signature.
        let sig_buf = read_bytes_at(&mut self.reader, list_abs, 4)?;
        let sig = &sig_buf[0..2];

        match sig {
            b"lf" | b"lh" => self.read_lf_lh_list(key.subkeys_list_offset, name),
            b"ri" => self.read_ri_list(key.subkeys_list_offset, name),
            b"li" => self.read_li_list(key.subkeys_list_offset, name),
            other => Err(RegistryError::Parse(abyss_cstruct::ParseError::InvalidField {
                field: "subkey_list_signature",
                detail: format!("unknown list type {:?}", other),
            })),
        }
    }

    /// Search an lf/lh subkey list for a key by name.
    fn read_lf_lh_list(&mut self, list_offset: u32, name: &str) -> Result<u32, RegistryError> {
        let abs = HIVE_HEADER_SIZE + list_offset as u64 + 4;
        let header = read_bytes_at(&mut self.reader, abs, 4)?;
        let count = read_u16_le(&header, 2)? as usize;

        // Each entry is 8 bytes: 4-byte cell offset + 4-byte hash.
        let entries_size = count * 8;
        let entries = read_bytes_at(&mut self.reader, abs + 4, entries_size)?;

        for i in 0..count {
            let entry_offset = i * 8;
            let cell_offset = read_u32_le(&entries, entry_offset)?;
            // Read the candidate key to compare names.
            let candidate = self.read_key_node(cell_offset)?;
            if candidate.name.eq_ignore_ascii_case(name) {
                return Ok(cell_offset);
            }
        }

        Err(RegistryError::KeyNotFound { path: name.to_string() })
    }

    /// Search an ri (index root) list for a key by name.
    fn read_ri_list(&mut self, list_offset: u32, name: &str) -> Result<u32, RegistryError> {
        let abs = HIVE_HEADER_SIZE + list_offset as u64 + 4;
        let header = read_bytes_at(&mut self.reader, abs, 4)?;
        let count = read_u16_le(&header, 2)? as usize;

        let entries_size = count * 4;
        let entries = read_bytes_at(&mut self.reader, abs + 4, entries_size)?;

        for i in 0..count {
            let sub_list_offset = read_u32_le(&entries, i * 4)?;
            match self.find_subkey_in_list(sub_list_offset, name) {
                Ok(offset) => return Ok(offset),
                Err(RegistryError::KeyNotFound { .. }) => continue,
                Err(e) => return Err(e),
            }
        }

        Err(RegistryError::KeyNotFound { path: name.to_string() })
    }

    /// Search an li (index leaf) list for a key by name.
    fn read_li_list(&mut self, list_offset: u32, name: &str) -> Result<u32, RegistryError> {
        let abs = HIVE_HEADER_SIZE + list_offset as u64 + 4;
        let header = read_bytes_at(&mut self.reader, abs, 4)?;
        let count = read_u16_le(&header, 2)? as usize;

        let entries_size = count * 4;
        let entries = read_bytes_at(&mut self.reader, abs + 4, entries_size)?;

        for i in 0..count {
            let cell_offset = read_u32_le(&entries, i * 4)?;
            let candidate = self.read_key_node(cell_offset)?;
            if candidate.name.eq_ignore_ascii_case(name) {
                return Ok(cell_offset);
            }
        }

        Err(RegistryError::KeyNotFound { path: name.to_string() })
    }

    /// Dispatch to the correct list reader given a list offset (used by ri sub-lists).
    fn find_subkey_in_list(&mut self, list_offset: u32, name: &str) -> Result<u32, RegistryError> {
        let abs = HIVE_HEADER_SIZE + list_offset as u64 + 4;
        let sig_buf = read_bytes_at(&mut self.reader, abs, 2)?;
        match &sig_buf[0..2] {
            b"lf" | b"lh" => self.read_lf_lh_list(list_offset, name),
            b"li" => self.read_li_list(list_offset, name),
            other => Err(RegistryError::Parse(abyss_cstruct::ParseError::InvalidField {
                field: "subkey_list_signature",
                detail: format!("unknown nested list type {:?}", other),
            })),
        }
    }
}
