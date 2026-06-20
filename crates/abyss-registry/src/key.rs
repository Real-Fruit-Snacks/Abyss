/// A parsed registry key node (nk cell).
#[derive(Debug, Clone)]
pub struct KeyNode {
    pub name: String,
    pub flags: u16,
    pub parent_offset: u32,
    pub num_subkeys: u32,
    pub subkeys_list_offset: u32,
    pub num_values: u32,
    pub values_list_offset: u32,
    /// The cell offset (relative to hive bins data) where this node lives.
    pub cell_offset: u32,
}

impl KeyNode {
    /// Returns true if this key is the root key (flags bit 0x0020 set).
    pub fn is_root(&self) -> bool {
        self.flags & 0x0020 != 0
    }
}
