/// A discovered partition on a disk.
#[derive(Debug, Clone)]
pub struct Partition {
    pub index: usize,
    pub offset: u64,
    pub size: u64,
    pub partition_type: String,
    pub type_name: String,
    pub label: Option<String>,
    pub scheme: PartitionScheme,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionScheme {
    Gpt,
    Mbr,
}
