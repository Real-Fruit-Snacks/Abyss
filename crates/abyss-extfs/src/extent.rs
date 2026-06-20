//! Ext4 extent tree parser.
//!
//! The 60-byte `i_block` field of an inode holds the root node of the extent
//! tree when `EXT4_EXTENTS_FL` is set.  Inner nodes contain `ExtentIndex`
//! entries that point to child blocks; leaf nodes contain `ExtentEntry`
//! records that map logical block ranges to physical block ranges.

use abyss_cstruct::read::{read_u16_le, read_u32_le, FromBytes};
use abyss_cstruct::ParseError;

/// Magic number at the start of every extent tree node.
pub const EXTENT_MAGIC: u16 = 0xF30A;

/// Header that starts every extent tree node (12 bytes).
#[derive(Debug, Clone)]
pub struct ExtentHeader {
    /// Magic value (must be EXTENT_MAGIC = 0xF30A).
    pub eh_magic: u16,
    /// Number of valid entries following the header.
    pub eh_entries: u16,
    /// Maximum number of entries that could follow the header.
    pub eh_max: u16,
    /// Depth of this node.  0 = leaf (entries are ExtentEntry), >0 = inner
    /// (entries are ExtentIndex).
    pub eh_depth: u16,
}

impl FromBytes for ExtentHeader {
    fn from_bytes(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < 12 {
            return Err(ParseError::BufferTooSmall {
                need: 12,
                have: buf.len(),
            });
        }

        let eh_magic = read_u16_le(buf, 0)?;
        if eh_magic != EXTENT_MAGIC {
            return Err(ParseError::InvalidField {
                field: "eh_magic",
                detail: format!("expected 0xF30A, got {:#06x}", eh_magic),
            });
        }

        Ok(ExtentHeader {
            eh_magic,
            eh_entries: read_u16_le(buf, 2)?,
            eh_max: read_u16_le(buf, 4)?,
            eh_depth: read_u16_le(buf, 6)?,
        })
    }

    fn fixed_size() -> Option<usize> {
        Some(12)
    }
}

/// Leaf-node entry in an extent tree (12 bytes).
///
/// Maps a range of logical file blocks to a contiguous range of physical
/// blocks on disk.
#[derive(Debug, Clone)]
pub struct ExtentEntry {
    /// First logical block covered by this extent.
    pub ee_block: u32,
    /// Number of blocks in the extent.  If the high bit is set the extent is
    /// uninitialized (pre-allocated but not yet written).
    pub ee_len: u16,
    /// High 16 bits of the starting physical block.
    pub ee_start_hi: u16,
    /// Low 32 bits of the starting physical block.
    pub ee_start_lo: u32,
}

impl FromBytes for ExtentEntry {
    fn from_bytes(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < 12 {
            return Err(ParseError::BufferTooSmall {
                need: 12,
                have: buf.len(),
            });
        }
        Ok(ExtentEntry {
            ee_block: read_u32_le(buf, 0)?,
            ee_len: read_u16_le(buf, 4)?,
            ee_start_hi: read_u16_le(buf, 6)?,
            ee_start_lo: read_u32_le(buf, 8)?,
        })
    }

    fn fixed_size() -> Option<usize> {
        Some(12)
    }
}

impl ExtentEntry {
    /// Absolute physical block number of the first block in this extent.
    pub fn physical_block(&self) -> u64 {
        ((self.ee_start_hi as u64) << 32) | self.ee_start_lo as u64
    }

    /// Actual (initialized) length of the extent in blocks.
    ///
    /// If `ee_len > 32768` the extent is uninitialized; the real length is
    /// `ee_len - 32768`.
    pub fn block_count(&self) -> u16 {
        if self.ee_len > 0x8000 {
            self.ee_len - 0x8000
        } else {
            self.ee_len
        }
    }
}

/// Inner-node entry in an extent tree (12 bytes).
///
/// Points to a child node block that covers logical blocks starting at
/// `ei_block`.
#[derive(Debug, Clone)]
pub struct ExtentIndex {
    /// First logical block covered by the child node.
    pub ei_block: u32,
    /// Low 32 bits of the child node's physical block number.
    pub ei_leaf_lo: u32,
    /// High 16 bits of the child node's physical block number.
    pub ei_leaf_hi: u16,
}

impl FromBytes for ExtentIndex {
    fn from_bytes(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < 12 {
            return Err(ParseError::BufferTooSmall {
                need: 12,
                have: buf.len(),
            });
        }
        Ok(ExtentIndex {
            ei_block: read_u32_le(buf, 0)?,
            ei_leaf_lo: read_u32_le(buf, 4)?,
            ei_leaf_hi: read_u16_le(buf, 8)?,
        })
    }

    fn fixed_size() -> Option<usize> {
        Some(12)
    }
}

impl ExtentIndex {
    /// Physical block number of the child extent tree node.
    pub fn child_block(&self) -> u64 {
        ((self.ei_leaf_hi as u64) << 32) | self.ei_leaf_lo as u64
    }
}
