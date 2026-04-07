//! Ext2/3/4 block group descriptor parser.
//!
//! Block group descriptors immediately follow the superblock (at block 1 on
//! 1 KiB-block filesystems, or in the first block on larger block sizes).
//! Each descriptor is 32 bytes for ext2/3 and up to 64 bytes for ext4.

use abyss_cstruct::read::{read_u16_le, read_u32_le, FromBytes};
use abyss_cstruct::ParseError;

/// Parsed block group descriptor.
///
/// Only the fields needed for inode-table location and free-space accounting
/// are stored here.  The 32-byte form covers ext2/3; the 64-byte form covers
/// ext4 with INCOMPAT_64BIT.
#[derive(Debug, Clone)]
pub struct BlockGroupDescriptor {
    /// Low 32 bits of the inode table starting block.
    pub bg_inode_table_lo: u32,
    /// High 32 bits of the inode table starting block (only in 64-byte form).
    pub bg_inode_table_hi: u32,
    /// Free block count (low 16 bits).
    pub bg_free_blocks_count_lo: u16,
    /// Free inode count (low 16 bits).
    pub bg_free_inodes_count_lo: u16,
}

impl FromBytes for BlockGroupDescriptor {
    fn from_bytes(buf: &[u8]) -> Result<Self, ParseError> {
        // Minimum 32-byte descriptor.
        if buf.len() < 32 {
            return Err(ParseError::BufferTooSmall {
                need: 32,
                have: buf.len(),
            });
        }

        // bg_inode_table_lo is at offset 8 in the descriptor.
        let bg_inode_table_lo = read_u32_le(buf, 8)?;
        let bg_free_blocks_count_lo = read_u16_le(buf, 12)?;
        let bg_free_inodes_count_lo = read_u16_le(buf, 14)?;

        // bg_inode_table_hi is at offset 40 in the 64-byte form.
        let bg_inode_table_hi = if buf.len() >= 44 {
            read_u32_le(buf, 40)?
        } else {
            0
        };

        Ok(BlockGroupDescriptor {
            bg_inode_table_lo,
            bg_inode_table_hi,
            bg_free_blocks_count_lo,
            bg_free_inodes_count_lo,
        })
    }
}

impl BlockGroupDescriptor {
    /// Starting block number of the inode table for this block group.
    ///
    /// Pass `is_64bit = true` when the filesystem has `INCOMPAT_64BIT` set so
    /// that the high 32 bits are included.
    pub fn inode_table(&self, is_64bit: bool) -> u64 {
        if is_64bit {
            ((self.bg_inode_table_hi as u64) << 32) | self.bg_inode_table_lo as u64
        } else {
            self.bg_inode_table_lo as u64
        }
    }
}
