//! Ext2/3/4 superblock parser.
//!
//! The superblock lives at byte offset 1024 from the start of the filesystem
//! and is 1024 bytes long.

use abyss_cstruct::read::{read_u16_le, read_u32_le, FromBytes};
use abyss_cstruct::ParseError;

/// Magic number identifying an ext filesystem.
pub const EXT_MAGIC: u16 = 0xEF53;

/// Incompatible feature: 64-bit block numbers.
pub const INCOMPAT_64BIT: u32 = 0x0080;
/// Incompatible feature: extent tree instead of block map.
pub const INCOMPAT_EXTENTS: u32 = 0x0040;
/// Incompatible feature: flexible block groups.
pub const INCOMPAT_FLEX_BG: u32 = 0x0200;

/// Byte offset of the superblock from the start of the filesystem.
pub const SUPERBLOCK_OFFSET: u64 = 1024;
/// Size of the superblock in bytes.
pub const SUPERBLOCK_SIZE: usize = 1024;

/// Parsed ext2/3/4 superblock.
#[derive(Debug, Clone)]
pub struct Superblock {
    /// Total inode count.
    pub s_inodes_count: u32,
    /// Total block count (low 32 bits).
    pub s_blocks_count_lo: u32,
    /// Free block count (low 32 bits).
    pub s_free_blocks_count_lo: u32,
    /// Free inode count.
    pub s_free_inodes_count: u32,
    /// Log2(block_size) - 10.  Actual block size = 1024 << s_log_block_size.
    pub s_log_block_size: u32,
    /// Log2(fragment_size) - 10.
    pub s_log_frag_size: u32,
    /// Blocks per block group.
    pub s_blocks_per_group: u32,
    /// Inodes per block group.
    pub s_inodes_per_group: u32,
    /// Mount time (Unix epoch).
    pub s_mtime: u32,
    /// Write time (Unix epoch).
    pub s_wtime: u32,
    /// Filesystem magic number (0xEF53).
    pub magic: u16,
    /// Filesystem state.
    pub s_state: u16,
    /// Behaviour on error.
    pub s_errors: u16,
    /// Revision level.
    pub s_rev_level: u32,
    /// First non-reserved inode (usually 11 for rev >= 1, 11 hardcoded for rev 0).
    pub s_first_ino: u32,
    /// Inode size in bytes (128 for ext2 rev 0, 256+ for ext4).
    pub s_inode_size: u16,
    /// Compatible feature set.
    pub s_feature_compat: u32,
    /// Incompatible feature set.
    pub s_feature_incompat: u32,
    /// Read-only compatible feature set.
    pub s_feature_ro_compat: u32,
    /// Total block count (high 32 bits, only valid when INCOMPAT_64BIT is set).
    pub s_blocks_count_hi: u32,
    /// Block group descriptor size (32 for ext2/3, 64 for ext4 with 64-bit).
    pub s_desc_size: u16,
}

impl FromBytes for Superblock {
    fn from_bytes(buf: &[u8]) -> Result<Self, ParseError> {
        // We need at least 340 bytes to cover s_blocks_count_hi at offset 336.
        if buf.len() < 340 {
            return Err(ParseError::BufferTooSmall {
                need: 340,
                have: buf.len(),
            });
        }

        let magic = read_u16_le(buf, 56)?;
        if magic != EXT_MAGIC {
            return Err(ParseError::InvalidField {
                field: "magic",
                detail: format!("expected 0xEF53, got {:#06x}", magic),
            });
        }

        let s_rev_level = read_u32_le(buf, 76)?;
        // For revision 0 filesystems, inode size and first inode are fixed.
        let s_inode_size = if s_rev_level >= 1 {
            read_u16_le(buf, 88)?
        } else {
            128
        };
        let s_first_ino = if s_rev_level >= 1 {
            read_u32_le(buf, 84)?
        } else {
            11
        };

        // s_desc_size at offset 254 only meaningful for ext4; default to 32.
        let s_desc_size = if buf.len() >= 256 {
            read_u16_le(buf, 254)?
        } else {
            32
        };

        Ok(Superblock {
            s_inodes_count: read_u32_le(buf, 0)?,
            s_blocks_count_lo: read_u32_le(buf, 4)?,
            s_free_blocks_count_lo: read_u32_le(buf, 12)?,
            s_free_inodes_count: read_u32_le(buf, 16)?,
            s_log_block_size: read_u32_le(buf, 24)?,
            s_log_frag_size: read_u32_le(buf, 28)?,
            s_blocks_per_group: read_u32_le(buf, 32)?,
            s_inodes_per_group: read_u32_le(buf, 40)?,
            s_mtime: read_u32_le(buf, 44)?,
            s_wtime: read_u32_le(buf, 48)?,
            magic,
            s_state: read_u16_le(buf, 58)?,
            s_errors: read_u16_le(buf, 60)?,
            s_rev_level,
            s_first_ino,
            s_inode_size,
            s_feature_compat: read_u32_le(buf, 96)?,
            s_feature_incompat: read_u32_le(buf, 100)?,
            s_feature_ro_compat: read_u32_le(buf, 104)?,
            s_blocks_count_hi: read_u32_le(buf, 336)?,
            s_desc_size,
        })
    }

    fn fixed_size() -> Option<usize> {
        Some(SUPERBLOCK_SIZE)
    }
}

impl Superblock {
    /// Actual block size in bytes: 1024 << s_log_block_size.
    pub fn block_size(&self) -> u64 {
        1024u64 << self.s_log_block_size
    }

    /// Returns `true` if the filesystem uses 64-bit block numbers.
    pub fn has_64bit(&self) -> bool {
        self.s_feature_incompat & INCOMPAT_64BIT != 0
    }

    /// Block group descriptor size: 64 if 64-bit mode, otherwise 32.
    pub fn desc_size(&self) -> u64 {
        if self.has_64bit() && self.s_desc_size >= 64 {
            self.s_desc_size as u64
        } else {
            32
        }
    }

    /// Total block count, combining the low and high 32-bit halves.
    pub fn total_blocks(&self) -> u64 {
        if self.has_64bit() {
            ((self.s_blocks_count_hi as u64) << 32) | self.s_blocks_count_lo as u64
        } else {
            self.s_blocks_count_lo as u64
        }
    }

    /// Number of block groups.
    pub fn block_group_count(&self) -> u64 {
        let total = self.total_blocks();
        let bpg = self.s_blocks_per_group as u64;
        if bpg == 0 {
            return 0;
        }
        (total + bpg - 1) / bpg
    }
}
