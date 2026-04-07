//! Ext2/3/4 inode parser.
//!
//! Inodes are 128 bytes on ext2 (revision 0) and 256 bytes on ext4.
//! The `i_block` field (60 bytes at offset 40) is either a traditional
//! block map or the root of an extent tree when EXT4_EXTENTS_FL is set.

use abyss_cstruct::read::{read_u16_le, read_u32_le, FromBytes};
use abyss_cstruct::ParseError;

/// File-type mask in i_mode.
pub const S_IFMT: u16 = 0xF000;
/// Regular file.
pub const S_IFREG: u16 = 0x8000;
/// Directory.
pub const S_IFDIR: u16 = 0x4000;
/// Symbolic link.
pub const S_IFLNK: u16 = 0xA000;

/// Inode flag: inode uses ext4 extent tree instead of block map.
pub const EXT4_EXTENTS_FL: u32 = 0x00080000;

/// Minimum inode size (ext2 revision 0).
pub const INODE_MIN_SIZE: usize = 128;

/// Parsed ext2/3/4 inode.
#[derive(Debug, Clone)]
pub struct Inode {
    /// File mode (type + permissions).
    pub i_mode: u16,
    /// Owner UID (low 16 bits).
    pub i_uid: u16,
    /// File size (low 32 bits).
    pub i_size_lo: u32,
    /// Last access time (Unix epoch).
    pub i_atime: u32,
    /// Inode change time (Unix epoch).
    pub i_ctime: u32,
    /// Last modification time (Unix epoch).
    pub i_mtime: u32,
    /// Owner GID (low 16 bits).
    pub i_gid: u16,
    /// Hard link count.
    pub i_links_count: u16,
    /// Block count (low 32 bits, in 512-byte units).
    pub i_blocks_lo: u32,
    /// Inode flags.
    pub i_flags: u32,
    /// Block map or extent tree root (60 bytes = 15 × u32).
    pub i_block: [u8; 60],
    /// File size (high 32 bits, for regular files in ext4).
    pub i_size_high: u32,
}

impl FromBytes for Inode {
    fn from_bytes(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < INODE_MIN_SIZE {
            return Err(ParseError::BufferTooSmall {
                need: INODE_MIN_SIZE,
                have: buf.len(),
            });
        }

        let mut i_block = [0u8; 60];
        i_block.copy_from_slice(&buf[40..100]);

        // i_size_high is at offset 108 (only valid for regular files in ext4).
        let i_size_high = if buf.len() >= 112 {
            read_u32_le(buf, 108)?
        } else {
            0
        };

        Ok(Inode {
            i_mode: read_u16_le(buf, 0)?,
            i_uid: read_u16_le(buf, 2)?,
            i_size_lo: read_u32_le(buf, 4)?,
            i_atime: read_u32_le(buf, 8)?,
            i_ctime: read_u32_le(buf, 12)?,
            i_mtime: read_u32_le(buf, 16)?,
            i_gid: read_u16_le(buf, 24)?,
            i_links_count: read_u16_le(buf, 26)?,
            i_blocks_lo: read_u32_le(buf, 28)?,
            i_flags: read_u32_le(buf, 32)?,
            i_block,
            i_size_high,
        })
    }

    fn fixed_size() -> Option<usize> {
        Some(INODE_MIN_SIZE)
    }
}

impl Inode {
    /// Returns `true` if this inode represents a directory.
    pub fn is_directory(&self) -> bool {
        self.i_mode & S_IFMT == S_IFDIR
    }

    /// Returns `true` if this inode represents a regular file.
    pub fn is_regular_file(&self) -> bool {
        self.i_mode & S_IFMT == S_IFREG
    }

    /// Returns `true` if this inode represents a symbolic link.
    pub fn is_symlink(&self) -> bool {
        self.i_mode & S_IFMT == S_IFLNK
    }

    /// Full 64-bit file size, combining the low and high 32-bit halves.
    pub fn size(&self) -> u64 {
        ((self.i_size_high as u64) << 32) | self.i_size_lo as u64
    }

    /// Returns `true` if this inode uses the ext4 extent tree.
    pub fn uses_extents(&self) -> bool {
        self.i_flags & EXT4_EXTENTS_FL != 0
    }
}
