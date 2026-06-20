//! Ext2/3/4 directory entry parser.
//!
//! Directory data is stored as a sequence of variable-length records.
//! Each record has a fixed 8-byte header followed by the entry name.
//! The `rec_len` field always pads to a 4-byte boundary and may include
//! unused space up to the next entry (or end of block).

use abyss_cstruct::read::{read_u16_le, read_u32_le};
use abyss_cstruct::ParseError;

/// File type byte in the directory entry (linear directory format).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExtFileType {
    Unknown = 0,
    RegularFile = 1,
    Directory = 2,
    CharDevice = 3,
    BlockDevice = 4,
    Fifo = 5,
    Socket = 6,
    Symlink = 7,
}

impl From<u8> for ExtFileType {
    fn from(v: u8) -> Self {
        match v {
            1 => ExtFileType::RegularFile,
            2 => ExtFileType::Directory,
            3 => ExtFileType::CharDevice,
            4 => ExtFileType::BlockDevice,
            5 => ExtFileType::Fifo,
            6 => ExtFileType::Socket,
            7 => ExtFileType::Symlink,
            _ => ExtFileType::Unknown,
        }
    }
}

/// A single parsed directory entry.
#[derive(Debug, Clone)]
pub struct ExtDirEntry {
    /// Inode number (0 means the entry is unused).
    pub inode: u32,
    /// Total length of this record, including the name and any padding.
    pub rec_len: u16,
    /// File type indicator.
    pub file_type: ExtFileType,
    /// Entry name (not NUL-terminated).
    pub name: String,
}

/// Parse all directory entries from a single directory block.
///
/// Walks the buffer using `rec_len` until the buffer is exhausted, collecting
/// entries whose inode number is non-zero (live entries).
pub fn parse_directory_block(buf: &[u8]) -> Result<Vec<ExtDirEntry>, ParseError> {
    let mut entries = Vec::new();
    let mut pos = 0usize;

    while pos < buf.len() {
        // Need at least the fixed 8-byte header.
        if pos + 8 > buf.len() {
            break;
        }

        let inode = read_u32_le(buf, pos)?;
        let rec_len = read_u16_le(buf, pos + 4)?;
        let name_len = buf[pos + 6] as usize;
        let file_type = ExtFileType::from(buf[pos + 7]);

        // rec_len of 0 would cause an infinite loop; treat as end.
        if rec_len == 0 {
            break;
        }

        // Only collect live entries.
        if inode != 0 && name_len > 0 {
            let name_start = pos + 8;
            let name_end = name_start + name_len;
            if name_end > buf.len() {
                return Err(ParseError::BufferTooSmall {
                    need: name_end,
                    have: buf.len(),
                });
            }
            let name = String::from_utf8_lossy(&buf[name_start..name_end]).into_owned();

            entries.push(ExtDirEntry {
                inode,
                rec_len,
                file_type,
                name,
            });
        }

        pos += rec_len as usize;
    }

    Ok(entries)
}
