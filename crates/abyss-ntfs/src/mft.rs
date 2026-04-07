//! NTFS MFT record parser.
//!
//! Parses FILE records from the Master File Table and iterates their attributes.

use abyss_cstruct::read::{read_u16_le, read_u32_le, read_u64_le, FromBytes};
use abyss_cstruct::ParseError;

use crate::attribute::AttributeHeader;

/// Magic bytes for a valid MFT record.
const MFT_MAGIC: &[u8; 4] = b"FILE";

/// MFT record flags.
pub const MFT_FLAG_IN_USE: u16 = 0x0001;
pub const MFT_FLAG_DIRECTORY: u16 = 0x0002;

/// Parsed NTFS MFT record header.
#[derive(Debug, Clone)]
pub struct MftRecord {
    /// Offset to the update sequence array.
    pub update_seq_offset: u16,
    /// Size of the update sequence array (in u16 entries).
    pub update_seq_count: u16,
    /// Log file sequence number.
    pub logfile_seq_number: u64,
    /// Sequence number of this record.
    pub sequence_number: u16,
    /// Hard link count.
    pub hard_link_count: u16,
    /// Offset of the first attribute from the start of the record.
    pub first_attribute_offset: u16,
    /// Record flags (in-use, directory, etc.).
    pub flags: u16,
    /// Number of bytes used in this record.
    pub used_size: u32,
    /// Total allocated size of this record.
    pub allocated_size: u32,
    /// File reference to the base record (0 for base records).
    pub base_record_ref: u64,
}

impl MftRecord {
    /// Returns true if this record is in use (not deleted).
    pub fn is_in_use(&self) -> bool {
        self.flags & MFT_FLAG_IN_USE != 0
    }

    /// Returns true if this record represents a directory.
    pub fn is_directory(&self) -> bool {
        self.flags & MFT_FLAG_DIRECTORY != 0
    }

    /// Returns an iterator over the attributes in this record.
    ///
    /// `record_buf` must be the full raw bytes of this MFT record.
    pub fn attributes<'a>(&self, record_buf: &'a [u8]) -> AttributeIterator<'a> {
        AttributeIterator {
            buf: record_buf,
            offset: self.first_attribute_offset as usize,
        }
    }
}

impl FromBytes for MftRecord {
    fn from_bytes(buf: &[u8]) -> Result<Self, ParseError> {
        // Need at least 48 bytes for the standard MFT record header.
        if buf.len() < 48 {
            return Err(ParseError::BufferTooSmall {
                need: 48,
                have: buf.len(),
            });
        }

        // Validate magic.
        if &buf[0..4] != MFT_MAGIC {
            return Err(ParseError::InvalidField {
                field: "magic",
                detail: format!("expected \"FILE\", got {:?}", &buf[0..4]),
            });
        }

        let update_seq_offset = read_u16_le(buf, 4)?;
        let update_seq_count = read_u16_le(buf, 6)?;
        let logfile_seq_number = read_u64_le(buf, 8)?;
        let sequence_number = read_u16_le(buf, 16)?;
        let hard_link_count = read_u16_le(buf, 18)?;
        let first_attribute_offset = read_u16_le(buf, 20)?;
        let flags = read_u16_le(buf, 22)?;
        let used_size = read_u32_le(buf, 24)?;
        let allocated_size = read_u32_le(buf, 28)?;
        let base_record_ref = read_u64_le(buf, 32)?;

        Ok(MftRecord {
            update_seq_offset,
            update_seq_count,
            logfile_seq_number,
            sequence_number,
            hard_link_count,
            first_attribute_offset,
            flags,
            used_size,
            allocated_size,
            base_record_ref,
        })
    }

    fn fixed_size() -> Option<usize> {
        Some(1024)
    }
}

/// Iterator over NTFS attributes in an MFT record buffer.
pub struct AttributeIterator<'a> {
    buf: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for AttributeIterator<'a> {
    type Item = (usize, AttributeHeader);

    fn next(&mut self) -> Option<Self::Item> {
        // Guard: need at least 4 bytes to read the type tag.
        if self.offset + 4 > self.buf.len() {
            return None;
        }

        match AttributeHeader::from_bytes_at(self.buf, self.offset) {
            Ok(Some(header)) => {
                let attr_offset = self.offset;
                // Advance by the attribute's declared length; guard against zero-length loops.
                let step = if header.length > 0 { header.length as usize } else { 8 };
                self.offset += step;
                Some((attr_offset, header))
            }
            _ => None,
        }
    }
}
