use std::io::{Seek, SeekFrom};

use abyss_cstruct::read::{FromBytes, ReadSeek};
use abyss_cstruct::ParseError;
use crate::error::EseError;
use crate::header::EseHeader;
use crate::page::{PageHeader, PageTag, parse_page_tags, get_tag_data};

/// Read n bytes from reader at a given offset. Works with dyn trait objects.
fn read_at(reader: &mut dyn ReadSeek, offset: u64, n: usize) -> Result<Vec<u8>, ParseError> {
    reader.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; n];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

/// Handle to an open ESE database.
pub struct EseDatabase {
    reader: Box<dyn ReadSeek>,
    pub header: EseHeader,
    pub page_size: u32,
    /// Whether this database uses the "new" tag format (format_version >= 0x620).
    pub new_format: bool,
}

impl EseDatabase {
    /// Open and validate an ESE database.
    pub fn open(mut reader: Box<dyn ReadSeek>) -> Result<Self, EseError> {
        // Read the first 4096 bytes (minimum page size) for the header
        let header_buf = read_at(&mut *reader, 0, 4096)?;
        let header = EseHeader::from_bytes(&header_buf)?;
        let page_size = header.page_size;

        // Determine format based on version — 0x620 and above use new tag format
        let new_format = header.format_version >= 0x620;

        Ok(Self { reader, header, page_size, new_format })
    }

    /// Read a raw page by page number (1-based ESE page numbering).
    /// Page 1 is at file offset page_size (right after the header page).
    /// The formula is: file_offset = page_num * page_size
    pub fn read_page(&mut self, page_num: u32) -> Result<Vec<u8>, EseError> {
        if page_num == 0 {
            return Err(EseError::PageOutOfRange { page: 0 });
        }
        let offset = page_num as u64 * self.page_size as u64;
        let buf = read_at(&mut *self.reader, offset, self.page_size as usize)?;
        Ok(buf)
    }

    /// Parse a page header from raw page bytes.
    pub fn parse_page_header(&self, page_buf: &[u8]) -> Result<PageHeader, EseError> {
        Ok(PageHeader::from_page(page_buf)?)
    }

    /// Parse tags from a page.
    pub fn parse_page_tags(&self, page_buf: &[u8]) -> Vec<PageTag> {
        parse_page_tags(page_buf, self.new_format)
    }

    /// Get tag data from a page buffer.
    pub fn get_tag_data<'a>(&self, page_buf: &'a [u8], tag: &PageTag) -> Option<&'a [u8]> {
        get_tag_data(page_buf, tag)
    }

    /// Total number of pages in the database (approximate, based on file size).
    pub fn page_count(&mut self) -> Result<u32, EseError> {
        let file_size = self.reader.seek(SeekFrom::End(0))?;
        self.reader.seek(SeekFrom::Start(0))?;
        Ok((file_size / self.page_size as u64) as u32)
    }
}
