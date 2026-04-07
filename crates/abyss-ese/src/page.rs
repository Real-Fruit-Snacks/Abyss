use abyss_cstruct::read::read_u32_le;
use abyss_cstruct::ParseError;

/// Flags indicating the page type.
#[derive(Debug, Clone, Copy)]
pub struct PageFlags(pub u32);

impl PageFlags {
    pub fn is_root(&self) -> bool { self.0 & 0x01 != 0 }
    pub fn is_leaf(&self) -> bool { self.0 & 0x02 != 0 }
    pub fn is_branch(&self) -> bool { self.0 & 0x04 != 0 }
    pub fn is_empty(&self) -> bool { self.0 & 0x08 != 0 }
    pub fn is_space_tree(&self) -> bool { self.0 & 0x20 != 0 }
    pub fn is_index(&self) -> bool { self.0 & 0x40 != 0 }
    pub fn is_long_value(&self) -> bool { self.0 & 0x80 != 0 }
}

/// A parsed page tag (pointer to data within a page).
#[derive(Debug, Clone)]
pub struct PageTag {
    pub offset: u16,
    pub size: u16,
    pub flags: u8,
}

/// Parsed ESE page header.
#[derive(Debug)]
pub struct PageHeader {
    pub page_flags: PageFlags,
}

pub const PAGE_HEADER_SIZE: usize = 40;

impl PageHeader {
    /// Parse page header from raw page bytes.
    pub fn from_page(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < PAGE_HEADER_SIZE {
            return Err(ParseError::BufferTooSmall { need: PAGE_HEADER_SIZE, have: buf.len() });
        }
        let flags = read_u32_le(buf, 32)?;
        Ok(Self { page_flags: PageFlags(flags) })
    }
}

/// Parse page tags from the end of a page.
/// Tags are stored backwards from the end of the page, each 4 bytes.
/// Tag 0 is at page_size - 4, tag 1 at page_size - 8, etc.
pub fn parse_page_tags(page_buf: &[u8], new_format: bool) -> Vec<PageTag> {
    let page_size = page_buf.len();
    if page_size < PAGE_HEADER_SIZE + 4 {
        return Vec::new();
    }

    let mut tags = Vec::new();
    let mut pos = page_size;

    loop {
        if pos < 4 {
            break;
        }
        pos -= 4;

        // Don't read into the page header
        if pos < PAGE_HEADER_SIZE {
            break;
        }

        let offset_raw = u16::from_le_bytes([page_buf[pos], page_buf[pos + 1]]);
        let size = u16::from_le_bytes([page_buf[pos + 2], page_buf[pos + 3]]);

        let (offset, flags) = if new_format {
            (offset_raw & 0x1FFF, (offset_raw >> 13) as u8)
        } else {
            (offset_raw, 0u8)
        };

        if tags.is_empty() {
            // Tag 0 (external header) — always include
            tags.push(PageTag { offset, size, flags });
        } else {
            // Subsequent tags: stop on all-zero entry
            if size == 0 && offset == 0 && flags == 0 {
                break;
            }
            // Stop if offset would place data before the header
            let data_start = PAGE_HEADER_SIZE as u16;
            if offset < data_start && size > 0 {
                break;
            }
            tags.push(PageTag { offset, size, flags });
        }
    }

    tags
}

/// Extract the data for a specific tag from a page buffer.
/// Tag offsets are relative to the end of the page header.
pub fn get_tag_data<'a>(page_buf: &'a [u8], tag: &PageTag) -> Option<&'a [u8]> {
    let start = PAGE_HEADER_SIZE + tag.offset as usize;
    let end = start + tag.size as usize;
    if end <= page_buf.len() {
        Some(&page_buf[start..end])
    } else {
        None
    }
}
