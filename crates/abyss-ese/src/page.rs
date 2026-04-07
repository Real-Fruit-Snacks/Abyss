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
///
/// The header is 40 bytes for standard pages. ESE databases with
/// format version >= 0x620 and file format revision >= 0x11 use an
/// 8-byte checksum at the start; older formats use 4-byte checksums
/// (possibly with a 4-byte ECC or page number). In all cases the
/// common fields are parsed relative to the 40-byte layout used by
/// gosecretsdump/impacket: page flags are always a u32 at offset 36.
#[derive(Debug)]
pub struct PageHeader {
    pub page_flags: PageFlags,
    /// Number of tags (entries) on this page (`FirstAvailablePageTag`).
    pub first_available_page_tag: u16,
    /// Next page number in the linked-list chain (0 if none).
    pub next_page_number: u32,
}

/// Standard page header size (always 40 bytes for all practical ESE databases).
pub const PAGE_HEADER_SIZE: usize = 40;

/// Tag flag: the common key prefix is present in this tag's data.
pub const TAG_COMMON: u8 = 0x4;

impl PageHeader {
    /// Parse page header from raw page bytes.
    ///
    /// Layout (after the 8-byte checksum for format >= 0x620 rev >= 0x11):
    ///   offset  8: LastModificationTime (u64)
    ///   offset 16: PreviousPageNumber (u32)
    ///   offset 20: NextPageNumber (u32)
    ///   offset 24: FatherDataPage (u32)
    ///   offset 28: AvailableDataSize (u16)
    ///   offset 30: AvailableUncommittedDataSize (u16)
    ///   offset 32: FirstAvailableDataOffset (u16)
    ///   offset 34: FirstAvailablePageTag (u16)
    ///   offset 36: PageFlags (u32)
    pub fn from_page(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < PAGE_HEADER_SIZE {
            return Err(ParseError::BufferTooSmall { need: PAGE_HEADER_SIZE, have: buf.len() });
        }
        let next_page_number = u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]);
        let first_available_page_tag = u16::from_le_bytes([buf[34], buf[35]]);
        let flags = u32::from_le_bytes([buf[36], buf[37], buf[38], buf[39]]);
        Ok(Self {
            page_flags: PageFlags(flags),
            first_available_page_tag,
            next_page_number,
        })
    }
}

/// Parse page tags from the end of a page, using `FirstAvailablePageTag` as the tag count.
///
/// Tags are stored backwards from the end of the page, each 4 bytes.
/// Tag 0 is at `page_size - 4`, tag 1 at `page_size - 8`, etc.
///
/// Tag layout: `[valueSize:u16 LE][offsetAndFlags:u16 LE]`
/// - `valueSize & 0x1FFF` = actual data size
/// - `offsetAndFlags & 0x1FFF` = offset within data area (relative to header end)
/// - `(offsetAndFlags >> 13) & 0x7` = per-tag flags (only in new-format databases)
pub fn parse_page_tags(page_buf: &[u8], tag_count: u16, new_format: bool) -> Vec<PageTag> {
    let page_size = page_buf.len();
    let mut tags = Vec::with_capacity(tag_count as usize);

    for i in 0..tag_count as usize {
        let pos = page_size.checked_sub(4 * (i + 1));
        let pos = match pos {
            Some(p) if p >= PAGE_HEADER_SIZE => p,
            _ => break,
        };

        let size_raw = u16::from_le_bytes([page_buf[pos], page_buf[pos + 1]]);
        let offset_raw = u16::from_le_bytes([page_buf[pos + 2], page_buf[pos + 3]]);

        // Both size and offset are masked with 0x1FFF.
        let size = size_raw & 0x1FFF;
        let offset = offset_raw & 0x1FFF;
        let flags = if new_format {
            ((offset_raw >> 13) & 0x7) as u8
        } else {
            0u8
        };

        tags.push(PageTag { offset, size, flags });
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

/// Parse a leaf entry's tag data to extract the record (EntryData).
///
/// In ESE, leaf tag data contains:
///   - If `TAG_COMMON` flag (0x4) is set: `CommonPageKeySize` (u16 LE) prefix
///   - `LocalPageKeySize` (u16 LE)
///   - `LocalPageKey` (N bytes, N = LocalPageKeySize)
///   - `EntryData` (remaining bytes = the actual record)
///
/// Returns the `EntryData` portion (the record data after key stripping).
pub fn strip_leaf_key(tag_data: &[u8], tag_flags: u8) -> Option<&[u8]> {
    let mut pos: usize = 0;

    // If TAG_COMMON flag set, skip 2-byte common key size
    if tag_flags & TAG_COMMON != 0 {
        if tag_data.len() < pos + 2 {
            return None;
        }
        pos += 2;
    }

    // Read local key size
    if tag_data.len() < pos + 2 {
        return None;
    }
    let local_key_size = u16::from_le_bytes([tag_data[pos], tag_data[pos + 1]]) as usize;
    pos += 2;

    // Skip local key bytes
    pos += local_key_size;
    if pos > tag_data.len() {
        return None;
    }

    Some(&tag_data[pos..])
}

/// Parse a branch entry's tag data to extract the child page number.
///
/// Branch entries have the same key prefix structure as leaf entries,
/// followed by a 4-byte child page number (u32 LE) instead of record data.
pub fn parse_branch_child(tag_data: &[u8], tag_flags: u8) -> Option<u32> {
    let mut pos: usize = 0;

    if tag_flags & TAG_COMMON != 0 {
        if tag_data.len() < pos + 2 {
            return None;
        }
        pos += 2;
    }

    if tag_data.len() < pos + 2 {
        return None;
    }
    let local_key_size = u16::from_le_bytes([tag_data[pos], tag_data[pos + 1]]) as usize;
    pos += 2;
    pos += local_key_size;

    if pos + 4 > tag_data.len() {
        return None;
    }
    let child = u32::from_le_bytes([
        tag_data[pos],
        tag_data[pos + 1],
        tag_data[pos + 2],
        tag_data[pos + 3],
    ]);
    Some(child)
}