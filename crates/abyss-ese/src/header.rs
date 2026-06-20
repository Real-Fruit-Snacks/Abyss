use abyss_cstruct::read::{FromBytes, read_u32_le};
use abyss_cstruct::ParseError;

const ESE_MAGIC: u32 = 0x89ABCDEF;

/// ESE database file header (parsed from page 0).
#[derive(Debug)]
pub struct EseHeader {
    pub checksum: u32,
    pub magic: u32,
    pub format_version: u32,
    pub file_type: u32,
    pub db_state: u32,
    pub page_size: u32,
}

impl FromBytes for EseHeader {
    fn from_bytes(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < 668 {
            return Err(ParseError::BufferTooSmall { need: 668, have: buf.len() });
        }
        let checksum = read_u32_le(buf, 0)?;
        let magic = read_u32_le(buf, 4)?;
        if magic != ESE_MAGIC {
            return Err(ParseError::InvalidMagic {
                expected: ESE_MAGIC as u64,
                got: magic as u64,
            });
        }
        let format_version = read_u32_le(buf, 8)?;
        let file_type = read_u32_le(buf, 12)?;
        let db_state = read_u32_le(buf, 52)?;
        let page_size = read_u32_le(buf, 236)?;

        // Validate page size is a power of 2 and reasonable
        if page_size < 4096 || page_size > 32768 || (page_size & (page_size - 1)) != 0 {
            return Err(ParseError::InvalidField {
                field: "page_size",
                detail: format!("invalid ESE page size: {}", page_size),
            });
        }

        Ok(Self { checksum, magic, format_version, file_type, db_state, page_size })
    }
}
