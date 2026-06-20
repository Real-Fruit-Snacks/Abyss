use crate::ParseError;
use std::io::{Read, Seek, SeekFrom};

/// Trait for types that can be parsed from a byte buffer.
pub trait FromBytes: Sized {
    /// Parse from a byte slice. Returns the parsed value.
    fn from_bytes(buf: &[u8]) -> Result<Self, ParseError>;

    /// Size of this structure in bytes, if fixed.
    fn fixed_size() -> Option<usize> {
        None
    }
}

/// Trait for readable + seekable streams (disk images, file handles).
pub trait ReadSeek: Read + Seek + Send {}
impl<T: Read + Seek + Send> ReadSeek for T {}

/// Read exactly `n` bytes from a stream at the current position.
pub fn read_bytes<R: Read>(reader: &mut R, n: usize) -> Result<Vec<u8>, ParseError> {
    let mut buf = vec![0u8; n];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

/// Read exactly `n` bytes from a stream at a given offset.
pub fn read_bytes_at<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    n: usize,
) -> Result<Vec<u8>, ParseError> {
    reader.seek(SeekFrom::Start(offset))?;
    read_bytes(reader, n)
}

/// Read a little-endian u16 from a byte slice at an offset.
pub fn read_u16_le(buf: &[u8], offset: usize) -> Result<u16, ParseError> {
    if offset + 2 > buf.len() {
        return Err(ParseError::BufferTooSmall {
            need: offset + 2,
            have: buf.len(),
        });
    }
    Ok(u16::from_le_bytes([buf[offset], buf[offset + 1]]))
}

/// Read a little-endian u32 from a byte slice at an offset.
pub fn read_u32_le(buf: &[u8], offset: usize) -> Result<u32, ParseError> {
    if offset + 4 > buf.len() {
        return Err(ParseError::BufferTooSmall {
            need: offset + 4,
            have: buf.len(),
        });
    }
    Ok(u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ]))
}

/// Read a little-endian u64 from a byte slice at an offset.
pub fn read_u64_le(buf: &[u8], offset: usize) -> Result<u64, ParseError> {
    if offset + 8 > buf.len() {
        return Err(ParseError::BufferTooSmall {
            need: offset + 8,
            have: buf.len(),
        });
    }
    Ok(u64::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
        buf[offset + 4],
        buf[offset + 5],
        buf[offset + 6],
        buf[offset + 7],
    ]))
}

/// Read a UTF-16LE string from a byte slice.
pub fn read_utf16le(buf: &[u8], offset: usize, byte_len: usize) -> Result<String, ParseError> {
    if offset + byte_len > buf.len() {
        return Err(ParseError::BufferTooSmall {
            need: offset + byte_len,
            have: buf.len(),
        });
    }
    let slice = &buf[offset..offset + byte_len];
    let chars: Vec<u16> = slice
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&chars).map_err(|_| ParseError::InvalidField {
        field: "utf16le_string",
        detail: "invalid UTF-16LE sequence".into(),
    })
}
