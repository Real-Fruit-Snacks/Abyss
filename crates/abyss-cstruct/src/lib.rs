use thiserror::Error;
use std::io::{Read, Seek, SeekFrom};

/// Error type for binary structure parsing.
#[derive(Debug, Error)]
pub enum ParseError {
    #[error("I/O error at offset {offset:#x}: {source}")]
    Io {
        offset: u64,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid magic/signature at offset {offset:#x}: expected {expected:?}, got {got:?}")]
    BadMagic {
        offset: u64,
        expected: Vec<u8>,
        got: Vec<u8>,
    },
    #[error("invalid UTF-16LE string at offset {offset:#x}: {reason}")]
    InvalidString { offset: u64, reason: String },
    #[error("truncated structure at offset {offset:#x}: need {needed} bytes, have {available}")]
    Truncated {
        offset: u64,
        needed: usize,
        available: usize,
    },
    #[error("value out of range at offset {offset:#x}: {detail}")]
    OutOfRange { offset: u64, detail: String },
}

/// Trait for types that can seek and read — the common bound used throughout the codebase.
pub trait ReadSeek: Read + Seek {}
impl<T: Read + Seek> ReadSeek for T {}

/// Trait for types that can be parsed from a byte stream.
pub trait FromBytes: Sized {
    fn from_bytes<R: ReadSeek>(reader: &mut R) -> Result<Self, ParseError>;
}

// ── Primitive readers ─────────────────────────────────────────────────────────

/// Read a little-endian u16 from the current stream position.
pub fn read_u16_le<R: ReadSeek>(reader: &mut R) -> Result<u16, ParseError> {
    let offset = current_pos(reader);
    let mut buf = [0u8; 2];
    reader.read_exact(&mut buf).map_err(|e| ParseError::Io { offset, source: e })?;
    Ok(u16::from_le_bytes(buf))
}

/// Read a little-endian u32 from the current stream position.
pub fn read_u32_le<R: ReadSeek>(reader: &mut R) -> Result<u32, ParseError> {
    let offset = current_pos(reader);
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf).map_err(|e| ParseError::Io { offset, source: e })?;
    Ok(u32::from_le_bytes(buf))
}

/// Read a little-endian u64 from the current stream position.
pub fn read_u64_le<R: ReadSeek>(reader: &mut R) -> Result<u64, ParseError> {
    let offset = current_pos(reader);
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf).map_err(|e| ParseError::Io { offset, source: e })?;
    Ok(u64::from_le_bytes(buf))
}

/// Read exactly `len` bytes from the current stream position.
pub fn read_bytes<R: ReadSeek>(reader: &mut R, len: usize) -> Result<Vec<u8>, ParseError> {
    let offset = current_pos(reader);
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).map_err(|e| ParseError::Io { offset, source: e })?;
    Ok(buf)
}

/// Seek to `offset`, read exactly `len` bytes, then return to the original position.
pub fn read_bytes_at<R: ReadSeek>(reader: &mut R, offset: u64, len: usize) -> Result<Vec<u8>, ParseError> {
    let saved = current_pos(reader);
    reader.seek(SeekFrom::Start(offset)).map_err(|e| ParseError::Io { offset, source: e })?;
    let data = read_bytes(reader, len)?;
    reader.seek(SeekFrom::Start(saved)).map_err(|e| ParseError::Io { offset: saved, source: e })?;
    Ok(data)
}

/// Read a null-terminated UTF-16LE string of at most `max_chars` code units.
/// Stops at the first null (0x0000) word or after `max_chars` characters.
pub fn read_utf16le<R: ReadSeek>(reader: &mut R, max_chars: usize) -> Result<String, ParseError> {
    let offset = current_pos(reader);
    let mut units = Vec::with_capacity(max_chars);
    for _ in 0..max_chars {
        let u = read_u16_le(reader)?;
        if u == 0 {
            break;
        }
        units.push(u);
    }
    String::from_utf16(&units).map_err(|_| ParseError::InvalidString {
        offset,
        reason: "invalid UTF-16LE sequence".into(),
    })
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn current_pos<R: ReadSeek>(reader: &mut R) -> u64 {
    reader.seek(SeekFrom::Current(0)).unwrap_or(0)
}
