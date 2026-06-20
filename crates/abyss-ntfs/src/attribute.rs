//! NTFS attribute header parsing.
//!
//! Handles both resident and non-resident attribute headers as defined by the NTFS spec.

use abyss_cstruct::read::{read_u16_le, read_u32_le, read_u64_le, FromBytes};
use abyss_cstruct::ParseError;

/// Known NTFS attribute types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributeType {
    StandardInformation,
    AttributeList,
    FileName,
    ObjectId,
    SecurityDescriptor,
    VolumeName,
    VolumeInformation,
    Data,
    IndexRoot,
    IndexAllocation,
    Bitmap,
    ReparsePoint,
    EaInformation,
    Ea,
    LoggedUtilityStream,
    Unknown(u32),
}

impl AttributeType {
    pub fn from_u32(v: u32) -> Self {
        match v {
            0x10 => AttributeType::StandardInformation,
            0x20 => AttributeType::AttributeList,
            0x30 => AttributeType::FileName,
            0x40 => AttributeType::ObjectId,
            0x50 => AttributeType::SecurityDescriptor,
            0x60 => AttributeType::VolumeName,
            0x70 => AttributeType::VolumeInformation,
            0x80 => AttributeType::Data,
            0x90 => AttributeType::IndexRoot,
            0xA0 => AttributeType::IndexAllocation,
            0xB0 => AttributeType::Bitmap,
            0xC0 => AttributeType::ReparsePoint,
            0xD0 => AttributeType::EaInformation,
            0xE0 => AttributeType::Ea,
            0x100 => AttributeType::LoggedUtilityStream,
            other => AttributeType::Unknown(other),
        }
    }
}

/// Parsed NTFS attribute header (resident or non-resident).
#[derive(Debug, Clone)]
pub struct AttributeHeader {
    /// Attribute type code.
    pub attr_type: AttributeType,
    /// Total length of this attribute record in bytes (header + value).
    pub length: u32,
    /// Whether this attribute is non-resident.
    pub non_resident: bool,
    /// Length of the name, in UTF-16 code units (0 = no name).
    pub name_length: u8,
    /// Offset of the name from the start of the attribute.
    pub name_offset: u16,
    /// Attribute flags.
    pub flags: u16,
    /// Attribute instance identifier.
    pub instance: u16,

    // Resident-only fields:
    /// Length of the value (resident only).
    pub value_length: Option<u32>,
    /// Offset of the value from attribute start (resident only).
    pub value_offset: Option<u16>,

    // Non-resident-only fields:
    /// Starting VCN of the data runs (non-resident only).
    pub start_vcn: Option<u64>,
    /// Last VCN of the data runs (non-resident only).
    pub last_vcn: Option<u64>,
    /// Offset to the data runs (non-resident only).
    pub data_runs_offset: Option<u16>,
    /// Allocated size in bytes (non-resident only).
    pub allocated_size: Option<u64>,
    /// Actual data size in bytes (non-resident only).
    pub data_size: Option<u64>,
}

impl AttributeHeader {
    /// Parse an attribute header from `buf` at `offset`.
    ///
    /// Returns `None` if `offset` is past the end of `buf` or the type is the
    /// end-of-attributes marker (0xFFFFFFFF).
    pub fn from_bytes_at(buf: &[u8], offset: usize) -> Result<Option<Self>, ParseError> {
        if offset + 4 > buf.len() {
            return Ok(None);
        }

        let type_raw = read_u32_le(buf, offset)?;

        // End-of-attributes marker.
        if type_raw == 0xFFFF_FFFF {
            return Ok(None);
        }

        // Need at least 16 bytes for the common header.
        if offset + 16 > buf.len() {
            return Err(ParseError::BufferTooSmall {
                need: offset + 16,
                have: buf.len(),
            });
        }

        let attr_type = AttributeType::from_u32(type_raw);
        let length = read_u32_le(buf, offset + 4)?;
        let non_resident = buf[offset + 8] != 0;
        let name_length = buf[offset + 9];
        let name_offset = read_u16_le(buf, offset + 10)?;
        let flags = read_u16_le(buf, offset + 12)?;
        let instance = read_u16_le(buf, offset + 14)?;

        let (value_length, value_offset, start_vcn, last_vcn, data_runs_offset, allocated_size, data_size);

        if !non_resident {
            // Resident: need 24 bytes total.
            if offset + 24 > buf.len() {
                return Err(ParseError::BufferTooSmall {
                    need: offset + 24,
                    have: buf.len(),
                });
            }
            value_length = Some(read_u32_le(buf, offset + 16)?);
            value_offset = Some(read_u16_le(buf, offset + 20)?);
            start_vcn = None;
            last_vcn = None;
            data_runs_offset = None;
            allocated_size = None;
            data_size = None;
        } else {
            // Non-resident: need 64 bytes total.
            if offset + 64 > buf.len() {
                return Err(ParseError::BufferTooSmall {
                    need: offset + 64,
                    have: buf.len(),
                });
            }
            value_length = None;
            value_offset = None;
            start_vcn = Some(read_u64_le(buf, offset + 16)?);
            last_vcn = Some(read_u64_le(buf, offset + 24)?);
            data_runs_offset = Some(read_u16_le(buf, offset + 32)?);
            allocated_size = Some(read_u64_le(buf, offset + 40)?);
            data_size = Some(read_u64_le(buf, offset + 48)?);
        }

        Ok(Some(AttributeHeader {
            attr_type,
            length,
            non_resident,
            name_length,
            name_offset,
            flags,
            instance,
            value_length,
            value_offset,
            start_vcn,
            last_vcn,
            data_runs_offset,
            allocated_size,
            data_size,
        }))
    }

    /// Return the resident value bytes from the full MFT record buffer, given
    /// the offset at which this attribute starts.
    pub fn resident_value<'a>(&self, record_buf: &'a [u8], attr_offset: usize) -> Option<&'a [u8]> {
        if self.non_resident {
            return None;
        }
        let val_len = self.value_length? as usize;
        let val_off = self.value_offset? as usize;
        let start = attr_offset + val_off;
        let end = start + val_len;
        if end > record_buf.len() {
            return None;
        }
        Some(&record_buf[start..end])
    }
}

impl FromBytes for AttributeHeader {
    fn from_bytes(buf: &[u8]) -> Result<Self, ParseError> {
        match Self::from_bytes_at(buf, 0)? {
            Some(h) => Ok(h),
            None => Err(ParseError::InvalidField {
                field: "attr_type",
                detail: "end-of-attributes marker or empty buffer".into(),
            }),
        }
    }
}
