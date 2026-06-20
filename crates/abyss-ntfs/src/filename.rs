//! NTFS $FILE_NAME attribute parser.
//!
//! Parses the $FILE_NAME attribute (type 0x30) from a resident attribute value.

use abyss_cstruct::read::read_u64_le;
use abyss_cstruct::ParseError;

/// Parsed $FILE_NAME attribute.
#[derive(Debug, Clone)]
pub struct FileName {
    /// Lower 48 bits of the parent directory MFT reference.
    pub parent_ref: u64,
    /// File name namespace (0=POSIX, 1=Win32, 2=DOS, 3=Win32&DOS).
    pub namespace: u8,
    /// File name string.
    pub name: String,
}

impl FileName {
    /// Parse a $FILE_NAME attribute value from `data`.
    ///
    /// Layout:
    /// - Offset 0  (8 bytes): parent directory MFT reference (lower 48 bits used)
    /// - Offset 64 (1 byte):  name length in UTF-16 code units
    /// - Offset 65 (1 byte):  namespace
    /// - Offset 66 (variable): name as UTF-16LE
    pub fn from_bytes(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < 66 {
            return Err(ParseError::BufferTooSmall {
                need: 66,
                have: data.len(),
            });
        }

        let parent_ref_raw = read_u64_le(data, 0)?;
        // Mask to lower 48 bits to get the MFT record index.
        let parent_ref = parent_ref_raw & 0x0000_FFFF_FFFF_FFFF;

        let name_length = data[64] as usize; // in UTF-16 code units
        let namespace = data[65];

        let name_end = 66 + name_length * 2;
        if data.len() < name_end {
            return Err(ParseError::BufferTooSmall {
                need: name_end,
                have: data.len(),
            });
        }

        // Decode UTF-16LE name.
        let name_bytes = &data[66..name_end];
        let utf16_units: Vec<u16> = name_bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let name = String::from_utf16_lossy(&utf16_units).to_string();

        Ok(FileName {
            parent_ref,
            namespace,
            name,
        })
    }

    /// Returns `true` if this is a Win32 or Win32&DOS name (namespace 1 or 3).
    ///
    /// These are the primary names used by Windows for file lookup.
    pub fn is_win32_name(&self) -> bool {
        self.namespace == 1 || self.namespace == 3
    }
}
