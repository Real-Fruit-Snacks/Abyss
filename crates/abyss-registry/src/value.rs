use crate::error::RegistryError;

/// Registry value data type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegType {
    None,
    Sz,
    ExpandSz,
    Binary,
    Dword,
    DwordBigEndian,
    Link,
    MultiSz,
    ResourceList,
    FullResourceDescriptor,
    ResourceRequirementsList,
    Qword,
    Unknown(u32),
}

impl From<u32> for RegType {
    fn from(v: u32) -> Self {
        match v {
            0 => RegType::None,
            1 => RegType::Sz,
            2 => RegType::ExpandSz,
            3 => RegType::Binary,
            4 => RegType::Dword,
            5 => RegType::DwordBigEndian,
            6 => RegType::Link,
            7 => RegType::MultiSz,
            8 => RegType::ResourceList,
            9 => RegType::FullResourceDescriptor,
            10 => RegType::ResourceRequirementsList,
            11 => RegType::Qword,
            other => RegType::Unknown(other),
        }
    }
}

/// A parsed registry value.
#[derive(Debug, Clone)]
pub struct RegValue {
    pub name: String,
    pub reg_type: RegType,
    pub data: Vec<u8>,
}

impl RegValue {
    /// Decode value as a UTF-16LE string (REG_SZ / REG_EXPAND_SZ).
    pub fn as_string(&self) -> Result<String, RegistryError> {
        if self.data.len() % 2 != 0 {
            return Err(RegistryError::Parse(
                abyss_cstruct::ParseError::InvalidField {
                    field: "RegValue::as_string",
                    detail: "data length is not a multiple of 2".into(),
                },
            ));
        }
        let chars: Vec<u16> = self
            .data
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        // Strip trailing NUL if present.
        let chars: Vec<u16> = chars
            .into_iter()
            .take_while(|&c| c != 0)
            .collect();
        String::from_utf16(&chars).map_err(|_| {
            RegistryError::Parse(abyss_cstruct::ParseError::InvalidField {
                field: "RegValue::as_string",
                detail: "invalid UTF-16LE sequence".into(),
            })
        })
    }

    /// Decode value as a little-endian u32 (REG_DWORD).
    pub fn as_u32(&self) -> Result<u32, RegistryError> {
        if self.data.len() < 4 {
            return Err(RegistryError::Parse(
                abyss_cstruct::ParseError::BufferTooSmall {
                    need: 4,
                    have: self.data.len(),
                },
            ));
        }
        Ok(u32::from_le_bytes([
            self.data[0],
            self.data[1],
            self.data[2],
            self.data[3],
        ]))
    }

    /// Decode value as a little-endian u64 (REG_QWORD).
    pub fn as_u64(&self) -> Result<u64, RegistryError> {
        if self.data.len() < 8 {
            return Err(RegistryError::Parse(
                abyss_cstruct::ParseError::BufferTooSmall {
                    need: 8,
                    have: self.data.len(),
                },
            ));
        }
        Ok(u64::from_le_bytes([
            self.data[0],
            self.data[1],
            self.data[2],
            self.data[3],
            self.data[4],
            self.data[5],
            self.data[6],
            self.data[7],
        ]))
    }
}
