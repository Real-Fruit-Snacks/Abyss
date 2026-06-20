//! Minidump (.dmp) file parser.
//!
//! Parses the MDMP format used by Windows for process/kernel dumps,
//! providing virtual address translation and memory region access.

use abyss_cstruct::read::{read_u16_le, read_u32_le, read_u64_le, read_utf16le, ReadSeek};
use log::debug;
use std::io::SeekFrom;

use crate::MemoryError;

/// Read exactly `n` bytes from a dyn ReadSeek at a given offset.
/// This avoids the Sized bound required by the generic `read_bytes_at`.
fn read_at(reader: &mut dyn ReadSeek, offset: u64, n: usize) -> Result<Vec<u8>, MemoryError> {
    reader.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; n];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

/// MDMP signature: "MDMP" in little-endian.
const MDMP_SIGNATURE: u32 = 0x504D_444D;

/// Minidump stream types.
const STREAM_MODULE_LIST: u32 = 4;
const STREAM_SYSTEM_INFO: u32 = 7;
const STREAM_MEMORY64_LIST: u32 = 9;

/// Processor architectures from MINIDUMP_SYSTEM_INFO.
const PROCESSOR_ARCHITECTURE_X86: u16 = 0;
const PROCESSOR_ARCHITECTURE_AMD64: u16 = 9;

/// CPU architecture of the dumped process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    X86,
    X64,
}

/// A contiguous range of virtual memory backed by file data.
#[derive(Debug, Clone)]
pub struct MemoryRange {
    pub virtual_address: u64,
    pub file_offset: u64,
    pub size: u64,
}

/// A loaded module (DLL/EXE) in the dump.
#[derive(Debug, Clone)]
pub struct Module {
    pub name: String,
    pub base_address: u64,
    pub size: u32,
}

/// Reader for Windows minidump files.
pub struct MinidumpReader {
    reader: Box<dyn ReadSeek>,
    pub arch: Architecture,
    pub os_build: u32,
    memory_ranges: Vec<MemoryRange>,
    modules: Vec<Module>,
}

impl MinidumpReader {
    /// Open and parse a minidump from a readable+seekable stream.
    pub fn open(mut reader: Box<dyn ReadSeek>) -> Result<Self, MemoryError> {
        // Read header (32 bytes).
        let header = read_at(&mut *reader, 0, 32)?;

        let signature = read_u32_le(&header, 0)?;
        if signature != MDMP_SIGNATURE {
            return Err(MemoryError::NotMemoryDump);
        }

        let _version = read_u32_le(&header, 4)?;
        let stream_count = read_u32_le(&header, 8)?;
        let stream_directory_rva = read_u32_le(&header, 12)?;

        debug!(
            "MDMP: version={:#x}, streams={}, directory_rva={:#x}",
            _version, stream_count, stream_directory_rva
        );

        // Read stream directory entries (12 bytes each).
        let dir_size = (stream_count as usize) * 12;
        let dir_data = read_at(&mut *reader, stream_directory_rva as u64, dir_size)?;

        let mut arch = Architecture::X64;
        let mut os_build: u32 = 0;
        let mut memory_ranges = Vec::new();
        let mut modules = Vec::new();

        for i in 0..stream_count as usize {
            let offset = i * 12;
            let stream_type = read_u32_le(&dir_data, offset)?;
            let data_size = read_u32_le(&dir_data, offset + 4)?;
            let rva = read_u32_le(&dir_data, offset + 8)?;

            match stream_type {
                STREAM_SYSTEM_INFO => {
                    let (a, b) = Self::parse_system_info(&mut *reader, rva as u64)?;
                    arch = a;
                    os_build = b;
                }
                STREAM_MEMORY64_LIST => {
                    memory_ranges =
                        Self::parse_memory64_list(&mut *reader, rva as u64, data_size)?;
                }
                STREAM_MODULE_LIST => {
                    modules = Self::parse_module_list(&mut *reader, rva as u64)?;
                }
                _ => {}
            }
        }

        // Sort memory ranges by virtual address for binary search.
        memory_ranges.sort_by_key(|r| r.virtual_address);

        debug!(
            "MDMP parsed: arch={:?}, build={}, ranges={}, modules={}",
            arch,
            os_build,
            memory_ranges.len(),
            modules.len()
        );

        Ok(Self {
            reader,
            arch,
            os_build,
            memory_ranges,
            modules,
        })
    }

    /// Parse MINIDUMP_SYSTEM_INFO stream.
    fn parse_system_info(
        reader: &mut dyn ReadSeek,
        rva: u64,
    ) -> Result<(Architecture, u32), MemoryError> {
        // SystemInfo is at least 64 bytes; we need arch (offset 0) and build (offset 24).
        let data = read_at(reader, rva, 28)?;
        let proc_arch = read_u16_le(&data, 0)?;
        let build_number = read_u32_le(&data, 24)?;

        let arch = match proc_arch {
            PROCESSOR_ARCHITECTURE_AMD64 => Architecture::X64,
            PROCESSOR_ARCHITECTURE_X86 => Architecture::X86,
            other => {
                return Err(MemoryError::UnsupportedFormat {
                    format: format!("unknown processor architecture: {}", other),
                })
            }
        };

        debug!("SystemInfo: arch={:?}, build={}", arch, build_number);
        Ok((arch, build_number))
    }

    /// Parse MINIDUMP_MEMORY64_LIST stream.
    fn parse_memory64_list(
        reader: &mut dyn ReadSeek,
        rva: u64,
        _data_size: u32,
    ) -> Result<Vec<MemoryRange>, MemoryError> {
        let header = read_at(reader, rva, 16)?;
        let number_of_ranges = read_u64_le(&header, 0)?;
        let base_rva = read_u64_le(&header, 8)?;

        debug!(
            "Memory64List: {} ranges, base_rva={:#x}",
            number_of_ranges, base_rva
        );

        // Each descriptor is 16 bytes: start_of_memory_range (u64) + data_size (u64).
        let desc_size = (number_of_ranges as usize) * 16;
        let desc_data = read_at(reader, rva + 16, desc_size)?;

        let mut ranges = Vec::with_capacity(number_of_ranges as usize);
        let mut current_file_offset = base_rva;

        for i in 0..number_of_ranges as usize {
            let off = i * 16;
            let start = read_u64_le(&desc_data, off)?;
            let size = read_u64_le(&desc_data, off + 8)?;

            ranges.push(MemoryRange {
                virtual_address: start,
                file_offset: current_file_offset,
                size,
            });

            current_file_offset += size;
        }

        Ok(ranges)
    }

    /// Parse MINIDUMP_MODULE_LIST stream.
    fn parse_module_list(
        reader: &mut dyn ReadSeek,
        rva: u64,
    ) -> Result<Vec<Module>, MemoryError> {
        let header = read_at(reader, rva, 4)?;
        let number_of_modules = read_u32_le(&header, 0)?;

        debug!("ModuleList: {} modules", number_of_modules);

        let mut modules = Vec::with_capacity(number_of_modules as usize);

        // Each MINIDUMP_MODULE entry is 108 bytes.
        const MODULE_ENTRY_SIZE: usize = 108;
        let entries_data = read_at(
            reader,
            rva + 4,
            (number_of_modules as usize) * MODULE_ENTRY_SIZE,
        )?;

        for i in 0..number_of_modules as usize {
            let off = i * MODULE_ENTRY_SIZE;
            let base_of_image = read_u64_le(&entries_data, off)?;
            let size_of_image = read_u32_le(&entries_data, off + 8)?;
            // Module name RVA is at offset 12 within MINIDUMP_MODULE (after
            // BaseOfImage(8) + SizeOfImage(4) + CheckSum(4) + TimeDateStamp(4)
            // + ModuleNameRva(4)). Actually the layout is:
            // 0: BaseOfImage (u64)
            // 8: SizeOfImage (u32)
            // 12: CheckSum (u32)
            // 16: TimeDateStamp (u32)
            // 20: ModuleNameRva (u32)
            let module_name_rva = read_u32_le(&entries_data, off + 20)?;

            let name = Self::read_minidump_string(reader, module_name_rva as u64)?;

            // Extract just the filename from the full path.
            let short_name = name
                .rsplit('\\')
                .next()
                .unwrap_or(&name)
                .to_lowercase();

            modules.push(Module {
                name: short_name,
                base_address: base_of_image,
                size: size_of_image,
            });
        }

        Ok(modules)
    }

    /// Read a MINIDUMP_STRING (length-prefixed UTF-16LE string).
    fn read_minidump_string(
        reader: &mut dyn ReadSeek,
        rva: u64,
    ) -> Result<String, MemoryError> {
        let len_buf = read_at(reader, rva, 4)?;
        let byte_len = read_u32_le(&len_buf, 0)? as usize;

        if byte_len == 0 {
            return Ok(String::new());
        }

        let str_buf = read_at(reader, rva + 4, byte_len)?;
        let s = read_utf16le(&str_buf, 0, byte_len)?;
        Ok(s)
    }

    /// Read bytes from a virtual address, translating through the memory map.
    pub fn read_virtual(&mut self, address: u64, size: usize) -> Result<Vec<u8>, MemoryError> {
        // Binary search for the range containing this address.
        let idx = self
            .memory_ranges
            .binary_search_by(|r| {
                if address < r.virtual_address {
                    std::cmp::Ordering::Greater
                } else if address >= r.virtual_address + r.size {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .map_err(|_| MemoryError::AddressNotMapped { addr: address })?;

        let range = &self.memory_ranges[idx];
        let offset_in_range = address - range.virtual_address;

        // Check that the read fits within this range.
        if offset_in_range + size as u64 > range.size {
            return Err(MemoryError::AddressNotMapped { addr: address });
        }

        let file_offset = range.file_offset + offset_in_range;
        let data = read_at(&mut *self.reader, file_offset, size)?;
        Ok(data)
    }

    /// Find a module by name (case-insensitive substring match).
    pub fn find_module(&self, name: &str) -> Option<&Module> {
        let needle = name.to_lowercase();
        self.modules.iter().find(|m| m.name.contains(&needle))
    }

    /// Search for a byte pattern within a specific module's memory.
    pub fn search_pattern_in_module(
        &mut self,
        module_name: &str,
        pattern: &[u8],
    ) -> Result<Vec<u64>, MemoryError> {
        let module = self
            .find_module(module_name)
            .cloned()
            .ok_or_else(|| MemoryError::LsassNotFound)?;

        let base = module.base_address;
        let size = module.size as u64;

        // Read the module's memory in chunks to handle large modules.
        self.search_pattern_in_range(base, size, pattern)
    }

    /// Search for a byte pattern across all mapped memory.
    pub fn search_pattern(&mut self, pattern: &[u8]) -> Result<Vec<u64>, MemoryError> {
        let mut results = Vec::new();

        // Clone ranges to avoid borrow conflict.
        let ranges: Vec<(u64, u64)> = self
            .memory_ranges
            .iter()
            .map(|r| (r.virtual_address, r.size))
            .collect();

        for (va, size) in ranges {
            match self.search_pattern_in_range(va, size, pattern) {
                Ok(mut hits) => results.append(&mut hits),
                Err(MemoryError::AddressNotMapped { .. }) => continue,
                Err(e) => return Err(e),
            }
        }

        Ok(results)
    }

    /// Search for a byte pattern in a virtual address range.
    fn search_pattern_in_range(
        &mut self,
        base: u64,
        size: u64,
        pattern: &[u8],
    ) -> Result<Vec<u64>, MemoryError> {
        if pattern.is_empty() {
            return Ok(Vec::new());
        }

        let mut results = Vec::new();
        const CHUNK_SIZE: usize = 64 * 1024; // 64KB chunks
        let overlap = pattern.len() - 1;
        let mut offset: u64 = 0;

        while offset < size {
            let read_size = std::cmp::min(CHUNK_SIZE, (size - offset) as usize);
            let chunk = match self.read_virtual(base + offset, read_size) {
                Ok(c) => c,
                Err(MemoryError::AddressNotMapped { .. }) => {
                    offset += (CHUNK_SIZE - overlap) as u64;
                    continue;
                }
                Err(e) => return Err(e),
            };

            // Search for pattern in this chunk.
            for i in 0..chunk.len().saturating_sub(pattern.len() - 1) {
                if chunk[i..].starts_with(pattern) {
                    results.push(base + offset + i as u64);
                }
            }

            if read_size < CHUNK_SIZE {
                break;
            }
            offset += (CHUNK_SIZE - overlap) as u64;
        }

        Ok(results)
    }

    /// Read a u64 from a virtual address (little-endian).
    pub fn read_virtual_u64(&mut self, address: u64) -> Result<u64, MemoryError> {
        let data = self.read_virtual(address, 8)?;
        Ok(read_u64_le(&data, 0)?)
    }

    /// Read a u32 from a virtual address (little-endian).
    pub fn read_virtual_u32(&mut self, address: u64) -> Result<u32, MemoryError> {
        let data = self.read_virtual(address, 4)?;
        Ok(read_u32_le(&data, 0)?)
    }

    /// Read a u16 from a virtual address (little-endian).
    pub fn read_virtual_u16(&mut self, address: u64) -> Result<u16, MemoryError> {
        let data = self.read_virtual(address, 2)?;
        Ok(read_u16_le(&data, 0)?)
    }

    /// Read a UNICODE_STRING from a virtual address.
    ///
    /// On x64 the structure is:
    ///   Length (u16), MaximumLength (u16), padding (u32), Buffer (u64)
    /// On x86:
    ///   Length (u16), MaximumLength (u16), Buffer (u32)
    pub fn read_unicode_string(&mut self, address: u64) -> Result<String, MemoryError> {
        match self.arch {
            Architecture::X64 => {
                let data = self.read_virtual(address, 16)?;
                let length = read_u16_le(&data, 0)? as usize;
                let _max_length = read_u16_le(&data, 2)?;
                let buffer = read_u64_le(&data, 8)?;

                if length == 0 || buffer == 0 {
                    return Ok(String::new());
                }

                let str_data = self.read_virtual(buffer, length)?;
                let s = read_utf16le(&str_data, 0, length)?;
                Ok(s)
            }
            Architecture::X86 => {
                let data = self.read_virtual(address, 8)?;
                let length = read_u16_le(&data, 0)? as usize;
                let _max_length = read_u16_le(&data, 2)?;
                let buffer = read_u32_le(&data, 4)? as u64;

                if length == 0 || buffer == 0 {
                    return Ok(String::new());
                }

                let str_data = self.read_virtual(buffer, length)?;
                let s = read_utf16le(&str_data, 0, length)?;
                Ok(s)
            }
        }
    }

    /// Get the list of loaded modules.
    pub fn modules(&self) -> &[Module] {
        &self.modules
    }

    /// Get the list of memory ranges.
    pub fn memory_ranges(&self) -> &[MemoryRange] {
        &self.memory_ranges
    }
}
