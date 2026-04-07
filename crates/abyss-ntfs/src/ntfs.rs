//! NtfsFilesystem — top-level handle for an NTFS volume.
//!
//! Provides volume probing, boot sector access, raw byte reading, and MFT
//! record retrieval.

use std::io::SeekFrom;

use abyss_cstruct::read::{FromBytes, ReadSeek};

use crate::attribute::AttributeType;
use crate::boot::NtfsBootSector;
use crate::datarun::decode_data_runs;
use crate::error::NtfsError;
use crate::filename::FileName;
use crate::mft::MftRecord;

/// Read `n` bytes from a `dyn ReadSeek` at the given offset.
fn read_at_dyn(reader: &mut dyn ReadSeek, offset: u64, n: usize) -> std::io::Result<Vec<u8>> {
    reader.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; n];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

/// Handle to an open NTFS volume.
pub struct NtfsFilesystem {
    /// Parsed boot sector.
    boot: NtfsBootSector,
    /// Underlying reader (disk image, block device, etc.).
    reader: Box<dyn ReadSeek>,
    /// Total volume size in bytes.
    volume_size: u64,
}

impl NtfsFilesystem {
    /// Returns `true` if `reader` looks like an NTFS volume.
    ///
    /// Reads the first 512 bytes and attempts to parse them as an
    /// [`NtfsBootSector`]. Any parse failure is treated as a non-NTFS volume.
    pub fn probe(reader: &mut Box<dyn ReadSeek>) -> bool {
        let buf = match read_at_dyn(reader.as_mut(), 0, 512) {
            Ok(b) => b,
            Err(_) => return false,
        };
        NtfsBootSector::from_bytes(&buf).is_ok()
    }

    /// Open an NTFS volume.
    ///
    /// Reads and validates the boot sector, then stores the reader for future
    /// operations.
    pub fn open(mut reader: Box<dyn ReadSeek>) -> Result<Self, NtfsError> {
        let buf = read_at_dyn(reader.as_mut(), 0, 512)?;
        let boot = NtfsBootSector::from_bytes(&buf)?;
        let volume_size = (boot.total_sectors + 1) * boot.bytes_per_sector as u64;
        Ok(Self {
            boot,
            reader,
            volume_size,
        })
    }

    /// Returns a reference to the parsed boot sector.
    pub fn boot_sector(&self) -> &NtfsBootSector {
        &self.boot
    }

    /// Total volume size in bytes.
    pub fn volume_size(&self) -> u64 {
        self.volume_size
    }

    /// Read `len` raw bytes from the volume starting at `offset`.
    pub fn read_at(&mut self, offset: u64, len: usize) -> Result<Vec<u8>, NtfsError> {
        let buf = read_at_dyn(self.reader.as_mut(), offset, len)?;
        Ok(buf)
    }

    /// Read and validate the MFT record at `index`.
    ///
    /// Returns the raw bytes of the record. Returns
    /// [`NtfsError::InvalidMftRecord`] if the record does not start with the
    /// `FILE` magic.
    pub fn read_mft_record(&mut self, index: u64) -> Result<Vec<u8>, NtfsError> {
        let record_size = self.boot.mft_record_size();
        let offset = self.boot.mft_offset() + index * record_size;
        let buf = read_at_dyn(self.reader.as_mut(), offset, record_size as usize)?;

        // Validate FILE magic.
        if buf.len() < 4 || &buf[0..4] != b"FILE" {
            return Err(NtfsError::InvalidMftRecord { index });
        }

        Ok(buf)
    }

    /// Returns the total number of MFT records by reading $MFT's $DATA attribute.
    ///
    /// Falls back to 1024 if the count cannot be determined.
    pub fn total_mft_records(&mut self) -> Result<u64, NtfsError> {
        let record_size = self.boot.mft_record_size();
        if record_size == 0 {
            return Ok(1024);
        }

        let buf = match self.read_mft_record(0) {
            Ok(b) => b,
            Err(_) => return Ok(1024),
        };
        let record = match MftRecord::from_bytes(&buf) {
            Ok(r) => r,
            Err(_) => return Ok(1024),
        };

        for (attr_offset, attr) in record.attributes(&buf) {
            if attr.attr_type != AttributeType::Data {
                continue;
            }
            // Unnamed $DATA only (name_length == 0).
            if attr.name_length != 0 {
                continue;
            }
            if attr.non_resident {
                if let Some(real_size) = attr.data_size {
                    return Ok(real_size / record_size);
                }
            }
            // Resident $DATA on $MFT itself is unusual; fall through.
            let _ = attr_offset;
        }

        Ok(1024)
    }

    /// Read the content of a file by MFT index.
    ///
    /// Finds the unnamed $DATA attribute and returns its bytes (resident or
    /// non-resident).
    pub fn read_file_by_index(&mut self, mft_index: u64) -> Result<Vec<u8>, NtfsError> {
        let buf = self.read_mft_record(mft_index)?;
        let record = MftRecord::from_bytes(&buf)?;

        for (attr_offset, attr) in record.attributes(&buf) {
            if attr.attr_type != AttributeType::Data {
                continue;
            }
            if attr.name_length != 0 {
                continue;
            }

            if !attr.non_resident {
                // Resident: return value bytes directly.
                if let Some(bytes) = attr.resident_value(&buf, attr_offset) {
                    return Ok(bytes.to_vec());
                }
                return Err(NtfsError::AttributeError {
                    detail: "resident $DATA value unavailable".into(),
                });
            } else {
                return self.read_non_resident_data(&attr, &buf, attr_offset);
            }
        }

        Err(NtfsError::AttributeError {
            detail: format!("no $DATA attribute found for MFT index {}", mft_index),
        })
    }

    /// Read non-resident attribute data by following data runs.
    fn read_non_resident_data(
        &mut self,
        attr: &crate::attribute::AttributeHeader,
        record_buf: &[u8],
        attr_offset: usize,
    ) -> Result<Vec<u8>, NtfsError> {
        let runs_offset = match attr.data_runs_offset {
            Some(o) => o as usize,
            None => {
                return Err(NtfsError::AttributeError {
                    detail: "non-resident attribute missing data_runs_offset".into(),
                })
            }
        };
        let real_size = attr.data_size.unwrap_or(0) as usize;
        let bytes_per_cluster = self.boot.bytes_per_cluster();

        let abs_runs_offset = attr_offset + runs_offset;
        if abs_runs_offset > record_buf.len() {
            return Err(NtfsError::AttributeError {
                detail: "data_runs_offset out of bounds".into(),
            });
        }
        let runs_buf = &record_buf[abs_runs_offset..];
        let runs = decode_data_runs(runs_buf)?;

        let mut out: Vec<u8> = Vec::with_capacity(real_size);
        for run in &runs {
            let cluster_bytes = (run.length * bytes_per_cluster) as usize;
            match run.cluster {
                None => {
                    // Sparse run — fill with zeros.
                    out.extend(std::iter::repeat(0u8).take(cluster_bytes));
                }
                Some(lcn) => {
                    let disk_offset = lcn * bytes_per_cluster;
                    let bytes = read_at_dyn(self.reader.as_mut(), disk_offset, cluster_bytes)?;
                    out.extend_from_slice(&bytes);
                }
            }
        }

        // Truncate to the declared real size.
        out.truncate(real_size);
        Ok(out)
    }

    /// Locate a file by path, returning its MFT index.
    ///
    /// Splits `path` on `/` and `\`, ignores empty components, then descends
    /// from the root directory (MFT index 5).
    pub fn find_file(&mut self, path: &str) -> Result<u64, NtfsError> {
        let components: Vec<&str> = path
            .split(|c| c == '/' || c == '\\')
            .filter(|s| !s.is_empty())
            .collect();

        let mut current = 5u64; // MFT index 5 = root directory
        for component in components {
            current = self.find_child_in_dir(current, component)?;
        }
        Ok(current)
    }

    /// Find a child entry named `name` inside a directory at `parent_mft_index`.
    ///
    /// Scans all MFT records looking for in-use records whose $FILE_NAME
    /// attribute matches the parent reference and name (case-insensitive,
    /// Win32 namespace).
    fn find_child_in_dir(
        &mut self,
        parent_mft_index: u64,
        name: &str,
    ) -> Result<u64, NtfsError> {
        let total = self.total_mft_records()?;
        let name_lower = name.to_lowercase();

        for idx in 0..total {
            let buf = match self.read_mft_record(idx) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let record = match MftRecord::from_bytes(&buf) {
                Ok(r) => r,
                Err(_) => continue,
            };
            if !record.is_in_use() {
                continue;
            }

            for (attr_offset, attr) in record.attributes(&buf) {
                if attr.attr_type != AttributeType::FileName {
                    continue;
                }
                if attr.non_resident {
                    continue;
                }
                let value = match attr.resident_value(&buf, attr_offset) {
                    Some(v) => v,
                    None => continue,
                };
                let fname = match FileName::from_bytes(value) {
                    Ok(f) => f,
                    Err(_) => continue,
                };
                if !fname.is_win32_name() {
                    continue;
                }
                if fname.parent_ref != parent_mft_index {
                    continue;
                }
                if fname.name.to_lowercase() == name_lower {
                    return Ok(idx);
                }
            }
        }

        Err(NtfsError::AttributeError {
            detail: format!("'{}' not found in directory MFT index {}", name, parent_mft_index),
        })
    }

    /// Read a file by path, returning its full contents.
    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>, NtfsError> {
        let idx = self.find_file(path)?;
        self.read_file_by_index(idx)
    }

    /// List directory contents at `dir_mft_index`.
    ///
    /// Returns a sorted, deduplicated list of `(name, is_directory, mft_index)`.
    pub fn list_directory(
        &mut self,
        dir_mft_index: u64,
    ) -> Result<Vec<(String, bool, u64)>, NtfsError> {
        let total = self.total_mft_records()?;
        // Deduplicate by lowercase name.
        let mut seen: std::collections::HashMap<String, (String, bool, u64)> =
            std::collections::HashMap::new();

        for idx in 0..total {
            let buf = match self.read_mft_record(idx) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let record = match MftRecord::from_bytes(&buf) {
                Ok(r) => r,
                Err(_) => continue,
            };
            if !record.is_in_use() {
                continue;
            }
            let is_dir = record.is_directory();

            for (attr_offset, attr) in record.attributes(&buf) {
                if attr.attr_type != AttributeType::FileName {
                    continue;
                }
                if attr.non_resident {
                    continue;
                }
                let value = match attr.resident_value(&buf, attr_offset) {
                    Some(v) => v,
                    None => continue,
                };
                let fname = match FileName::from_bytes(value) {
                    Ok(f) => f,
                    Err(_) => continue,
                };
                if !fname.is_win32_name() {
                    continue;
                }
                if fname.parent_ref != dir_mft_index {
                    continue;
                }
                let key = fname.name.to_lowercase();
                seen.entry(key).or_insert((fname.name, is_dir, idx));
            }
        }

        let mut entries: Vec<(String, bool, u64)> = seen.into_values().collect();
        entries.sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()));
        Ok(entries)
    }
}
