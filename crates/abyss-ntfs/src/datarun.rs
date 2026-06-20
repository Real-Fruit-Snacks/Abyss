//! NTFS data run decoder.
//!
//! Decodes variable-length cluster run lists used by NTFS to map file data
//! to logical cluster numbers (LCNs) on the volume.

use abyss_cstruct::ParseError;

/// A single decoded data run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataRun {
    /// Starting cluster number on the volume. `None` indicates a sparse run
    /// (a hole filled with zeroes, with no allocated clusters).
    pub cluster: Option<u64>,
    /// Number of clusters in this run.
    pub length: u64,
}

/// Decode an NTFS data run list from `buf`.
///
/// Each entry in a data run list is encoded as:
/// - 1 header byte: low nibble = byte count of length field, high nibble = byte count of offset field.
/// - N bytes: run length (unsigned, little-endian).
/// - M bytes: cluster offset (signed, little-endian, relative to the previous run's starting cluster).
///
/// A `0x00` header byte terminates the list.
pub fn decode_data_runs(buf: &[u8]) -> Result<Vec<DataRun>, ParseError> {
    let mut runs = Vec::new();
    let mut pos = 0usize;
    let mut prev_cluster: i64 = 0;

    loop {
        if pos >= buf.len() {
            break;
        }

        let header = buf[pos];
        pos += 1;

        // 0x00 is the end-of-list marker.
        if header == 0x00 {
            break;
        }

        let length_size = (header & 0x0F) as usize;
        let offset_size = ((header >> 4) & 0x0F) as usize;

        // length_size must be 1–8; 0 would be an invalid run.
        if length_size == 0 || length_size > 8 {
            return Err(ParseError::InvalidField {
                field: "data_run_length_size",
                detail: format!("invalid length field size: {}", length_size),
            });
        }
        if offset_size > 8 {
            return Err(ParseError::InvalidField {
                field: "data_run_offset_size",
                detail: format!("invalid offset field size: {}", offset_size),
            });
        }

        // Read run length (unsigned).
        if pos + length_size > buf.len() {
            return Err(ParseError::BufferTooSmall {
                need: pos + length_size,
                have: buf.len(),
            });
        }
        let mut length_bytes = [0u8; 8];
        length_bytes[..length_size].copy_from_slice(&buf[pos..pos + length_size]);
        let length = u64::from_le_bytes(length_bytes);
        pos += length_size;

        // Read signed cluster offset (sign-extended from offset_size bytes).
        let cluster = if offset_size == 0 {
            // Sparse run: no cluster allocation.
            None
        } else {
            if pos + offset_size > buf.len() {
                return Err(ParseError::BufferTooSmall {
                    need: pos + offset_size,
                    have: buf.len(),
                });
            }
            let mut offset_bytes = [0u8; 8];
            offset_bytes[..offset_size].copy_from_slice(&buf[pos..pos + offset_size]);
            // Sign-extend from offset_size bytes.
            let raw = i64::from_le_bytes(offset_bytes);
            let shift = (8 - offset_size as u32) * 8;
            let signed_offset = (raw << shift) >> shift;
            prev_cluster += signed_offset;
            Some(prev_cluster as u64)
        };
        pos += offset_size;

        runs.push(DataRun { cluster, length });
    }

    Ok(runs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_run() {
        // Header 0x11: length_size=1, offset_size=1
        // Length=5 clusters, offset=+3 (absolute cluster 3)
        let buf = [0x11, 0x05, 0x03, 0x00];
        let runs = decode_data_runs(&buf).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].cluster, Some(3));
        assert_eq!(runs[0].length, 5);
    }

    #[test]
    fn test_multiple_runs() {
        // Run 1: header=0x11, length=4, offset=+10 -> cluster 10
        // Run 2: header=0x11, length=2, offset=+5  -> cluster 15
        // End: 0x00
        let buf = [0x11, 0x04, 0x0A, 0x11, 0x02, 0x05, 0x00];
        let runs = decode_data_runs(&buf).unwrap();
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].cluster, Some(10));
        assert_eq!(runs[0].length, 4);
        assert_eq!(runs[1].cluster, Some(15));
        assert_eq!(runs[1].length, 2);
    }

    #[test]
    fn test_sparse_run() {
        // Header 0x01: length_size=1, offset_size=0 -> sparse
        // Length=8 clusters
        // End: 0x00
        let buf = [0x01, 0x08, 0x00];
        let runs = decode_data_runs(&buf).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].cluster, None);
        assert_eq!(runs[0].length, 8);
    }
}
