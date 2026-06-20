use crate::error::ContainerError;
use crate::traits::{BlockDevice, ContainerParser};
use abyss_cstruct::read::ReadSeek;
use flate2::read::ZlibDecoder;
use std::io::{Read, Seek, SeekFrom};

const EVF_SIGNATURE: [u8; 8] = [0x45, 0x56, 0x46, 0x09, 0x0D, 0x0A, 0xFF, 0x00];
const DEFAULT_CHUNK_SIZE: usize = 32768;

struct ChunkEntry {
    offset: u64,
    compressed: bool,
}

pub struct E01Container {
    reader: Box<dyn ReadSeek>,
    chunk_offsets: Vec<ChunkEntry>,
    chunk_size: usize,
    media_size: u64,
    position: u64,
    cache: Option<(usize, Vec<u8>)>,
}

/// Section header is 76 bytes:
///   type_str:     16 bytes (null-padded ASCII)
///   next_offset:   8 bytes (u64 LE)
///   section_size:  8 bytes (u64 LE)
///   padding:       40 bytes
///   checksum:      4 bytes (u32 LE)
fn read_section_header(reader: &mut dyn ReadSeek) -> std::io::Result<([u8; 16], u64, u64)> {
    let mut type_str = [0u8; 16];
    reader.read_exact(&mut type_str)?;
    let mut buf8 = [0u8; 8];
    reader.read_exact(&mut buf8)?;
    let next_offset = u64::from_le_bytes(buf8);
    reader.read_exact(&mut buf8)?;
    let section_size = u64::from_le_bytes(buf8);
    // padding (40) + checksum (4) = 44 bytes to skip
    let mut skip = [0u8; 44];
    reader.read_exact(&mut skip)?;
    Ok((type_str, next_offset, section_size))
}

impl ContainerParser for E01Container {
    fn probe(input: &mut dyn ReadSeek) -> Result<bool, ContainerError>
    where
        Self: Sized,
    {
        let mut sig = [0u8; 8];
        match input.read_exact(&mut sig) {
            Ok(_) => Ok(sig == EVF_SIGNATURE),
            Err(_) => Ok(false),
        }
    }

    fn open(mut input: Box<dyn ReadSeek>) -> Result<Box<dyn BlockDevice>, ContainerError>
    where
        Self: Sized,
    {
        // Validate signature
        let mut sig = [0u8; 8];
        input.read_exact(&mut sig)?;
        if sig != EVF_SIGNATURE {
            return Err(ContainerError::InvalidE01 {
                detail: "bad signature".into(),
            });
        }

        // Skip fields_start byte
        let mut fields_start = [0u8; 1];
        input.read_exact(&mut fields_start)?;

        let mut chunk_size = DEFAULT_CHUNK_SIZE;
        let mut media_size: u64 = 0;
        let mut chunk_offsets: Vec<ChunkEntry> = Vec::new();
        let mut sectors_data_offset: u64 = 0;
        let mut sectors_section_size: u64 = 0;

        // Walk sections starting after the 9-byte file header
        let mut current_offset: u64 = 9;

        loop {
            input.seek(SeekFrom::Start(current_offset))?;
            let (type_buf, next_offset, section_size) = read_section_header(&mut *input)?;

            // section header is 76 bytes; data starts right after
            let data_offset = current_offset + 76;

            let type_name = std::str::from_utf8(&type_buf)
                .unwrap_or("")
                .trim_end_matches('\0')
                .trim();

            match type_name {
                "volume" | "disk" => {
                    // volume data layout (offsets relative to data_offset):
                    //  0: reserved (4 bytes)
                    //  4: chunk_count (u32 LE)
                    //  8: sectors_per_chunk (u32 LE)
                    // 12: bytes_per_sector (u32 LE)
                    // 16: sector_count (u64 LE)
                    input.seek(SeekFrom::Start(data_offset))?;
                    let mut vol = [0u8; 24];
                    input.read_exact(&mut vol)?;
                    let sectors_per_chunk = u32::from_le_bytes(vol[8..12].try_into().unwrap());
                    let bytes_per_sector = u32::from_le_bytes(vol[12..16].try_into().unwrap());
                    let sector_count = u64::from_le_bytes(vol[16..24].try_into().unwrap());
                    chunk_size = (sectors_per_chunk as usize) * (bytes_per_sector as usize);
                    if chunk_size == 0 {
                        chunk_size = DEFAULT_CHUNK_SIZE;
                    }
                    media_size = sector_count * (bytes_per_sector as u64);
                }
                "table" | "table2" => {
                    // table data layout:
                    //  0: chunk_count (u32 LE)
                    //  4: padding (16 bytes)
                    // 20: array of u32 LE offsets
                    input.seek(SeekFrom::Start(data_offset))?;
                    let mut hdr = [0u8; 4];
                    input.read_exact(&mut hdr)?;
                    let chunk_count = u32::from_le_bytes(hdr) as usize;
                    // skip 16 bytes padding
                    let mut pad = [0u8; 16];
                    input.read_exact(&mut pad)?;
                    // Only populate on first table section (not table2 redundant copy)
                    if chunk_offsets.is_empty() && chunk_count > 0 {
                        chunk_offsets.reserve(chunk_count);
                        for _ in 0..chunk_count {
                            let mut entry_buf = [0u8; 4];
                            input.read_exact(&mut entry_buf)?;
                            let raw = u32::from_le_bytes(entry_buf);
                            let compressed = (raw & 0x8000_0000) != 0;
                            let offset = (raw & 0x7FFF_FFFF) as u64;
                            chunk_offsets.push(ChunkEntry { offset, compressed });
                        }
                    }
                }
                "sectors" => {
                    sectors_data_offset = data_offset;
                    // section_size includes the 76-byte header; data size is section_size - 76
                    sectors_section_size = if section_size > 76 {
                        section_size - 76
                    } else {
                        0
                    };
                }
                "done" | "next" => {
                    break;
                }
                _ => {}
            }

            if next_offset == 0 || next_offset == current_offset {
                break;
            }
            current_offset = next_offset;
        }

        if chunk_offsets.is_empty() {
            return Err(ContainerError::InvalidE01 {
                detail: "no chunk table found".into(),
            });
        }

        // Convert relative offsets to absolute: offsets in the table are relative
        // to the start of the sectors section data.
        for entry in &mut chunk_offsets {
            entry.offset += sectors_data_offset;
        }

        // Store end-of-sectors for last-chunk size calculation
        let sectors_end = sectors_data_offset + sectors_section_size;
        // Attach as a sentinel by storing it as a field we compute on-the-fly.
        // We'll keep sectors_end in a closure by putting it into the struct as
        // a plain field approach — just extend the struct.
        // Instead, we use a simpler approach: append a sentinel entry.
        chunk_offsets.push(ChunkEntry {
            offset: sectors_end,
            compressed: false,
        });

        Ok(Box::new(E01Container {
            reader: input,
            chunk_offsets,
            chunk_size,
            media_size,
            position: 0,
            cache: None,
        }))
    }
}

impl E01Container {
    fn read_chunk(&mut self, chunk_index: usize) -> Result<Vec<u8>, ContainerError> {
        if chunk_index + 1 >= self.chunk_offsets.len() {
            return Err(ContainerError::InvalidE01 {
                detail: format!("chunk index {} out of range", chunk_index),
            });
        }
        let entry = &self.chunk_offsets[chunk_index];
        let offset = entry.offset;
        let compressed = entry.compressed;
        let next_offset = self.chunk_offsets[chunk_index + 1].offset;
        let raw_size = (next_offset.saturating_sub(offset)) as usize;

        self.reader.seek(SeekFrom::Start(offset))?;

        if compressed {
            let mut raw = vec![0u8; raw_size];
            self.reader.read_exact(&mut raw)?;
            let mut decoder = ZlibDecoder::new(raw.as_slice());
            let mut decompressed = Vec::with_capacity(self.chunk_size);
            decoder
                .read_to_end(&mut decompressed)
                .map_err(|e| ContainerError::Decompression(e.to_string()))?;
            Ok(decompressed)
        } else {
            let read_size = raw_size.min(self.chunk_size);
            let mut buf = vec![0u8; read_size];
            self.reader.read_exact(&mut buf)?;
            // Pad to chunk_size if this is the last real chunk and it's short
            if buf.len() < self.chunk_size {
                buf.resize(self.chunk_size, 0);
            }
            Ok(buf)
        }
    }
}

impl Read for E01Container {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.position >= self.media_size {
            return Ok(0);
        }
        let chunk_index = (self.position / self.chunk_size as u64) as usize;
        let offset_in_chunk = (self.position % self.chunk_size as u64) as usize;

        // Load cache if needed
        let cached_index = self.cache.as_ref().map(|(i, _)| *i);
        if cached_index != Some(chunk_index) {
            let data = self
                .read_chunk(chunk_index)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
            self.cache = Some((chunk_index, data));
        }

        let chunk_data = &self.cache.as_ref().unwrap().1;
        let available = chunk_data.len().saturating_sub(offset_in_chunk);
        let remaining_media = (self.media_size - self.position) as usize;
        let to_copy = buf.len().min(available).min(remaining_media);

        buf[..to_copy].copy_from_slice(&chunk_data[offset_in_chunk..offset_in_chunk + to_copy]);
        self.position += to_copy as u64;
        Ok(to_copy)
    }
}

impl Seek for E01Container {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(n) => n,
            SeekFrom::End(n) => {
                if n < 0 {
                    self.media_size.saturating_sub((-n) as u64)
                } else {
                    self.media_size.saturating_add(n as u64)
                }
            }
            SeekFrom::Current(n) => {
                if n < 0 {
                    self.position.saturating_sub((-n) as u64)
                } else {
                    self.position.saturating_add(n as u64)
                }
            }
        };
        self.position = new_pos.min(self.media_size);
        Ok(self.position)
    }
}

impl BlockDevice for E01Container {
    fn size(&self) -> u64 {
        self.media_size
    }
}
