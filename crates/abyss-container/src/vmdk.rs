use crate::error::ContainerError;
use crate::traits::{BlockDevice, ContainerParser};
use abyss_cstruct::read::ReadSeek;
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};

const VMDK_MAGIC: u32 = 0x564D_444B;

pub struct VmdkContainer {
    reader: Box<dyn ReadSeek>,
    grain_size_bytes: u64,
    capacity_bytes: u64,
    gd_entries: Vec<u32>,
    gt_cache: HashMap<usize, Vec<u32>>,
    num_gtes_per_gt: usize,
    position: u64,
}

/// Read a u32 LE from a byte slice at the given offset.
#[inline]
fn read_u32_le(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap())
}

/// Read a u64 LE from a byte slice at the given offset.
#[inline]
fn read_u64_le(buf: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(buf[offset..offset + 8].try_into().unwrap())
}

impl ContainerParser for VmdkContainer {
    fn probe(input: &mut dyn ReadSeek) -> Result<bool, ContainerError>
    where
        Self: Sized,
    {
        let mut buf = [0u8; 4];
        match input.read_exact(&mut buf) {
            Ok(_) => Ok(u32::from_le_bytes(buf) == VMDK_MAGIC),
            Err(_) => Ok(false),
        }
    }

    fn open(mut input: Box<dyn ReadSeek>) -> Result<Box<dyn BlockDevice>, ContainerError>
    where
        Self: Sized,
    {
        // Read 512-byte sparse extent header
        let mut hdr = [0u8; 512];
        input.read_exact(&mut hdr)?;

        let magic = read_u32_le(&hdr, 0);
        if magic != VMDK_MAGIC {
            return Err(ContainerError::InvalidVmdk {
                detail: "bad magic".into(),
            });
        }

        // capacity at offset 12 (u64)
        let capacity = read_u64_le(&hdr, 12);
        // grain_size at offset 20 (u64)
        let grain_size = read_u64_le(&hdr, 20);
        // num_gtes_per_gt at offset 44 (u32)
        let num_gtes_per_gt = read_u32_le(&hdr, 44) as usize;
        // gd_offset at offset 56 (u64)
        let gd_offset = read_u64_le(&hdr, 56);

        if grain_size == 0 {
            return Err(ContainerError::InvalidVmdk {
                detail: "grain_size is zero".into(),
            });
        }
        let num_gtes = if num_gtes_per_gt == 0 { 512 } else { num_gtes_per_gt };

        let grain_size_bytes = grain_size * 512;
        let capacity_bytes = capacity * 512;

        // Number of GD entries = ceil(capacity / (grain_size * num_gtes))
        let grains_per_gt = grain_size * num_gtes as u64;
        let gd_count = if grains_per_gt == 0 {
            0
        } else {
            ((capacity + grains_per_gt - 1) / grains_per_gt) as usize
        };

        // Read grain directory
        input.seek(SeekFrom::Start(gd_offset * 512))?;
        let mut gd_entries = vec![0u32; gd_count];
        {
            let mut buf = vec![0u8; gd_count * 4];
            input.read_exact(&mut buf)?;
            for (i, chunk) in buf.chunks_exact(4).enumerate() {
                gd_entries[i] = u32::from_le_bytes(chunk.try_into().unwrap());
            }
        }

        Ok(Box::new(VmdkContainer {
            reader: input,
            grain_size_bytes,
            capacity_bytes,
            gd_entries,
            gt_cache: HashMap::new(),
            num_gtes_per_gt: num_gtes,
            position: 0,
        }))
    }
}

impl VmdkContainer {
    fn load_grain_table(&mut self, gd_idx: usize) -> Result<(), ContainerError> {
        if self.gt_cache.contains_key(&gd_idx) {
            return Ok(());
        }
        let gd_entry = if gd_idx < self.gd_entries.len() {
            self.gd_entries[gd_idx]
        } else {
            0
        };
        if gd_entry == 0 {
            // unallocated GT — store all zeros
            self.gt_cache
                .insert(gd_idx, vec![0u32; self.num_gtes_per_gt]);
            return Ok(());
        }
        let gt_offset = (gd_entry as u64) * 512;
        self.reader.seek(SeekFrom::Start(gt_offset))?;
        let mut buf = vec![0u8; self.num_gtes_per_gt * 4];
        self.reader.read_exact(&mut buf)?;
        let mut gt = vec![0u32; self.num_gtes_per_gt];
        for (i, chunk) in buf.chunks_exact(4).enumerate() {
            gt[i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }
        self.gt_cache.insert(gd_idx, gt);
        Ok(())
    }
}

impl Read for VmdkContainer {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.position >= self.capacity_bytes {
            return Ok(0);
        }

        let grain_index = self.position / self.grain_size_bytes;
        let offset_in_grain = (self.position % self.grain_size_bytes) as usize;
        let gd_idx = (grain_index / self.num_gtes_per_gt as u64) as usize;
        let gt_idx = (grain_index % self.num_gtes_per_gt as u64) as usize;

        // Load grain table
        self.load_grain_table(gd_idx)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        let gt_entry = self.gt_cache[&gd_idx][gt_idx];

        let available_in_grain = (self.grain_size_bytes as usize).saturating_sub(offset_in_grain);
        let remaining_media = (self.capacity_bytes - self.position) as usize;
        let to_copy = buf.len().min(available_in_grain).min(remaining_media);

        if gt_entry == 0 {
            // Unallocated grain — return zeros
            for b in &mut buf[..to_copy] {
                *b = 0;
            }
        } else {
            let grain_offset = (gt_entry as u64) * 512 + offset_in_grain as u64;
            self.reader
                .seek(SeekFrom::Start(grain_offset))
                .map_err(|e| std::io::Error::new(e.kind(), e))?;
            self.reader
                .read_exact(&mut buf[..to_copy])
                .map_err(|e| std::io::Error::new(e.kind(), e))?;
        }

        self.position += to_copy as u64;
        Ok(to_copy)
    }
}

impl Seek for VmdkContainer {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(n) => n,
            SeekFrom::End(n) => {
                if n < 0 {
                    self.capacity_bytes.saturating_sub((-n) as u64)
                } else {
                    self.capacity_bytes.saturating_add(n as u64)
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
        self.position = new_pos.min(self.capacity_bytes);
        Ok(self.position)
    }
}

impl BlockDevice for VmdkContainer {
    fn size(&self) -> u64 {
        self.capacity_bytes
    }
}
