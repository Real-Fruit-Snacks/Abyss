//! Top-level ext2/3/4 filesystem handle.
//!
//! `ExtFilesystem` wraps a `Box<dyn ReadSeek>` and provides high-level
//! operations: probing, opening, block/inode reading, directory listing,
//! and path-based file access.

use std::io::SeekFrom;

use abyss_cstruct::read::{read_u32_le, FromBytes, ReadSeek};

use crate::block_group::BlockGroupDescriptor;
use crate::dir::{parse_directory_block, ExtDirEntry};
use crate::error::ExtfsError;
use crate::extent::{ExtentEntry, ExtentHeader, ExtentIndex};
use crate::inode::Inode;
use crate::superblock::{Superblock, SUPERBLOCK_OFFSET, SUPERBLOCK_SIZE};

/// Read `n` bytes from a `dyn ReadSeek` at a given byte offset.
fn read_at(reader: &mut dyn ReadSeek, offset: u64, n: usize) -> std::io::Result<Vec<u8>> {
    reader.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; n];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

/// Handle to an open ext2/3/4 filesystem image.
pub struct ExtFilesystem {
    /// Parsed superblock.
    superblock: Superblock,
    /// Underlying reader (disk image, block device, raw file, etc.).
    reader: Box<dyn ReadSeek>,
    /// All block group descriptors, loaded at open time.
    block_group_descriptors: Vec<BlockGroupDescriptor>,
}

impl ExtFilesystem {
    /// Returns `true` when `reader` appears to contain an ext filesystem.
    ///
    /// Reads the 2-byte magic field at superblock offset + 56 and checks for
    /// `0xEF53`.
    pub fn probe(reader: &mut Box<dyn ReadSeek>) -> bool {
        let magic_offset = SUPERBLOCK_OFFSET + 56;
        let buf = match read_at(reader.as_mut(), magic_offset, 2) {
            Ok(b) => b,
            Err(_) => return false,
        };
        buf.len() == 2 && buf[0] == 0x53 && buf[1] == 0xEF
    }

    /// Open an ext filesystem, parsing the superblock and all block group
    /// descriptors.
    pub fn open(mut reader: Box<dyn ReadSeek>) -> Result<Self, ExtfsError> {
        // Read and parse the superblock.
        let sb_buf = read_at(reader.as_mut(), SUPERBLOCK_OFFSET, SUPERBLOCK_SIZE)?;
        let superblock = Superblock::from_bytes(&sb_buf)?;

        // Block group descriptors start at the block immediately after the
        // superblock.  On 1 KiB-block filesystems that is block 2 (byte 2048);
        // on larger block sizes it is the second block (= block_size bytes in).
        let block_size = superblock.block_size();
        let desc_table_offset = if block_size == 1024 {
            2 * block_size
        } else {
            block_size
        };

        let group_count = superblock.block_group_count() as usize;
        let desc_size = superblock.desc_size() as usize;
        let is_64bit = superblock.has_64bit();

        let total_desc_bytes = group_count * desc_size;
        let desc_buf = read_at(reader.as_mut(), desc_table_offset, total_desc_bytes)?;

        let mut block_group_descriptors = Vec::with_capacity(group_count);
        for i in 0..group_count {
            let start = i * desc_size;
            let end = start + desc_size;
            let bgd = BlockGroupDescriptor::from_bytes(&desc_buf[start..end])?;
            let _ = is_64bit; // used via inode_table() at call sites
            block_group_descriptors.push(bgd);
        }

        Ok(ExtFilesystem {
            superblock,
            reader,
            block_group_descriptors,
        })
    }

    /// Read a single filesystem block by block number.
    pub fn read_block(&mut self, block_num: u64) -> Result<Vec<u8>, ExtfsError> {
        let block_size = self.superblock.block_size();
        let total = self.superblock.total_blocks();
        if block_num >= total {
            return Err(ExtfsError::BlockOutOfRange { block: block_num });
        }
        let offset = block_num * block_size;
        let buf = read_at(self.reader.as_mut(), offset, block_size as usize)?;
        Ok(buf)
    }

    /// Read and parse the inode at the given 1-based inode number.
    ///
    /// The inode's location is:
    /// ```text
    /// block_group  = (ino - 1) / inodes_per_group
    /// local_index  = (ino - 1) % inodes_per_group
    /// byte_offset  = inode_table_block * block_size + local_index * inode_size
    /// ```
    pub fn read_inode(&mut self, ino: u64) -> Result<Inode, ExtfsError> {
        if ino == 0 {
            return Err(ExtfsError::InvalidInode { inode: ino });
        }

        let inodes_per_group = self.superblock.s_inodes_per_group as u64;
        let inode_size = self.superblock.s_inode_size as u64;
        let block_size = self.superblock.block_size();
        let is_64bit = self.superblock.has_64bit();

        let group = (ino - 1) / inodes_per_group;
        let index = (ino - 1) % inodes_per_group;

        let bgd = self
            .block_group_descriptors
            .get(group as usize)
            .ok_or(ExtfsError::InvalidInode { inode: ino })?;

        let inode_table_block = bgd.inode_table(is_64bit);
        let byte_offset = inode_table_block * block_size + index * inode_size;

        let buf = read_at(self.reader.as_mut(), byte_offset, inode_size as usize)?;
        let inode = Inode::from_bytes(&buf)?;
        Ok(inode)
    }

    /// Read all data blocks referenced by `inode` and return the concatenated
    /// bytes, truncated to `inode.size()`.
    pub fn read_inode_data(&mut self, inode: &Inode) -> Result<Vec<u8>, ExtfsError> {
        let file_size = inode.size() as usize;
        let data = if inode.uses_extents() {
            self.read_extent_data(inode)?
        } else {
            self.read_blockmap_data(inode)?
        };
        let mut data = data;
        data.truncate(file_size);
        Ok(data)
    }

    // -------------------------------------------------------------------------
    // Extent tree traversal
    // -------------------------------------------------------------------------

    /// Collect all leaf `ExtentEntry` records reachable from the root node
    /// stored in `inode.i_block`.
    fn collect_extents(&mut self, node_buf: &[u8]) -> Result<Vec<ExtentEntry>, ExtfsError> {
        let header = ExtentHeader::from_bytes(node_buf)?;
        let entry_count = header.eh_entries as usize;

        if header.eh_depth == 0 {
            // Leaf node — entries immediately follow the 12-byte header.
            let mut leaves = Vec::with_capacity(entry_count);
            for i in 0..entry_count {
                let off = 12 + i * 12;
                if off + 12 > node_buf.len() {
                    break;
                }
                let entry = ExtentEntry::from_bytes(&node_buf[off..off + 12])?;
                leaves.push(entry);
            }
            Ok(leaves)
        } else {
            // Inner node — entries are ExtentIndex records pointing to children.
            let mut leaves = Vec::new();
            for i in 0..entry_count {
                let off = 12 + i * 12;
                if off + 12 > node_buf.len() {
                    break;
                }
                let idx = ExtentIndex::from_bytes(&node_buf[off..off + 12])?;
                let child_block = idx.child_block();
                let child_buf = self.read_block(child_block)?;
                let mut child_leaves = self.collect_extents(&child_buf)?;
                leaves.append(&mut child_leaves);
            }
            Ok(leaves)
        }
    }

    /// Read file data by walking the ext4 extent tree.
    fn read_extent_data(&mut self, inode: &Inode) -> Result<Vec<u8>, ExtfsError> {
        let block_size = self.superblock.block_size() as usize;
        let root_buf = &inode.i_block[..];
        let extents = self.collect_extents(root_buf)?;

        let file_size = inode.size() as usize;
        let mut out = vec![0u8; file_size];

        for ext in &extents {
            let phys_start = ext.physical_block();
            let log_start = ext.ee_block as usize;
            let count = ext.block_count() as usize;

            for b in 0..count {
                let file_off = (log_start + b) * block_size;
                if file_off >= file_size {
                    break;
                }
                let phys_block = phys_start + b as u64;
                let phys_off = phys_block * block_size as u64;
                let read_len = block_size.min(file_size - file_off);
                let block_data = read_at(self.reader.as_mut(), phys_off, read_len)?;
                out[file_off..file_off + read_len].copy_from_slice(&block_data);
            }
        }

        Ok(out)
    }

    // -------------------------------------------------------------------------
    // Traditional block-map traversal (ext2/3)
    // -------------------------------------------------------------------------

    /// Read file data using the traditional 15-pointer block map.
    fn read_blockmap_data(&mut self, inode: &Inode) -> Result<Vec<u8>, ExtfsError> {
        let block_size = self.superblock.block_size() as usize;
        let file_size = inode.size() as usize;
        let ptrs_per_block = block_size / 4; // each pointer is a u32

        // Extract the 15 direct+indirect pointers from i_block.
        let mut pointers = [0u32; 15];
        for i in 0..15 {
            pointers[i] = read_u32_le(&inode.i_block, i * 4)?;
        }

        // Logical block numbers in order.
        let mut logical_blocks: Vec<u64> = Vec::new();

        // 12 direct blocks (indices 0–11).
        for &blk in &pointers[0..12] {
            if blk != 0 {
                logical_blocks.push(blk as u64);
            } else {
                logical_blocks.push(0);
            }
        }

        // Single indirect (index 12).
        if pointers[12] != 0 {
            let ind_buf = self.read_block(pointers[12] as u64)?;
            for i in 0..ptrs_per_block {
                let p = read_u32_le(&ind_buf, i * 4).unwrap_or(0);
                logical_blocks.push(p as u64);
            }
        }

        // Double indirect (index 13).
        if pointers[13] != 0 {
            let dind_buf = self.read_block(pointers[13] as u64)?;
            for i in 0..ptrs_per_block {
                let p1 = read_u32_le(&dind_buf, i * 4).unwrap_or(0);
                if p1 == 0 {
                    for _ in 0..ptrs_per_block {
                        logical_blocks.push(0);
                    }
                    continue;
                }
                let ind_buf = self.read_block(p1 as u64)?;
                for j in 0..ptrs_per_block {
                    let p2 = read_u32_le(&ind_buf, j * 4).unwrap_or(0);
                    logical_blocks.push(p2 as u64);
                }
            }
        }

        // Triple indirect (index 14).
        if pointers[14] != 0 {
            let tind_buf = self.read_block(pointers[14] as u64)?;
            for i in 0..ptrs_per_block {
                let p1 = read_u32_le(&tind_buf, i * 4).unwrap_or(0);
                if p1 == 0 {
                    for _ in 0..ptrs_per_block * ptrs_per_block {
                        logical_blocks.push(0);
                    }
                    continue;
                }
                let dind_buf = self.read_block(p1 as u64)?;
                for j in 0..ptrs_per_block {
                    let p2 = read_u32_le(&dind_buf, j * 4).unwrap_or(0);
                    if p2 == 0 {
                        for _ in 0..ptrs_per_block {
                            logical_blocks.push(0);
                        }
                        continue;
                    }
                    let ind_buf = self.read_block(p2 as u64)?;
                    for k in 0..ptrs_per_block {
                        let p3 = read_u32_le(&ind_buf, k * 4).unwrap_or(0);
                        logical_blocks.push(p3 as u64);
                    }
                }
            }
        }

        let mut out: Vec<u8> = Vec::with_capacity(file_size);
        for blk in logical_blocks {
            if out.len() >= file_size {
                break;
            }
            if blk == 0 {
                // Sparse / hole — fill with zeros.
                let remaining = file_size - out.len();
                let fill = block_size.min(remaining);
                out.extend(std::iter::repeat(0u8).take(fill));
            } else {
                let phys_off = blk * block_size as u64;
                let remaining = file_size - out.len();
                let read_len = block_size.min(remaining);
                let block_data = read_at(self.reader.as_mut(), phys_off, read_len)?;
                out.extend_from_slice(&block_data);
            }
        }

        Ok(out)
    }

    // -------------------------------------------------------------------------
    // Higher-level helpers
    // -------------------------------------------------------------------------

    /// List the directory at inode `ino`, returning all live entries.
    pub fn list_directory(&mut self, ino: u64) -> Result<Vec<ExtDirEntry>, ExtfsError> {
        let inode = self.read_inode(ino)?;
        let data = self.read_inode_data(&inode)?;
        let block_size = self.superblock.block_size() as usize;

        let mut entries = Vec::new();
        let mut pos = 0usize;
        while pos < data.len() {
            let end = (pos + block_size).min(data.len());
            let block_entries = parse_directory_block(&data[pos..end])?;
            entries.extend(block_entries);
            pos += block_size;
        }
        Ok(entries)
    }

    /// Walk the directory tree from inode 2 (root) along the given path,
    /// returning the inode number and parsed `Inode` of the target.
    ///
    /// Path components are split on `/`; empty components (leading slash,
    /// trailing slash, double slash) are ignored.
    pub fn find_file(&mut self, path: &str) -> Result<(u64, Inode), ExtfsError> {
        let components: Vec<&str> = path
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        let mut current_ino = 2u64; // inode 2 = root directory
        for component in &components {
            let entries = self.list_directory(current_ino)?;
            let found = entries.into_iter().find(|e| e.name == *component);
            match found {
                Some(entry) => current_ino = entry.inode as u64,
                None => {
                    return Err(ExtfsError::InvalidInode { inode: 0 });
                }
            }
        }

        let inode = self.read_inode(current_ino)?;
        Ok((current_ino, inode))
    }

    /// Read the contents of the file at `path`.
    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>, ExtfsError> {
        let (_, inode) = self.find_file(path)?;
        self.read_inode_data(&inode)
    }

    /// Returns a reference to the parsed superblock.
    pub fn superblock(&self) -> &Superblock {
        &self.superblock
    }

    /// Total volume size in bytes (total_blocks × block_size).
    pub fn volume_size(&self) -> u64 {
        self.superblock.total_blocks() * self.superblock.block_size()
    }
}
