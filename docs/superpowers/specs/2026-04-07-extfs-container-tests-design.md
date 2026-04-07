# Design: abyss-extfs, abyss-container (E01/VMDK), and Workspace Tests

**Date:** 2026-04-07
**Scope:** Flesh out ext2/3/4 filesystem parsing, add E01 and VMDK container formats, comprehensive test coverage

---

## 1. abyss-extfs — ext2/3/4 Filesystem Parser

### Architecture

Follows the same layered pattern as `abyss-ntfs`: low-level `FromBytes` structs composed into a high-level `ExtFilesystem` abstraction.

### Structures

**Superblock** (1024 bytes at byte offset 1024):
- Magic: `0xEF53` at offset 56
- Fields: block_size (1024 << s_log_block_size), inode_size, inodes_per_group, blocks_per_group, total inodes/blocks, feature flags
- Detect ext version from compat/incompat/ro_compat feature flags
- 64-bit mode when `INCOMPAT_64BIT` flag is set (uses 64-byte block group descriptors)

**BlockGroupDescriptor** (32 or 64 bytes):
- Inode table location, inode/block bitmap locations, free counts
- 32-byte for ext2/3, 64-byte for ext4 with INCOMPAT_64BIT

**Inode** (128 or 256 bytes, from superblock `s_inode_size`):
- Mode, uid, gid, size (low + high), timestamps (atime, ctime, mtime)
- 12 direct block pointers, 1 indirect, 1 double-indirect, 1 triple-indirect
- Ext4 extents: when inode flag `0x80000` (EXTENTS) is set, `i_block` is an extent tree
  - Extent header: magic `0xF30A`, entries count, depth
  - Extent entries: logical block, length, physical block (high + low)
  - Extent index entries for multi-level trees (depth > 0)

**DirectoryEntry** (variable length):
- inode number, rec_len, name_len, file_type, name bytes
- Traversal via rec_len linked list until end of block

### Top-Level API: `ExtFilesystem`

```rust
impl ExtFilesystem {
    fn probe(reader: &mut dyn ReadSeek) -> Result<bool, ExtfsError>;
    fn open(reader: Box<dyn ReadSeek>) -> Result<Self, ExtfsError>;
    fn read_inode(&mut self, ino: u64) -> Result<Inode, ExtfsError>;
    fn read_file(&mut self, inode: &Inode) -> Result<Vec<u8>, ExtfsError>;
    fn list_directory(&mut self, inode: &Inode) -> Result<Vec<DirEntry>, ExtfsError>;
    fn find_file(&mut self, path: &str) -> Result<(Inode, Vec<u8>), ExtfsError>;
}
```

- Root directory is always inode 2
- Block pointer resolution: direct → indirect → double-indirect → triple-indirect
- Extent resolution: walk extent tree, handle multi-level (depth > 0) via index nodes

### Not in scope (YAGNI)
- Journal (ext3/4 journaling)
- Extended attributes / ACLs
- Hash tree directories (htree) — linear traversal sufficient for forensics
- Inline data / inline directories
- Filesystem writing

---

## 2. abyss-container — E01 and VMDK Parsers

### E01 (EnCase Evidence File)

**Format overview:**
- Segments identified by `EVF` signature (magic: `45 56 46 09 0D 0A FF 00`)
- Sections: header, volume, data (sectors), hash, done
- Each section has: type (16 bytes), next offset (u64), size (u64), checksum (u32)
- Data section contains chunks (default 32KB), optionally zlib-compressed
- Chunk table at start of data section maps chunk index → offset + compressed size

**Implementation:**
```rust
pub struct E01Container {
    reader: Box<dyn ReadSeek>,
    chunk_offsets: Vec<ChunkEntry>,  // offset + size + compressed flag
    chunk_size: usize,               // default 32KB (32768)
    media_size: u64,                 // total uncompressed size
    cache: Option<(usize, Vec<u8>)>, // single-chunk LRU cache
}
```

- `probe()`: check 8-byte magic
- `open()`: parse segment header, walk sections to build chunk table
- `BlockDevice` impl: translate read offset → chunk index → decompress if needed → serve bytes
- Single-chunk cache to avoid repeated decompression for sequential reads
- New dependency: `flate2` for zlib decompression

### VMDK (Virtual Machine Disk — sparse format)

**Format overview:**
- Sparse extent header (`KDMV` magic) at offset 0
- Grain size (typically 128 sectors = 64KB)
- Grain directory → grain tables → grains (data chunks)
- Two-level indirection: GD entry points to GT, GT entry points to grain

**Implementation:**
```rust
pub struct VmdkContainer {
    reader: Box<dyn ReadSeek>,
    grain_size: u64,        // in bytes
    grain_directory: Vec<u32>,
    grain_tables: HashMap<usize, Vec<u32>>,
    capacity: u64,
}
```

- `probe()`: check `KDMV` magic (4 bytes)
- `open()`: parse sparse header, read grain directory, lazy-load grain tables
- `BlockDevice` impl: offset → grain index → GT lookup → read grain data
- Zero-filled grains for unallocated entries (GD/GT entry == 0)

### Auto-Detection

```rust
pub fn detect_and_open(input: Box<dyn ReadSeek>) -> Result<Box<dyn BlockDevice>, ContainerError> {
    // Try E01 first (most specific magic), then VMDK, then Raw fallback
}
```

### New Dependencies
- `flate2 = "1"` for E01 zlib decompression

---

## 3. Integration — Wire into abyss-target

- Add `abyss-extfs` dependency to `abyss-target`
- In `Target::open()`: after NTFS probe fails, try `ExtFilesystem::probe()`
- Store opened `ExtFilesystem` alongside `NtfsFilesystem` (enum or Option fields)
- Update `abyss-container` usage in target: use `detect_and_open()` instead of hardcoded `RawContainer`
- Linux extractors (SSH keys, `/etc/shadow`, etc.) already exist — they'll work once ext4 file reading is wired up

---

## 4. Tests — Synthetic Fixtures, No External Data

All tests use `std::io::Cursor<Vec<u8>>` with hand-crafted binary data.

### abyss-cstruct
- `FromBytes` trait: valid parse, buffer too short, invalid magic
- Helper functions: LE integer reads at offsets, UTF-16LE string decoding

### abyss-container
- `RawContainer`: open, size, read, seek
- `E01Container`: probe magic, parse chunk table, read uncompressed chunks, read compressed chunks, seek across chunk boundaries
- `VmdkContainer`: probe magic, grain directory/table lookup, read allocated grain, zero-fill unallocated grain
- `detect_and_open()`: routes E01/VMDK/raw correctly

### abyss-volume
- MBR: valid parse, invalid signature, empty partition table
- GPT: valid header + entries, GUID decoding, partition type names

### abyss-ntfs
- Boot sector: valid parse, invalid OEM ID
- MFT record: valid FILE header, attribute iteration, resident vs non-resident
- Data runs: single run, multi-run, sparse
- FileName: UTF-16LE decoding, namespace types

### abyss-extfs
- Superblock: valid parse, bad magic, ext4 feature detection, block size calculation
- Block group descriptor: 32-byte and 64-byte variants
- Inode: mode/size parsing, direct blocks, extent tree parsing
- Directory entries: linear traversal, file type detection
- Integration: find_file from root (inode 2) through directory chain

### abyss-registry
- Hive header: valid parse (regf magic), invalid magic
- Named key (nk): parse, subkey enumeration
- Value (vk): parse different data types

### abyss-crypto
- SAM hash extraction with known test vectors
- SYSKEY derivation
- MD5/DES round-trip where applicable

### abyss-output
- Finding variant construction
- Hashcat format output for known hash types
- JSON serialization round-trip

---

## Dependencies Changes

**abyss-container/Cargo.toml** — add:
- `flate2 = "1"` (zlib for E01)

**abyss-target/Cargo.toml** — add:
- `abyss-extfs = { workspace = true }` (if not already present)

**Workspace Cargo.toml** — add:
- `flate2 = "1"` to `[workspace.dependencies]`
