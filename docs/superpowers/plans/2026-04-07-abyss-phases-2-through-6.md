# Abyss Phases 2-6 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix container passthrough (E01/VMDK), add NTDS.dit AD analysis, memory analysis, Firefox credential extraction, and cloud credential expansion.

**Architecture:** Each phase is independent and builds on the existing extractor pipeline. Phase 1 fixes a critical integration bug. Phases 2-5 each add a new crate or extractor module that plugs into the existing `Extractor` trait → `Collector` → `Finding` pipeline.

**Tech Stack:** Rust, existing abyss workspace crates, flate2 (zlib), aes/hmac/sha2 (crypto)

---

## Phase 1: Fix Container Passthrough (E01/VMDK end-to-end)

**Problem:** `Target::open()` calls `detect_and_open()` but discards the returned `BlockDevice`. All subsequent operations use raw `File` handles, meaning E01 and VMDK images silently fail — the compressed/remapped bytes can't be parsed as MBR/GPT/NTFS/ext4.

**Fix:** Thread the `BlockDevice` through the pipeline. Use a single `Box<dyn BlockDevice>` for partition discovery and filesystem probing instead of opening fresh `File` handles.

### Task 1.1: Make BlockDevice cloneable via reopen pattern

**Files:**
- Modify: `crates/abyss-container/src/traits.rs`
- Modify: `crates/abyss-container/src/raw.rs`
- Modify: `crates/abyss-container/src/e01.rs`
- Modify: `crates/abyss-container/src/vmdk.rs`

The core problem is that `Target::open()` needs multiple independent readers (partition discovery, NTFS probe, NTFS open, ext probe, ext open) but `BlockDevice` is consumed. We need the ability to create sub-readers from a single BlockDevice.

- [ ] **Step 1: Add a `SubReader` wrapper that shares data via `Arc<Mutex<>>`**

Create `crates/abyss-container/src/shared.rs`:

```rust
//! SharedBlockDevice — wraps a BlockDevice so multiple readers can share it.

use std::io::{Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex};

use crate::traits::BlockDevice;

/// Inner state shared between all sub-readers.
struct SharedInner {
    device: Box<dyn BlockDevice>,
}

/// A cloneable handle to a shared BlockDevice.
/// Each clone maintains its own virtual seek position.
pub struct SharedBlockDevice {
    inner: Arc<Mutex<SharedInner>>,
    position: u64,
    size: u64,
}

impl SharedBlockDevice {
    /// Wrap a BlockDevice for shared access.
    pub fn new(device: Box<dyn BlockDevice>) -> Self {
        let size = device.size();
        Self {
            inner: Arc::new(Mutex::new(SharedInner { device })),
            position: 0,
            size,
        }
    }

    /// Create a new independent reader at position 0.
    pub fn clone_reader(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            position: 0,
            size: self.size,
        }
    }

    /// Total media size.
    pub fn size(&self) -> u64 {
        self.size
    }
}

impl Read for SharedBlockDevice {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut inner = self.inner.lock().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::Other, "lock poisoned")
        })?;
        inner.device.seek(SeekFrom::Start(self.position))?;
        let n = inner.device.read(buf)?;
        self.position += n as u64;
        Ok(n)
    }
}

impl Seek for SharedBlockDevice {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::End(offset) => (self.size as i64 + offset).max(0) as u64,
            SeekFrom::Current(offset) => (self.position as i64 + offset).max(0) as u64,
        };
        self.position = new_pos.min(self.size);
        Ok(self.position)
    }
}

// SharedBlockDevice is Send because Arc<Mutex<>> is Send.
unsafe impl Send for SharedBlockDevice {}
```

- [ ] **Step 2: Export the new module**

Update `crates/abyss-container/src/lib.rs`:

```rust
pub mod detect;
pub mod e01;
pub mod error;
pub mod raw;
pub mod shared;
pub mod traits;
pub mod vmdk;

pub use detect::detect_and_open;
pub use error::ContainerError;
pub use shared::SharedBlockDevice;
pub use traits::{BlockDevice, ContainerParser};
```

- [ ] **Step 3: Build and verify**

Run: `cargo build -p abyss-container`
Expected: compiles clean

- [ ] **Step 4: Commit**

```
git add crates/abyss-container/src/shared.rs crates/abyss-container/src/lib.rs
git commit -m "feat(container): add SharedBlockDevice for multi-reader access"
```

### Task 1.2: Refactor Target::open() to use BlockDevice

**Files:**
- Modify: `crates/abyss-target/src/target.rs`

- [ ] **Step 1: Replace File-based pipeline with SharedBlockDevice**

Replace the `Target::open()` method. Key changes:
1. Call `detect_and_open()` to get a `Box<dyn BlockDevice>`
2. Wrap in `SharedBlockDevice`
3. Use `clone_reader()` for partition discovery, each filesystem probe, and each filesystem open
4. Remove all `File::open(path)` calls after the initial one
5. Remove `PartitionReader` — instead use a new `SliceReader` that wraps a `SharedBlockDevice` with base offset + size

```rust
use abyss_container::{detect_and_open, SharedBlockDevice};

/// Reader that presents a slice of a SharedBlockDevice as a standalone ReadSeek.
struct SliceReader {
    device: SharedBlockDevice,
    base_offset: u64,
    size: u64,
    position: u64,
}

impl SliceReader {
    fn new(device: SharedBlockDevice, base_offset: u64, size: u64) -> Self {
        Self { device, base_offset, size, position: 0 }
    }
}

impl Read for SliceReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self.size.saturating_sub(self.position);
        if remaining == 0 { return Ok(0); }
        let max = buf.len().min(remaining as usize);
        self.device.seek(SeekFrom::Start(self.base_offset + self.position))?;
        let n = self.device.read(&mut buf[..max])?;
        self.position += n as u64;
        Ok(n)
    }
}

impl Seek for SliceReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::End(offset) => (self.size as i64 + offset).max(0) as u64,
            SeekFrom::Current(offset) => (self.position as i64 + offset).max(0) as u64,
        };
        self.position = new_pos.min(self.size);
        Ok(self.position)
    }
}
```

Then rewrite `Target::open()`:

```rust
pub fn open(path: &Path) -> Result<Self, TargetError> {
    let file = File::open(path).map_err(|e| TargetError::OpenFailed {
        detail: e.to_string(),
    })?;
    let reader: Box<dyn ReadSeek> = Box::new(BufReader::new(file));
    let container = detect_and_open(reader)?;
    let shared = SharedBlockDevice::new(container);

    // Partition discovery using the virtual disk surface
    let mut disc_reader = shared.clone_reader();
    let partitions = match discover_partitions(&mut disc_reader, 512u64) {
        Ok(parts) => parts,
        Err(_) => Vec::new(),
    };

    let mut os = OsType::Unknown;
    let mut ntfs: Option<NtfsFilesystem> = None;
    let mut extfs: Option<ExtFilesystem> = None;

    if partitions.is_empty() {
        // Try whole image as filesystem
        let size = shared.size();
        let mut probe_reader: Box<dyn ReadSeek> =
            Box::new(SliceReader::new(shared.clone_reader(), 0, size));
        if NtfsFilesystem::probe(&mut probe_reader) {
            let open_reader: Box<dyn ReadSeek> =
                Box::new(SliceReader::new(shared.clone_reader(), 0, size));
            match NtfsFilesystem::open(open_reader) {
                Ok(fs) => { os = OsType::Windows; ntfs = Some(fs); }
                Err(e) => log::debug!("NTFS open failed on whole image: {}", e),
            }
        }
        if ntfs.is_none() {
            let mut probe_reader: Box<dyn ReadSeek> =
                Box::new(SliceReader::new(shared.clone_reader(), 0, size));
            if ExtFilesystem::probe(&mut probe_reader) {
                let open_reader: Box<dyn ReadSeek> =
                    Box::new(SliceReader::new(shared.clone_reader(), 0, size));
                match ExtFilesystem::open(open_reader) {
                    Ok(fs) => { os = OsType::Linux; extfs = Some(fs); }
                    Err(e) => log::debug!("ext open failed on whole image: {}", e),
                }
            }
        }
    } else {
        // Probe partitions
        for partition in &partitions {
            let mut probe_reader: Box<dyn ReadSeek> = Box::new(SliceReader::new(
                shared.clone_reader(), partition.offset, partition.size,
            ));
            if NtfsFilesystem::probe(&mut probe_reader) {
                let open_reader: Box<dyn ReadSeek> = Box::new(SliceReader::new(
                    shared.clone_reader(), partition.offset, partition.size,
                ));
                match NtfsFilesystem::open(open_reader) {
                    Ok(fs) => { os = OsType::Windows; ntfs = Some(fs); break; }
                    Err(e) => log::debug!("NTFS open failed on partition {}: {}", partition.index, e),
                }
            }
        }
        if ntfs.is_none() {
            for partition in &partitions {
                let mut probe_reader: Box<dyn ReadSeek> = Box::new(SliceReader::new(
                    shared.clone_reader(), partition.offset, partition.size,
                ));
                if ExtFilesystem::probe(&mut probe_reader) {
                    let open_reader: Box<dyn ReadSeek> = Box::new(SliceReader::new(
                        shared.clone_reader(), partition.offset, partition.size,
                    ));
                    match ExtFilesystem::open(open_reader) {
                        Ok(fs) => { os = OsType::Linux; extfs = Some(fs); break; }
                        Err(e) => log::debug!("ext open failed on partition {}: {}", partition.index, e),
                    }
                }
            }
        }
    }

    Ok(Target { os, hostname: None, version: None, domain: None, partitions, ntfs, extfs })
}
```

- [ ] **Step 2: Remove the old PartitionReader struct and unused imports**

Delete the `PartitionReader` struct and `use std::fs::File` (keep only one `File` import for the initial open). Remove `use abyss_container::raw::RawContainer` and `use abyss_container::traits::ContainerParser` if present.

- [ ] **Step 3: Build and verify**

Run: `cargo build`
Expected: full workspace compiles clean

- [ ] **Step 4: Run all tests**

Run: `cargo test`
Expected: all 286+ tests pass

- [ ] **Step 5: Commit**

```
git commit -m "fix(target): thread BlockDevice through pipeline for E01/VMDK support"
```

### Task 1.3: Add SharedBlockDevice tests

**Files:**
- Create: `crates/abyss-container/tests/shared_test.rs`

- [ ] **Step 1: Write tests**

```rust
use std::io::{Cursor, Read, Seek, SeekFrom};
use abyss_container::{detect_and_open, SharedBlockDevice};

#[test]
fn shared_clone_readers_are_independent() {
    let data = vec![0xAA; 1024];
    let cursor: Box<dyn abyss_cstruct::read::ReadSeek> = Box::new(Cursor::new(data.clone()));
    let container = detect_and_open(cursor).unwrap();
    let shared = SharedBlockDevice::new(container);

    let mut r1 = shared.clone_reader();
    let mut r2 = shared.clone_reader();

    // Read 10 bytes from r1
    let mut buf1 = [0u8; 10];
    r1.read_exact(&mut buf1).unwrap();
    assert_eq!(buf1, [0xAA; 10]);

    // r2 is still at position 0
    r2.seek(SeekFrom::Current(0)).unwrap();
    let mut buf2 = [0u8; 5];
    r2.read_exact(&mut buf2).unwrap();
    assert_eq!(buf2, [0xAA; 5]);
}

#[test]
fn shared_size_matches_original() {
    let data = vec![0x55; 2048];
    let cursor: Box<dyn abyss_cstruct::read::ReadSeek> = Box::new(Cursor::new(data));
    let container = detect_and_open(cursor).unwrap();
    let shared = SharedBlockDevice::new(container);
    assert_eq!(shared.size(), 2048);
}

#[test]
fn shared_seek_from_end() {
    let data: Vec<u8> = (0..100).collect();
    let cursor: Box<dyn abyss_cstruct::read::ReadSeek> = Box::new(Cursor::new(data));
    let container = detect_and_open(cursor).unwrap();
    let shared = SharedBlockDevice::new(container);
    let mut reader = shared.clone_reader();

    reader.seek(SeekFrom::End(-10)).unwrap();
    let mut buf = [0u8; 10];
    reader.read_exact(&mut buf).unwrap();
    assert_eq!(buf, [90, 91, 92, 93, 94, 95, 96, 97, 98, 99]);
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test -p abyss-container`
Expected: all pass

- [ ] **Step 3: Commit**

```
git commit -m "test(container): add SharedBlockDevice integration tests"
```

---

## Phase 2: NTDS.dit / Active Directory Analysis

**Goal:** Parse NTDS.dit (ESE/JET database), extract domain user hashes, and emit findings.

**Architecture:** New `abyss-ese` crate for Extensible Storage Engine database parsing. New `NtdsExtractor` in abyss-target that reads NTDS.dit + SYSTEM hive, derives the PEK (Password Encryption Key), and decrypts NT/LM hashes for all domain accounts.

### Task 2.1: Create abyss-ese crate scaffold

**Files:**
- Create: `crates/abyss-ese/Cargo.toml`
- Create: `crates/abyss-ese/src/lib.rs`
- Create: `crates/abyss-ese/src/error.rs`
- Modify: `Cargo.toml` (workspace)

- [ ] **Step 1: Add crate to workspace**

Add `"crates/abyss-ese"` to workspace members in root `Cargo.toml`.
Add `abyss-ese = { path = "crates/abyss-ese" }` to `[workspace.dependencies]`.

- [ ] **Step 2: Create Cargo.toml**

```toml
[package]
name = "abyss-ese"
version.workspace = true
edition.workspace = true
license.workspace = true
description = "ESE/JET database parser for NTDS.dit"

[dependencies]
abyss-cstruct = { workspace = true }
thiserror = { workspace = true }
log = { workspace = true }
```

- [ ] **Step 3: Create error.rs**

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EseError {
    #[error("not an ESE database")]
    NotEse,

    #[error("unsupported ESE version: {version}")]
    UnsupportedVersion { version: u32 },

    #[error("table not found: {name}")]
    TableNotFound { name: String },

    #[error("column not found: {name}")]
    ColumnNotFound { name: String },

    #[error("page {page} out of range")]
    PageOutOfRange { page: u32 },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("parse error: {0}")]
    Parse(#[from] abyss_cstruct::ParseError),
}
```

- [ ] **Step 4: Create lib.rs**

```rust
//! abyss-ese: Extensible Storage Engine (ESE/JET) database parser.
//!
//! Parses NTDS.dit and other ESE databases used by Windows.

pub mod error;

pub use error::EseError;
```

- [ ] **Step 5: Build**

Run: `cargo build -p abyss-ese`

- [ ] **Step 6: Commit**

```
git commit -m "feat: scaffold abyss-ese crate for ESE/JET database parsing"
```

### Task 2.2: Implement ESE database header and page parsing

**Files:**
- Create: `crates/abyss-ese/src/header.rs`
- Create: `crates/abyss-ese/src/page.rs`
- Create: `crates/abyss-ese/tests/ese_test.rs`

The ESE database format:
- Header at page 0 (4096 or 8192 bytes): magic `0x89ABCDEF` at offset 4, page size at offset 236 (u32)
- Pages are fixed-size (4096 or 8192 bytes)
- Each page has a 40-byte header: checksum, page number, flags, etc.
- Page types: database header (0), branch (1-4), leaf data (7), leaf index (8), space tree (3), long value (5)

- [ ] **Step 1: Implement database header parser**

Parse the file header (first page):
- `magic` (u32 at offset 4) = `0x89ABCDEF`
- `database_version` (u32 at offset 8) — ESE version
- `page_size` (u32 at offset 236) — 4096 or 8192

- [ ] **Step 2: Implement page header parser**

Parse the 40-byte page header:
- `checksum` (u64 at 0)
- `page_number` (u32 at 8)
- `previous_page` (u32 at 16)
- `next_page` (u32 at 20)
- `available_data_size` (u16 at 30)
- `page_flags` (u32 at 32) — leaf/branch/empty/etc.

- [ ] **Step 3: Implement page reader**

```rust
pub struct EseDatabase {
    reader: Box<dyn ReadSeek>,
    pub page_size: u32,
    pub version: u32,
}

impl EseDatabase {
    pub fn open(reader: Box<dyn ReadSeek>) -> Result<Self, EseError>;
    pub fn read_page(&mut self, page_num: u32) -> Result<Vec<u8>, EseError>;
}
```

- [ ] **Step 4: Write tests with synthetic ESE header**

- [ ] **Step 5: Build and test**

Run: `cargo test -p abyss-ese`

- [ ] **Step 6: Commit**

```
git commit -m "feat(ese): implement ESE database header and page parsing"
```

### Task 2.3: Implement ESE table catalog and record parsing

**Files:**
- Create: `crates/abyss-ese/src/catalog.rs`
- Create: `crates/abyss-ese/src/record.rs`
- Create: `crates/abyss-ese/src/table.rs`
- Modify: `crates/abyss-ese/src/lib.rs`

The ESE catalog lives in the MSysObjects table (object ID 2):
- Columns define the schema: column ID, name, type, size
- Records are stored in B+ tree leaf pages
- Tagged columns store variable-length data (where NT hashes live)

- [ ] **Step 1: Parse MSysObjects catalog**

Walk page tree starting from root page for object ID 2. Extract table definitions, column definitions (ID, name, type, size, tagged flag).

```rust
pub struct CatalogEntry {
    pub obj_id: u32,
    pub obj_type: u16,      // 1=table, 2=column, 3=index
    pub name: String,
    pub column_id: Option<u32>,
    pub column_type: Option<u16>,
}
```

- [ ] **Step 2: Implement leaf page record parsing**

Parse variable-length record format:
- Fixed columns (known size, packed sequentially)
- Variable columns (2-byte offset array after fixed data)
- Tagged columns (tag ID + offset pairs, then data)

```rust
pub struct EseRecord {
    pub columns: Vec<(u32, Vec<u8>)>,  // column_id -> raw bytes
}
```

- [ ] **Step 3: Implement table reader**

```rust
impl EseDatabase {
    pub fn open_table(&mut self, name: &str) -> Result<EseTable, EseError>;
}

pub struct EseTable {
    pub name: String,
    pub columns: Vec<ColumnDef>,
    pub root_page: u32,
}

impl EseTable {
    pub fn iter_records<'a>(&'a self, db: &'a mut EseDatabase) -> RecordIterator<'a>;
}
```

- [ ] **Step 4: Write tests**

- [ ] **Step 5: Build and test**

Run: `cargo test -p abyss-ese`

- [ ] **Step 6: Commit**

```
git commit -m "feat(ese): implement catalog parsing and record iteration"
```

### Task 2.4: Add NTDS hash extraction

**Files:**
- Create: `crates/abyss-crypto/src/ntds.rs`
- Modify: `crates/abyss-crypto/src/lib.rs`
- Create: `crates/abyss-target/src/extractors/ntds.rs`
- Modify: `crates/abyss-target/src/extractors/mod.rs`

NTDS.dit hash extraction:
1. Open datatable from NTDS.dit ESE database
2. Find columns: ATTm590045 (SAM account name), ATTk590689 (NT hash encrypted), ATTk590690 (LM hash encrypted), ATTr589970 (RID from objectSid), ATTq589922 (userAccountControl)
3. Derive PEK (Password Encryption Key) from SYSTEM hive SYSKEY + PEK table in datatable
4. For each user row: decrypt NT/LM hash using PEK + RID

- [ ] **Step 1: Implement PEK decryption in abyss-crypto**

```rust
// crates/abyss-crypto/src/ntds.rs
pub fn decrypt_pek(encrypted_pek: &[u8], syskey: &[u8; 16]) -> Result<Vec<u8>, CryptoError>;
pub fn decrypt_ntds_hash(encrypted: &[u8], pek: &[u8], rid: u32) -> Result<Vec<u8>, CryptoError>;
```

PEK decryption: MD5(syskey + RC4_key_material) → RC4 → decrypted PEK
Hash decryption: AES-128-CBC (PEK v4) or RC4 (PEK v1) → remove padding → DES with RID

- [ ] **Step 2: Add NtdsHash Finding variant**

Add to `crates/abyss-output/src/finding.rs`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtdsHashFinding {
    pub domain: String,
    pub username: String,
    pub rid: u32,
    pub nt_hash: String,
    pub lm_hash: String,
    pub enabled: bool,
    pub history: Vec<String>,  // NT hash history entries
}
```

Add `NtdsHash(NtdsHashFinding)` to the Finding enum.
Update `type_name()`, text formatter, JSON formatter, hashcat formatter (mode 1000, same as SAM).

- [ ] **Step 3: Implement NtdsExtractor**

```rust
pub struct NtdsExtractor;

impl Extractor for NtdsExtractor {
    fn name(&self) -> &'static str { "NTDS" }
    fn is_compatible(&self, ctx: &ExtractionContext) -> bool {
        ctx.system_hive.is_some() // Need SYSKEY
    }
    fn extract(&self, ctx: &mut ExtractionContext, collector: &mut Collector) -> Result<(), TargetError> {
        // 1. Read NTDS.dit from filesystem
        // 2. Open as ESE database
        // 3. Derive PEK from SYSKEY
        // 4. Iterate datatable rows, decrypt hashes
        // 5. Emit NtdsHash findings
    }
}
```

- [ ] **Step 4: Wire NtdsExtractor into Target::extract()**

Add `NtdsExtractor` to the extractor list in `target.rs`.
Update `build_extraction_context()` to read `Windows/NTDS/ntds.dit` from the filesystem into a new `ntds_dit` field on `ExtractionContext`.

- [ ] **Step 5: Add abyss-ese dependency to abyss-target**

- [ ] **Step 6: Write tests**

- [ ] **Step 7: Build and test**

Run: `cargo test`

- [ ] **Step 8: Commit**

```
git commit -m "feat: add NTDS.dit parsing and domain hash extraction"
```

---

## Phase 3: Memory Analysis

**Goal:** Parse Windows memory dumps (full dumps, minidumps) to extract credentials from LSASS process memory.

**Architecture:** New `abyss-memory` crate for memory dump parsing (minidump format). New `MemoryExtractor` that locates LSASS credential structures (Wdigest, Kerberos, NTLM, DPAPI) in memory.

### Task 3.1: Create abyss-memory crate scaffold

**Files:**
- Create: `crates/abyss-memory/Cargo.toml`
- Create: `crates/abyss-memory/src/lib.rs`
- Create: `crates/abyss-memory/src/error.rs`
- Modify: `Cargo.toml` (workspace)

- [ ] **Step 1: Add crate to workspace**

Add `"crates/abyss-memory"` to workspace members.
Add `abyss-memory = { path = "crates/abyss-memory" }` to workspace deps.

- [ ] **Step 2: Create Cargo.toml**

```toml
[package]
name = "abyss-memory"
version.workspace = true
edition.workspace = true
license.workspace = true
description = "Memory dump parser for credential extraction"

[dependencies]
abyss-cstruct = { workspace = true }
thiserror = { workspace = true }
log = { workspace = true }
```

- [ ] **Step 3: Create error.rs**

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MemoryError {
    #[error("not a valid memory dump")]
    NotMemoryDump,

    #[error("unsupported dump format: {format}")]
    UnsupportedFormat { format: String },

    #[error("LSASS process not found")]
    LsassNotFound,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("parse error: {0}")]
    Parse(#[from] abyss_cstruct::ParseError),
}
```

- [ ] **Step 4: Create lib.rs**

```rust
//! abyss-memory: Memory dump parser for credential extraction.

pub mod error;

pub use error::MemoryError;
```

- [ ] **Step 5: Build and commit**

```
git commit -m "feat: scaffold abyss-memory crate for memory analysis"
```

### Task 3.2: Implement minidump parser

**Files:**
- Create: `crates/abyss-memory/src/minidump.rs`
- Create: `crates/abyss-memory/src/streams.rs`
- Create: `crates/abyss-memory/tests/minidump_test.rs`

Minidump format (MDMP):
- Header: signature `MDMP` (4D 44 4D 50) at offset 0, version, stream count, stream directory RVA
- Stream directory: array of (stream_type, data_size, RVA) entries
- Key streams: SystemInfo (7), ModuleList (4), Memory64List (9), MemoryList (6)
- Memory64List contains (start_address, data_size) pairs followed by contiguous memory data

- [ ] **Step 1: Parse minidump header**

```rust
pub struct MinidumpHeader {
    pub signature: u32,        // MDMP = 0x504D444D
    pub version: u32,
    pub stream_count: u32,
    pub stream_directory_rva: u32,
}
```

- [ ] **Step 2: Parse stream directory**

```rust
pub struct StreamDirectoryEntry {
    pub stream_type: u32,
    pub data_size: u32,
    pub rva: u32,
}
```

- [ ] **Step 3: Parse Memory64List**

```rust
pub struct Memory64List {
    pub ranges: Vec<MemoryRange>,
    pub base_rva: u64,  // where contiguous data starts
}

pub struct MemoryRange {
    pub start: u64,
    pub size: u64,
}
```

- [ ] **Step 4: Implement virtual address reader**

```rust
pub struct MinidumpReader {
    reader: Box<dyn ReadSeek>,
    memory_ranges: Vec<(u64, u64, u64)>,  // (virtual_addr, file_offset, size)
}

impl MinidumpReader {
    pub fn open(reader: Box<dyn ReadSeek>) -> Result<Self, MemoryError>;
    pub fn read_virtual(&mut self, address: u64, size: usize) -> Result<Vec<u8>, MemoryError>;
    pub fn search_pattern(&mut self, pattern: &[u8]) -> Result<Vec<u64>, MemoryError>;
}
```

- [ ] **Step 5: Write tests with synthetic minidump**

- [ ] **Step 6: Build, test, commit**

```
git commit -m "feat(memory): implement minidump parser with virtual address translation"
```

### Task 3.3: Implement LSASS credential extraction

**Files:**
- Create: `crates/abyss-memory/src/lsass.rs`
- Create: `crates/abyss-memory/src/credentials.rs`
- Create: `crates/abyss-target/src/extractors/memory.rs`
- Modify: `crates/abyss-target/src/extractors/mod.rs`

LSASS credential structures:
- Scan for known signatures of credential provider structs (Wdigest, Kerberos, MSVC1, TSPKG)
- Each has fixed-offset fields: username (UNICODE_STRING), domain (UNICODE_STRING), password/hash
- UNICODE_STRING: { length (u16), max_length (u16), buffer_pointer (u64 on x64) }
- Encryption: 3DES-CBC or AES-256-CFB depending on Windows version
- Crypto keys stored in lsasrv.dll memory — located by signature scanning

- [ ] **Step 1: Implement credential structure definitions**

```rust
pub struct LsassCredential {
    pub provider: String,       // "wdigest", "kerberos", "msv1_0", "tspkg"
    pub domain: String,
    pub username: String,
    pub password: Option<String>,
    pub nt_hash: Option<Vec<u8>>,
}
```

- [ ] **Step 2: Implement signature scanning for credential providers**

Known Wdigest signature: specific byte patterns near l_LogSessList pointer.
Known MSV1 signature: patterns near NlpSessions.

- [ ] **Step 3: Add MemoryCredential Finding variant**

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryCredentialFinding {
    pub provider: String,
    pub domain: String,
    pub username: String,
    pub password: Option<String>,
    pub nt_hash: Option<String>,
}
```

- [ ] **Step 4: Implement MemoryExtractor**

- [ ] **Step 5: Add `memory` CLI subcommand**

Update `abyss-cli/src/main.rs` to add:
```rust
Memory {
    /// Path to memory dump
    path: String,
}
```

- [ ] **Step 6: Wire into extractors, write tests, build**

Run: `cargo test`

- [ ] **Step 7: Commit**

```
git commit -m "feat: add LSASS memory dump credential extraction"
```

---

## Phase 4: Firefox Credential Extraction

**Goal:** Extract saved passwords from Firefox profiles (key4.db + logins.json).

**Architecture:** New module in `abyss-browser` crate. Firefox uses NSS key storage — key4.db is a SQLite-like database containing the master key encrypted with PKCS#5/PBKDF2, and logins.json contains 3DES-CBC encrypted credentials.

### Task 4.1: Implement Firefox profile discovery

**Files:**
- Create: `crates/abyss-browser/src/firefox.rs`
- Modify: `crates/abyss-browser/src/lib.rs`

- [ ] **Step 1: Implement Firefox profile path scanning**

Firefox profiles live at:
- Windows: `Users/<user>/AppData/Roaming/Mozilla/Firefox/Profiles/`
- Linux: `home/<user>/.mozilla/firefox/`

Each profile directory contains `key4.db` (master key) and `logins.json` (encrypted creds).

```rust
pub struct FirefoxProfile {
    pub user: String,
    pub profile_name: String,
    pub key4_db: Vec<u8>,
    pub logins_json: Vec<u8>,
}

pub fn discover_firefox_profiles(
    filesystem_files: &HashMap<String, Vec<u8>>
) -> Vec<FirefoxProfile>;
```

- [ ] **Step 2: Build and commit**

```
git commit -m "feat(browser): add Firefox profile discovery"
```

### Task 4.2: Implement key4.db parser and master key decryption

**Files:**
- Modify: `crates/abyss-browser/src/firefox.rs`
- Create: `crates/abyss-browser/tests/firefox_test.rs`

key4.db is a BerkeleyDB or SQLite database containing:
- `metaData` table: `password-check` entry encrypted with the master key
- `nssPrivate` table: contains the actual decryption key (a11 + a102 entries)
- Key derivation: PKCS#5 PBKDF2 with SHA-256, then 3DES-CBC

For no-master-password case (most common in forensics):
1. Read `globalSalt` from metaData
2. Read encrypted private key from nssPrivate (a11 attribute)
3. Derive key: SHA1(globalSalt + empty_password) → PBKDF2-HMAC-SHA256 → 3DES key
4. Decrypt the private key → this is the content decryption key

- [ ] **Step 1: Implement BerkeleyDB/SQLite minimal parser for key4.db**

The key4.db format changed across Firefox versions:
- Older: BerkeleyDB hash format
- Newer (67+): SQLite

Since we're parsing raw bytes (no SQLite library), implement a minimal SQLite page parser that reads the `metaData` and `nssPrivate` tables. SQLite format:
- 100-byte header with magic `SQLite format 3\000`
- Page size at offset 16 (u16, big-endian)
- B-tree pages with cell pointers

```rust
pub fn parse_key4_db(data: &[u8]) -> Result<Key4Data, FirefoxError>;

pub struct Key4Data {
    pub global_salt: Vec<u8>,
    pub encrypted_key: Vec<u8>,  // a11 from nssPrivate
    pub password_check: Vec<u8>, // from metaData
}
```

- [ ] **Step 2: Implement PKCS#5 key derivation and 3DES decryption**

```rust
pub fn derive_firefox_key(
    global_salt: &[u8],
    master_password: &[u8],  // empty for no-master-password
    encrypted_key: &[u8],
) -> Result<Vec<u8>, FirefoxError>;
```

- [ ] **Step 3: Write tests**

- [ ] **Step 4: Build, test, commit**

```
git commit -m "feat(browser): implement Firefox key4.db parsing and key derivation"
```

### Task 4.3: Implement logins.json decryption and extraction

**Files:**
- Modify: `crates/abyss-browser/src/firefox.rs`
- Create: `crates/abyss-target/src/extractors/firefox.rs` (or extend browser.rs)
- Modify: `crates/abyss-target/src/extractors/mod.rs`

logins.json format:
```json
{
  "logins": [
    {
      "hostname": "https://example.com",
      "encryptedUsername": "<base64 ASN.1 blob>",
      "encryptedPassword": "<base64 ASN.1 blob>"
    }
  ]
}
```

Each encrypted field is a base64-encoded ASN.1 structure:
- SEQUENCE { OID (DES-EDE3-CBC), SEQUENCE { OCTET STRING (IV) }, OCTET STRING (ciphertext) }

- [ ] **Step 1: Parse logins.json**

```rust
pub fn parse_logins_json(data: &[u8]) -> Result<Vec<EncryptedLogin>, FirefoxError>;

pub struct EncryptedLogin {
    pub hostname: String,
    pub encrypted_username: Vec<u8>,
    pub encrypted_password: Vec<u8>,
}
```

- [ ] **Step 2: Implement ASN.1 blob parsing and 3DES decryption**

```rust
pub fn decrypt_firefox_field(
    encrypted: &[u8],
    key: &[u8],
) -> Result<String, FirefoxError>;
```

Parse the ASN.1 to extract IV + ciphertext, then 3DES-CBC decrypt with the derived key.

- [ ] **Step 3: Wire into BrowserExtractor or create FirefoxExtractor**

Add Firefox profile scanning to `build_extraction_context()` — read key4.db and logins.json files for each discovered user.

Emit `BrowserCredential` findings (reuse existing variant with browser="Firefox").

- [ ] **Step 4: Write tests, build, test all**

Run: `cargo test`

- [ ] **Step 5: Commit**

```
git commit -m "feat: add Firefox credential extraction from key4.db + logins.json"
```

---

## Phase 5: Cloud Credential Expansion

**Goal:** Detect and extract cloud provider credentials (AWS, Azure, GCP) and common service tokens from disk images.

**Architecture:** Extend the existing `LinuxCredsExtractor` and add a new `CloudExtractor` that scans known config file paths and environment variable files for credential material.

### Task 5.1: Add CloudCredential Finding variant

**Files:**
- Modify: `crates/abyss-output/src/finding.rs`
- Modify: `crates/abyss-output/src/text.rs`
- Modify: `crates/abyss-output/src/json.rs`

- [ ] **Step 1: Add the Finding variant**

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudCredentialFinding {
    pub provider: String,       // "aws", "azure", "gcp", "github", "gitlab", "digitalocean"
    pub credential_type: String, // "access_key", "token", "service_account", "connection_string"
    pub identifier: Option<String>, // key ID, subscription, project
    pub secret_preview: String,  // first 8 chars + "..." for safety
    pub source_path: String,     // where it was found
    pub user: Option<String>,
}
```

- [ ] **Step 2: Update formatters**

- [ ] **Step 3: Build, commit**

```
git commit -m "feat(output): add CloudCredential finding variant"
```

### Task 5.2: Implement cloud credential scanner

**Files:**
- Create: `crates/abyss-target/src/extractors/cloud.rs`
- Modify: `crates/abyss-target/src/extractors/mod.rs`

- [ ] **Step 1: Define scan paths and patterns**

```rust
// AWS
"home/{user}/.aws/credentials"     // [default] aws_access_key_id / aws_secret_access_key
"home/{user}/.aws/config"          // region, role_arn
"root/.aws/credentials"

// Azure
"home/{user}/.azure/accessTokens.json"   // OAuth tokens
"home/{user}/.azure/azureProfile.json"   // subscription info
"home/{user}/.azure/msal_token_cache.json"

// GCP
"home/{user}/.config/gcloud/credentials.db"
"home/{user}/.config/gcloud/application_default_credentials.json"  // service account JSON
"home/{user}/.config/gcloud/properties"

// GitHub/GitLab
"home/{user}/.config/gh/hosts.yml"        // GitHub CLI token
"home/{user}/.config/hub"                 // Hub CLI token

// Docker
"home/{user}/.docker/config.json"         // registry auth (base64 user:pass)

// Kubernetes
"home/{user}/.kube/config"                // cluster certs + tokens

// Terraform
"home/{user}/.terraform.d/credentials.tfrc.json"  // Terraform Cloud token

// Environment files
"home/{user}/.env"
"home/{user}/.bashrc"                     // export AWS_SECRET_ACCESS_KEY=...
"home/{user}/.bash_profile"
"home/{user}/.profile"
"home/{user}/.zshrc"

// Windows equivalents
"Users/{user}/.aws/credentials"
"Users/{user}/.azure/accessTokens.json"
"Users/{user}/AppData/Roaming/gcloud/credentials.db"
```

- [ ] **Step 2: Implement credential parsers**

For each format, parse and extract:
- INI format (AWS credentials): section/key/value parsing
- JSON format (Azure, GCP, GitHub): serde_json value extraction
- YAML format (kube config): basic key scanning (no full YAML parser — regex for `token:`, `password:`, `client-certificate-data:`)
- Shell format (.bashrc, .env): regex for `export KEY=VALUE` and `KEY=VALUE` patterns matching known credential variable names
- Docker config.json: base64-decode the `auth` field

```rust
pub struct CloudExtractor;

impl Extractor for CloudExtractor {
    fn name(&self) -> &'static str { "Cloud Credentials" }
    fn is_compatible(&self, ctx: &ExtractionContext) -> bool {
        !ctx.filesystem_files.is_empty() || !ctx.discovered_users.is_empty()
    }
    fn extract(&self, ctx: &mut ExtractionContext, collector: &mut Collector) -> Result<(), TargetError>;
}
```

Known credential env var names to scan for:
```rust
const CREDENTIAL_ENV_VARS: &[(&str, &str)] = &[
    ("AWS_ACCESS_KEY_ID", "aws"),
    ("AWS_SECRET_ACCESS_KEY", "aws"),
    ("AWS_SESSION_TOKEN", "aws"),
    ("AZURE_CLIENT_SECRET", "azure"),
    ("AZURE_TENANT_ID", "azure"),
    ("GOOGLE_APPLICATION_CREDENTIALS", "gcp"),
    ("GITHUB_TOKEN", "github"),
    ("GITLAB_TOKEN", "gitlab"),
    ("DIGITALOCEAN_TOKEN", "digitalocean"),
    ("HEROKU_API_KEY", "heroku"),
    ("SLACK_TOKEN", "slack"),
    ("STRIPE_SECRET_KEY", "stripe"),
    ("DATABASE_URL", "database"),
    ("REDIS_URL", "redis"),
];
```

- [ ] **Step 3: Update build_extraction_context() to read cloud paths**

Add all the cloud config paths to the filesystem scanning in both `build_extraction_context()` (Windows/NTFS) and `build_linux_extraction_context()` (Linux/ext).

- [ ] **Step 4: Wire CloudExtractor into Target::extract()**

Add `Box::new(CloudExtractor)` to the extractors vec.

- [ ] **Step 5: Write tests**

Test INI parsing, JSON parsing, env var extraction with synthetic file data.

- [ ] **Step 6: Build, test all**

Run: `cargo test`

- [ ] **Step 7: Commit**

```
git commit -m "feat: add cloud credential scanning (AWS, Azure, GCP, GitHub, k8s, Docker)"
```

---

## Summary: Phase Dependency Graph

```
Phase 1 (Container fix) ← MUST be first, unblocks E01/VMDK
    ↓
Phase 2 (NTDS.dit)     ← Independent, Windows-focused
Phase 3 (Memory)        ← Independent, new file format
Phase 4 (Firefox)       ← Independent, extends browser crate
Phase 5 (Cloud creds)   ← Independent, extends extraction pipeline
```

Phases 2-5 are independent of each other and can be built in any order after Phase 1.
