/// Comprehensive unit tests for abyss-extfs.
///
/// All test data is constructed inline.  Filesystem-level tests use
/// `std::io::Cursor<Vec<u8>>`.
use std::io::Cursor;

use abyss_cstruct::read::FromBytes;
use abyss_extfs::{
    block_group::BlockGroupDescriptor,
    dir::{parse_directory_block, ExtFileType},
    extent::{ExtentEntry, ExtentHeader, ExtentIndex, EXTENT_MAGIC},
    extfs::ExtFilesystem,
    inode::{Inode, EXT4_EXTENTS_FL, S_IFDIR, S_IFREG},
    superblock::{Superblock, EXT_MAGIC, INCOMPAT_64BIT, SUPERBLOCK_SIZE},
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Write a little-endian u16 into `buf` at `offset`.
fn put_u16(buf: &mut [u8], offset: usize, val: u16) {
    let bytes = val.to_le_bytes();
    buf[offset] = bytes[0];
    buf[offset + 1] = bytes[1];
}

/// Write a little-endian u32 into `buf` at `offset`.
fn put_u32(buf: &mut [u8], offset: usize, val: u32) {
    let bytes = val.to_le_bytes();
    buf[offset..offset + 4].copy_from_slice(&bytes);
}

/// Build a minimal valid 1024-byte superblock buffer.
///
/// Offsets (relative to the superblock buffer, i.e. after the 1024-byte
/// bootloader gap):
///   0   s_inodes_count
///   4   s_blocks_count_lo
///  12   s_free_blocks_count_lo
///  16   s_free_inodes_count
///  24   s_log_block_size
///  28   s_log_frag_size
///  32   s_blocks_per_group
///  40   s_inodes_per_group
///  44   s_mtime
///  48   s_wtime
///  56   magic
///  58   s_state
///  60   s_errors
///  76   s_rev_level
///  84   s_first_ino       (rev >= 1)
///  88   s_inode_size      (rev >= 1)
///  96   s_feature_compat
/// 100   s_feature_incompat
/// 104   s_feature_ro_compat
/// 254   s_desc_size
/// 336   s_blocks_count_hi
fn make_superblock_buf() -> Vec<u8> {
    let mut buf = vec![0u8; SUPERBLOCK_SIZE];
    // magic
    put_u16(&mut buf, 56, EXT_MAGIC);
    // revision 1 so inode_size / first_ino fields are read
    put_u32(&mut buf, 76, 1);
    // inode count
    put_u32(&mut buf, 0, 1024);
    // block count lo
    put_u32(&mut buf, 4, 8192);
    // free blocks lo
    put_u32(&mut buf, 12, 4096);
    // free inodes
    put_u32(&mut buf, 16, 512);
    // log_block_size = 1 => 2048 bytes
    put_u32(&mut buf, 24, 1);
    // log_frag_size
    put_u32(&mut buf, 28, 1);
    // blocks_per_group
    put_u32(&mut buf, 32, 8192);
    // inodes_per_group
    put_u32(&mut buf, 40, 256);
    // mtime
    put_u32(&mut buf, 44, 0x6600_0000);
    // wtime
    put_u32(&mut buf, 48, 0x6600_0001);
    // state (clean)
    put_u16(&mut buf, 58, 1);
    // errors (continue)
    put_u16(&mut buf, 60, 1);
    // first_ino
    put_u32(&mut buf, 84, 11);
    // inode_size
    put_u16(&mut buf, 88, 256);
    // feature_compat
    put_u32(&mut buf, 96, 0x0038);
    // feature_incompat
    put_u32(&mut buf, 100, 0x02C6);
    // feature_ro_compat
    put_u32(&mut buf, 104, 0x0003);
    // desc_size (32 for non-64bit)
    put_u16(&mut buf, 254, 32);
    // blocks_count_hi (only used in 64-bit mode)
    put_u32(&mut buf, 336, 0);
    buf
}

// ---------------------------------------------------------------------------
// Superblock tests
// ---------------------------------------------------------------------------

#[test]
fn superblock_valid_parse() {
    let buf = make_superblock_buf();
    let sb = Superblock::from_bytes(&buf).expect("should parse");

    assert_eq!(sb.magic, EXT_MAGIC);
    assert_eq!(sb.s_inodes_count, 1024);
    assert_eq!(sb.s_blocks_count_lo, 8192);
    assert_eq!(sb.s_free_blocks_count_lo, 4096);
    assert_eq!(sb.s_free_inodes_count, 512);
    assert_eq!(sb.s_log_block_size, 1);
    assert_eq!(sb.s_blocks_per_group, 8192);
    assert_eq!(sb.s_inodes_per_group, 256);
    assert_eq!(sb.s_mtime, 0x6600_0000);
    assert_eq!(sb.s_wtime, 0x6600_0001);
    assert_eq!(sb.s_rev_level, 1);
    assert_eq!(sb.s_first_ino, 11);
    assert_eq!(sb.s_inode_size, 256);
    assert_eq!(sb.s_feature_compat, 0x0038);
    assert_eq!(sb.s_feature_incompat, 0x02C6);
    assert_eq!(sb.s_feature_ro_compat, 0x0003);
}

#[test]
fn superblock_invalid_magic() {
    let mut buf = make_superblock_buf();
    // Overwrite magic with wrong bytes
    put_u16(&mut buf, 56, 0x1234);
    let result = Superblock::from_bytes(&buf);
    assert!(result.is_err(), "should fail with wrong magic");
}

#[test]
fn superblock_buffer_too_small() {
    let buf = vec![0u8; 100]; // way too small
    let result = Superblock::from_bytes(&buf);
    assert!(result.is_err(), "should fail on undersized buffer");
}

#[test]
fn superblock_block_size_log0() {
    let mut buf = make_superblock_buf();
    put_u32(&mut buf, 24, 0); // log_block_size = 0 => 1024
    let sb = Superblock::from_bytes(&buf).unwrap();
    assert_eq!(sb.block_size(), 1024);
}

#[test]
fn superblock_block_size_log1() {
    let mut buf = make_superblock_buf();
    put_u32(&mut buf, 24, 1); // log_block_size = 1 => 2048
    let sb = Superblock::from_bytes(&buf).unwrap();
    assert_eq!(sb.block_size(), 2048);
}

#[test]
fn superblock_block_size_log2() {
    let mut buf = make_superblock_buf();
    put_u32(&mut buf, 24, 2); // log_block_size = 2 => 4096
    let sb = Superblock::from_bytes(&buf).unwrap();
    assert_eq!(sb.block_size(), 4096);
}

#[test]
fn superblock_has_64bit_false() {
    let mut buf = make_superblock_buf();
    // Clear INCOMPAT_64BIT (0x0080) from feature_incompat
    let fi: u32 = 0x02C6 & !(INCOMPAT_64BIT);
    put_u32(&mut buf, 100, fi);
    let sb = Superblock::from_bytes(&buf).unwrap();
    assert!(!sb.has_64bit());
}

#[test]
fn superblock_has_64bit_true() {
    let mut buf = make_superblock_buf();
    // Ensure INCOMPAT_64BIT is set
    put_u32(&mut buf, 100, INCOMPAT_64BIT);
    let sb = Superblock::from_bytes(&buf).unwrap();
    assert!(sb.has_64bit());
}

#[test]
fn superblock_total_blocks_no_64bit() {
    let mut buf = make_superblock_buf();
    // No 64-bit flag; total_blocks == blocks_count_lo
    put_u32(&mut buf, 100, 0); // clear incompat flags
    put_u32(&mut buf, 4, 12345);
    put_u32(&mut buf, 336, 0xDEAD_BEEF); // hi should be ignored
    let sb = Superblock::from_bytes(&buf).unwrap();
    assert_eq!(sb.total_blocks(), 12345);
}

#[test]
fn superblock_total_blocks_with_64bit() {
    let mut buf = make_superblock_buf();
    put_u32(&mut buf, 100, INCOMPAT_64BIT);
    put_u32(&mut buf, 4, 0x0000_0001);  // lo
    put_u32(&mut buf, 336, 0x0000_0002); // hi
    // expected: (0x2 << 32) | 0x1 = 0x0000_0002_0000_0001
    let sb = Superblock::from_bytes(&buf).unwrap();
    assert_eq!(sb.total_blocks(), 0x0000_0002_0000_0001u64);
}

#[test]
fn superblock_block_group_count_exact() {
    let mut buf = make_superblock_buf();
    // 8192 blocks / 8192 per group = 1 group exactly
    put_u32(&mut buf, 100, 0); // no 64-bit
    put_u32(&mut buf, 4, 8192);
    put_u32(&mut buf, 32, 8192);
    let sb = Superblock::from_bytes(&buf).unwrap();
    assert_eq!(sb.block_group_count(), 1);
}

#[test]
fn superblock_block_group_count_ceiling() {
    let mut buf = make_superblock_buf();
    // 8193 blocks / 8192 per group = 2 groups (ceiling)
    put_u32(&mut buf, 100, 0); // no 64-bit
    put_u32(&mut buf, 4, 8193);
    put_u32(&mut buf, 32, 8192);
    let sb = Superblock::from_bytes(&buf).unwrap();
    assert_eq!(sb.block_group_count(), 2);
}

#[test]
fn superblock_block_group_count_zero_bpg() {
    let mut buf = make_superblock_buf();
    put_u32(&mut buf, 100, 0);
    put_u32(&mut buf, 4, 8192);
    put_u32(&mut buf, 32, 0); // blocks_per_group = 0 => no division
    let sb = Superblock::from_bytes(&buf).unwrap();
    assert_eq!(sb.block_group_count(), 0);
}

// ---------------------------------------------------------------------------
// BlockGroupDescriptor tests
// ---------------------------------------------------------------------------

/// Build a 32-byte block group descriptor buffer.
fn make_bgd_buf_32(inode_table_lo: u32, free_blocks: u16, free_inodes: u16) -> Vec<u8> {
    let mut buf = vec![0u8; 32];
    // bg_inode_table_lo at offset 8
    put_u32(&mut buf, 8, inode_table_lo);
    // bg_free_blocks_count_lo at offset 12
    put_u16(&mut buf, 12, free_blocks);
    // bg_free_inodes_count_lo at offset 14
    put_u16(&mut buf, 14, free_inodes);
    buf
}

/// Build a 64-byte block group descriptor buffer.
fn make_bgd_buf_64(inode_table_lo: u32, inode_table_hi: u32) -> Vec<u8> {
    let mut buf = vec![0u8; 64];
    put_u32(&mut buf, 8, inode_table_lo);
    put_u32(&mut buf, 40, inode_table_hi);
    buf
}

#[test]
fn bgd_parse_32byte() {
    let buf = make_bgd_buf_32(42, 100, 50);
    let bgd = BlockGroupDescriptor::from_bytes(&buf).unwrap();
    assert_eq!(bgd.bg_inode_table_lo, 42);
    assert_eq!(bgd.bg_free_blocks_count_lo, 100);
    assert_eq!(bgd.bg_free_inodes_count_lo, 50);
    // hi should be zero when buffer is exactly 32 bytes
    assert_eq!(bgd.bg_inode_table_hi, 0);
}

#[test]
fn bgd_parse_64byte() {
    let buf = make_bgd_buf_64(0xAAAA_AAAA, 0x0000_0001);
    let bgd = BlockGroupDescriptor::from_bytes(&buf).unwrap();
    assert_eq!(bgd.bg_inode_table_lo, 0xAAAA_AAAA);
    assert_eq!(bgd.bg_inode_table_hi, 0x0000_0001);
}

#[test]
fn bgd_inode_table_32bit_mode() {
    let buf = make_bgd_buf_32(999, 0, 0);
    let bgd = BlockGroupDescriptor::from_bytes(&buf).unwrap();
    // is_64bit = false: only lo is used
    assert_eq!(bgd.inode_table(false), 999);
}

#[test]
fn bgd_inode_table_64bit_mode() {
    let buf = make_bgd_buf_64(0x0000_0001, 0x0000_0002);
    let bgd = BlockGroupDescriptor::from_bytes(&buf).unwrap();
    // is_64bit = true: (hi << 32) | lo
    assert_eq!(bgd.inode_table(true), 0x0000_0002_0000_0001u64);
}

#[test]
fn bgd_buffer_too_small() {
    let buf = vec![0u8; 16];
    let result = BlockGroupDescriptor::from_bytes(&buf);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Inode tests
// ---------------------------------------------------------------------------

/// Build a minimal 128-byte inode buffer.
fn make_inode_buf(mode: u16, size_lo: u32, size_hi: u32, flags: u32) -> Vec<u8> {
    let mut buf = vec![0u8; 128];
    put_u16(&mut buf, 0, mode);       // i_mode
    put_u32(&mut buf, 4, size_lo);    // i_size_lo
    put_u32(&mut buf, 32, flags);     // i_flags
    // i_size_high is at offset 108 — but 128-byte buffer covers it fine
    // (108 + 4 = 112 <= 128)
    put_u32(&mut buf, 108, size_hi);  // i_size_high
    buf
}

#[test]
fn inode_parse_basic() {
    let buf = make_inode_buf(0x81A4, 4096, 0, 0);
    let inode = Inode::from_bytes(&buf).unwrap();
    assert_eq!(inode.i_mode, 0x81A4);
    assert_eq!(inode.i_size_lo, 4096);
    assert_eq!(inode.i_flags, 0);
}

#[test]
fn inode_is_directory_true() {
    // mode = S_IFDIR | permissions
    let buf = make_inode_buf(S_IFDIR | 0x01ED, 0, 0, 0);
    let inode = Inode::from_bytes(&buf).unwrap();
    assert!(inode.is_directory());
    assert!(!inode.is_regular_file());
}

#[test]
fn inode_is_directory_false() {
    let buf = make_inode_buf(S_IFREG | 0x01A4, 0, 0, 0);
    let inode = Inode::from_bytes(&buf).unwrap();
    assert!(!inode.is_directory());
}

#[test]
fn inode_is_regular_file_true() {
    let buf = make_inode_buf(S_IFREG | 0x01A4, 0, 0, 0);
    let inode = Inode::from_bytes(&buf).unwrap();
    assert!(inode.is_regular_file());
    assert!(!inode.is_directory());
}

#[test]
fn inode_is_regular_file_false() {
    let buf = make_inode_buf(S_IFDIR | 0x01ED, 0, 0, 0);
    let inode = Inode::from_bytes(&buf).unwrap();
    assert!(!inode.is_regular_file());
}

#[test]
fn inode_size_lo_only() {
    let buf = make_inode_buf(S_IFREG, 12345, 0, 0);
    let inode = Inode::from_bytes(&buf).unwrap();
    assert_eq!(inode.size(), 12345);
}

#[test]
fn inode_size_combined_hi_lo() {
    let buf = make_inode_buf(S_IFREG, 0x0000_0001, 0x0000_0002, 0);
    let inode = Inode::from_bytes(&buf).unwrap();
    // (0x2 << 32) | 0x1
    assert_eq!(inode.size(), 0x0000_0002_0000_0001u64);
}

#[test]
fn inode_uses_extents_false() {
    let buf = make_inode_buf(S_IFREG, 0, 0, 0);
    let inode = Inode::from_bytes(&buf).unwrap();
    assert!(!inode.uses_extents());
}

#[test]
fn inode_uses_extents_true() {
    let buf = make_inode_buf(S_IFREG, 0, 0, EXT4_EXTENTS_FL);
    let inode = Inode::from_bytes(&buf).unwrap();
    assert!(inode.uses_extents());
}

#[test]
fn inode_buffer_too_small() {
    let buf = vec![0u8; 64];
    let result = Inode::from_bytes(&buf);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Extent tests
// ---------------------------------------------------------------------------

/// Build a 12-byte ExtentHeader buffer.
fn make_extent_header_buf(magic: u16, entries: u16, max: u16, depth: u16) -> Vec<u8> {
    let mut buf = vec![0u8; 12];
    put_u16(&mut buf, 0, magic);
    put_u16(&mut buf, 2, entries);
    put_u16(&mut buf, 4, max);
    put_u16(&mut buf, 6, depth);
    buf
}

/// Build a 12-byte ExtentEntry buffer.
fn make_extent_entry_buf(ee_block: u32, ee_len: u16, ee_start_hi: u16, ee_start_lo: u32) -> Vec<u8> {
    let mut buf = vec![0u8; 12];
    put_u32(&mut buf, 0, ee_block);
    put_u16(&mut buf, 4, ee_len);
    put_u16(&mut buf, 6, ee_start_hi);
    put_u32(&mut buf, 8, ee_start_lo);
    buf
}

/// Build a 12-byte ExtentIndex buffer.
fn make_extent_index_buf(ei_block: u32, ei_leaf_lo: u32, ei_leaf_hi: u16) -> Vec<u8> {
    let mut buf = vec![0u8; 12];
    put_u32(&mut buf, 0, ei_block);
    put_u32(&mut buf, 4, ei_leaf_lo);
    put_u16(&mut buf, 8, ei_leaf_hi);
    buf
}

#[test]
fn extent_header_valid() {
    let buf = make_extent_header_buf(EXTENT_MAGIC, 3, 4, 0);
    let hdr = ExtentHeader::from_bytes(&buf).unwrap();
    assert_eq!(hdr.eh_magic, EXTENT_MAGIC);
    assert_eq!(hdr.eh_entries, 3);
    assert_eq!(hdr.eh_max, 4);
    assert_eq!(hdr.eh_depth, 0);
}

#[test]
fn extent_header_invalid_magic() {
    let buf = make_extent_header_buf(0xDEAD, 1, 4, 0);
    let result = ExtentHeader::from_bytes(&buf);
    assert!(result.is_err(), "bad magic should error");
}

#[test]
fn extent_header_buffer_too_small() {
    let buf = vec![0u8; 8];
    let result = ExtentHeader::from_bytes(&buf);
    assert!(result.is_err());
}

#[test]
fn extent_entry_physical_block_lo_only() {
    let buf = make_extent_entry_buf(0, 8, 0, 500);
    let entry = ExtentEntry::from_bytes(&buf).unwrap();
    assert_eq!(entry.ee_block, 0);
    assert_eq!(entry.ee_len, 8);
    assert_eq!(entry.physical_block(), 500);
}

#[test]
fn extent_entry_physical_block_combined() {
    // hi = 1, lo = 0x0000_0001 => (1 << 32) | 1 = 0x1_0000_0001
    let buf = make_extent_entry_buf(0, 1, 1, 1);
    let entry = ExtentEntry::from_bytes(&buf).unwrap();
    assert_eq!(entry.physical_block(), 0x0000_0001_0000_0001u64);
}

#[test]
fn extent_entry_block_count_normal() {
    let buf = make_extent_entry_buf(0, 32, 0, 100);
    let entry = ExtentEntry::from_bytes(&buf).unwrap();
    assert_eq!(entry.block_count(), 32);
}

#[test]
fn extent_entry_block_count_uninitialized() {
    // ee_len > 0x8000 means uninitialized; block_count = ee_len - 0x8000
    let buf = make_extent_entry_buf(0, 0x8010, 0, 100);
    let entry = ExtentEntry::from_bytes(&buf).unwrap();
    assert_eq!(entry.block_count(), 0x10);
}

#[test]
fn extent_index_child_block_lo_only() {
    let buf = make_extent_index_buf(0, 1000, 0);
    let idx = ExtentIndex::from_bytes(&buf).unwrap();
    assert_eq!(idx.child_block(), 1000);
}

#[test]
fn extent_index_child_block_combined() {
    // hi = 2, lo = 3 => (2 << 32) | 3
    let buf = make_extent_index_buf(0, 3, 2);
    let idx = ExtentIndex::from_bytes(&buf).unwrap();
    assert_eq!(idx.child_block(), 0x0000_0002_0000_0003u64);
}

// ---------------------------------------------------------------------------
// Directory entry tests
// ---------------------------------------------------------------------------

/// Build a raw directory block buffer with the given entries.
///
/// Each entry: (inode, file_type, name).  The last entry's rec_len is
/// stretched to the end of the `block_size`-byte block.
fn make_dir_block(entries: &[(u32, u8, &str)], block_size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; block_size];
    let mut pos = 0usize;

    for (i, &(inode, file_type, name)) in entries.iter().enumerate() {
        let name_bytes = name.as_bytes();
        let name_len = name_bytes.len() as u8;
        let is_last = i == entries.len() - 1;

        // rec_len: 8 (header) + name_len, rounded up to 4 bytes.
        // The last entry stretches to fill the block.
        let rec_len: u16 = if is_last {
            (block_size - pos) as u16
        } else {
            let raw = 8 + name_bytes.len();
            ((raw + 3) & !3) as u16
        };

        put_u32(&mut buf, pos, inode);
        put_u16(&mut buf, pos + 4, rec_len);
        buf[pos + 6] = name_len;
        buf[pos + 7] = file_type;
        buf[pos + 8..pos + 8 + name_bytes.len()].copy_from_slice(name_bytes);

        pos += rec_len as usize;
    }
    buf
}

#[test]
fn dir_parse_multiple_entries() {
    let entries_in = &[
        (2u32, 2u8, "."),
        (2u32, 2u8, ".."),
        (12u32, 1u8, "hello.txt"),
    ];
    let block = make_dir_block(entries_in, 1024);
    let entries = parse_directory_block(&block).unwrap();

    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].inode, 2);
    assert_eq!(entries[0].name, ".");
    assert_eq!(entries[0].file_type, ExtFileType::Directory);

    assert_eq!(entries[1].inode, 2);
    assert_eq!(entries[1].name, "..");
    assert_eq!(entries[1].file_type, ExtFileType::Directory);

    assert_eq!(entries[2].inode, 12);
    assert_eq!(entries[2].name, "hello.txt");
    assert_eq!(entries[2].file_type, ExtFileType::RegularFile);
}

#[test]
fn dir_skip_deleted_entries() {
    // inode == 0 means deleted/unused; should not appear in output
    let entries_in = &[
        (2u32, 2u8, "."),
        (0u32, 0u8, "deleted"), // inode 0 => skip
        (5u32, 1u8, "live.txt"),
    ];
    let block = make_dir_block(entries_in, 1024);
    let entries = parse_directory_block(&block).unwrap();

    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, ".");
    assert_eq!(entries[1].name, "live.txt");
    assert!(!entries.iter().any(|e| e.inode == 0));
}

#[test]
fn dir_last_entry_extends_to_block_boundary() {
    // Single entry whose rec_len covers the entire block.
    let entries_in = &[(2u32, 2u8, "root")];
    let block_size = 512;
    let block = make_dir_block(entries_in, block_size);

    let entries = parse_directory_block(&block).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "root");
    // rec_len should equal the entire block size
    assert_eq!(entries[0].rec_len as usize, block_size);
}

#[test]
fn dir_empty_block() {
    // A block of all zeros: inode == 0 at pos 0, rec_len == 0 => immediate stop
    let block = vec![0u8; 512];
    let entries = parse_directory_block(&block).unwrap();
    assert!(entries.is_empty());
}

// ---------------------------------------------------------------------------
// ExtFilesystem::probe tests
// ---------------------------------------------------------------------------

/// Build a minimal filesystem image with a valid ext superblock at offset 1024.
/// The superblock needs at least 340 bytes (to cover s_blocks_count_hi at 336).
/// The image is padded to `total_size` bytes.
///
/// For probe() we only need the 2-byte magic at offset 1024+56 = 1080.
fn make_minimal_image_with_ext_magic(total_size: usize) -> Vec<u8> {
    let mut img = vec![0u8; total_size];
    // Write ext magic (0xEF53) at superblock_offset(1024) + 56 = 1080
    // little-endian: 0x53, 0xEF
    img[1080] = 0x53;
    img[1081] = 0xEF;
    img
}

#[test]
fn probe_returns_true_for_ext_image() {
    let img = make_minimal_image_with_ext_magic(8192);
    let mut reader: Box<dyn abyss_cstruct::read::ReadSeek> = Box::new(Cursor::new(img));
    assert!(ExtFilesystem::probe(&mut reader));
}

#[test]
fn probe_returns_false_for_non_ext_image() {
    // Image with zeros — no magic bytes
    let img = vec![0u8; 4096];
    let mut reader: Box<dyn abyss_cstruct::read::ReadSeek> = Box::new(Cursor::new(img));
    assert!(!ExtFilesystem::probe(&mut reader));
}

#[test]
fn probe_returns_false_for_wrong_magic() {
    let mut img = vec![0u8; 4096];
    // Put wrong magic bytes at 1080
    img[1080] = 0x12;
    img[1081] = 0x34;
    let mut reader: Box<dyn abyss_cstruct::read::ReadSeek> = Box::new(Cursor::new(img));
    assert!(!ExtFilesystem::probe(&mut reader));
}

#[test]
fn probe_returns_false_for_too_small_image() {
    // Image smaller than 1082 bytes cannot contain the magic field
    let img = vec![0u8; 512];
    let mut reader: Box<dyn abyss_cstruct::read::ReadSeek> = Box::new(Cursor::new(img));
    assert!(!ExtFilesystem::probe(&mut reader));
}
