/// Integration tests for abyss-container.
///
/// All test data is constructed inline using `std::io::Cursor<Vec<u8>>`.
use abyss_container::{
    detect_and_open,
    e01::E01Container,
    raw::RawContainer,
    traits::ContainerParser,
    vmdk::VmdkContainer,
};
use std::io::{Cursor, Read, Seek, SeekFrom};

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────

/// Wrap a `Vec<u8>` in a `Box<dyn ReadSeek>` as required by `ContainerParser::open`.
fn boxed(data: Vec<u8>) -> Box<dyn abyss_cstruct::read::ReadSeek> {
    Box::new(Cursor::new(data))
}

/// EVF magic bytes.
const EVF_MAGIC: [u8; 8] = [0x45, 0x56, 0x46, 0x09, 0x0D, 0x0A, 0xFF, 0x00];

// ─────────────────────────────────────────────────────────────
// RawContainer tests
// ─────────────────────────────────────────────────────────────

#[test]
fn raw_probe_always_true() {
    let mut cursor = Cursor::new(vec![0u8; 16]);
    let result = RawContainer::probe(&mut cursor).unwrap();
    assert!(result, "RawContainer::probe should always return true");
}

#[test]
fn raw_probe_empty_input_true() {
    let mut cursor = Cursor::new(vec![]);
    let result = RawContainer::probe(&mut cursor).unwrap();
    assert!(result, "RawContainer::probe returns true even on empty input");
}

#[test]
fn raw_open_size_matches_data_length() {
    let data: Vec<u8> = (0u8..=255).collect(); // 256 bytes
    let dev = RawContainer::open(boxed(data)).unwrap();
    assert_eq!(dev.size(), 256, "size() must equal the input length");
}

#[test]
fn raw_read_returns_correct_bytes() {
    let data: Vec<u8> = (0u8..=255).collect();
    let mut dev = RawContainer::open(boxed(data.clone())).unwrap();

    let mut buf = vec![0u8; 256];
    let n = dev.read(&mut buf).unwrap();
    assert_eq!(n, 256);
    assert_eq!(&buf[..n], data.as_slice());
}

#[test]
fn raw_seek_and_read() {
    let data: Vec<u8> = (0u8..=255).collect();
    let mut dev = RawContainer::open(boxed(data)).unwrap();

    // Seek to offset 128 and read 4 bytes.
    dev.seek(SeekFrom::Start(128)).unwrap();
    let mut buf = [0u8; 4];
    dev.read_exact(&mut buf).unwrap();
    assert_eq!(buf, [128, 129, 130, 131]);
}

#[test]
fn raw_seek_from_end() {
    let data: Vec<u8> = (0u8..=255).collect();
    let mut dev = RawContainer::open(boxed(data)).unwrap();

    // Seek to the last 8 bytes.
    dev.seek(SeekFrom::End(-8)).unwrap();
    let mut buf = [0u8; 8];
    dev.read_exact(&mut buf).unwrap();
    assert_eq!(buf, [248, 249, 250, 251, 252, 253, 254, 255]);
}

// ─────────────────────────────────────────────────────────────
// E01Container tests
// ─────────────────────────────────────────────────────────────

#[test]
fn e01_probe_valid_magic_returns_true() {
    let mut data = EVF_MAGIC.to_vec();
    data.extend_from_slice(&[0u8; 64]); // extra bytes
    let mut cursor = Cursor::new(data);
    assert!(E01Container::probe(&mut cursor).unwrap());
}

#[test]
fn e01_probe_invalid_magic_returns_false() {
    let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00];
    let mut cursor = Cursor::new(data);
    assert!(!E01Container::probe(&mut cursor).unwrap());
}

#[test]
fn e01_probe_too_short_returns_false() {
    let data = vec![0x45, 0x56]; // only 2 bytes
    let mut cursor = Cursor::new(data);
    assert!(!E01Container::probe(&mut cursor).unwrap());
}

#[test]
fn e01_open_truncated_data_fails_gracefully() {
    // Valid magic but no section data at all — open must return an Err, not panic.
    let mut data = EVF_MAGIC.to_vec();
    data.push(0x01); // fields_start
    // No section headers follow — all reads will hit EOF.
    let result = E01Container::open(boxed(data));
    assert!(result.is_err(), "truncated E01 must fail with an error");
}

/// Build a minimal but fully-valid single-chunk E01 image in memory.
///
/// Layout
/// ------
/// Offset  0: 8-byte EVF signature
/// Offset  8: 1-byte fields_start
/// Offset  9: "volume" section  (header=76 bytes, data=24 bytes → total=100)
/// Offset109: "table"  section  (header=76 bytes, data=24 bytes → total=100)
/// Offset209: "sectors" section (header=76 bytes, data=512 bytes → total=588)
/// Offset797: "done"   section  (header=76 bytes)
///
/// Volume data:
///   reserved(4)=0, chunk_count(4)=1, sectors_per_chunk(4)=1,
///   bytes_per_sector(4)=512, sector_count(8)=1
///   → chunk_size = 1*512 = 512, media_size = 1*512 = 512
///
/// Table data:
///   chunk_count(4)=1, padding(16)=0, entry(4)=0
///   (offset 0, not compressed; after open() it becomes 0+285=285 absolute)
///
/// Sectors data: 512 bytes starting with 0x41..0x41+255 repeated pattern.
fn build_minimal_e01() -> Vec<u8> {
    let mut img: Vec<u8> = Vec::new();

    // ── file header ──────────────────────────────────────────
    img.extend_from_slice(&EVF_MAGIC);
    img.push(0x01); // fields_start — value ignored by parser

    // ── section header helper ─────────────────────────────────
    // Writes a 76-byte section header.
    let write_section_hdr =
        |img: &mut Vec<u8>, type_name: &str, next_offset: u64, section_size: u64| {
            let mut type_buf = [0u8; 16];
            let name_bytes = type_name.as_bytes();
            type_buf[..name_bytes.len()].copy_from_slice(name_bytes);
            img.extend_from_slice(&type_buf);
            img.extend_from_slice(&next_offset.to_le_bytes());
            img.extend_from_slice(&section_size.to_le_bytes());
            img.extend_from_slice(&[0u8; 40]); // padding
            img.extend_from_slice(&[0u8; 4]); // checksum (ignored by parser)
        };

    // ── volume section at offset 9 ────────────────────────────
    // section_size = 76 (header) + 24 (data) = 100
    // next_offset  = 9 + 100 = 109
    write_section_hdr(&mut img, "volume", 109, 100);
    // volume data (24 bytes):
    img.extend_from_slice(&0u32.to_le_bytes()); // reserved
    img.extend_from_slice(&1u32.to_le_bytes()); // chunk_count = 1
    img.extend_from_slice(&1u32.to_le_bytes()); // sectors_per_chunk = 1
    img.extend_from_slice(&512u32.to_le_bytes()); // bytes_per_sector = 512
    img.extend_from_slice(&1u64.to_le_bytes()); // sector_count = 1

    // ── table section at offset 109 ───────────────────────────
    // section_size = 76 + 4 + 16 + 4 = 100
    // next_offset  = 109 + 100 = 209
    write_section_hdr(&mut img, "table", 209, 100);
    // table data:
    img.extend_from_slice(&1u32.to_le_bytes()); // chunk_count = 1
    img.extend_from_slice(&[0u8; 16]); // padding
    // one entry: offset=0 (relative to sectors data), not compressed
    img.extend_from_slice(&0u32.to_le_bytes());

    // ── sectors section at offset 209 ────────────────────────
    // data = 512 bytes; section_size = 76 + 512 = 588
    // next_offset = 209 + 588 = 797
    write_section_hdr(&mut img, "sectors", 797, 588);
    // 512 bytes of payload: fill with 0xA5 so we can verify later
    img.extend(std::iter::repeat(0xA5u8).take(512));

    // ── done section at offset 797 ────────────────────────────
    write_section_hdr(&mut img, "done", 0, 76);

    img
}

#[test]
fn e01_round_trip_size() {
    let img = build_minimal_e01();
    let dev = E01Container::open(boxed(img)).unwrap();
    assert_eq!(dev.size(), 512, "media_size should be 1 sector * 512 bytes");
}

#[test]
fn e01_round_trip_read_data() {
    let img = build_minimal_e01();
    let mut dev = E01Container::open(boxed(img)).unwrap();

    let mut buf = vec![0u8; 512];
    let n = dev.read(&mut buf).unwrap();
    assert_eq!(n, 512);
    assert!(
        buf.iter().all(|&b| b == 0xA5),
        "all bytes should be 0xA5 fill value"
    );
}

#[test]
fn e01_round_trip_seek_and_read() {
    let img = build_minimal_e01();
    let mut dev = E01Container::open(boxed(img)).unwrap();

    // Seek to offset 256 and read 4 bytes.
    dev.seek(SeekFrom::Start(256)).unwrap();
    let mut buf = [0u8; 4];
    dev.read_exact(&mut buf).unwrap();
    assert_eq!(buf, [0xA5; 4]);
}

#[test]
fn e01_read_past_end_returns_zero() {
    let img = build_minimal_e01();
    let mut dev = E01Container::open(boxed(img)).unwrap();
    dev.seek(SeekFrom::Start(512)).unwrap();
    let mut buf = [0u8; 16];
    let n = dev.read(&mut buf).unwrap();
    assert_eq!(n, 0, "read past media end must return 0");
}

// ─────────────────────────────────────────────────────────────
// VmdkContainer tests
// ─────────────────────────────────────────────────────────────

const VMDK_MAGIC_BYTES: [u8; 4] = [0x4B, 0x44, 0x4D, 0x56]; // "KDMV" little-endian u32 = 0x564D444B

#[test]
fn vmdk_probe_valid_magic_returns_true() {
    let mut data = VMDK_MAGIC_BYTES.to_vec();
    data.extend_from_slice(&[0u8; 64]);
    let mut cursor = Cursor::new(data);
    assert!(VmdkContainer::probe(&mut cursor).unwrap());
}

#[test]
fn vmdk_probe_invalid_magic_returns_false() {
    let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00];
    let mut cursor = Cursor::new(data);
    assert!(!VmdkContainer::probe(&mut cursor).unwrap());
}

#[test]
fn vmdk_probe_too_short_returns_false() {
    let data = vec![0x4B, 0x44]; // only 2 bytes
    let mut cursor = Cursor::new(data);
    assert!(!VmdkContainer::probe(&mut cursor).unwrap());
}

#[test]
fn vmdk_open_truncated_fails_gracefully() {
    // Valid magic in first 4 bytes but only 8 bytes total — cannot read 512-byte header.
    let mut data = VMDK_MAGIC_BYTES.to_vec();
    data.extend_from_slice(&[0u8; 4]);
    let result = VmdkContainer::open(boxed(data));
    assert!(result.is_err(), "truncated VMDK must fail with an error");
}

/// Build a minimal sparse VMDK image in memory.
///
/// Sector layout
/// -------------
/// Sector 0  (offset    0): 512-byte sparse extent header
/// Sector 1  (offset  512): unused (padding so GD lands on sector 2)
/// Sector 2  (offset 1024): grain directory — 1 entry pointing to sector 3
/// Sector 3  (offset 1536): grain table    — 1 entry pointing to sector 4
/// Sector 4  (offset 2048): grain data     — 512 bytes of 0xBB fill
///
/// Header fields (little-endian):
///   magic          (u32, offset  0): 0x564D444B
///   version        (u32, offset  4): 1
///   flags          (u32, offset  8): 0
///   capacity       (u64, offset 12): 1  (1 sector)
///   grain_size     (u64, offset 20): 1  (1 sector per grain)
///   descriptor_offset (u64, offset 28): 0
///   descriptor_size   (u64, offset 36): 0
///   num_gtes_per_gt   (u32, offset 44): 1
///   rgd_offset     (u64, offset 48): 0
///   gd_offset      (u64, offset 56): 2  (sector 2)
fn build_minimal_vmdk() -> Vec<u8> {
    // Total image: 5 sectors = 2560 bytes
    let mut img = vec![0u8; 5 * 512];

    // ── sector 0: header ──────────────────────────────────────
    let magic: u32 = 0x564D_444B;
    img[0..4].copy_from_slice(&magic.to_le_bytes());
    // version = 1
    img[4..8].copy_from_slice(&1u32.to_le_bytes());
    // flags = 0 (already zero)
    // capacity = 1 sector
    img[12..20].copy_from_slice(&1u64.to_le_bytes());
    // grain_size = 1 sector
    img[20..28].copy_from_slice(&1u64.to_le_bytes());
    // num_gtes_per_gt = 1
    img[44..48].copy_from_slice(&1u32.to_le_bytes());
    // gd_offset = 2 (sector 2)
    img[56..64].copy_from_slice(&2u64.to_le_bytes());

    // ── sector 2 (offset 1024): grain directory ───────────────
    // GD entry 0 = 3 (sector 3 holds the grain table)
    let gd_entry: u32 = 3;
    img[1024..1028].copy_from_slice(&gd_entry.to_le_bytes());

    // ── sector 3 (offset 1536): grain table ──────────────────
    // GT entry 0 = 4 (sector 4 holds the grain data)
    let gt_entry: u32 = 4;
    img[1536..1540].copy_from_slice(&gt_entry.to_le_bytes());

    // ── sector 4 (offset 2048): grain data ───────────────────
    for b in &mut img[2048..2560] {
        *b = 0xBB;
    }

    img
}

#[test]
fn vmdk_round_trip_size() {
    let img = build_minimal_vmdk();
    let dev = VmdkContainer::open(boxed(img)).unwrap();
    assert_eq!(dev.size(), 512, "capacity_bytes = 1 sector * 512");
}

#[test]
fn vmdk_round_trip_read_data() {
    let img = build_minimal_vmdk();
    let mut dev = VmdkContainer::open(boxed(img)).unwrap();

    let mut buf = vec![0u8; 512];
    let n = dev.read(&mut buf).unwrap();
    assert_eq!(n, 512);
    assert!(
        buf.iter().all(|&b| b == 0xBB),
        "all bytes should be 0xBB fill value"
    );
}

#[test]
fn vmdk_round_trip_seek_and_read() {
    let img = build_minimal_vmdk();
    let mut dev = VmdkContainer::open(boxed(img)).unwrap();

    dev.seek(SeekFrom::Start(256)).unwrap();
    let mut buf = [0u8; 4];
    dev.read_exact(&mut buf).unwrap();
    assert_eq!(buf, [0xBB; 4]);
}

#[test]
fn vmdk_read_past_end_returns_zero() {
    let img = build_minimal_vmdk();
    let mut dev = VmdkContainer::open(boxed(img)).unwrap();
    dev.seek(SeekFrom::Start(512)).unwrap();
    let mut buf = [0u8; 16];
    let n = dev.read(&mut buf).unwrap();
    assert_eq!(n, 0, "read past capacity must return 0");
}

// ─────────────────────────────────────────────────────────────
// detect_and_open tests
// ─────────────────────────────────────────────────────────────

#[test]
fn detect_raw_data_opens_as_raw() {
    // No recognisable magic — should fall through to RawContainer.
    let data: Vec<u8> = (0u8..=255).collect();
    let dev = detect_and_open(boxed(data)).unwrap();
    assert_eq!(dev.size(), 256, "raw fallback should expose the full 256 bytes");
}

#[test]
fn detect_evf_magic_detected_as_e01() {
    // Just EVF magic followed by zeros — probe should succeed, open will likely
    // fail on the truncated body, but the detection path (probe) must fire first.
    let mut data = EVF_MAGIC.to_vec();
    data.extend_from_slice(&[0u8; 100]);
    // If detect_and_open returns Ok it opened successfully (lucky parse).
    // If it returns Err it correctly identified the format but couldn't fully parse.
    // Either way, it must NOT return the raw fallback size (108 bytes).
    match detect_and_open(boxed(data)) {
        Ok(dev) => {
            // Opened — it's not a raw passthrough (raw would be 108 bytes)
            // A successfully-opened E01 would have a media_size from the volume section.
            // Just confirm it's some container (size != raw fallback size proves detection).
            assert_ne!(
                dev.size(),
                108,
                "should not have fallen back to raw (108-byte passthrough)"
            );
        }
        Err(_) => {
            // Correctly rejected the truncated E01 data — detection worked.
        }
    }
}

#[test]
fn detect_vmdk_magic_detected_as_vmdk() {
    // Just VMDK magic followed by zeros — open will likely fail on the truncated body,
    // but must not fall through to raw.
    let mut data = VMDK_MAGIC_BYTES.to_vec();
    data.extend_from_slice(&[0u8; 100]);
    match detect_and_open(boxed(data)) {
        Ok(dev) => {
            assert_ne!(
                dev.size(),
                104,
                "should not have fallen back to raw (104-byte passthrough)"
            );
        }
        Err(_) => {
            // Correctly detected VMDK and failed to parse truncated body.
        }
    }
}

#[test]
fn detect_full_e01_opens_successfully() {
    let img = build_minimal_e01();
    let dev = detect_and_open(boxed(img)).unwrap();
    assert_eq!(dev.size(), 512);
}

#[test]
fn detect_full_vmdk_opens_successfully() {
    let img = build_minimal_vmdk();
    let dev = detect_and_open(boxed(img)).unwrap();
    assert_eq!(dev.size(), 512);
}
