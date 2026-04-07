use abyss_volume::gpt::parse_gpt;
use abyss_volume::partition::PartitionScheme;
use std::io::Cursor;

/// Build a minimal valid GPT disk image in memory.
fn build_test_gpt_disk() -> Vec<u8> {
    let sector_size: usize = 512;
    let total_sectors: usize = 2048;
    let mut disk = vec![0u8; total_sectors * sector_size];

    // --- Protective MBR at LBA 0 ---
    disk[510] = 0x55;
    disk[511] = 0xAA;
    disk[446 + 4] = 0xEE; // GPT protective type

    // --- GPT header at LBA 1 (offset 512) ---
    let hdr = sector_size;
    disk[hdr..hdr + 8].copy_from_slice(b"EFI PART");
    disk[hdr + 8..hdr + 12].copy_from_slice(&0x00010000u32.to_le_bytes());
    disk[hdr + 12..hdr + 16].copy_from_slice(&92u32.to_le_bytes());
    disk[hdr + 24..hdr + 32].copy_from_slice(&1u64.to_le_bytes());
    disk[hdr + 32..hdr + 40].copy_from_slice(&((total_sectors - 1) as u64).to_le_bytes());
    disk[hdr + 40..hdr + 48].copy_from_slice(&34u64.to_le_bytes());
    disk[hdr + 48..hdr + 56].copy_from_slice(&((total_sectors - 34) as u64).to_le_bytes());
    disk[hdr + 56..hdr + 72].copy_from_slice(&[0x01; 16]);
    disk[hdr + 72..hdr + 80].copy_from_slice(&2u64.to_le_bytes()); // entry start LBA
    disk[hdr + 80..hdr + 84].copy_from_slice(&1u32.to_le_bytes()); // num entries
    disk[hdr + 84..hdr + 88].copy_from_slice(&128u32.to_le_bytes()); // entry size

    // --- Partition entry at LBA 2 (offset 1024) ---
    let ent = 2 * sector_size;
    // Type GUID: Microsoft Basic Data (mixed-endian)
    // ebd0a0a2-b9e5-4433-87c0-68b6b72699c7
    let type_guid: [u8; 16] = [
        0xa2, 0xa0, 0xd0, 0xeb, // ebd0a0a2 LE
        0xe5, 0xb9,             // b9e5 LE
        0x33, 0x44,             // 4433 LE
        0x87, 0xc0,             // 87c0 BE
        0x68, 0xb6, 0xb7, 0x26, 0x99, 0xc7, // BE
    ];
    disk[ent..ent + 16].copy_from_slice(&type_guid);
    disk[ent + 16..ent + 32].copy_from_slice(&[0x02; 16]); // unique GUID
    disk[ent + 32..ent + 40].copy_from_slice(&34u64.to_le_bytes()); // start LBA
    disk[ent + 40..ent + 48].copy_from_slice(&2013u64.to_le_bytes()); // end LBA
    // Name: "TestPart" as UTF-16LE
    let name = "TestPart";
    for (i, ch) in name.chars().enumerate() {
        let off = ent + 56 + i * 2;
        disk[off..off + 2].copy_from_slice(&(ch as u16).to_le_bytes());
    }

    disk
}

#[test]
fn test_parse_gpt_finds_one_partition() {
    let disk = build_test_gpt_disk();
    let mut cursor = Cursor::new(disk);
    let partitions = parse_gpt(&mut cursor, 512).unwrap();

    assert_eq!(partitions.len(), 1);
    let p = &partitions[0];
    assert_eq!(p.index, 0);
    assert_eq!(p.offset, 34 * 512);
    assert_eq!(p.size, (2013 - 34 + 1) * 512);
    assert_eq!(p.scheme, PartitionScheme::Gpt);
    assert_eq!(p.label.as_deref(), Some("TestPart"));
    assert_eq!(p.type_name, "Microsoft Basic Data");
}

#[test]
fn test_parse_gpt_rejects_non_gpt() {
    let disk = vec![0u8; 4096];
    let mut cursor = Cursor::new(disk);
    let result = parse_gpt(&mut cursor, 512);
    assert!(result.is_err());
}
