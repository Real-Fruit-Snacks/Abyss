//! Temporary diagnostic test to understand page layout of real NTDS.dit

use std::io::Cursor;
use abyss_cstruct::read::ReadSeek;
use abyss_ese::EseDatabase;
use abyss_ese::page::PAGE_HEADER_SIZE;

#[test]
fn debug_btree_walk() {
    let data = match std::fs::read("../../test-data/gosecretsdump/test/ntds.dit") {
        Ok(d) => d,
        Err(_) => { eprintln!("Skipping"); return; }
    };

    let reader: Box<dyn ReadSeek> = Box::new(Cursor::new(data));
    let mut db = EseDatabase::open(reader).unwrap();

    eprintln!("page_size={}, new_format={}", db.page_size, db.new_format);

    // Check page 4 with db methods (which use correct header size)
    let page4 = db.read_page(4).unwrap();
    let hdr = db.parse_page_header(&page4).unwrap();
    eprintln!("Page 4 flags: {:#x} root={} leaf={} branch={} empty={} space={}",
        hdr.page_flags.0, hdr.page_flags.is_root(), hdr.page_flags.is_leaf(),
        hdr.page_flags.is_branch(), hdr.page_flags.is_empty(), hdr.page_flags.is_space_tree());

    let tags = db.parse_page_tags(&page4, hdr.first_available_page_tag);
    eprintln!("Page 4 tags: {}", tags.len());
    for (i, tag) in tags.iter().enumerate().take(10) {
        eprintln!("  tag[{}]: offset={}, size={}, flags={:#x}", i, tag.offset, tag.size, tag.flags);
        if let Some(data) = db.get_tag_data(&page4, tag) {
            eprintln!("    data[..{}]: {:02x?}", data.len().min(48), &data[..data.len().min(48)]);
        }
    }

    // Check page 5 directly
    let page5 = db.read_page(5).unwrap();
    let hdr5 = db.parse_page_header(&page5).unwrap();
    let tags5 = db.parse_page_tags(&page5, hdr5.first_available_page_tag);
    eprintln!("\nPage 5 flags: {:#x} root={} leaf={} branch={} empty={} space={}",
        hdr5.page_flags.0, hdr5.page_flags.is_root(), hdr5.page_flags.is_leaf(),
        hdr5.page_flags.is_branch(), hdr5.page_flags.is_empty(), hdr5.page_flags.is_space_tree());
    eprintln!("Page 5 tags: {}", tags5.len());
    for (i, tag) in tags5.iter().enumerate().take(3) {
        eprintln!("  tag[{}]: offset={}, size={}, flags={:#x}", i, tag.offset, tag.size, tag.flags);
        if let Some(data) = db.get_tag_data(&page5, tag) {
            eprintln!("    data[..{}]: {:02x?}", data.len().min(48), &data[..data.len().min(48)]);
        }
    }

    // Try walking btree at page 5 directly (skip FDP)
    let raw5 = db.walk_btree(5).unwrap();
    eprintln!("\nwalk_btree(5) returned {} records", raw5.len());

    // Try walking btree at page 4
    let raw = db.walk_btree(4).unwrap();
    eprintln!("walk_btree(4) returned {} records", raw.len());
    for (i, r) in raw.iter().enumerate().take(5) {
        eprintln!("  record[{}]: {} bytes, first 32: {:02x?}", i, r.len(), &r[..r.len().min(32)]);
    }

    // Try parse_catalog_record on them
    use abyss_ese::catalog::parse_catalog_record;
    let mut parsed = 0;
    for r in &raw {
        if let Some((obj_id, etype, id, coltyp, flags, name)) = parse_catalog_record(r) {
            eprintln!("  catalog entry: obj_id={} type={} id={} coltyp={} flags={} name='{}'",
                obj_id, etype, id, coltyp, flags, name);
            parsed += 1;
            if parsed >= 10 { break; }
        }
    }
    eprintln!("Parsed {} catalog entries out of {} raw records", parsed, raw.len());
}
