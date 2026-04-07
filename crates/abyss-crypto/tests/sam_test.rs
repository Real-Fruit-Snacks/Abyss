/// Integration tests for SAM hash extraction.

use abyss_crypto::{extract_sam_hashes, sam::decrypt_aes_128_cbc};

#[test]
fn test_public_api_accessible() {
    // Verify public items are reachable from outside the crate.
    let _ = std::hint::black_box(extract_sam_hashes as fn(_, _) -> _);
}

#[test]
fn test_decrypt_aes_128_cbc_bad_inputs() {
    // Too-short key should return an error.
    let result = decrypt_aes_128_cbc(&[0u8; 8], &[0u8; 16], &[0u8; 16]);
    assert!(result.is_err(), "expected error for 8-byte key");

    // Too-short data should return an error.
    let result = decrypt_aes_128_cbc(&[0u8; 16], &[0u8; 16], &[0u8; 8]);
    assert!(result.is_err(), "expected error for 8-byte data");
}

#[test]
fn test_sam_entry_fields() {
    use abyss_crypto::SamEntry;
    let entry = SamEntry {
        username: "Administrator".to_string(),
        rid: 500,
        ntlm: vec![0u8; 16],
        lm: vec![],
    };
    assert_eq!(entry.username, "Administrator");
    assert_eq!(entry.rid, 500);
    assert_eq!(entry.ntlm.len(), 16);
    assert!(entry.lm.is_empty());
}
