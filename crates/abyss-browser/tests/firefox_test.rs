use abyss_browser::firefox::{
    parse_logins_json, parse_encrypted_blob, decrypt_firefox_field,
    EncryptionAlgorithm, EncryptedBlob, FirefoxCredential,
    FirefoxProfile, extract_firefox_credentials,
};

// ─── logins.json parsing ───────────────────────────────────────────────────

#[test]
fn test_parse_logins_json_valid() {
    let json = br#"{
        "nextId": 3,
        "logins": [
            {
                "id": 1,
                "hostname": "https://example.com",
                "encryptedUsername": "dXNlcm5hbWU=",
                "encryptedPassword": "cGFzc3dvcmQ="
            },
            {
                "id": 2,
                "hostname": "https://other.org",
                "encryptedUsername": "YWRtaW4=",
                "encryptedPassword": "c2VjcmV0"
            }
        ]
    }"#;

    let logins = parse_logins_json(json).unwrap();
    assert_eq!(logins.len(), 2);
    assert_eq!(logins[0].hostname, "https://example.com");
    assert_eq!(logins[0].encrypted_username, "dXNlcm5hbWU=");
    assert_eq!(logins[0].encrypted_password, "cGFzc3dvcmQ=");
    assert_eq!(logins[1].hostname, "https://other.org");
}

#[test]
fn test_parse_logins_json_empty_logins() {
    let json = br#"{"logins": []}"#;
    let logins = parse_logins_json(json).unwrap();
    assert!(logins.is_empty());
}

#[test]
fn test_parse_logins_json_invalid_json() {
    let result = parse_logins_json(b"not json at all");
    assert!(result.is_err());
}

#[test]
fn test_parse_logins_json_missing_logins_field() {
    let json = br#"{"nextId": 1}"#;
    let result = parse_logins_json(json);
    assert!(result.is_err());
}

#[test]
fn test_parse_logins_json_skips_empty_entries() {
    // Entries with no encrypted fields should be skipped.
    let json = br#"{
        "logins": [
            {
                "hostname": "https://example.com",
                "encryptedUsername": "",
                "encryptedPassword": ""
            }
        ]
    }"#;
    let logins = parse_logins_json(json).unwrap();
    assert!(logins.is_empty());
}

// ─── ASN.1 blob parsing ───────────────────────────────────────────────────

#[test]
fn test_parse_encrypted_blob_3des() {
    // Build a minimal DER structure for 3DES-CBC:
    // SEQUENCE {
    //   SEQUENCE {
    //     OID (des-ede3-cbc = 1.2.840.113549.3.7)
    //     OCTET STRING (8-byte IV)
    //   }
    //   OCTET STRING (ciphertext)
    // }
    let oid_3des: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x07];
    let iv = [0x11u8; 8];
    let ciphertext = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11];

    let mut inner_seq = Vec::new();
    // OID
    inner_seq.push(0x06); // TAG_OID
    inner_seq.push(oid_3des.len() as u8);
    inner_seq.extend_from_slice(oid_3des);
    // IV
    inner_seq.push(0x04); // TAG_OCTET_STRING
    inner_seq.push(iv.len() as u8);
    inner_seq.extend_from_slice(&iv);

    let mut outer = Vec::new();
    // Inner SEQUENCE
    outer.push(0x30); // TAG_SEQUENCE
    outer.push(inner_seq.len() as u8);
    outer.extend_from_slice(&inner_seq);
    // Ciphertext
    outer.push(0x04); // TAG_OCTET_STRING
    outer.push(ciphertext.len() as u8);
    outer.extend_from_slice(&ciphertext);

    let mut blob_bytes = Vec::new();
    blob_bytes.push(0x30); // TAG_SEQUENCE (outer)
    blob_bytes.push(outer.len() as u8);
    blob_bytes.extend_from_slice(&outer);

    let blob = parse_encrypted_blob(&blob_bytes).unwrap();
    assert_eq!(blob.algorithm, EncryptionAlgorithm::TripleDes);
    assert_eq!(blob.iv, iv.to_vec());
    assert_eq!(blob.ciphertext, ciphertext.to_vec());
}

#[test]
fn test_parse_encrypted_blob_aes256() {
    // Build a minimal DER structure for AES-256-CBC:
    let oid_aes256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A];
    let iv = [0x22u8; 16];
    let ciphertext = [0xDD; 32];

    let mut inner_seq = Vec::new();
    inner_seq.push(0x06);
    inner_seq.push(oid_aes256.len() as u8);
    inner_seq.extend_from_slice(oid_aes256);
    inner_seq.push(0x04);
    inner_seq.push(iv.len() as u8);
    inner_seq.extend_from_slice(&iv);

    let mut outer = Vec::new();
    outer.push(0x30);
    outer.push(inner_seq.len() as u8);
    outer.extend_from_slice(&inner_seq);
    outer.push(0x04);
    outer.push(ciphertext.len() as u8);
    outer.extend_from_slice(&ciphertext);

    let mut blob_bytes = Vec::new();
    blob_bytes.push(0x30);
    blob_bytes.push(outer.len() as u8);
    blob_bytes.extend_from_slice(&outer);

    let blob = parse_encrypted_blob(&blob_bytes).unwrap();
    assert_eq!(blob.algorithm, EncryptionAlgorithm::Aes256Cbc);
    assert_eq!(blob.iv, iv.to_vec());
    assert_eq!(blob.ciphertext, ciphertext.to_vec());
}

#[test]
fn test_parse_encrypted_blob_unknown_oid() {
    // Use a bogus OID
    let oid_bogus: &[u8] = &[0x01, 0x02, 0x03];
    let iv = [0x00u8; 8];
    let ciphertext = [0xFF; 8];

    let mut inner_seq = Vec::new();
    inner_seq.push(0x06);
    inner_seq.push(oid_bogus.len() as u8);
    inner_seq.extend_from_slice(oid_bogus);
    inner_seq.push(0x04);
    inner_seq.push(iv.len() as u8);
    inner_seq.extend_from_slice(&iv);

    let mut outer = Vec::new();
    outer.push(0x30);
    outer.push(inner_seq.len() as u8);
    outer.extend_from_slice(&inner_seq);
    outer.push(0x04);
    outer.push(ciphertext.len() as u8);
    outer.extend_from_slice(&ciphertext);

    let mut blob_bytes = Vec::new();
    blob_bytes.push(0x30);
    blob_bytes.push(outer.len() as u8);
    blob_bytes.extend_from_slice(&outer);

    let result = parse_encrypted_blob(&blob_bytes);
    assert!(result.is_err());
}

#[test]
fn test_parse_encrypted_blob_not_a_sequence() {
    // Start with OCTET STRING instead of SEQUENCE
    let data = [0x04, 0x02, 0xAA, 0xBB];
    let result = parse_encrypted_blob(&data);
    assert!(result.is_err());
}

// ─── decrypt_firefox_field ─────────────────────────────────────────────────

#[test]
fn test_decrypt_firefox_field_empty_string() {
    let result = decrypt_firefox_field("", &[0u8; 24]).unwrap();
    assert_eq!(result, "");
}

#[test]
fn test_decrypt_firefox_field_bad_base64() {
    let result = decrypt_firefox_field("not!valid!base64!!!", &[0u8; 24]);
    assert!(result.is_err());
}

// ─── 3DES-CBC round-trip ───────────────────────────────────────────────────

#[test]
fn test_decrypt_firefox_field_3des_roundtrip() {
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};
    use des::TdesEde3;

    type TdesCbcEnc = cbc::Encryptor<TdesEde3>;

    let key = [0x42u8; 24];
    let iv = [0x11u8; 8];
    let plaintext = b"hello_firefox!!!" ; // 16 bytes = 2 blocks of 3DES (8-byte block)

    // PKCS#7 pad to 8-byte boundary — 16 is already multiple of 8, so full
    // block of padding (8 bytes of 0x08).
    let mut padded = plaintext.to_vec();
    let pad_len = 8 - (padded.len() % 8);
    for _ in 0..pad_len {
        padded.push(pad_len as u8);
    }

    // Encrypt
    let encryptor = TdesCbcEnc::new((&key).into(), (&iv).into());
    let ciphertext = encryptor
        .encrypt_padded_vec_mut::<cbc::cipher::block_padding::NoPadding>(&padded);

    // Build ASN.1 blob
    let oid_3des: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x07];

    let mut inner_seq = Vec::new();
    inner_seq.push(0x06);
    inner_seq.push(oid_3des.len() as u8);
    inner_seq.extend_from_slice(oid_3des);
    inner_seq.push(0x04);
    inner_seq.push(iv.len() as u8);
    inner_seq.extend_from_slice(&iv);

    let mut outer = Vec::new();
    outer.push(0x30);
    outer.push(inner_seq.len() as u8);
    outer.extend_from_slice(&inner_seq);
    outer.push(0x04);
    outer.push(ciphertext.len() as u8);
    outer.extend_from_slice(&ciphertext);

    let mut blob_bytes = Vec::new();
    blob_bytes.push(0x30);
    blob_bytes.push(outer.len() as u8);
    blob_bytes.extend_from_slice(&outer);

    // Base64 encode
    let b64 = simple_base64_encode(&blob_bytes);

    let result = decrypt_firefox_field(&b64, &key).unwrap();
    assert_eq!(result, "hello_firefox!!!");
}

// ─── AES-256-CBC round-trip ────────────────────────────────────────────────

#[test]
fn test_decrypt_firefox_field_aes256_roundtrip() {
    use aes::Aes256;
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};

    type Aes256CbcEnc = cbc::Encryptor<Aes256>;

    let key = [0x55u8; 32];
    let iv = [0x33u8; 16];
    let plaintext = b"aes_password"; // 12 bytes

    // PKCS#7 pad to 16-byte boundary
    let mut padded = plaintext.to_vec();
    let pad_len = 16 - (padded.len() % 16);
    for _ in 0..pad_len {
        padded.push(pad_len as u8);
    }

    // Encrypt
    let encryptor = Aes256CbcEnc::new((&key).into(), (&iv).into());
    let ciphertext = encryptor
        .encrypt_padded_vec_mut::<cbc::cipher::block_padding::NoPadding>(&padded);

    // Build ASN.1 blob
    let oid_aes256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A];

    let mut inner_seq = Vec::new();
    inner_seq.push(0x06);
    inner_seq.push(oid_aes256.len() as u8);
    inner_seq.extend_from_slice(oid_aes256);
    inner_seq.push(0x04);
    inner_seq.push(iv.len() as u8);
    inner_seq.extend_from_slice(&iv);

    let mut outer = Vec::new();
    outer.push(0x30);
    outer.push(inner_seq.len() as u8);
    outer.extend_from_slice(&inner_seq);
    outer.push(0x04);
    outer.push(ciphertext.len() as u8);
    outer.extend_from_slice(&ciphertext);

    let mut blob_bytes = Vec::new();
    blob_bytes.push(0x30);
    blob_bytes.push(outer.len() as u8);
    blob_bytes.extend_from_slice(&outer);

    let b64 = simple_base64_encode(&blob_bytes);

    let result = decrypt_firefox_field(&b64, &key).unwrap();
    assert_eq!(result, "aes_password");
}

// ─── FirefoxProfile / extract_firefox_credentials ──────────────────────────

#[test]
fn test_extract_firefox_credentials_invalid_key4db() {
    let profile = FirefoxProfile {
        user: "testuser".to_string(),
        profile_path: "test/profile".to_string(),
        key4_db: b"not a sqlite file".to_vec(),
        logins_json: br#"{"logins": []}"#.to_vec(),
    };

    // Should return empty vec (logs warning) rather than panic.
    let creds = extract_firefox_credentials(&profile);
    assert!(creds.is_empty());
}

#[test]
fn test_extract_firefox_credentials_invalid_logins_json() {
    // Provide valid SQLite magic but bogus content — key extraction will fail.
    let mut key4 = b"SQLite format 3\0".to_vec();
    key4.extend_from_slice(&[0u8; 100]);

    let profile = FirefoxProfile {
        user: "testuser".to_string(),
        profile_path: "test/profile".to_string(),
        key4_db: key4,
        logins_json: b"not json".to_vec(),
    };

    let creds = extract_firefox_credentials(&profile);
    assert!(creds.is_empty());
}

#[test]
fn test_firefox_credential_fields() {
    let cred = FirefoxCredential {
        url: "https://example.com".to_string(),
        username: "user@example.com".to_string(),
        password: "hunter2".to_string(),
    };
    assert_eq!(cred.url, "https://example.com");
    assert_eq!(cred.username, "user@example.com");
    assert_eq!(cred.password, "hunter2");
}

#[test]
fn test_encrypted_blob_fields() {
    let blob = EncryptedBlob {
        algorithm: EncryptionAlgorithm::TripleDes,
        iv: vec![1, 2, 3, 4, 5, 6, 7, 8],
        ciphertext: vec![0xAA, 0xBB],
    };
    assert_eq!(blob.algorithm, EncryptionAlgorithm::TripleDes);
    assert_eq!(blob.iv.len(), 8);
    assert_eq!(blob.ciphertext.len(), 2);
}

// ─── Helpers ───────────────────────────────────────────────────────────────

/// Minimal base64 encoder for test payloads (standard alphabet, with padding).
fn simple_base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i] as u32;
        let b1 = if i + 1 < data.len() { data[i + 1] as u32 } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        result.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        if i + 1 < data.len() {
            result.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if i + 2 < data.len() {
            result.push(ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        i += 3;
    }
    result
}
