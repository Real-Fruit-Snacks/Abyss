use abyss_browser::chromium::{
    BrowserCredential, base64_decode, decrypt_chromium_password, extract_state_key,
};
use abyss_browser::BrowserError;

#[test]
fn test_browser_credential_structure() {
    let cred = BrowserCredential {
        browser: "Chrome".to_string(),
        url: "https://example.com".to_string(),
        username: "user@example.com".to_string(),
        password: "secret123".to_string(),
    };

    assert_eq!(cred.browser, "Chrome");
    assert_eq!(cred.url, "https://example.com");
    assert_eq!(cred.username, "user@example.com");
    assert_eq!(cred.password, "secret123");
}

#[test]
fn test_base64_decode_roundtrip() {
    // "Hello, World!" in standard base64.
    let encoded = "SGVsbG8sIFdvcmxkIQ==";
    let decoded = base64_decode(encoded).expect("decode should succeed");
    assert_eq!(decoded, b"Hello, World!");
}

#[test]
fn test_base64_decode_empty() {
    let decoded = base64_decode("").expect("empty string should decode to empty");
    assert!(decoded.is_empty());
}

#[test]
fn test_base64_decode_invalid_length() {
    // Length 5 is not a multiple of 4.
    let result = base64_decode("AAAAA");
    assert!(result.is_err());
}

#[test]
fn test_decrypt_chromium_password_bad_version() {
    let key = [0u8; 32];
    // Blob starting with "v09" should be rejected.
    let bad: Vec<u8> = b"v09".iter().chain(&[0u8; 20]).copied().collect();
    let result = decrypt_chromium_password(&bad, &key);
    assert!(result.is_err());
}

#[test]
fn test_decrypt_chromium_password_too_short() {
    let key = [0u8; 32];
    let short = b"v10abc"; // only 6 bytes, less than the 15-byte minimum
    let result = decrypt_chromium_password(short, &key);
    assert!(result.is_err());
}

#[test]
fn test_decrypt_chromium_password_roundtrip() {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    let key = [0x42u8; 32];
    let nonce_bytes = [0x11u8; 12];
    let plaintext = b"super_secret_password";

    // Encrypt with the same scheme Chromium uses.
    let cipher = Aes256Gcm::new(&key.into());
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();

    // Build the blob: b"v10" + nonce + ciphertext+tag
    let mut blob = b"v10".to_vec();
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    let result = decrypt_chromium_password(&blob, &key).unwrap();
    assert_eq!(result, "super_secret_password");
}

#[test]
fn test_extract_state_key_missing_field() {
    use abyss_crypto::dpapi::DpapiKeyring;

    let json = br#"{"some_other_key": "value"}"#;
    let keyring = DpapiKeyring::new();
    let result = extract_state_key(json, &keyring);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, BrowserError::InvalidData { .. }));
}

#[test]
fn test_extract_state_key_bad_base64() {
    use abyss_crypto::dpapi::DpapiKeyring;

    let json = br#"{"os_crypt": {"encrypted_key": "not!valid!base64!!!"}}"#;
    let keyring = DpapiKeyring::new();
    let result = extract_state_key(json, &keyring);
    assert!(result.is_err());
}
