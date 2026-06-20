//! Chromium-family browser credential extraction.
//!
//! Extracts saved passwords from Chrome, Edge, Brave, and other Chromium-based
//! browsers.  The credentials are stored in a SQLite database (`Login Data`)
//! and the encryption key is stored in `Local State` (a JSON file), protected
//! by DPAPI.
//!
//! Decryption flow:
//!   1. Parse `Local State` JSON → base64-decode `os_crypt.encrypted_key`
//!   2. Strip the 5-byte `DPAPI` prefix → decrypt the remainder with DPAPI
//!      via the provided [`DpapiKeyring`] → yields a 32-byte AES-256 state key
//!   3. Open the `Login Data` SQLite database
//!   4. For each row in the `logins` table, decrypt `password_value` with
//!      AES-256-GCM using the state key (v10/v11 prefix, nonce at [3..15],
//!      ciphertext+tag at [15..])

use crate::error::BrowserError;
use abyss_crypto::dpapi::DpapiKeyring;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
/// A single decrypted browser credential.
#[derive(Debug, Clone)]
pub struct BrowserCredential {
    /// Human-readable browser name (e.g. "Chrome", "Edge").
    pub browser: String,
    /// The URL the credential is associated with.
    pub url: String,
    /// The stored username.
    pub username: String,
    /// The decrypted plaintext password.
    pub password: String,
}

/// Extract all credentials from a Chromium-family browser.
///
/// # Arguments
/// * `local_state_data` — raw bytes of the `Local State` JSON file
/// * `login_data_db`    — raw bytes of the `Login Data` SQLite database file
/// * `browser_name`     — display name used to tag each [`BrowserCredential`]
/// * `keyring`          — DPAPI keyring used to decrypt the AES state key
///
/// Returns all credentials that could be successfully decrypted.  Rows that
/// fail to decrypt are logged as warnings and skipped.
pub fn extract_chromium_credentials(
    local_state_data: &[u8],
    login_data_db: &[u8],
    browser_name: &str,
    keyring: &DpapiKeyring,
) -> Vec<BrowserCredential> {
    let state_key = match extract_state_key(local_state_data, keyring) {
        Ok(k) => k,
        Err(e) => {
            log::warn!("{browser_name}: failed to extract state key: {e}");
            return Vec::new();
        }
    };

    match extract_login_data(login_data_db, &state_key, browser_name) {
        Ok(creds) => creds,
        Err(e) => {
            log::warn!("{browser_name}: failed to extract login data: {e}");
            Vec::new()
        }
    }
}

/// Parse `Local State`, base64-decode and DPAPI-decrypt the AES state key.
///
/// The JSON path is `os_crypt.encrypted_key`.  After base64 decoding the value
/// starts with the 5-byte ASCII string `DPAPI` followed by the raw DPAPI blob.
/// We strip that prefix before passing the blob to the keyring.
pub fn extract_state_key(
    local_state_data: &[u8],
    keyring: &DpapiKeyring,
) -> Result<[u8; 32], BrowserError> {
    let json: serde_json::Value = serde_json::from_slice(local_state_data)?;

    let encoded = json
        .get("os_crypt")
        .and_then(|v| v.get("encrypted_key"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| BrowserError::InvalidData {
            detail: "os_crypt.encrypted_key not found in Local State".to_string(),
        })?;

    let decoded = base64_decode(encoded).map_err(|e| BrowserError::InvalidData {
        detail: format!("base64 decode of encrypted_key failed: {e}"),
    })?;

    // Strip the 5-byte "DPAPI" prefix.
    const PREFIX: &[u8] = b"DPAPI";
    if decoded.len() < PREFIX.len() || &decoded[..PREFIX.len()] != PREFIX {
        return Err(BrowserError::InvalidData {
            detail: "encrypted_key does not start with 'DPAPI' prefix".to_string(),
        });
    }
    let blob = &decoded[PREFIX.len()..];

    let decrypted = keyring.decrypt_blob(blob)?;

    if decrypted.len() < 32 {
        return Err(BrowserError::InvalidData {
            detail: format!(
                "decrypted state key too short: {} bytes (need 32)",
                decrypted.len()
            ),
        });
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&decrypted[..32]);
    Ok(key)
}

/// Write the SQLite database bytes to a temp file, open with rusqlite, and
/// query the `logins` table.
pub fn extract_login_data(
    db_data: &[u8],
    state_key: &[u8; 32],
    browser_name: &str,
) -> Result<Vec<BrowserCredential>, BrowserError> {
    // Write database bytes to a temp file — rusqlite requires a file path.
    let mut tmp = tempfile_named()?;
    tmp.write_all(db_data)?;
    tmp.flush()?;

    let path = tmp.path().to_owned();
    let conn = rusqlite::Connection::open(&path)?;

    let mut stmt = conn.prepare(
        "SELECT origin_url, username_value, password_value FROM logins",
    )?;

    let mut credentials = Vec::new();

    let rows = stmt.query_map([], |row| {
        let url: String = row.get(0)?;
        let username: String = row.get(1)?;
        let password_bytes: Vec<u8> = row.get(2)?;
        Ok((url, username, password_bytes))
    })?;

    for row_result in rows {
        match row_result {
            Ok((url, username, encrypted)) => {
                match decrypt_chromium_password(&encrypted, state_key) {
                    Ok(password) => {
                        credentials.push(BrowserCredential {
                            browser: browser_name.to_string(),
                            url,
                            username,
                            password,
                        });
                    }
                    Err(e) => {
                        log::warn!(
                            "{browser_name}: failed to decrypt password for {url}: {e}"
                        );
                    }
                }
            }
            Err(e) => {
                log::warn!("{browser_name}: row error: {e}");
            }
        }
    }

    Ok(credentials)
}

/// Decrypt a Chromium `password_value` blob using AES-256-GCM.
///
/// Format (v10 / v11):
/// ```text
/// [0..3]   version tag: b"v10" or b"v11"
/// [3..15]  12-byte GCM nonce
/// [15..]   ciphertext + 16-byte GCM tag
/// ```
pub fn decrypt_chromium_password(
    encrypted: &[u8],
    state_key: &[u8; 32],
) -> Result<String, BrowserError> {
    if encrypted.len() < 15 {
        return Err(BrowserError::InvalidData {
            detail: format!(
                "encrypted password too short: {} bytes",
                encrypted.len()
            ),
        });
    }

    let tag = &encrypted[..3];
    if tag != b"v10" && tag != b"v11" {
        return Err(BrowserError::InvalidData {
            detail: format!(
                "unexpected version tag: {:?}",
                String::from_utf8_lossy(tag)
            ),
        });
    }

    let cipher = Aes256Gcm::new(state_key.into());
    let nonce = Nonce::from_slice(&encrypted[3..15]);
    let plaintext = cipher
        .decrypt(nonce, &encrypted[15..])
        .map_err(|_| BrowserError::AesGcm)?;

    String::from_utf8(plaintext).map_err(|e| BrowserError::InvalidData {
        detail: format!("password is not valid UTF-8: {e}"),
    })
}

/// Minimal standard base64 decoder (RFC 4648, no padding variants).
///
/// Returns the decoded bytes or an error string describing the problem.
/// Uses no external crate — alphabet is A-Z a-z 0-9 + /.
pub fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    // Build a lookup table: char value → 6-bit index (0..=63), 255 = invalid, 64 = padding.
    let mut table = [255u8; 256];
    for (i, &c) in ALPHABET.iter().enumerate() {
        table[c as usize] = i as u8;
    }
    table[b'=' as usize] = 64; // padding sentinel

    let input = input.trim();
    let bytes = input.as_bytes();

    if bytes.len() % 4 != 0 {
        return Err(format!(
            "base64 input length {} is not a multiple of 4",
            bytes.len()
        ));
    }

    let mut output = Vec::with_capacity(bytes.len() / 4 * 3);

    for chunk in bytes.chunks(4) {
        let a = table[chunk[0] as usize];
        let b = table[chunk[1] as usize];
        let c = table[chunk[2] as usize];
        let d = table[chunk[3] as usize];

        if a == 255 || b == 255 {
            return Err(format!("invalid base64 character in chunk {:?}", chunk));
        }

        output.push((a << 2) | (b >> 4));

        if c != 64 {
            if c == 255 {
                return Err(format!("invalid base64 character in chunk {:?}", chunk));
            }
            output.push((b << 4) | (c >> 2));

            if d != 64 {
                if d == 255 {
                    return Err(format!("invalid base64 character in chunk {:?}", chunk));
                }
                output.push((c << 6) | d);
            }
        }
    }

    Ok(output)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Create a named temporary file.  We use [`tempfile::NamedTempFile`] if it
/// were available, but since we don't want an extra dependency we write to a
/// file in the system temp directory with a generated name.
struct TempFile {
    path: std::path::PathBuf,
    file: std::fs::File,
}

impl TempFile {
    fn path(&self) -> &std::path::Path {
        &self.path
    }

    fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
        use std::io::Write;
        self.file.write_all(data)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        use std::io::Write;
        self.file.flush()
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn tempfile_named() -> Result<TempFile, BrowserError> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    let pid = std::process::id();
    let name = format!("abyss_browser_{pid}_{ts}.db");
    let path = std::env::temp_dir().join(name);

    let file = std::fs::File::create(&path)?;
    Ok(TempFile { path, file })
}
