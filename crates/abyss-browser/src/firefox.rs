//! Firefox browser credential extraction.
//!
//! Extracts saved passwords from Firefox profiles by parsing `key4.db` (SQLite)
//! and `logins.json`.  Supports the common forensic scenario where no master
//! password is set.
//!
//! Decryption flow:
//!   1. Parse `key4.db` raw bytes to locate the PKCS#5 PBES2 encrypted private
//!      key (nssPrivate `a11` attribute).
//!   2. Derive the content decryption key with PBKDF2-HMAC-SHA256 using an
//!      empty password (no master password case).
//!   3. Decrypt the content key with AES-256-CBC.
//!   4. Parse `logins.json` to extract base64-encoded encrypted credentials.
//!   5. For each credential, base64-decode, parse the ASN.1 DER envelope, and
//!      decrypt with 3DES-CBC or AES-256-CBC using the content key.

use crate::chromium::base64_decode;
use crate::error::BrowserError;

// ─── Public types ───────────────────────────────────────────────────────────

/// A discovered Firefox profile with raw file data.
#[derive(Debug)]
pub struct FirefoxProfile {
    /// Username that owns this profile.
    pub user: String,
    /// Filesystem path to the profile directory.
    pub profile_path: String,
    /// Raw bytes of `key4.db`.
    pub key4_db: Vec<u8>,
    /// Raw bytes of `logins.json`.
    pub logins_json: Vec<u8>,
}

/// A decrypted Firefox credential.
#[derive(Debug, Clone)]
pub struct FirefoxCredential {
    /// The URL the credential is associated with.
    pub url: String,
    /// The decrypted username.
    pub username: String,
    /// The decrypted password.
    pub password: String,
}

/// An encrypted login entry parsed from `logins.json`.
#[derive(Debug)]
pub struct EncryptedLogin {
    /// Hostname / URL (e.g. `https://example.com`).
    pub hostname: String,
    /// Base64-encoded encrypted username.
    pub encrypted_username: String,
    /// Base64-encoded encrypted password.
    pub encrypted_password: String,
}

// ─── ASN.1 / DER helpers ───────────────────────────────────────────────────

/// Encryption algorithm identified in a Firefox credential blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    /// DES-EDE3-CBC (OID 1.2.840.113549.3.7)
    TripleDes,
    /// AES-256-CBC (OID 2.16.840.1.101.3.4.1.42)
    Aes256Cbc,
}

/// Parsed encrypted blob from a Firefox credential field.
#[derive(Debug)]
pub struct EncryptedBlob {
    /// Which cipher was used.
    pub algorithm: EncryptionAlgorithm,
    /// Initialisation vector.
    pub iv: Vec<u8>,
    /// Raw ciphertext (before padding removal).
    pub ciphertext: Vec<u8>,
}

// ─── ASN.1 DER tag constants ───────────────────────────────────────────────

const TAG_SEQUENCE: u8 = 0x30;
const TAG_OID: u8 = 0x06;
const TAG_OCTET_STRING: u8 = 0x04;

/// OID bytes for DES-EDE3-CBC (1.2.840.113549.3.7).
const OID_DES_EDE3_CBC: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x07];

/// OID bytes for AES-256-CBC (2.16.840.1.101.3.4.1.42).
const OID_AES_256_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A];

/// OID bytes for PBES2 (1.2.840.113549.1.5.13).
const OID_PBES2: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D];

/// OID bytes for PBKDF2 (1.2.840.113549.1.5.12).
const OID_PBKDF2: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C];

/// OID bytes for HMAC-SHA256 (1.2.840.113549.2.9).
#[allow(dead_code)]
const OID_HMAC_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09];

/// Read a DER length from `data[pos..]`.
/// Returns `(length_value, number_of_bytes_consumed)`.
fn der_read_length(data: &[u8], pos: usize) -> Result<(usize, usize), BrowserError> {
    if pos >= data.len() {
        return Err(BrowserError::InvalidData {
            detail: "DER length: unexpected end of data".to_string(),
        });
    }
    let first = data[pos];
    if first < 0x80 {
        Ok((first as usize, 1))
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 4 {
            return Err(BrowserError::InvalidData {
                detail: format!("DER length: unsupported length encoding ({num_bytes} bytes)"),
            });
        }
        if pos + 1 + num_bytes > data.len() {
            return Err(BrowserError::InvalidData {
                detail: "DER length: not enough bytes for multi-byte length".to_string(),
            });
        }
        let mut length: usize = 0;
        for i in 0..num_bytes {
            length = (length << 8) | (data[pos + 1 + i] as usize);
        }
        Ok((length, 1 + num_bytes))
    }
}

/// Read a DER element at `data[pos..]`.
/// Returns `(tag, content_slice, total_bytes_consumed)`.
fn der_read_element(data: &[u8], pos: usize) -> Result<(u8, &[u8], usize), BrowserError> {
    if pos >= data.len() {
        return Err(BrowserError::InvalidData {
            detail: "DER element: unexpected end of data".to_string(),
        });
    }
    let tag = data[pos];
    let (length, len_size) = der_read_length(data, pos + 1)?;
    let content_start = pos + 1 + len_size;
    let content_end = content_start + length;
    if content_end > data.len() {
        return Err(BrowserError::InvalidData {
            detail: format!(
                "DER element: content extends beyond data (need {content_end}, have {})",
                data.len()
            ),
        });
    }
    Ok((tag, &data[content_start..content_end], 1 + len_size + length))
}

/// Parse a Firefox encrypted credential blob (after base64 decoding).
///
/// Expected structure:
/// ```text
/// SEQUENCE {
///   SEQUENCE {
///     OID (des-ede3-cbc or aes-256-cbc)
///     OCTET STRING (IV)
///   }
///   OCTET STRING (ciphertext)
/// }
/// ```
pub fn parse_encrypted_blob(data: &[u8]) -> Result<EncryptedBlob, BrowserError> {
    // Outer SEQUENCE
    let (tag, outer_content, _) = der_read_element(data, 0)?;
    if tag != TAG_SEQUENCE {
        return Err(BrowserError::InvalidData {
            detail: format!("expected SEQUENCE (0x30), got 0x{tag:02x}"),
        });
    }

    // First inner SEQUENCE (algorithm identifier)
    let (tag, algo_content, algo_total) = der_read_element(outer_content, 0)?;
    if tag != TAG_SEQUENCE {
        return Err(BrowserError::InvalidData {
            detail: format!("expected inner SEQUENCE (0x30), got 0x{tag:02x}"),
        });
    }

    // Parse OID inside algorithm identifier
    let (tag, oid_bytes, oid_total) = der_read_element(algo_content, 0)?;
    if tag != TAG_OID {
        return Err(BrowserError::InvalidData {
            detail: format!("expected OID (0x06), got 0x{tag:02x}"),
        });
    }

    let algorithm = if oid_bytes == OID_DES_EDE3_CBC {
        EncryptionAlgorithm::TripleDes
    } else if oid_bytes == OID_AES_256_CBC {
        EncryptionAlgorithm::Aes256Cbc
    } else {
        return Err(BrowserError::InvalidData {
            detail: format!("unknown encryption OID: {:02x?}", oid_bytes),
        });
    };

    // IV follows the OID
    let (tag, iv_bytes, _) = der_read_element(algo_content, oid_total)?;
    if tag != TAG_OCTET_STRING {
        return Err(BrowserError::InvalidData {
            detail: format!("expected OCTET STRING for IV (0x04), got 0x{tag:02x}"),
        });
    }

    // Ciphertext is the second element of the outer SEQUENCE
    let (tag, ct_bytes, _) = der_read_element(outer_content, algo_total)?;
    if tag != TAG_OCTET_STRING {
        return Err(BrowserError::InvalidData {
            detail: format!("expected OCTET STRING for ciphertext (0x04), got 0x{tag:02x}"),
        });
    }

    Ok(EncryptedBlob {
        algorithm,
        iv: iv_bytes.to_vec(),
        ciphertext: ct_bytes.to_vec(),
    })
}

// ─── PBES2 structure from key4.db ──────────────────────────────────────────

/// Parsed PBES2 parameters from the key4.db nssPrivate entry.
#[derive(Debug)]
struct Pbes2Params {
    salt: Vec<u8>,
    iterations: u32,
    iv: Vec<u8>,
    encrypted_data: Vec<u8>,
}

/// Search raw key4.db bytes for the PBES2-encrypted nssPrivate key.
///
/// We scan for the PBES2 OID pattern and then parse the surrounding ASN.1
/// structure to extract salt, iteration count, IV, and encrypted key material.
fn find_pbes2_encrypted_key(data: &[u8]) -> Result<Pbes2Params, BrowserError> {
    // The nssPrivate a11 value is a DER-encoded SEQUENCE starting with PBES2.
    // We look for SEQUENCE { SEQUENCE { OID(PBES2), SEQUENCE { ... } }, OCTET STRING }
    //
    // Strategy: scan for the PBES2 OID bytes, then back up to find the
    // enclosing SEQUENCE tag and parse from there.

    let pbes2_oid_with_tag: Vec<u8> = {
        let mut v = vec![TAG_OID, OID_PBES2.len() as u8];
        v.extend_from_slice(OID_PBES2);
        v
    };

    // Find all occurrences of the PBES2 OID in the raw data
    let mut search_pos = 0;
    while search_pos + pbes2_oid_with_tag.len() <= data.len() {
        if let Some(offset) = find_bytes(&data[search_pos..], &pbes2_oid_with_tag) {
            let abs_offset = search_pos + offset;

            // The OID should be inside a SEQUENCE (algorithm identifier),
            // which is inside another SEQUENCE (the outer wrapper).
            // Try to find the outer SEQUENCE by scanning backwards.
            if let Some(params) = try_parse_pbes2_from_oid(data, abs_offset) {
                return Ok(params);
            }

            search_pos = abs_offset + 1;
        } else {
            break;
        }
    }

    Err(BrowserError::InvalidData {
        detail: "could not locate PBES2 encrypted key in key4.db".to_string(),
    })
}

/// Try to parse a PBES2 structure given the position of the PBES2 OID tag byte.
fn try_parse_pbes2_from_oid(data: &[u8], oid_tag_pos: usize) -> Option<Pbes2Params> {
    // Walk backwards (max 10 bytes) looking for a SEQUENCE tag that encloses
    // the algorithm identifier SEQUENCE.
    let min_start = oid_tag_pos.saturating_sub(10);
    for start in (min_start..oid_tag_pos).rev() {
        if data[start] == TAG_SEQUENCE {
            // Try to parse from two levels up — the outermost SEQUENCE that
            // contains both the AlgorithmIdentifier and the encrypted data.
            // The algo-id SEQUENCE starts here; the outer SEQUENCE is one
            // level up.
            let outer_start = if start >= 1 {
                // Look for the outer SEQUENCE
                let outer_min = start.saturating_sub(10);
                let mut found_outer = None;
                for os in (outer_min..start).rev() {
                    if data[os] == TAG_SEQUENCE {
                        if let Ok((_, content, _)) = der_read_element(data, os) {
                            // Check if this SEQUENCE contains our algo-id SEQUENCE
                            let content_start = os + (data.len() - (data.len() - (start.saturating_sub(os))));
                            let _ = content_start; // just need the content to reach past
                            let content_end_abs = os + 1
                                + der_read_length(data, os + 1).ok()?.1
                                + content.len();
                            if content_end_abs > oid_tag_pos {
                                found_outer = Some(os);
                                break;
                            }
                        }
                    }
                }
                found_outer.unwrap_or(start)
            } else {
                start
            };

            if let Ok(params) = parse_pbes2_structure(data, outer_start) {
                return Some(params);
            }
        }
    }
    None
}

/// Parse a complete PBES2 structure starting at `pos`.
///
/// ```text
/// SEQUENCE {                          -- outer
///   SEQUENCE {                        -- algorithm identifier
///     OID (PBES2)
///     SEQUENCE {                      -- PBES2 parameters
///       SEQUENCE {                    -- key derivation function
///         OID (PBKDF2)
///         SEQUENCE {                  -- PBKDF2 params
///           OCTET STRING (salt)
///           INTEGER (iterations)
///           SEQUENCE {                -- PRF (optional, defaults to HMAC-SHA1)
///             OID (HMAC-SHA256)
///             NULL
///           }
///         }
///       }
///       SEQUENCE {                    -- encryption scheme
///         OID (AES-256-CBC)
///         OCTET STRING (IV)
///       }
///     }
///   }
///   OCTET STRING (encrypted data)
/// }
/// ```
fn parse_pbes2_structure(data: &[u8], pos: usize) -> Result<Pbes2Params, BrowserError> {
    // Outer SEQUENCE
    let (tag, outer_content, _) = der_read_element(data, pos)?;
    if tag != TAG_SEQUENCE {
        return Err(BrowserError::InvalidData {
            detail: "PBES2: expected outer SEQUENCE".to_string(),
        });
    }

    // Algorithm Identifier SEQUENCE
    let (tag, algo_id_content, algo_id_total) = der_read_element(outer_content, 0)?;
    if tag != TAG_SEQUENCE {
        return Err(BrowserError::InvalidData {
            detail: "PBES2: expected AlgorithmIdentifier SEQUENCE".to_string(),
        });
    }

    // OID (should be PBES2)
    let (tag, oid_bytes, oid_total) = der_read_element(algo_id_content, 0)?;
    if tag != TAG_OID || oid_bytes != OID_PBES2 {
        return Err(BrowserError::InvalidData {
            detail: "PBES2: expected PBES2 OID".to_string(),
        });
    }

    // PBES2 parameters SEQUENCE
    let (tag, pbes2_params_content, _) = der_read_element(algo_id_content, oid_total)?;
    if tag != TAG_SEQUENCE {
        return Err(BrowserError::InvalidData {
            detail: "PBES2: expected parameters SEQUENCE".to_string(),
        });
    }

    // Key derivation function SEQUENCE
    let (tag, kdf_content, kdf_total) = der_read_element(pbes2_params_content, 0)?;
    if tag != TAG_SEQUENCE {
        return Err(BrowserError::InvalidData {
            detail: "PBES2: expected KDF SEQUENCE".to_string(),
        });
    }

    // PBKDF2 OID
    let (tag, kdf_oid, kdf_oid_total) = der_read_element(kdf_content, 0)?;
    if tag != TAG_OID || kdf_oid != OID_PBKDF2 {
        return Err(BrowserError::InvalidData {
            detail: "PBES2: expected PBKDF2 OID".to_string(),
        });
    }

    // PBKDF2 parameters SEQUENCE
    let (tag, pbkdf2_content, _) = der_read_element(kdf_content, kdf_oid_total)?;
    if tag != TAG_SEQUENCE {
        return Err(BrowserError::InvalidData {
            detail: "PBES2: expected PBKDF2 params SEQUENCE".to_string(),
        });
    }

    // Salt (OCTET STRING)
    let (tag, salt_bytes, salt_total) = der_read_element(pbkdf2_content, 0)?;
    if tag != TAG_OCTET_STRING {
        return Err(BrowserError::InvalidData {
            detail: "PBES2: expected salt OCTET STRING".to_string(),
        });
    }

    // Iteration count (INTEGER, tag 0x02)
    let (tag, iter_bytes, _iter_total) = der_read_element(pbkdf2_content, salt_total)?;
    if tag != 0x02 {
        return Err(BrowserError::InvalidData {
            detail: format!("PBES2: expected INTEGER for iterations, got 0x{tag:02x}"),
        });
    }
    let iterations = der_integer_to_u32(iter_bytes)?;

    // Encryption scheme SEQUENCE (after KDF)
    let (tag, enc_content, _) = der_read_element(pbes2_params_content, kdf_total)?;
    if tag != TAG_SEQUENCE {
        return Err(BrowserError::InvalidData {
            detail: "PBES2: expected encryption scheme SEQUENCE".to_string(),
        });
    }

    // Encryption OID (AES-256-CBC expected)
    let (tag, _enc_oid, enc_oid_total) = der_read_element(enc_content, 0)?;
    if tag != TAG_OID {
        return Err(BrowserError::InvalidData {
            detail: "PBES2: expected encryption OID".to_string(),
        });
    }

    // IV (OCTET STRING)
    let (tag, iv_bytes, _) = der_read_element(enc_content, enc_oid_total)?;
    if tag != TAG_OCTET_STRING {
        return Err(BrowserError::InvalidData {
            detail: "PBES2: expected IV OCTET STRING".to_string(),
        });
    }

    // Encrypted data (OCTET STRING after the AlgorithmIdentifier)
    let (tag, encrypted_bytes, _) = der_read_element(outer_content, algo_id_total)?;
    if tag != TAG_OCTET_STRING {
        return Err(BrowserError::InvalidData {
            detail: "PBES2: expected encrypted data OCTET STRING".to_string(),
        });
    }

    Ok(Pbes2Params {
        salt: salt_bytes.to_vec(),
        iterations,
        iv: iv_bytes.to_vec(),
        encrypted_data: encrypted_bytes.to_vec(),
    })
}

/// Convert a DER INTEGER byte sequence to u32.
fn der_integer_to_u32(bytes: &[u8]) -> Result<u32, BrowserError> {
    if bytes.is_empty() || bytes.len() > 4 {
        return Err(BrowserError::InvalidData {
            detail: format!("DER INTEGER: unexpected length {}", bytes.len()),
        });
    }
    let mut value: u32 = 0;
    for &b in bytes {
        value = (value << 8) | (b as u32);
    }
    Ok(value)
}

/// Search `haystack` for `needle`, returning the offset of the first match.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

// ─── Master password detection ─────────────────────────────────────────────

/// Search raw key4.db bytes for the encrypted `password-check` blob.
///
/// Firefox stores a sentinel value encrypted under the same key used for
/// credentials.  The plaintext is `"password-check"` with two bytes of PKCS#7
/// padding (`\x02\x02`), making the expected decrypted value 16 bytes total.
///
/// We locate this by finding the ASCII text `"password-check"` in the raw
/// SQLite file and then scanning forward for the nearest DER SEQUENCE tag that
/// looks like an encrypted credential blob.
fn find_password_check_blob(data: &[u8]) -> Option<Vec<u8>> {
    let marker = b"password-check";
    let mut search_pos = 0;

    while let Some(offset) = find_bytes(&data[search_pos..], marker) {
        let abs = search_pos + offset;

        // Scan forward up to 512 bytes for a SEQUENCE tag (0x30) that begins a
        // valid encrypted blob.
        let scan_end = (abs + 512).min(data.len());
        let mut pos = abs + marker.len();
        while pos < scan_end {
            if data[pos] == TAG_SEQUENCE {
                // Try parsing as an encrypted credential blob.
                if let Ok(blob) = parse_encrypted_blob(&data[pos..]) {
                    // The blob must have a non-empty ciphertext.
                    if !blob.ciphertext.is_empty() {
                        return Some(data[pos..pos + 512.min(data.len() - pos)].to_vec());
                    }
                }
            }
            pos += 1;
        }

        search_pos = abs + 1;
    }

    None
}

/// Check that the derived key is correct by attempting to decrypt the
/// `password-check` sentinel stored in key4.db.
///
/// Returns `true` when no master password is set (i.e. the empty password
/// produces the correct key).  Returns `false` if the sentinel could not be
/// found (treated as "assume no master password") or if decryption produces
/// unexpected plaintext (master password is set).
pub fn verify_no_master_password(key4_data: &[u8], derived_key: &[u8]) -> bool {
    let blob_data = match find_password_check_blob(key4_data) {
        Some(d) => d,
        // If there is no password-check entry we cannot verify — assume OK.
        None => return true,
    };

    let blob = match parse_encrypted_blob(&blob_data) {
        Ok(b) => b,
        Err(_) => return true,
    };

    let plaintext = match blob.algorithm {
        EncryptionAlgorithm::TripleDes => {
            let k = if derived_key.len() >= 24 {
                &derived_key[..24]
            } else {
                derived_key
            };
            match triple_des_cbc_decrypt(k, &blob.iv, &blob.ciphertext) {
                Ok(p) => p,
                Err(_) => return false,
            }
        }
        EncryptionAlgorithm::Aes256Cbc => {
            let k = if derived_key.len() >= 32 {
                &derived_key[..32]
            } else {
                derived_key
            };
            match aes256_cbc_decrypt(k, &blob.iv, &blob.ciphertext) {
                Ok(p) => p,
                Err(_) => return false,
            }
        }
    };

    // Expected plaintext: "password-check" (14 bytes) + "\x02\x02" (PKCS#7 padding already stripped,
    // so we look for just the string — after unpadding the 16-byte block becomes 14 bytes).
    // pkcs7_unpad already removed the padding bytes, so plaintext should be exactly b"password-check".
    plaintext == b"password-check"
}

// ─── Crypto helpers ────────────────────────────────────────────────────────

/// PKCS#7 unpad.  Returns the unpadded slice or an error.
fn pkcs7_unpad(data: &[u8], block_size: usize) -> Result<&[u8], BrowserError> {
    if data.is_empty() {
        return Err(BrowserError::InvalidData {
            detail: "PKCS#7 unpad: empty data".to_string(),
        });
    }
    let pad_byte = *data.last().unwrap();
    let pad_len = pad_byte as usize;
    if pad_len == 0 || pad_len > block_size || pad_len > data.len() {
        return Err(BrowserError::InvalidData {
            detail: format!("PKCS#7 unpad: invalid padding byte 0x{pad_byte:02x}"),
        });
    }
    // Verify all padding bytes
    for &b in &data[data.len() - pad_len..] {
        if b != pad_byte {
            return Err(BrowserError::InvalidData {
                detail: "PKCS#7 unpad: inconsistent padding".to_string(),
            });
        }
    }
    Ok(&data[..data.len() - pad_len])
}

/// Decrypt with AES-256-CBC.
fn aes256_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, BrowserError> {
    use aes::Aes256;
    use cbc::cipher::{BlockDecryptMut, KeyIvInit};

    type Aes256CbcDec = cbc::Decryptor<Aes256>;

    if key.len() != 32 {
        return Err(BrowserError::InvalidData {
            detail: format!("AES-256-CBC: key must be 32 bytes, got {}", key.len()),
        });
    }
    if iv.len() != 16 {
        return Err(BrowserError::InvalidData {
            detail: format!("AES-256-CBC: IV must be 16 bytes, got {}", iv.len()),
        });
    }

    let mut buf = ciphertext.to_vec();
    let decryptor = Aes256CbcDec::new(key.into(), iv.into());
    let plaintext = decryptor
        .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf)
        .map_err(|_| BrowserError::InvalidData {
            detail: "AES-256-CBC decryption failed".to_string(),
        })?;

    let unpadded = pkcs7_unpad(plaintext, 16)?;
    Ok(unpadded.to_vec())
}

/// Decrypt with 3DES-CBC (DES-EDE3-CBC).
fn triple_des_cbc_decrypt(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, BrowserError> {
    use cbc::cipher::{BlockDecryptMut, KeyIvInit};
    use des::TdesEde3;

    type TdesCbcDec = cbc::Decryptor<TdesEde3>;

    if key.len() != 24 {
        return Err(BrowserError::InvalidData {
            detail: format!("3DES-CBC: key must be 24 bytes, got {}", key.len()),
        });
    }
    if iv.len() != 8 {
        return Err(BrowserError::InvalidData {
            detail: format!("3DES-CBC: IV must be 8 bytes, got {}", iv.len()),
        });
    }

    let mut buf = ciphertext.to_vec();
    let decryptor = TdesCbcDec::new(key.into(), iv.into());
    let plaintext = decryptor
        .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf)
        .map_err(|_| BrowserError::InvalidData {
            detail: "3DES-CBC decryption failed".to_string(),
        })?;

    let unpadded = pkcs7_unpad(plaintext, 8)?;
    Ok(unpadded.to_vec())
}

/// PBKDF2-HMAC-SHA256 key derivation.
fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, key_len: usize) -> Vec<u8> {
    // PBKDF2 implementation
    // Each block: U_1 = PRF(password, salt || INT(i))
    //             U_j = PRF(password, U_{j-1})
    //             block = U_1 ^ U_2 ^ ... ^ U_c

    let hash_len = 32; // SHA-256 output
    let num_blocks = (key_len + hash_len - 1) / hash_len;
    let mut derived_key = Vec::with_capacity(num_blocks * hash_len);

    for block_num in 1..=(num_blocks as u32) {
        // U_1 = HMAC-SHA256(password, salt || BE32(block_num))
        let mut salt_block = salt.to_vec();
        salt_block.extend_from_slice(&block_num.to_be_bytes());

        let mut u = hmac_sha256(password, &salt_block);
        let mut result = u.clone();

        for _ in 1..iterations {
            u = hmac_sha256(password, &u);
            for (r, x) in result.iter_mut().zip(u.iter()) {
                *r ^= x;
            }
        }

        derived_key.extend_from_slice(&result);
    }

    derived_key.truncate(key_len);
    derived_key
}

/// Compute HMAC-SHA256.
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac =
        <Hmac<Sha256>>::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

// ─── SQLite magic check ────────────────────────────────────────────────────

/// SQLite file header magic bytes.
const SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";

/// Verify that data starts with the SQLite magic header.
fn is_sqlite(data: &[u8]) -> bool {
    data.len() >= SQLITE_MAGIC.len() && &data[..SQLITE_MAGIC.len()] == SQLITE_MAGIC
}

// ─── Public API ────────────────────────────────────────────────────────────

/// Parse `logins.json` and extract encrypted login entries.
pub fn parse_logins_json(data: &[u8]) -> Result<Vec<EncryptedLogin>, BrowserError> {
    let json: serde_json::Value = serde_json::from_slice(data)?;

    let logins = json
        .get("logins")
        .and_then(|v| v.as_array())
        .ok_or_else(|| BrowserError::InvalidData {
            detail: "logins.json: missing or invalid 'logins' array".to_string(),
        })?;

    let mut results = Vec::new();

    for entry in logins {
        let hostname = entry
            .get("hostname")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let encrypted_username = entry
            .get("encryptedUsername")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let encrypted_password = entry
            .get("encryptedPassword")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        if !encrypted_username.is_empty() || !encrypted_password.is_empty() {
            results.push(EncryptedLogin {
                hostname,
                encrypted_username,
                encrypted_password,
            });
        }
    }

    Ok(results)
}

/// Attempt to extract the content decryption key from `key4.db` raw bytes.
///
/// This handles the most common forensic scenario: **no master password**.
/// The key is derived via PBKDF2-HMAC-SHA256 with an empty password, then used
/// to AES-256-CBC-decrypt the stored content key.
pub fn extract_key_from_key4db(data: &[u8]) -> Result<Vec<u8>, BrowserError> {
    if !is_sqlite(data) {
        return Err(BrowserError::InvalidData {
            detail: "key4.db: not a SQLite file".to_string(),
        });
    }

    let pbes2 = find_pbes2_encrypted_key(data)?;

    // Derive the decryption key from an empty password.
    let derived = pbkdf2_sha256(b"", &pbes2.salt, pbes2.iterations, 32);

    // Decrypt the content key using AES-256-CBC.
    let decrypted = aes256_cbc_decrypt(&derived, &pbes2.iv, &pbes2.encrypted_data)?;

    // The decrypted data should contain the actual content encryption key.
    // Firefox stores a 24-byte 3DES key or a 32-byte AES key inside.
    // The decrypted blob may have extra wrapper data; the key is typically
    // the last 24 or 32 bytes after stripping any ASN.1 wrapper.
    //
    // In practice, the decrypted result from the nssPrivate a11 entry is
    // itself an ASN.1 structure.  For the common case, the key bytes are
    // embedded directly.  We return the full decrypted blob and let the
    // credential decryption step use whatever length it needs.

    if decrypted.is_empty() {
        return Err(BrowserError::InvalidData {
            detail: "key4.db: decrypted content key is empty".to_string(),
        });
    }

    Ok(decrypted)
}

/// Decrypt a single Firefox encrypted field.
///
/// The field value is base64-encoded.  After decoding, it contains a DER
/// structure identifying the cipher (3DES-CBC or AES-256-CBC) plus IV and
/// ciphertext.
pub fn decrypt_firefox_field(base64_data: &str, key: &[u8]) -> Result<String, BrowserError> {
    if base64_data.is_empty() {
        return Ok(String::new());
    }

    let raw = base64_decode(base64_data).map_err(|e| BrowserError::InvalidData {
        detail: format!("base64 decode failed: {e}"),
    })?;

    let blob = parse_encrypted_blob(&raw)?;

    let plaintext = match blob.algorithm {
        EncryptionAlgorithm::TripleDes => {
            // 3DES needs a 24-byte key.  If we have more, take the first 24.
            let k = if key.len() >= 24 { &key[..24] } else { key };
            triple_des_cbc_decrypt(k, &blob.iv, &blob.ciphertext)?
        }
        EncryptionAlgorithm::Aes256Cbc => {
            // AES-256 needs a 32-byte key.  If we have more, take the first 32.
            let k = if key.len() >= 32 { &key[..32] } else { key };
            aes256_cbc_decrypt(k, &blob.iv, &blob.ciphertext)?
        }
    };

    String::from_utf8(plaintext).map_err(|e| BrowserError::InvalidData {
        detail: format!("decrypted value is not valid UTF-8: {e}"),
    })
}

/// Full extraction: given a [`FirefoxProfile`], return all decrypted credentials.
///
/// Returns an empty Vec (with warnings logged) if the key cannot be extracted
/// or if there are no logins.
pub fn extract_firefox_credentials(profile: &FirefoxProfile) -> Vec<FirefoxCredential> {
    let key = match extract_key_from_key4db(&profile.key4_db) {
        Ok(k) => k,
        Err(e) => {
            log::warn!(
                "Firefox ({}): failed to extract key from key4.db: {e}",
                profile.profile_path
            );
            return Vec::new();
        }
    };

    // Verify that no master password is set before attempting decryption.
    // If a master password is set, the derived key is wrong and all decrypted
    // values would be garbage.
    if !verify_no_master_password(&profile.key4_db, &key) {
        log::warn!(
            "Firefox profile has a master password set — cannot extract credentials without it"
        );
        return Vec::new();
    }

    let logins = match parse_logins_json(&profile.logins_json) {
        Ok(l) => l,
        Err(e) => {
            log::warn!(
                "Firefox ({}): failed to parse logins.json: {e}",
                profile.profile_path
            );
            return Vec::new();
        }
    };

    let mut credentials = Vec::new();

    for login in &logins {
        let username = match decrypt_firefox_field(&login.encrypted_username, &key) {
            Ok(u) => u,
            Err(e) => {
                log::warn!(
                    "Firefox ({}): failed to decrypt username for {}: {e}",
                    profile.profile_path,
                    login.hostname
                );
                continue;
            }
        };
        let password = match decrypt_firefox_field(&login.encrypted_password, &key) {
            Ok(p) => p,
            Err(e) => {
                log::warn!(
                    "Firefox ({}): failed to decrypt password for {}: {e}",
                    profile.profile_path,
                    login.hostname
                );
                continue;
            }
        };

        credentials.push(FirefoxCredential {
            url: login.hostname.clone(),
            username,
            password,
        });
    }

    credentials
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_der_read_length_short() {
        let data = [0x05]; // length = 5
        let (len, consumed) = der_read_length(&data, 0).unwrap();
        assert_eq!(len, 5);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_der_read_length_long() {
        let data = [0x82, 0x01, 0x00]; // length = 256, 2-byte encoding
        let (len, consumed) = der_read_length(&data, 0).unwrap();
        assert_eq!(len, 256);
        assert_eq!(consumed, 3);
    }

    #[test]
    fn test_der_read_element_octet_string() {
        let data = [TAG_OCTET_STRING, 0x03, 0xAA, 0xBB, 0xCC];
        let (tag, content, total) = der_read_element(&data, 0).unwrap();
        assert_eq!(tag, TAG_OCTET_STRING);
        assert_eq!(content, &[0xAA, 0xBB, 0xCC]);
        assert_eq!(total, 5);
    }

    #[test]
    fn test_pkcs7_unpad_valid() {
        let data = [0x41, 0x42, 0x43, 0x05, 0x05, 0x05, 0x05, 0x05];
        let result = pkcs7_unpad(&data, 8).unwrap();
        assert_eq!(result, &[0x41, 0x42, 0x43]);
    }

    #[test]
    fn test_pkcs7_unpad_invalid() {
        let data = [0x41, 0x42, 0x00]; // pad byte 0 is invalid
        assert!(pkcs7_unpad(&data, 8).is_err());
    }

    #[test]
    fn test_find_bytes() {
        let haystack = b"hello world test";
        assert_eq!(find_bytes(haystack, b"world"), Some(6));
        assert_eq!(find_bytes(haystack, b"xyz"), None);
        assert_eq!(find_bytes(haystack, b""), None);
    }

    #[test]
    fn test_is_sqlite() {
        let mut header = SQLITE_MAGIC.to_vec();
        header.extend_from_slice(&[0u8; 100]);
        assert!(is_sqlite(&header));
        assert!(!is_sqlite(b"not a sqlite file"));
    }

    #[test]
    fn test_der_integer_to_u32() {
        assert_eq!(der_integer_to_u32(&[0x01]).unwrap(), 1);
        assert_eq!(der_integer_to_u32(&[0x01, 0x00]).unwrap(), 256);
        assert_eq!(der_integer_to_u32(&[0x00, 0x01, 0x00, 0x00]).unwrap(), 65536);
    }

    // ─── Master password detection tests ──────────────────────────────────────

    /// When key4.db contains no "password-check" marker, verification should
    /// assume no master password and return true.
    #[test]
    fn test_verify_no_master_password_no_sentinel() {
        // Arbitrary data without the "password-check" string.
        let data = b"some random key4.db bytes without the sentinel";
        let key = vec![0u8; 24];
        assert!(verify_no_master_password(data, &key));
    }

    /// When key4.db contains "password-check" but decryption (with a wrong key)
    /// produces incorrect plaintext, verification should return false.
    #[test]
    fn test_verify_no_master_password_wrong_key_detected() {
        use cbc::cipher::{BlockEncryptMut, KeyIvInit};
        use des::TdesEde3;

        type TdesCbcEnc = cbc::Encryptor<TdesEde3>;

        // Encrypt "password-check\x02\x02" (16 bytes, valid PKCS#7 padding for 3DES block=8)
        // under a "correct" key.
        let correct_key = [0x01u8; 24];
        let iv = [0x00u8; 8];
        // "password-check" is 14 bytes; PKCS#7 pad to 16 bytes -> append \x02\x02
        let plaintext = b"password-check\x02\x02";
        let buf = plaintext.to_vec();
        // Pad to block boundary: 16 bytes is already a multiple of 8, so add a full block of padding.
        // Actually for encryption with NoPadding we supply exactly 16 bytes (two 8-byte blocks).
        let enc = TdesCbcEnc::new((&correct_key).into(), (&iv).into());
        let ciphertext = enc
            .encrypt_padded_vec_mut::<cbc::cipher::block_padding::NoPadding>(&buf);

        // Build a DER-encoded encrypted blob:
        // SEQUENCE {
        //   SEQUENCE { OID(des-ede3-cbc), OCTET STRING(iv) }
        //   OCTET STRING(ciphertext)
        // }
        let oid_bytes = OID_DES_EDE3_CBC;
        let mut algo_seq_inner = Vec::new();
        algo_seq_inner.push(TAG_OID);
        algo_seq_inner.push(oid_bytes.len() as u8);
        algo_seq_inner.extend_from_slice(oid_bytes);
        algo_seq_inner.push(TAG_OCTET_STRING);
        algo_seq_inner.push(iv.len() as u8);
        algo_seq_inner.extend_from_slice(&iv);

        let mut algo_seq = Vec::new();
        algo_seq.push(TAG_SEQUENCE);
        algo_seq.push(algo_seq_inner.len() as u8);
        algo_seq.extend_from_slice(&algo_seq_inner);

        let mut ct_field = Vec::new();
        ct_field.push(TAG_OCTET_STRING);
        ct_field.push(ciphertext.len() as u8);
        ct_field.extend_from_slice(&ciphertext);

        let mut outer_content = Vec::new();
        outer_content.extend_from_slice(&algo_seq);
        outer_content.extend_from_slice(&ct_field);

        let mut blob_der = Vec::new();
        blob_der.push(TAG_SEQUENCE);
        blob_der.push(outer_content.len() as u8);
        blob_der.extend_from_slice(&outer_content);

        // Build a fake key4.db containing the marker string followed by the blob.
        let mut fake_db = Vec::new();
        fake_db.extend_from_slice(b"password-check");
        fake_db.extend_from_slice(&blob_der);

        // With the correct key, decryption should succeed and return true.
        assert!(verify_no_master_password(&fake_db, &correct_key));

        // With a wrong key (simulating a master password being set), the
        // decrypted plaintext will not match and should return false.
        let wrong_key = [0x42u8; 24];
        assert!(!verify_no_master_password(&fake_db, &wrong_key));

    }
}
