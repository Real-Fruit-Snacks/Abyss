//! LSA secrets extraction from the SECURITY registry hive.
//!
//! Given a SECURITY hive and the 16-byte SYSKEY derived from the SYSTEM hive,
//! this module derives the LSA key and decrypts LSA secrets stored under
//! Policy\Secrets.
//!
//! Supported Windows versions:
//!   - Vista+ (Windows 6.0+): AES-128-CBC with HMAC-SHA256 derived key
//!   - XP / pre-Vista: RC4 with MD5-derived key (1000 hash iterations)

use crate::error::CryptoError;
use crate::sam::decrypt_aes_128_cbc;
use abyss_registry::RegistryHive;

use hmac::{Hmac, Mac};
use md5::Digest as Md5Digest;
use rc4::{KeyInit as Rc4KeyInit, Rc4, StreamCipher};
use sha2::Sha256;
use typenum::U32;

type HmacSha256 = Hmac<Sha256>;

/// A single decrypted LSA secret.
#[derive(Debug, Clone)]
pub struct LsaSecret {
    /// The secret name (registry key name under Policy\Secrets).
    pub name: String,
    /// The current (CurrVal) decrypted secret bytes.
    pub current_value: Vec<u8>,
    /// The old (OldVal) decrypted secret bytes, if present.
    pub old_value: Option<Vec<u8>>,
}

/// Derive the 16-byte LSA key from the SECURITY hive and SYSKEY.
///
/// Tries Vista+ path (Policy\PolEKList) first; falls back to XP path
/// (Policy\PolSecretEncryptionKey).
pub fn derive_lsa_key(
    security: &mut RegistryHive,
    syskey: &[u8; 16],
) -> Result<Vec<u8>, CryptoError> {
    // Try Vista+ path first.
    let policy_key = security
        .open_key("Policy")
        .map_err(|_| CryptoError::KeyNotFound {
            key: "Policy".to_string(),
        })?;

    if let Ok(val) = security.read_value(&policy_key, "PolEKList") {
        log::debug!("LSA: using Vista+ PolEKList path");
        return derive_lsa_key_vista(&val.data, syskey);
    }

    // Fall back to XP path.
    if let Ok(val) = security.read_value(&policy_key, "PolSecretEncryptionKey") {
        log::debug!("LSA: using XP PolSecretEncryptionKey path");
        return derive_lsa_key_xp(&val.data, syskey);
    }

    Err(CryptoError::KeyNotFound {
        key: "Policy\\PolEKList or Policy\\PolSecretEncryptionKey".to_string(),
    })
}

/// Vista+ LSA key derivation using AES-128-CBC with HMAC-SHA256.
///
/// PolEKList layout:
///   bytes 0..28:  header (ignored)
///   bytes 28..60: 32-byte HMAC-SHA256 hash
///   bytes 60..76: 16-byte AES IV
///   bytes 76..92: 16-byte AES-encrypted LSA key
fn derive_lsa_key_vista(data: &[u8], syskey: &[u8; 16]) -> Result<Vec<u8>, CryptoError> {
    if data.len() < 92 {
        return Err(CryptoError::BufferTooSmall {
            need: 92,
            have: data.len(),
        });
    }

    // HMAC-SHA256(syskey, data[28..60]) → 32-byte AES key (use first 16 bytes as key)
    let hmac_hash = &data[28..60];
    let iv = &data[60..76];
    let encrypted = &data[76..92];

    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(syskey).map_err(|e| CryptoError::Decrypt {
            detail: format!("HMAC-SHA256 init: {e}"),
        })?;
    mac.update(hmac_hash);
    let derived = mac.finalize().into_bytes();

    // Use first 16 bytes of the 32-byte HMAC output as the AES key.
    let aes_key = &derived[..16];
    let decrypted = decrypt_aes_128_cbc(aes_key, iv, encrypted)?;

    // The decrypted block contains the actual 16-byte LSA key at bytes 68..84
    // relative to the decrypted structure — but for PolEKList the full decrypted
    // blob IS the key material. Impacket takes bytes [68..84] of the raw PolEKList
    // data after decryption. Since we only decrypt the 16-byte block starting at
    // offset 76, the result is the LSA key directly.
    Ok(decrypted.to_vec())
}

/// XP LSA key derivation using RC4 with MD5 (1000 iterations).
///
/// PolSecretEncryptionKey layout:
///   bytes 0..60:  header (ignored)
///   bytes 60..76: 16-byte MD5 salt
///   bytes 76..108: 32-byte RC4-encrypted blob (take first 16 as LSA key)
fn derive_lsa_key_xp(data: &[u8], syskey: &[u8; 16]) -> Result<Vec<u8>, CryptoError> {
    if data.len() < 108 {
        return Err(CryptoError::BufferTooSmall {
            need: 108,
            have: data.len(),
        });
    }

    let salt = &data[60..76];
    let encrypted = &data[76..108];

    // Build RC4 key via 1000 MD5 iterations:
    //   md5(syskey + salt repeated 1000 times)
    let mut md5_input = Vec::with_capacity(16 + salt.len());
    md5_input.extend_from_slice(syskey);
    md5_input.extend_from_slice(salt);

    let mut digest = md5::Md5::digest(&md5_input);
    for _ in 1..1000 {
        digest = md5::Md5::digest(&digest);
    }
    let rc4_key = digest;

    let mut data_buf = encrypted.to_vec();
    let mut rc4: Rc4<U32> = Rc4KeyInit::new(rc4_key.as_slice().into());
    rc4.apply_keystream(&mut data_buf);

    // First 16 bytes are the LSA key.
    Ok(data_buf[..16].to_vec())
}

/// Extract and decrypt all LSA secrets from the SECURITY hive.
///
/// Enumerates Policy\Secrets\*, decrypts CurrVal and OldVal for each.
/// Non-fatal parse failures are logged as warnings and skipped.
pub fn extract_lsa_secrets(
    security: &mut RegistryHive,
    lsa_key: &[u8],
) -> Result<Vec<LsaSecret>, CryptoError> {
    let secrets_key = match security.open_key("Policy\\Secrets") {
        Ok(k) => k,
        Err(_) => {
            log::warn!("LSA: Policy\\Secrets key not found, returning empty list");
            return Ok(Vec::new());
        }
    };

    let subkey_names = security
        .subkey_names(&secrets_key)
        .map_err(|e| CryptoError::InvalidData {
            detail: format!("enumerating Policy\\Secrets subkeys: {e}"),
        })?;

    let mut secrets = Vec::new();

    for name in subkey_names {
        let secret_path = format!("Policy\\Secrets\\{name}");

        let current_value = match read_and_decrypt_secret(security, &secret_path, "CurrVal", lsa_key) {
            Ok(v) => v,
            Err(e) => {
                log::warn!("LSA: failed to decrypt CurrVal for {name}: {e}");
                continue;
            }
        };

        let old_value = match read_and_decrypt_secret(security, &secret_path, "OldVal", lsa_key) {
            Ok(v) => Some(v),
            Err(_) => None,
        };

        secrets.push(LsaSecret {
            name,
            current_value,
            old_value,
        });
    }

    Ok(secrets)
}

/// Read and decrypt a single secret value (CurrVal or OldVal).
fn read_and_decrypt_secret(
    security: &mut RegistryHive,
    secret_path: &str,
    value_name: &str,
    lsa_key: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let key = security
        .open_key(secret_path)
        .map_err(|_| CryptoError::KeyNotFound {
            key: secret_path.to_string(),
        })?;

    // Registry value name "(Default)" means empty string in the registry API.
    let val_name = if value_name == "(Default)" { "" } else { value_name };

    let val = security
        .read_value(&key, val_name)
        .map_err(|_| CryptoError::ValueNotFound {
            name: format!("{secret_path}\\{value_name}"),
        })?;

    decrypt_lsa_secret_blob(&val.data, lsa_key)
}

/// Decrypt an LSA secret blob.
///
/// Vista+ blob layout:
///   bytes 0..4:   version / magic (0x00000001)
///   bytes 4..20:  HMAC-SHA256 hash (16 bytes used for MAC check, skipped here)
///   bytes 20..36: AES-128 IV (16 bytes)
///   bytes 36..52: AES-encrypted data (16 bytes, may have trailing blocks)
///
/// XP blob layout:
///   bytes 0..4:   version / magic
///   bytes 4..20:  16-byte RC4 IV/salt
///   bytes 20..:   RC4-encrypted data
fn decrypt_lsa_secret_blob(data: &[u8], lsa_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.len() < 20 {
        return Err(CryptoError::BufferTooSmall {
            need: 20,
            have: data.len(),
        });
    }

    let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

    match version {
        0x00000001 => {
            // Vista+ AES path
            if data.len() < 52 {
                return Err(CryptoError::BufferTooSmall {
                    need: 52,
                    have: data.len(),
                });
            }
            let hmac_hash = &data[4..20];
            let iv = &data[20..36];
            let encrypted = &data[36..];

            // Derive AES key: HMAC-SHA256(lsa_key, hmac_hash)
            let mut mac = <HmacSha256 as Mac>::new_from_slice(lsa_key).map_err(|e| {
                CryptoError::Decrypt {
                    detail: format!("HMAC-SHA256 init: {e}"),
                }
            })?;
            mac.update(hmac_hash);
            let derived = mac.finalize().into_bytes();
            let aes_key = &derived[..16];

            // Decrypt all 16-byte blocks.
            let mut result = Vec::new();
            let mut offset = 0;
            while offset + 16 <= encrypted.len() {
                let block_iv = if offset == 0 {
                    iv
                } else {
                    &encrypted[offset - 16..offset]
                };
                let decrypted = decrypt_aes_128_cbc(aes_key, block_iv, &encrypted[offset..])?;
                result.extend_from_slice(&decrypted);
                offset += 16;
            }

            // Strip length prefix: first 4 bytes are the plaintext length.
            if result.len() >= 4 {
                let plaintext_len =
                    u32::from_le_bytes([result[0], result[1], result[2], result[3]]) as usize;
                if result.len() >= 4 + plaintext_len {
                    return Ok(result[4..4 + plaintext_len].to_vec());
                }
            }
            Ok(result)
        }
        _ => {
            // XP RC4 path: salt at [4..20], encrypted at [20..]
            let salt = &data[4..20];
            let encrypted = &data[20..];

            let mut mac = <HmacSha256 as Mac>::new_from_slice(lsa_key).map_err(|e| {
                CryptoError::Decrypt {
                    detail: format!("HMAC-SHA256 init for XP: {e}"),
                }
            })?;
            mac.update(salt);
            let derived = mac.finalize().into_bytes();
            let rc4_key = &derived[..16];

            let mut buf = encrypted.to_vec();
            let mut rc4: Rc4<typenum::U16> = Rc4KeyInit::new(rc4_key.into());
            rc4.apply_keystream(&mut buf);

            Ok(buf)
        }
    }
}
