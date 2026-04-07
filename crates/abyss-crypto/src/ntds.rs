//! NTDS.dit hash extraction.
//!
//! Decrypts NT and LM password hashes from the NTDS.dit ESE database using the
//! PEK (Password Encryption Key) derived from the SYSTEM hive's SYSKEY.
//!
//! Supported PEK versions:
//!   - Version 2 (pre-Windows 2019): RC4-based PEK decryption
//!   - Version 3 (Windows 2019+): not yet supported (AES-based)
//!
//! After PEK decryption, each user's encrypted NT/LM hash is decrypted in two
//! steps: RC4 with PEK-derived key, then DES with RID-derived keys (same final
//! step as SAM hash extraction).

use crate::error::CryptoError;
use crate::sam::des_decrypt_hash;

use md5::Digest as _;
use rc4::{KeyInit as Rc4KeyInit, Rc4, StreamCipher};
use typenum::U16;

/// Decrypt the PEK (Password Encryption Key) from the NTDS.dit pekList blob.
///
/// # Arguments
/// * `pek_list` - Raw `ATTk589918` bytes from the datatable.
/// * `syskey` - 16-byte boot key derived from the SYSTEM hive.
///
/// # Returns
/// The 16-byte PEK used to decrypt individual user hashes.
pub fn decrypt_pek(pek_list: &[u8], syskey: &[u8; 16]) -> Result<Vec<u8>, CryptoError> {
    if pek_list.len() < 28 {
        return Err(CryptoError::InvalidData {
            detail: "pekList too short".into(),
        });
    }
    let version = u32::from_le_bytes([pek_list[0], pek_list[1], pek_list[2], pek_list[3]]);

    match version {
        2 => decrypt_pek_v2(pek_list, syskey),
        3 => Err(CryptoError::InvalidData {
            detail: "PEK v3 (AES) not yet supported".into(),
        }),
        _ => Err(CryptoError::InvalidData {
            detail: format!("unsupported PEK version: {}", version),
        }),
    }
}

/// Decrypt PEK version 2 (RC4-based, pre-Windows 2019).
///
/// Layout: `[version:4][flags:4][salt:16][encrypted_pek_data...]`
///
/// Key derivation: `MD5(syskey || salt)` iterated 1000 times, then RC4 decrypt.
/// The 16-byte PEK is at offset 36 in the decrypted data.
fn decrypt_pek_v2(pek_list: &[u8], syskey: &[u8; 16]) -> Result<Vec<u8>, CryptoError> {
    if pek_list.len() < 24 {
        return Err(CryptoError::BufferTooSmall {
            need: 24,
            have: pek_list.len(),
        });
    }

    let salt = &pek_list[8..24];
    let encrypted = &pek_list[24..];

    // Derive RC4 key: MD5(syskey + salt) iterated 1000 times.
    // Each iteration: key_material = MD5(key_material + salt)
    let mut key_material = Vec::with_capacity(32);
    key_material.extend_from_slice(syskey);
    for _ in 0..1000 {
        let mut hasher = md5::Md5::new();
        hasher.update(&key_material);
        hasher.update(salt);
        let digest = hasher.finalize();
        key_material = digest.to_vec();
    }

    // RC4 decrypt with the derived key
    let mut data = encrypted.to_vec();
    let mut rc4: Rc4<U16> = Rc4KeyInit::new(key_material[..16].into());
    rc4.apply_keystream(&mut data);

    // PEK is at offset 36 in decrypted data, 16 bytes
    if data.len() < 52 {
        return Err(CryptoError::InvalidData {
            detail: "decrypted PEK data too short".into(),
        });
    }
    Ok(data[36..52].to_vec())
}

/// Decrypt an NTDS hash (NT or LM) using the PEK and RID.
///
/// The encrypted hash blob format (version 1):
///   `[header:8][key_material:16][encrypted_hash...]`
///
/// Decryption steps:
///   1. RC4 key = MD5(PEK + key_material)
///   2. RC4 decrypt the encrypted hash
///   3. DES decrypt with RID-derived keys (same as SAM)
///
/// Returns an empty Vec for empty/disabled hashes (blob too short).
pub fn decrypt_ntds_hash(encrypted: &[u8], pek: &[u8], rid: u32) -> Result<Vec<u8>, CryptoError> {
    if encrypted.len() < 24 {
        // Empty/disabled hash
        return Ok(vec![]);
    }

    let key_material = &encrypted[8..24];
    let enc_hash = &encrypted[24..];

    // RC4 key = MD5(PEK + key_material)
    let mut hasher = md5::Md5::new();
    hasher.update(pek);
    hasher.update(key_material);
    let rc4_key = hasher.finalize();

    let mut data = enc_hash.to_vec();
    let mut rc4: Rc4<U16> = Rc4KeyInit::new(rc4_key.as_slice().into());
    rc4.apply_keystream(&mut data);

    if data.len() < 16 {
        return Ok(vec![]);
    }

    // Final DES decryption with RID (same as SAM)
    des_decrypt_hash(&data, rid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decrypt_pek_too_short() {
        let syskey = [0u8; 16];
        let pek_list = [0u8; 10];
        assert!(decrypt_pek(&pek_list, &syskey).is_err());
    }

    #[test]
    fn test_decrypt_pek_unsupported_version() {
        let syskey = [0u8; 16];
        // Version 99, flags 0, then 16 bytes salt + some data
        let mut pek_list = vec![0u8; 60];
        pek_list[0] = 99; // unsupported version
        let result = decrypt_pek(&pek_list, &syskey);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("unsupported PEK version"));
    }

    #[test]
    fn test_decrypt_pek_v3_unsupported() {
        let syskey = [0u8; 16];
        let mut pek_list = vec![0u8; 60];
        pek_list[0] = 3; // v3
        let result = decrypt_pek(&pek_list, &syskey);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("PEK v3"));
    }

    #[test]
    fn test_decrypt_ntds_hash_empty() {
        let pek = [0u8; 16];
        // Too short to contain a hash — should return empty
        let encrypted = [0u8; 10];
        let result = decrypt_ntds_hash(&encrypted, &pek, 500).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_rc4_roundtrip() {
        // Verify RC4 is its own inverse
        let key = [0x42u8; 16];
        let plaintext = b"hello world 1234";

        let mut encrypted = plaintext.to_vec();
        let mut rc4: Rc4<U16> = Rc4KeyInit::new(key[..].into());
        rc4.apply_keystream(&mut encrypted);
        assert_ne!(encrypted.as_slice(), plaintext);

        let mut decrypted = encrypted.clone();
        let mut rc4: Rc4<U16> = Rc4KeyInit::new(key[..].into());
        rc4.apply_keystream(&mut decrypted);
        assert_eq!(decrypted.as_slice(), plaintext);
    }
}
