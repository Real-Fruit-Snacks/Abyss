//! Cached domain credential (DCC2) extraction from the SECURITY registry hive.
//!
//! Given a SECURITY hive and the NL$KM key (the NL$Control secret decrypted
//! from LSA secrets), this module extracts and decrypts cached logon entries
//! stored under Cache\NL$*.
//!
//! Decryption: HMAC-SHA256(NL$KM, IV) produces the AES-128-CBC key.
//! The decrypted record contains the NT hash (first 16 bytes) followed by
//! variable-length username and domain fields.

use crate::error::CryptoError;
use crate::sam::decrypt_aes_128_cbc;
use abyss_registry::RegistryHive;

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// A single decrypted cached domain credential entry.
#[derive(Debug, Clone)]
pub struct CachedCredential {
    /// The username from the cached logon record.
    pub username: String,
    /// The domain from the cached logon record.
    pub domain: String,
    /// The NT hash (16 bytes) extracted from the decrypted record.
    pub nt_hash: [u8; 16],
    /// The PBKDF2 iteration count (DCC2 format); 10240 by default on modern Windows.
    pub iteration_count: u32,
}

/// Extract and decrypt all cached domain credentials from the SECURITY hive.
///
/// `nlkm` is the raw NL$KM key material (typically 128 bytes from the
/// NL$Control LSA secret).  Only the first 16 bytes are used as the HMAC key.
pub fn extract_cached_creds(
    security: &mut RegistryHive,
    nlkm: &[u8],
) -> Result<Vec<CachedCredential>, CryptoError> {
    let cache_key = match security.open_key("Cache") {
        Ok(k) => k,
        Err(_) => {
            log::warn!("cached_creds: Cache key not found, returning empty list");
            return Ok(Vec::new());
        }
    };

    let all_values = security
        .read_values(&cache_key)
        .map_err(|e| CryptoError::InvalidData {
            detail: format!("enumerating Cache values: {e}"),
        })?;

    let mut creds = Vec::new();

    for val in all_values {
        let vname: &str = &val.name;
        // Only process NL$* values (e.g. NL$1, NL$2, …); skip NL$Control.
        if !vname.starts_with("NL$") || vname == "NL$Control" {
            continue;
        }

        if val.data.is_empty() || val.data.iter().all(|&b| b == 0) {
            // Empty / zeroed slot — no cached credential stored here.
            continue;
        }

        match decrypt_cache_entry(&val.data, nlkm) {
            Ok(Some(cred)) => creds.push(cred),
            Ok(None) => {}
            Err(e) => {
                log::warn!("cached_creds: failed to decrypt {vname}: {e}");
            }
        }
    }

    Ok(creds)
}

/// Decrypt a single NL$ cache entry blob and parse it into a CachedCredential.
///
/// Cache entry layout (all multi-byte values are little-endian):
///   offset 0x00 (2 bytes): username length in bytes
///   offset 0x02 (2 bytes): domain name length in bytes
///   offset 0x04 (2 bytes): effective name length (unused here)
///   offset 0x06 (2 bytes): full name length (unused here)
///   offset 0x08 (2 bytes): logon script length (unused here)
///   offset 0x0A (2 bytes): profile path length (unused here)
///   offset 0x0C (2 bytes): home dir length (unused here)
///   offset 0x0E (2 bytes): home dir drive length (unused here)
///   offset 0x10 (2 bytes): user id (RID)
///   offset 0x12 (2 bytes): primary group id
///   offset 0x14 (4 bytes): group count
///   offset 0x18 (2 bytes): logon domain name length
///   offset 0x1A (2 bytes): logon domain id length (unused)
///   offset 0x1C (8 bytes): last write timestamp
///   offset 0x24 (4 bytes): revision
///   offset 0x28 (4 bytes): sid count (unused)
///   offset 0x2C (2 bytes): flags
///   offset 0x2E (2 bytes): logon package length (unused)
///   offset 0x30 (2 bytes): dns domain name length (unused)
///   offset 0x32 (2 bytes): upn length (unused)
///   offset 0x38 (4 bytes): iteration count (DCC2)
///   offset 0x40 (16 bytes): IV for AES decryption
///   offset 0x50 (16 bytes): CH (HMAC-SHA256 input for key derivation — same as IV slot)
///   offset 0x60+: encrypted data (username, domain, NT hash embedded at [0..16])
///
/// Note: exact offsets vary by Windows version. We use the common modern layout.
fn decrypt_cache_entry(
    data: &[u8],
    nlkm: &[u8],
) -> Result<Option<CachedCredential>, CryptoError> {
    // Minimum header size to read the fields we need.
    const HEADER_MIN: usize = 0x60;
    if data.len() < HEADER_MIN {
        return Ok(None);
    }

    let username_len = u16::from_le_bytes([data[0x00], data[0x01]]) as usize;
    let domain_len = u16::from_le_bytes([data[0x02], data[0x03]]) as usize;
    let iteration_count = u32::from_le_bytes([data[0x38], data[0x39], data[0x3A], data[0x3B]]);

    // IV is at offset 0x40..0x50.
    let iv = &data[0x40..0x50];

    // Encrypted payload starts at 0x60.
    let encrypted = &data[0x60..];
    if encrypted.is_empty() {
        return Ok(None);
    }

    // Derive AES key: HMAC-SHA256(nlkm[0..16], iv).
    let hmac_key = if nlkm.len() >= 16 { &nlkm[..16] } else { nlkm };
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(hmac_key).map_err(|e| CryptoError::Decrypt {
            detail: format!("HMAC-SHA256 init: {e}"),
        })?;
    mac.update(iv);
    let derived = mac.finalize().into_bytes();
    let aes_key = &derived[..16];

    // Decrypt all 16-byte blocks.
    let mut plaintext = Vec::new();
    let mut offset = 0;
    while offset + 16 <= encrypted.len() {
        let block_iv = if offset == 0 {
            iv
        } else {
            &encrypted[offset - 16..offset]
        };
        let block = decrypt_aes_128_cbc(aes_key, block_iv, &encrypted[offset..])?;
        plaintext.extend_from_slice(&block);
        offset += 16;
    }

    if plaintext.len() < 16 {
        return Ok(None);
    }

    // First 16 bytes of plaintext are the NT hash.
    let mut nt_hash = [0u8; 16];
    nt_hash.copy_from_slice(&plaintext[..16]);

    // Username follows the NT hash (UTF-16LE), aligned to 4 bytes.
    let username_start = 16; // NT hash is 16 bytes
    let username_end = username_start + username_len;

    let username = if username_len > 0 && username_end <= plaintext.len() {
        decode_utf16le(&plaintext[username_start..username_end])
    } else {
        String::new()
    };

    // Domain follows username (aligned to 4 bytes).
    let username_aligned = align4(username_len);
    let domain_start = username_start + username_aligned;
    let domain_end = domain_start + domain_len;

    let domain = if domain_len > 0 && domain_end <= plaintext.len() {
        decode_utf16le(&plaintext[domain_start..domain_end])
    } else {
        String::new()
    };

    Ok(Some(CachedCredential {
        username,
        domain,
        nt_hash,
        iteration_count,
    }))
}

/// Round up to next 4-byte boundary.
fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Decode a UTF-16LE byte slice to a String.
fn decode_utf16le(bytes: &[u8]) -> String {
    let chars: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&chars).to_string()
}
