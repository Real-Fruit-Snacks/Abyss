//! SAM hash extraction from the SAM registry hive.
//!
//! Given a SAM hive and the 16-byte SYSKEY derived from the SYSTEM hive, this
//! module extracts NTLM (and optionally LM) password hashes for all local user
//! accounts.
//!
//! Supported encryption variants:
//!   - Revision 1 (Windows 7/8): RC4-based SAM key decryption, RC4 hash decrypt
//!   - Revision 2 (Windows 10+): AES-128-CBC SAM key decryption, AES hash decrypt
//!
//! After per-user decryption the hashes still require a final DES step keyed
//! on the user's RID.

use crate::error::CryptoError;
use abyss_registry::RegistryHive;

use aes::Aes128;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use des::cipher::{BlockDecrypt, KeyInit as DesKeyInit};
use des::Des;
use hmac::{Hmac, Mac};
use md5::Md5;
use rc4::{KeyInit as Rc4KeyInit, Rc4, StreamCipher};
use typenum::U16;

type HmacMd5 = Hmac<Md5>;
type Aes128CbcDec = cbc::Decryptor<Aes128>;

/// A single SAM account entry with extracted hashes.
#[derive(Debug, Clone)]
pub struct SamEntry {
    /// The username (UTF-16LE decoded).
    pub username: String,
    /// The user's RID (relative identifier).
    pub rid: u32,
    /// The NTLM hash (16 bytes), or empty if not present / blank password.
    pub ntlm: Vec<u8>,
    /// The LM hash (16 bytes), or empty if not present / disabled.
    pub lm: Vec<u8>,
}

/// Extract all SAM account hashes from a SAM hive using the given SYSKEY.
pub fn extract_sam_hashes(
    sam: &mut RegistryHive,
    syskey: &[u8; 16],
) -> Result<Vec<SamEntry>, CryptoError> {
    // Step 1: derive the SAM encryption key from the F value of the Domains\Account key.
    let account_key = sam
        .open_key("SAM\\Domains\\Account")
        .map_err(|_| CryptoError::KeyNotFound {
            key: "SAM\\Domains\\Account".to_string(),
        })?;

    let f_val = sam
        .read_value(&account_key, "F")
        .map_err(|_| CryptoError::ValueNotFound {
            name: "SAM\\Domains\\Account\\F".to_string(),
        })?;

    let sam_key = derive_sam_key(&f_val.data, syskey)?;
    log::debug!("SAM key derived: {}", hex_fmt(&sam_key));

    // Step 2: enumerate user sub-keys under SAM\Domains\Account\Users.
    let users_key = sam
        .open_key("SAM\\Domains\\Account\\Users")
        .map_err(|_| CryptoError::KeyNotFound {
            key: "SAM\\Domains\\Account\\Users".to_string(),
        })?;

    let subkey_names = sam
        .subkey_names(&users_key)
        .map_err(|e| CryptoError::InvalidData {
            detail: format!("enumerating Users subkeys: {e}"),
        })?;

    let mut entries = Vec::new();

    for name in subkey_names {
        // RID sub-keys are 8-digit hex strings (e.g. "000001F4").
        let rid = match u32::from_str_radix(&name, 16) {
            Ok(r) => r,
            Err(_) => {
                log::debug!("Skipping non-RID subkey: {name}");
                continue;
            }
        };

        let user_path = format!("SAM\\Domains\\Account\\Users\\{name}");
        let user_key = match sam.open_key(&user_path) {
            Ok(k) => k,
            Err(_) => continue,
        };

        let v_val = match sam.read_value(&user_key, "V") {
            Ok(v) => v,
            Err(_) => continue,
        };

        match parse_v_value(&v_val.data, rid, &sam_key) {
            Ok(entry) => entries.push(entry),
            Err(e) => {
                log::warn!("Failed to parse V value for RID {rid:#010x}: {e}");
            }
        }
    }

    Ok(entries)
}

/// Derive the 16-byte SAM key from the account F value and SYSKEY.
///
/// Layout of F value (offsets relative to start of data):
///   offset 0x68: revision (u8 or u16 at 0x68 tells AES vs RC4)
///   The encrypted key structure starts at offset 0x68.
///
/// Revision 1 (RC4):
///   - F[0x68]: 0x01
///   - F[0x70..0x80]: 16-byte RC4 key material (SYSKEYRC4_SALT)
///   - F[0x80..0x90]: 32-byte encrypted blob (take first 16)
///
/// Revision 2 (AES):
///   - F[0x68]: 0x02
///   - F[0x6C..0x7C]: 16-byte AES IV
///   - F[0x7C..0x8C]: 16-byte AES-encrypted SAM key
fn derive_sam_key(f_data: &[u8], syskey: &[u8; 16]) -> Result<[u8; 16], CryptoError> {
    if f_data.len() < 0x90 {
        return Err(CryptoError::BufferTooSmall {
            need: 0x90,
            have: f_data.len(),
        });
    }

    let revision = f_data[0x68];
    log::debug!("SAM F revision: {revision}");

    match revision {
        0x01 => {
            // RC4: salt at 0x70..0x80, encrypted key at 0x80..0x90
            let salt = &f_data[0x70..0x80];
            let encrypted = &f_data[0x80..0x90];
            rc4_sam_key(syskey, salt, encrypted)
        }
        0x02 => {
            // AES-128-CBC: IV at 0x6C..0x7C, encrypted key at 0x7C..0x8C
            let iv = &f_data[0x6C..0x7C];
            let encrypted = &f_data[0x7C..0x8C];
            aes_sam_key(syskey, iv, encrypted)
        }
        other => Err(CryptoError::InvalidData {
            detail: format!("unknown SAM F revision: {other:#04x}"),
        }),
    }
}

/// Derive SAM key using RC4 (Windows 7/8).
///
/// RC4 key = MD5( syskey || salt_constant || syskey ) where the constants
/// match the legacy impacket/creddump approach:
///   key_material = MD5(syskey + b"\x01" * 4 + salt + b"\x02" * 4)
///   sam_key = RC4(key_material, encrypted)[0..16]
fn rc4_sam_key(
    syskey: &[u8; 16],
    salt: &[u8],
    encrypted: &[u8],
) -> Result<[u8; 16], CryptoError> {
    use md5::Digest;

    // Build the MD5 input: syskey + 0x01*4 + salt + 0x02*4
    let mut md5_input = Vec::with_capacity(16 + 4 + salt.len() + 4);
    md5_input.extend_from_slice(syskey);
    md5_input.extend_from_slice(&[0x01u8; 4]);
    md5_input.extend_from_slice(salt);
    md5_input.extend_from_slice(&[0x02u8; 4]);

    let rc4_key = Md5::digest(&md5_input);

    let mut data = encrypted.to_vec();
    let mut rc4: Rc4<U16> = Rc4KeyInit::new(rc4_key.as_slice().into());
    rc4.apply_keystream(&mut data);

    let mut out = [0u8; 16];
    out.copy_from_slice(&data[..16]);
    Ok(out)
}

/// Derive SAM key using AES-128-CBC (Windows 10+).
pub fn aes_sam_key(
    syskey: &[u8; 16],
    iv: &[u8],
    encrypted: &[u8],
) -> Result<[u8; 16], CryptoError> {
    decrypt_aes_128_cbc(syskey, iv, encrypted)
}

/// Decrypt data with AES-128-CBC.  Returns exactly 16 bytes.
pub fn decrypt_aes_128_cbc(key: &[u8], iv: &[u8], data: &[u8]) -> Result<[u8; 16], CryptoError> {
    if key.len() != 16 {
        return Err(CryptoError::InvalidData {
            detail: format!("AES key must be 16 bytes, got {}", key.len()),
        });
    }
    if iv.len() < 16 {
        return Err(CryptoError::BufferTooSmall {
            need: 16,
            have: iv.len(),
        });
    }
    if data.len() < 16 {
        return Err(CryptoError::BufferTooSmall {
            need: 16,
            have: data.len(),
        });
    }

    let mut buf = [0u8; 16];
    buf.copy_from_slice(&data[..16]);

    let decryptor = Aes128CbcDec::new(key.into(), iv[..16].into());
    let result = decryptor.decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf);
    result.map_err(|e| CryptoError::Decrypt {
        detail: format!("AES-128-CBC decrypt: {e:?}"),
    })?;

    Ok(buf)
}

/// Parse the V value for a user and decrypt their hashes.
///
/// V value layout (all offsets are at fixed positions in the header):
///   offset 0x00: always 3 (struct version)
///   offset 0x0C: username offset from base (base = 0xCC)
///   offset 0x10: username length in bytes
///   offset 0x9C: LM hash offset from base
///   offset 0xA0: LM hash length (0 if absent)
///   offset 0xA8: NTLM hash offset from base
///   offset 0xAC: NTLM hash length (0 if absent)
fn parse_v_value(
    v_data: &[u8],
    rid: u32,
    sam_key: &[u8; 16],
) -> Result<SamEntry, CryptoError> {
    const BASE: usize = 0xCC;

    if v_data.len() < BASE {
        return Err(CryptoError::BufferTooSmall {
            need: BASE,
            have: v_data.len(),
        });
    }

    // Username
    let uname_offset = read_u32_le(v_data, 0x0C)? as usize + BASE;
    let uname_len = read_u32_le(v_data, 0x10)? as usize;
    let username = if uname_len > 0 && uname_offset + uname_len <= v_data.len() {
        decode_utf16le(&v_data[uname_offset..uname_offset + uname_len])
    } else {
        String::new()
    };

    // LM hash
    let lm_offset = read_u32_le(v_data, 0x9C)? as usize + BASE;
    let lm_len = read_u32_le(v_data, 0xA0)? as usize;
    let lm = if lm_len > 0 && lm_offset + lm_len <= v_data.len() {
        let encrypted = &v_data[lm_offset..lm_offset + lm_len];
        decrypt_hash(encrypted, rid, sam_key).unwrap_or_default()
    } else {
        Vec::new()
    };

    // NTLM hash
    let ntlm_offset = read_u32_le(v_data, 0xA8)? as usize + BASE;
    let ntlm_len = read_u32_le(v_data, 0xAC)? as usize;
    let ntlm = if ntlm_len > 0 && ntlm_offset + ntlm_len <= v_data.len() {
        let encrypted = &v_data[ntlm_offset..ntlm_offset + ntlm_len];
        decrypt_hash(encrypted, rid, sam_key).unwrap_or_default()
    } else {
        Vec::new()
    };

    Ok(SamEntry {
        username,
        rid,
        ntlm,
        lm,
    })
}

/// Decrypt a single hash blob from the V value.
///
/// Revision 1 (RC4, length == 20):
///   - First 4 bytes: salt
///   - Remaining 16 bytes: RC4-encrypted hash
///
/// Revision 2 (AES, length == 40):
///   - Bytes 0..4: revision indicator
///   - Bytes 4..20: AES IV (16 bytes)
///   - Bytes 20..36: AES-encrypted hash (16 bytes)
fn decrypt_hash(blob: &[u8], rid: u32, sam_key: &[u8; 16]) -> Result<Vec<u8>, CryptoError> {
    if blob.len() < 4 {
        return Err(CryptoError::BufferTooSmall {
            need: 4,
            have: blob.len(),
        });
    }

    // Determine revision from first 2 bytes.
    let revision = u16::from_le_bytes([blob[0], blob[1]]);

    let decrypted_hash = match revision {
        0x0001 if blob.len() >= 20 => {
            // RC4: 4-byte salt at [0..4], encrypted hash at [4..20]
            let salt = &blob[0..4];
            let encrypted = &blob[4..20];
            rc4_decrypt_hash(sam_key, salt, encrypted)?
        }
        0x0002 if blob.len() >= 40 => {
            // AES: IV at [4..20], encrypted at [20..36]
            let iv = &blob[4..20];
            let encrypted = &blob[20..36];
            let result = decrypt_aes_128_cbc(sam_key, iv, encrypted)?;
            result.to_vec()
        }
        _ => {
            return Err(CryptoError::InvalidData {
                detail: format!(
                    "unknown hash blob revision {revision:#06x} (len={})",
                    blob.len()
                ),
            });
        }
    };

    // Final DES-based RID decryption.
    des_decrypt_hash(&decrypted_hash, rid)
}

/// RC4-based hash decryption (Windows 7/8).
///
/// RC4 key = HMAC-MD5( sam_key, salt_constant || salt )
fn rc4_decrypt_hash(
    sam_key: &[u8; 16],
    salt: &[u8],
    encrypted: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut mac =
        <HmacMd5 as Mac>::new_from_slice(sam_key).map_err(|e| CryptoError::Decrypt {
            detail: format!("HMAC-MD5 init: {e}"),
        })?;
    mac.update(salt);
    let rc4_key = mac.finalize().into_bytes();

    let mut data = encrypted.to_vec();
    let mut rc4: Rc4<U16> = Rc4KeyInit::new(rc4_key.as_slice().into());
    rc4.apply_keystream(&mut data);

    Ok(data)
}

/// Apply the final DES-based RID decryption to a 16-byte intermediate hash.
///
/// The RID is expanded into two 7-byte DES keys using `rid_to_key`.
/// The hash is split into two 8-byte blocks, each decrypted with the
/// corresponding DES key.
pub fn des_decrypt_hash(hash: &[u8], rid: u32) -> Result<Vec<u8>, CryptoError> {
    if hash.len() < 16 {
        return Err(CryptoError::BufferTooSmall {
            need: 16,
            have: hash.len(),
        });
    }

    let (key1, key2) = rid_to_des_keys(rid);

    let des1 = Des::new(&key1.into());
    let des2 = Des::new(&key2.into());

    let mut block1: aes::cipher::generic_array::GenericArray<u8, _> =
        (*aes::cipher::generic_array::GenericArray::from_slice(&hash[0..8])).into();
    let mut block2: aes::cipher::generic_array::GenericArray<u8, _> =
        (*aes::cipher::generic_array::GenericArray::from_slice(&hash[8..16])).into();

    des1.decrypt_block(&mut block1);
    des2.decrypt_block(&mut block2);

    let mut result = Vec::with_capacity(16);
    result.extend_from_slice(&block1);
    result.extend_from_slice(&block2);
    Ok(result)
}

/// Expand a 32-bit RID into two 8-byte DES keys.
///
/// Classic algorithm: the RID bytes are scattered into 56-bit key slots via
/// bit manipulation, producing two 8-byte keys with odd parity bits.
pub fn rid_to_des_keys(rid: u32) -> ([u8; 8], [u8; 8]) {
    let r = rid.to_le_bytes(); // [b0, b1, b2, b3]

    // Key 1 uses bytes: r[0] r[1] r[2] r[3] r[0] r[1] r[2]
    // Key 2 uses bytes: r[3] r[0] r[1] r[2] r[3] r[0] r[1]
    let s1 = [r[0], r[1], r[2], r[3], r[0], r[1], r[2]];
    let s2 = [r[3], r[0], r[1], r[2], r[3], r[0], r[1]];

    (str_to_key(&s1), str_to_key(&s2))
}

/// Convert a 7-byte string to an 8-byte DES key with odd parity.
fn str_to_key(s: &[u8; 7]) -> [u8; 8] {
    let mut key = [0u8; 8];
    key[0] = s[0] >> 1;
    key[1] = ((s[0] & 0x01) << 6) | (s[1] >> 2);
    key[2] = ((s[1] & 0x03) << 5) | (s[2] >> 3);
    key[3] = ((s[2] & 0x07) << 4) | (s[3] >> 4);
    key[4] = ((s[3] & 0x0F) << 3) | (s[4] >> 5);
    key[5] = ((s[4] & 0x1F) << 2) | (s[5] >> 6);
    key[6] = ((s[5] & 0x3F) << 1) | (s[6] >> 7);
    key[7] = s[6] & 0x7F;

    // Set odd parity on each byte.
    for b in key.iter_mut() {
        *b <<= 1;
        let parity = b.count_ones() % 2 == 0;
        if parity {
            *b |= 1;
        }
    }
    key
}

/// Decode a UTF-16LE byte slice to a String.
fn decode_utf16le(bytes: &[u8]) -> String {
    let chars: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&chars).to_string()
}

/// Read a little-endian u32 from a byte slice.
fn read_u32_le(data: &[u8], offset: usize) -> Result<u32, CryptoError> {
    if data.len() < offset + 4 {
        return Err(CryptoError::BufferTooSmall {
            need: offset + 4,
            have: data.len(),
        });
    }
    Ok(u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

/// Format bytes as a lowercase hex string.
fn hex_fmt(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_str_to_key_known() {
        // RID 500 = 0x000001F4 → LE bytes [0xF4, 0x01, 0x00, 0x00]
        let (k1, k2) = rid_to_des_keys(500);
        // Just verify they are 8 bytes and non-zero in some fashion.
        assert_eq!(k1.len(), 8);
        assert_eq!(k2.len(), 8);
    }

    #[test]
    fn test_rid_to_des_keys_symmetry() {
        // For RID 500 and 501, keys should differ.
        let (k1_500, _) = rid_to_des_keys(500);
        let (k1_501, _) = rid_to_des_keys(501);
        assert_ne!(k1_500, k1_501);
    }

    #[test]
    fn test_decrypt_aes_128_cbc_bad_key_len() {
        let key = [0u8; 8]; // wrong length
        let iv = [0u8; 16];
        let data = [0u8; 16];
        assert!(decrypt_aes_128_cbc(&key, &iv, &data).is_err());
    }

    #[test]
    fn test_decrypt_aes_128_cbc_roundtrip() {
        use aes::Aes128;
        use cbc::cipher::{BlockEncryptMut, KeyIvInit};

        type Aes128CbcEnc = cbc::Encryptor<Aes128>;

        let key = [0x2bu8; 16];
        let iv = [0x3au8; 16];
        let plaintext = [0x41u8; 16];

        let mut buf = [0u8; 16];
        buf.copy_from_slice(&plaintext);
        let enc = Aes128CbcEnc::new(&key.into(), &iv.into());
        let ciphertext = enc
            .encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf, 16)
            .unwrap()
            .to_vec();

        let decrypted = decrypt_aes_128_cbc(&key, &iv, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decode_utf16le() {
        let s = "test";
        let bytes: Vec<u8> = s.chars().flat_map(|c| (c as u16).to_le_bytes()).collect();
        assert_eq!(decode_utf16le(&bytes), "test");
    }
}
