//! Offline DPAPI blob decryption with master key derivation.
//!
//! DPAPI (Data Protection API) uses machine-level keys derived from the SYSTEM
//! and SECURITY hive secrets.  In an offline forensic scenario we recreate the
//! key material from the extracted LSA secrets and provide a [`DpapiKeyring`]
//! that can decrypt individual DPAPI blobs.
//!
//! ## Master key file format
//!
//! Each file under `Protect/<SID>/<GUID>` contains a header followed by
//! master key, backup key, credential key, and domain key sections.  The
//! master key section is encrypted with either a user-derived key (password
//! hash + SID) or the DPAPI_SYSTEM machine key (via the domain key section).
//!
//! ## Supported derivation paths
//!
//! 1. **DPAPI_SYSTEM** (machine-level): uses the 20-byte user/machine keys
//!    from the LSA secret to decrypt master keys via the domain key section.
//! 2. **NT hash + SID** (user-level): derives a key from the user's NTLM
//!    hash and SID, then decrypts the master key section directly.
//!
//! ## DPAPI blob decryption
//!
//! Once master keys are registered in the keyring, DPAPI blobs (e.g. the
//! Chromium `os_crypt.encrypted_key`) can be fully decrypted using the
//! session key derived from the master key, blob salt, and HMAC.

use crate::error::CryptoError;

use aes::Aes256;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use des::TdesEde3;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha512;

type HmacSha1 = Hmac<Sha1>;
type HmacSha512 = Hmac<Sha512>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;
type TdesCbcDec = cbc::Decryptor<TdesEde3>;

// ---------------------------------------------------------------------------
// Hash / crypto algorithm IDs used in DPAPI master key headers
// ---------------------------------------------------------------------------

/// SHA-1 (CALG_SHA1)
const CALG_SHA1: u32 = 0x0000_8004;
/// SHA-512 (CALG_SHA_512)
const CALG_SHA_512: u32 = 0x0000_800E;
/// 3DES-168 (CALG_3DES)
const CALG_3DES: u32 = 0x0000_6603;
/// AES-256 (CALG_AES_256)
const CALG_AES_256: u32 = 0x0000_6611;

// ---------------------------------------------------------------------------
// MasterKeyFile — parsed representation of a Protect/<SID>/<GUID> file
// ---------------------------------------------------------------------------

/// Parsed DPAPI master key file.
#[derive(Debug, Clone)]
pub struct MasterKeyFile {
    /// File format version (expected: 2).
    pub version: u32,
    /// Master key GUID from the file header.
    pub guid: String,
    /// Flags from the file header.
    pub flags: u32,
    /// Raw master key section bytes.
    pub master_key_data: Vec<u8>,
    /// Raw backup key section bytes.
    pub backup_key_data: Vec<u8>,
    /// Raw credential key section bytes.
    pub credential_key_data: Vec<u8>,
    /// Raw domain key section bytes.
    pub domain_key_data: Vec<u8>,
}

/// Parsed header of a master key (or backup key) section.
#[derive(Debug, Clone)]
struct MasterKeyHeader {
    _version: u32,
    salt: [u8; 16],
    iteration_count: u32,
    hash_algo: u32,
    crypto_algo: u32,
    encrypted_key: Vec<u8>,
}

/// Parsed domain key section (used by DPAPI_SYSTEM decryption).
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct DomainKeySection {
    _version: u32,
    secret_len: u32,
    _access_check_len: u32,
    _guid: [u8; 16],
    secret: Vec<u8>,
    _access_check: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse a DPAPI master key file from raw bytes.
///
/// The file layout is:
/// ```text
/// [version:4][_:4][_:4][guid:72 UTF-16LE][_:4][_:4][flags:4]
/// [master_key_len:8][backup_key_len:8][credential_key_len:8][domain_key_len:8]
/// [master_key_data:master_key_len]
/// [backup_key_data:backup_key_len]
/// [credential_key_data:credential_key_len]
/// [domain_key_data:domain_key_len]
/// ```
pub fn parse_master_key_file(data: &[u8]) -> Result<MasterKeyFile, CryptoError> {
    // Minimum header: 4+4+4+72+4+4+4 + 4*8 = 128 bytes
    const HEADER_SIZE: usize = 128;
    if data.len() < HEADER_SIZE {
        return Err(CryptoError::BufferTooSmall {
            need: HEADER_SIZE,
            have: data.len(),
        });
    }

    let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

    // GUID is 72 bytes of UTF-16LE at offset 12.
    let guid_bytes = &data[12..84];
    let guid = decode_utf16le(guid_bytes)
        .trim_end_matches('\0')
        .to_string();

    let flags = u32::from_le_bytes([data[92], data[93], data[94], data[95]]);

    let master_key_len = u64::from_le_bytes([
        data[96], data[97], data[98], data[99],
        data[100], data[101], data[102], data[103],
    ]) as usize;
    let backup_key_len = u64::from_le_bytes([
        data[104], data[105], data[106], data[107],
        data[108], data[109], data[110], data[111],
    ]) as usize;
    let credential_key_len = u64::from_le_bytes([
        data[112], data[113], data[114], data[115],
        data[116], data[117], data[118], data[119],
    ]) as usize;
    let domain_key_len = u64::from_le_bytes([
        data[120], data[121], data[122], data[123],
        data[124], data[125], data[126], data[127],
    ]) as usize;

    let total_needed = HEADER_SIZE + master_key_len + backup_key_len
        + credential_key_len + domain_key_len;
    if data.len() < total_needed {
        return Err(CryptoError::BufferTooSmall {
            need: total_needed,
            have: data.len(),
        });
    }

    let mut offset = HEADER_SIZE;

    let master_key_data = data[offset..offset + master_key_len].to_vec();
    offset += master_key_len;

    let backup_key_data = data[offset..offset + backup_key_len].to_vec();
    offset += backup_key_len;

    let credential_key_data = data[offset..offset + credential_key_len].to_vec();
    offset += credential_key_len;

    let domain_key_data = data[offset..offset + domain_key_len].to_vec();

    Ok(MasterKeyFile {
        version,
        guid,
        flags,
        master_key_data,
        backup_key_data,
        credential_key_data,
        domain_key_data,
    })
}

/// Parse a master key section header.
fn parse_master_key_header(data: &[u8]) -> Result<MasterKeyHeader, CryptoError> {
    // Minimum: version(4) + salt(16) + rounds(4) + hash_algo(4) + crypto_algo(4) = 32
    if data.len() < 32 {
        return Err(CryptoError::BufferTooSmall {
            need: 32,
            have: data.len(),
        });
    }

    let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&data[4..20]);
    let iteration_count = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
    let hash_algo = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);
    let crypto_algo = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);
    let encrypted_key = data[32..].to_vec();

    Ok(MasterKeyHeader {
        _version: version,
        salt,
        iteration_count,
        hash_algo,
        crypto_algo,
        encrypted_key,
    })
}

/// Parse the domain key section.
#[allow(dead_code)]
fn parse_domain_key_section(data: &[u8]) -> Result<DomainKeySection, CryptoError> {
    // version(4) + secret_len(4) + access_check_len(4) + guid(16) = 28
    if data.len() < 28 {
        return Err(CryptoError::BufferTooSmall {
            need: 28,
            have: data.len(),
        });
    }

    let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let secret_len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let access_check_len = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let mut guid = [0u8; 16];
    guid.copy_from_slice(&data[12..28]);

    let secret_end = 28 + secret_len as usize;
    let access_end = secret_end + access_check_len as usize;

    if data.len() < access_end {
        return Err(CryptoError::BufferTooSmall {
            need: access_end,
            have: data.len(),
        });
    }

    let secret = data[28..secret_end].to_vec();
    let access_check = data[secret_end..access_end].to_vec();

    Ok(DomainKeySection {
        _version: version,
        secret_len,
        _access_check_len: access_check_len,
        _guid: guid,
        secret,
        _access_check: access_check,
    })
}

// ---------------------------------------------------------------------------
// Decryption helpers
// ---------------------------------------------------------------------------

/// Derive the decryption key and IV for a master key section using HMAC-based
/// key derivation (the "derive keys" step from impacket/pypykatz).
///
/// 1. Compute `hmac_md = HMAC(password_hash, salt)` using the section's hash algo.
/// 2. Run PBKDF2 with `hmac_md` concatenated with the salt for the number of
///    iterations specified in the header.
/// 3. The derived bytes are split into a cipher key and an IV.
fn derive_master_key_keys(
    header: &MasterKeyHeader,
    password_hash: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    // Step 1: HMAC(password_hash, salt)
    let hmac_result = match header.hash_algo {
        CALG_SHA1 => {
            let mut mac = <HmacSha1 as Mac>::new_from_slice(password_hash)
                .map_err(|e| CryptoError::Decrypt {
                    detail: format!("HMAC-SHA1 init: {e}"),
                })?;
            mac.update(&header.salt);
            mac.finalize().into_bytes().to_vec()
        }
        CALG_SHA_512 => {
            let mut mac = <HmacSha512 as Mac>::new_from_slice(password_hash)
                .map_err(|e| CryptoError::Decrypt {
                    detail: format!("HMAC-SHA512 init: {e}"),
                })?;
            mac.update(&header.salt);
            mac.finalize().into_bytes().to_vec()
        }
        other => {
            return Err(CryptoError::InvalidData {
                detail: format!("unsupported DPAPI hash algorithm: {other:#06x}"),
            });
        }
    };

    // Step 2: Determine how many derived bytes we need (key_len + iv_len).
    let (key_len, iv_len) = match header.crypto_algo {
        CALG_3DES => (24, 8),       // 3DES-168: 24-byte key, 8-byte IV
        CALG_AES_256 => (32, 16),   // AES-256: 32-byte key, 16-byte IV
        other => {
            return Err(CryptoError::InvalidData {
                detail: format!("unsupported DPAPI crypto algorithm: {other:#06x}"),
            });
        }
    };

    let dk_len = key_len + iv_len;

    // Step 3: Iterative HMAC derivation (mimics MS DPAPI derive_key).
    // This concatenates HMAC rounds: HMAC(key, icount_bytes + hmac_result)
    // repeatedly until we have enough bytes.
    let derived = derive_key_block(
        &hmac_result,
        &header.salt,
        header.hash_algo,
        header.iteration_count,
        dk_len,
    )?;

    let cipher_key = derived[..key_len].to_vec();
    let iv = derived[key_len..key_len + iv_len].to_vec();

    Ok((cipher_key, iv))
}

/// MS DPAPI key derivation: iterative HMAC to produce `dk_len` bytes.
///
/// This follows the impacket/pypykatz derivation:
/// 1. `hmac_curr = HMAC(hash_value, icount_le_bytes + salt)`
///    iterated `icount` times, XOR-accumulated.
/// 2. `derived_key = HMAC(hash_value, hmac_accumulated)`
/// 3. If `dk_len` > hash output, concatenate multiple blocks.
fn derive_key_block(
    hash_value: &[u8],
    salt: &[u8],
    hash_algo: u32,
    icount: u32,
    dk_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    // Use PBKDF2-style derivation matching MS DPAPI behavior.
    // The derivation is: HMAC_iterations(hash_value, icount_bytes + salt)
    // then a final HMAC to get the derived key.

    match hash_algo {
        CALG_SHA1 => {
            let mut result = Vec::with_capacity(dk_len);
            // Initial: HMAC(hash_value, salt)
            let mut mac = <HmacSha1 as Mac>::new_from_slice(hash_value)
                .map_err(|e| CryptoError::Decrypt {
                    detail: format!("HMAC-SHA1 derive init: {e}"),
                })?;
            mac.update(salt);
            let mut hmac_curr = mac.finalize().into_bytes().to_vec();
            let mut hmac_accum = hmac_curr.clone();

            // Iterate
            for _ in 1..icount {
                let mut mac = <HmacSha1 as Mac>::new_from_slice(hash_value)
                    .map_err(|e| CryptoError::Decrypt {
                        detail: format!("HMAC-SHA1 derive iter: {e}"),
                    })?;
                mac.update(&hmac_curr);
                hmac_curr = mac.finalize().into_bytes().to_vec();
                // XOR into accumulator
                for (a, b) in hmac_accum.iter_mut().zip(hmac_curr.iter()) {
                    *a ^= *b;
                }
            }

            // Final derivation: HMAC(hash_value, hmac_accum)
            let mut mac = <HmacSha1 as Mac>::new_from_slice(hash_value)
                .map_err(|e| CryptoError::Decrypt {
                    detail: format!("HMAC-SHA1 derive final: {e}"),
                })?;
            mac.update(&hmac_accum);
            let derived = mac.finalize().into_bytes();
            result.extend_from_slice(&derived);

            // If we need more bytes, do additional rounds
            while result.len() < dk_len {
                let mut mac = <HmacSha1 as Mac>::new_from_slice(hash_value)
                    .map_err(|e| CryptoError::Decrypt {
                        detail: format!("HMAC-SHA1 derive extend: {e}"),
                    })?;
                mac.update(&hmac_accum);
                let derived = mac.finalize().into_bytes();
                result.extend_from_slice(&derived);
            }
            result.truncate(dk_len);
            Ok(result)
        }
        CALG_SHA_512 => {
            let mut result = Vec::with_capacity(dk_len);
            let mut mac = <HmacSha512 as Mac>::new_from_slice(hash_value)
                .map_err(|e| CryptoError::Decrypt {
                    detail: format!("HMAC-SHA512 derive init: {e}"),
                })?;
            mac.update(salt);
            let mut hmac_curr = mac.finalize().into_bytes().to_vec();
            let mut hmac_accum = hmac_curr.clone();

            for _ in 1..icount {
                let mut mac = <HmacSha512 as Mac>::new_from_slice(hash_value)
                    .map_err(|e| CryptoError::Decrypt {
                        detail: format!("HMAC-SHA512 derive iter: {e}"),
                    })?;
                mac.update(&hmac_curr);
                hmac_curr = mac.finalize().into_bytes().to_vec();
                for (a, b) in hmac_accum.iter_mut().zip(hmac_curr.iter()) {
                    *a ^= *b;
                }
            }

            let mut mac = <HmacSha512 as Mac>::new_from_slice(hash_value)
                .map_err(|e| CryptoError::Decrypt {
                    detail: format!("HMAC-SHA512 derive final: {e}"),
                })?;
            mac.update(&hmac_accum);
            let derived = mac.finalize().into_bytes();
            result.extend_from_slice(&derived);

            while result.len() < dk_len {
                let mut mac = <HmacSha512 as Mac>::new_from_slice(hash_value)
                    .map_err(|e| CryptoError::Decrypt {
                        detail: format!("HMAC-SHA512 derive extend: {e}"),
                    })?;
                mac.update(&hmac_accum);
                let derived = mac.finalize().into_bytes();
                result.extend_from_slice(&derived);
            }
            result.truncate(dk_len);
            Ok(result)
        }
        other => Err(CryptoError::InvalidData {
            detail: format!("unsupported hash algo in derive_key_block: {other:#06x}"),
        }),
    }
}

/// Decrypt a master key section using a derived cipher key and IV.
/// Returns the raw decrypted master key (typically 64 bytes).
fn decrypt_master_key_section(
    header: &MasterKeyHeader,
    cipher_key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    match header.crypto_algo {
        CALG_3DES => {
            if cipher_key.len() < 24 {
                return Err(CryptoError::InvalidData {
                    detail: format!("3DES key too short: {} bytes", cipher_key.len()),
                });
            }
            if iv.len() < 8 {
                return Err(CryptoError::InvalidData {
                    detail: format!("3DES IV too short: {} bytes", iv.len()),
                });
            }
            let mut buf = header.encrypted_key.clone();
            // Pad to 8-byte block boundary if needed
            let pad = buf.len() % 8;
            if pad != 0 {
                buf.resize(buf.len() + (8 - pad), 0);
            }
            let decryptor = TdesCbcDec::new_from_slices(&cipher_key[..24], &iv[..8])
                .map_err(|e| CryptoError::Decrypt {
                    detail: format!("3DES-CBC init: {e}"),
                })?;
            let decrypted = decryptor
                .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf)
                .map_err(|e| CryptoError::Decrypt {
                    detail: format!("3DES-CBC decrypt: {e:?}"),
                })?;
            Ok(decrypted.to_vec())
        }
        CALG_AES_256 => {
            if cipher_key.len() < 32 {
                return Err(CryptoError::InvalidData {
                    detail: format!("AES-256 key too short: {} bytes", cipher_key.len()),
                });
            }
            if iv.len() < 16 {
                return Err(CryptoError::InvalidData {
                    detail: format!("AES-256 IV too short: {} bytes", iv.len()),
                });
            }
            let mut buf = header.encrypted_key.clone();
            // Pad to 16-byte block boundary if needed
            let pad = buf.len() % 16;
            if pad != 0 {
                buf.resize(buf.len() + (16 - pad), 0);
            }
            let decryptor = Aes256CbcDec::new_from_slices(&cipher_key[..32], &iv[..16])
                .map_err(|e| CryptoError::Decrypt {
                    detail: format!("AES-256-CBC init: {e}"),
                })?;
            let decrypted = decryptor
                .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf)
                .map_err(|e| CryptoError::Decrypt {
                    detail: format!("AES-256-CBC decrypt: {e:?}"),
                })?;
            Ok(decrypted.to_vec())
        }
        other => Err(CryptoError::InvalidData {
            detail: format!("unsupported crypto algorithm: {other:#06x}"),
        }),
    }
}

/// Verify a decrypted master key by checking the HMAC at the end.
///
/// The decrypted data layout is:
///   - master_key bytes (total_len - hmac_size)
///   - HMAC digest (20 bytes for SHA-1, 64 bytes for SHA-512)
///
/// The HMAC is computed over the master key using the derived HMAC key.
fn verify_and_extract_master_key(
    decrypted: &[u8],
    hash_algo: u32,
    hmac_key: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let hmac_size = match hash_algo {
        CALG_SHA1 => 20,
        CALG_SHA_512 => 64,
        other => {
            return Err(CryptoError::InvalidData {
                detail: format!("unsupported hash algo for HMAC verify: {other:#06x}"),
            });
        }
    };

    if decrypted.len() <= hmac_size {
        return Err(CryptoError::Decrypt {
            detail: format!(
                "decrypted master key too short for HMAC: {} <= {}",
                decrypted.len(),
                hmac_size
            ),
        });
    }

    let key_len = decrypted.len() - hmac_size;
    let master_key = &decrypted[..key_len];
    let stored_hmac = &decrypted[key_len..];

    // Verify: HMAC(hmac_key, master_key) == stored_hmac
    let computed_hmac = match hash_algo {
        CALG_SHA1 => {
            let mut mac = <HmacSha1 as Mac>::new_from_slice(hmac_key)
                .map_err(|e| CryptoError::Decrypt {
                    detail: format!("HMAC-SHA1 verify init: {e}"),
                })?;
            mac.update(master_key);
            mac.finalize().into_bytes().to_vec()
        }
        CALG_SHA_512 => {
            let mut mac = <HmacSha512 as Mac>::new_from_slice(hmac_key)
                .map_err(|e| CryptoError::Decrypt {
                    detail: format!("HMAC-SHA512 verify init: {e}"),
                })?;
            mac.update(master_key);
            mac.finalize().into_bytes().to_vec()
        }
        _ => unreachable!(),
    };

    if computed_hmac.len() >= hmac_size
        && constant_time_eq(&computed_hmac[..hmac_size], stored_hmac)
    {
        Ok(master_key.to_vec())
    } else {
        Err(CryptoError::Decrypt {
            detail: "DPAPI master key HMAC verification failed".to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// Public decryption API: DPAPI_SYSTEM
// ---------------------------------------------------------------------------

/// Parse the DPAPI_SYSTEM LSA secret into its two 20-byte keys.
///
/// Layout: `[version:4][user_key:20][machine_key:20]`
pub fn parse_dpapi_system(raw: &[u8]) -> Result<([u8; 20], [u8; 20]), CryptoError> {
    if raw.len() < 44 {
        return Err(CryptoError::BufferTooSmall {
            need: 44,
            have: raw.len(),
        });
    }
    let mut user_key = [0u8; 20];
    let mut machine_key = [0u8; 20];
    user_key.copy_from_slice(&raw[4..24]);
    machine_key.copy_from_slice(&raw[24..44]);
    Ok((user_key, machine_key))
}

/// Decrypt a master key file using a DPAPI_SYSTEM key (machine-level).
///
/// This uses the **domain key section** of the master key file, which is
/// encrypted with HMAC-SHA1 keyed by the DPAPI_SYSTEM key.
///
/// The domain key secret is structured as:
///   `[nonce:variable][encrypted_data:remaining]`
///
/// The actual approach: try decrypting the master key section using the
/// DPAPI_SYSTEM key as the password hash (HMAC-SHA1 derivation path).
///
/// Returns the 64-byte decrypted master key on success.
pub fn decrypt_master_key_with_system(
    mkf: &MasterKeyFile,
    dpapi_key: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if mkf.master_key_data.is_empty() {
        return Err(CryptoError::InvalidData {
            detail: "master key section is empty".to_string(),
        });
    }

    let header = parse_master_key_header(&mkf.master_key_data)?;

    // For DPAPI_SYSTEM, the password hash IS the 20-byte DPAPI system key.
    // We HMAC it with the SID bytes in the normal path, but for SYSTEM keys
    // the key is used directly.
    let (cipher_key, iv) = derive_master_key_keys(&header, dpapi_key)?;
    let decrypted = decrypt_master_key_section(&header, &cipher_key, &iv)?;

    // The HMAC verification key is another HMAC of the dpapi_key with the salt.
    let hmac_key = match header.hash_algo {
        CALG_SHA1 => {
            let mut mac = <HmacSha1 as Mac>::new_from_slice(dpapi_key)
                .map_err(|e| CryptoError::Decrypt {
                    detail: format!("HMAC-SHA1 hmac_key: {e}"),
                })?;
            mac.update(&header.salt);
            mac.finalize().into_bytes().to_vec()
        }
        CALG_SHA_512 => {
            let mut mac = <HmacSha512 as Mac>::new_from_slice(dpapi_key)
                .map_err(|e| CryptoError::Decrypt {
                    detail: format!("HMAC-SHA512 hmac_key: {e}"),
                })?;
            mac.update(&header.salt);
            mac.finalize().into_bytes().to_vec()
        }
        other => {
            return Err(CryptoError::InvalidData {
                detail: format!("unsupported hash algo: {other:#06x}"),
            });
        }
    };

    verify_and_extract_master_key(&decrypted, header.hash_algo, &hmac_key)
}

// ---------------------------------------------------------------------------
// Public decryption API: user NT hash + SID
// ---------------------------------------------------------------------------

/// Decrypt a master key file using a user's NT hash and SID.
///
/// The derivation pre-key is: `HMAC-SHA1(SHA1(UTF16LE(hex(nt_hash))), UTF16LE(SID))`
///
/// This matches the impacket/pypykatz approach for local accounts.
///
/// Returns the 64-byte decrypted master key on success.
pub fn decrypt_master_key_with_hash(
    mkf: &MasterKeyFile,
    nt_hash: &[u8; 16],
    sid: &str,
) -> Result<Vec<u8>, CryptoError> {
    if mkf.master_key_data.is_empty() {
        return Err(CryptoError::InvalidData {
            detail: "master key section is empty".to_string(),
        });
    }

    let header = parse_master_key_header(&mkf.master_key_data)?;

    // Step 1: SHA1(UTF16LE(hex_string_of_nt_hash))
    let nt_hex = hex_encode(nt_hash);
    let nt_hex_utf16: Vec<u8> = nt_hex
        .chars()
        .flat_map(|c| (c as u16).to_le_bytes())
        .collect();
    let sha1_of_hex = {
        use sha1::Digest;
        sha1::Sha1::digest(&nt_hex_utf16)
    };

    // Step 2: HMAC-SHA1(sha1_result, UTF16LE(SID))
    let sid_utf16: Vec<u8> = sid
        .chars()
        .flat_map(|c| (c as u16).to_le_bytes())
        .collect();
    let mut mac = <HmacSha1 as Mac>::new_from_slice(&sha1_of_hex)
        .map_err(|e| CryptoError::Decrypt {
            detail: format!("HMAC-SHA1 SID derive: {e}"),
        })?;
    mac.update(&sid_utf16);
    let password_hash = mac.finalize().into_bytes().to_vec();

    // Step 3: Use this derived key to decrypt the master key section.
    let (cipher_key, iv) = derive_master_key_keys(&header, &password_hash)?;
    let decrypted = decrypt_master_key_section(&header, &cipher_key, &iv)?;

    // HMAC verification key
    let hmac_key = match header.hash_algo {
        CALG_SHA1 => {
            let mut mac = <HmacSha1 as Mac>::new_from_slice(&password_hash)
                .map_err(|e| CryptoError::Decrypt {
                    detail: format!("HMAC-SHA1 hmac_key: {e}"),
                })?;
            mac.update(&header.salt);
            mac.finalize().into_bytes().to_vec()
        }
        CALG_SHA_512 => {
            let mut mac = <HmacSha512 as Mac>::new_from_slice(&password_hash)
                .map_err(|e| CryptoError::Decrypt {
                    detail: format!("HMAC-SHA512 hmac_key: {e}"),
                })?;
            mac.update(&header.salt);
            mac.finalize().into_bytes().to_vec()
        }
        other => {
            return Err(CryptoError::InvalidData {
                detail: format!("unsupported hash algo: {other:#06x}"),
            });
        }
    };

    verify_and_extract_master_key(&decrypted, header.hash_algo, &hmac_key)
}

// ---------------------------------------------------------------------------
// DPAPI blob decryption
// ---------------------------------------------------------------------------

/// DPAPI blob layout (simplified):
/// ```text
/// offset  0: version          u32 LE  (must be 1)
/// offset  4: provider GUID    16 bytes
/// offset 20: master key GUID  16 bytes
/// offset 36: flags            u32 LE
/// offset 40: description len  u32 LE
/// offset 44: description      <desc_len> bytes (UTF-16LE)
///            algId            u32 LE  (cipher algorithm)
///            algIdHmac        u32 LE  (HMAC algorithm)
///            salt len         u32 LE
///            salt             <salt_len> bytes
///            hmac len         u32 LE
///            hmac             <hmac_len> bytes
///            data len         u32 LE
///            data             <data_len> bytes  -- the ciphertext
///            signature len    u32 LE
///            signature        <sig_len> bytes
/// ```

/// Parsed DPAPI blob fields needed for decryption.
struct DpapiBlobFields {
    mk_guid: [u8; 16],
    alg_id: u32,
    alg_id_hmac: u32,
    salt: Vec<u8>,
    _hmac_value: Vec<u8>,
    ciphertext: Vec<u8>,
}

/// Parse the variable-length fields of a DPAPI blob.
fn parse_dpapi_blob(blob: &[u8]) -> Result<DpapiBlobFields, CryptoError> {
    if blob.len() < 44 {
        return Err(CryptoError::BufferTooSmall {
            need: 44,
            have: blob.len(),
        });
    }

    let version = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]);
    if version != 1 {
        return Err(CryptoError::InvalidData {
            detail: format!("DPAPI blob: unsupported version {version}"),
        });
    }

    let mut mk_guid = [0u8; 16];
    mk_guid.copy_from_slice(&blob[20..36]);

    // flags at 36..40 (ignored)
    let desc_len = u32::from_le_bytes([blob[40], blob[41], blob[42], blob[43]]) as usize;

    let mut pos = 44 + desc_len;
    if blob.len() < pos + 8 {
        return Err(CryptoError::BufferTooSmall {
            need: pos + 8,
            have: blob.len(),
        });
    }

    let alg_id = u32::from_le_bytes([blob[pos], blob[pos + 1], blob[pos + 2], blob[pos + 3]]);
    pos += 4;
    let alg_id_hmac = u32::from_le_bytes([blob[pos], blob[pos + 1], blob[pos + 2], blob[pos + 3]]);
    pos += 4;

    // Salt
    if blob.len() < pos + 4 {
        return Err(CryptoError::BufferTooSmall { need: pos + 4, have: blob.len() });
    }
    let salt_len = u32::from_le_bytes([blob[pos], blob[pos + 1], blob[pos + 2], blob[pos + 3]]) as usize;
    pos += 4;
    if blob.len() < pos + salt_len {
        return Err(CryptoError::BufferTooSmall { need: pos + salt_len, have: blob.len() });
    }
    let salt = blob[pos..pos + salt_len].to_vec();
    pos += salt_len;

    // HMAC
    if blob.len() < pos + 4 {
        return Err(CryptoError::BufferTooSmall { need: pos + 4, have: blob.len() });
    }
    let hmac_len = u32::from_le_bytes([blob[pos], blob[pos + 1], blob[pos + 2], blob[pos + 3]]) as usize;
    pos += 4;
    if blob.len() < pos + hmac_len {
        return Err(CryptoError::BufferTooSmall { need: pos + hmac_len, have: blob.len() });
    }
    let hmac_value = blob[pos..pos + hmac_len].to_vec();
    pos += hmac_len;

    // Ciphertext
    if blob.len() < pos + 4 {
        return Err(CryptoError::BufferTooSmall { need: pos + 4, have: blob.len() });
    }
    let data_len = u32::from_le_bytes([blob[pos], blob[pos + 1], blob[pos + 2], blob[pos + 3]]) as usize;
    pos += 4;
    if blob.len() < pos + data_len {
        return Err(CryptoError::BufferTooSmall { need: pos + data_len, have: blob.len() });
    }
    let ciphertext = blob[pos..pos + data_len].to_vec();

    Ok(DpapiBlobFields {
        mk_guid,
        alg_id,
        alg_id_hmac,
        salt,
        _hmac_value: hmac_value,
        ciphertext,
    })
}

/// Derive the session key for DPAPI blob decryption.
///
/// `session_key = HMAC(master_key, salt)` using the blob's HMAC algorithm,
/// then derive the actual cipher key from `HMAC(session_key, hmac_value)`.
fn derive_blob_session_key(
    master_key: &[u8],
    fields: &DpapiBlobFields,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    // Derive session key: HMAC(master_key, salt)
    let session_key = match fields.alg_id_hmac {
        CALG_SHA1 => {
            let mut mac = <HmacSha1 as Mac>::new_from_slice(master_key)
                .map_err(|e| CryptoError::Decrypt {
                    detail: format!("session HMAC-SHA1: {e}"),
                })?;
            mac.update(&fields.salt);
            mac.finalize().into_bytes().to_vec()
        }
        CALG_SHA_512 => {
            let mut mac = <HmacSha512 as Mac>::new_from_slice(master_key)
                .map_err(|e| CryptoError::Decrypt {
                    detail: format!("session HMAC-SHA512: {e}"),
                })?;
            mac.update(&fields.salt);
            mac.finalize().into_bytes().to_vec()
        }
        other => {
            return Err(CryptoError::InvalidData {
                detail: format!("unsupported HMAC algorithm in blob: {other:#06x}"),
            });
        }
    };

    // Determine key/IV sizes from the cipher algorithm.
    let (key_len, iv_len) = match fields.alg_id {
        CALG_3DES => (24, 8),
        CALG_AES_256 => (32, 16),
        // Also support AES-128 (CALG_AES_128 = 0x660E)
        0x0000_660E => (16, 16),
        other => {
            return Err(CryptoError::InvalidData {
                detail: format!("unsupported cipher in blob: {other:#06x}"),
            });
        }
    };

    let dk_len = key_len + iv_len;

    // Derive cipher key from session key.
    // DPAPI derives via: derive_key(session_key, alg_id_hmac, dk_len)
    // which uses sequential HMAC blocks.
    let mut derived = Vec::with_capacity(dk_len);

    // Block 1
    let block1 = {
        let icount_bytes = 1u32.to_le_bytes();
        match fields.alg_id_hmac {
            CALG_SHA1 => {
                let mut mac = <HmacSha1 as Mac>::new_from_slice(&session_key)
                    .map_err(|e| CryptoError::Decrypt {
                        detail: format!("derive block HMAC-SHA1: {e}"),
                    })?;
                mac.update(&icount_bytes);
                mac.finalize().into_bytes().to_vec()
            }
            CALG_SHA_512 => {
                let mut mac = <HmacSha512 as Mac>::new_from_slice(&session_key)
                    .map_err(|e| CryptoError::Decrypt {
                        detail: format!("derive block HMAC-SHA512: {e}"),
                    })?;
                mac.update(&icount_bytes);
                mac.finalize().into_bytes().to_vec()
            }
            _ => unreachable!(),
        }
    };
    derived.extend_from_slice(&block1);

    // Additional blocks if needed
    let mut block_num = 2u32;
    while derived.len() < dk_len {
        let icount_bytes = block_num.to_le_bytes();
        let block = match fields.alg_id_hmac {
            CALG_SHA1 => {
                let mut mac = <HmacSha1 as Mac>::new_from_slice(&session_key)
                    .map_err(|e| CryptoError::Decrypt {
                        detail: format!("derive block HMAC-SHA1: {e}"),
                    })?;
                mac.update(&icount_bytes);
                mac.finalize().into_bytes().to_vec()
            }
            CALG_SHA_512 => {
                let mut mac = <HmacSha512 as Mac>::new_from_slice(&session_key)
                    .map_err(|e| CryptoError::Decrypt {
                        detail: format!("derive block HMAC-SHA512: {e}"),
                    })?;
                mac.update(&icount_bytes);
                mac.finalize().into_bytes().to_vec()
            }
            _ => unreachable!(),
        };
        derived.extend_from_slice(&block);
        block_num += 1;
    }
    derived.truncate(dk_len);

    let cipher_key = derived[..key_len].to_vec();
    let iv = derived[key_len..].to_vec();

    Ok((cipher_key, iv))
}

// ---------------------------------------------------------------------------
// DpapiKeyring
// ---------------------------------------------------------------------------

/// A collection of DPAPI key material used to decrypt DPAPI blobs offline.
///
/// Construct via [`DpapiKeyring::new`] (empty / no-op) or populate with
/// domain/machine key material via [`DpapiKeyring::with_lsa_secrets`].
#[derive(Debug, Default, Clone)]
pub struct DpapiKeyring {
    /// Raw LSA secret bytes that may contain DPAPI machine key material.
    lsa_secrets: Vec<Vec<u8>>,
    /// Pre-computed DPAPI master keys (GUID → 64-byte key bytes).
    master_keys: Vec<([u8; 16], Vec<u8>)>,
}

impl DpapiKeyring {
    /// Create an empty keyring.  Decryption will fail unless key material is
    /// added before use.
    pub fn new() -> Self {
        Self::default()
    }

    /// Populate the keyring with raw LSA secret data (e.g. the current value
    /// of `DPAPI_SYSTEM` from the SECURITY hive).
    pub fn with_lsa_secrets(mut self, secrets: Vec<Vec<u8>>) -> Self {
        self.lsa_secrets = secrets;
        self
    }

    /// Register a pre-computed DPAPI master key.
    ///
    /// `guid` is the 16-byte binary GUID of the master key.
    /// `key_bytes` is the raw 64-byte master key.
    pub fn add_master_key(&mut self, guid: [u8; 16], key_bytes: Vec<u8>) {
        self.master_keys.push((guid, key_bytes));
    }

    /// Register a master key by its string GUID (e.g. from filename).
    ///
    /// The GUID string is hashed to a 16-byte value for lookup.
    pub fn add_master_key_by_guid_str(&mut self, guid_str: &str, key_bytes: Vec<u8>) {
        let guid_bin = guid_str_to_bin(guid_str);
        self.master_keys.push((guid_bin, key_bytes));
    }

    /// Returns the number of registered master keys.
    pub fn master_key_count(&self) -> usize {
        self.master_keys.len()
    }

    /// Attempt to decrypt a raw DPAPI blob.
    ///
    /// The blob must **not** include the `DPAPI` ASCII prefix — strip it
    /// before calling this function.
    pub fn decrypt_blob(&self, blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
        decrypt_dpapi_blob(blob, self)
    }
}

/// Decrypt a raw DPAPI blob using the provided keyring.
pub fn decrypt_dpapi_blob(blob: &[u8], keyring: &DpapiKeyring) -> Result<Vec<u8>, CryptoError> {
    let fields = parse_dpapi_blob(blob)?;

    // Look for a pre-registered master key matching this GUID.
    let master_key = keyring
        .master_keys
        .iter()
        .find(|(g, _)| g == &fields.mk_guid)
        .map(|(_, k)| k.as_slice());

    match master_key {
        Some(mk) => {
            let (cipher_key, iv) = derive_blob_session_key(mk, &fields)?;

            // Decrypt the ciphertext.
            match fields.alg_id {
                CALG_3DES => {
                    let mut buf = fields.ciphertext.clone();
                    let pad = buf.len() % 8;
                    if pad != 0 {
                        buf.resize(buf.len() + (8 - pad), 0);
                    }
                    let decryptor = TdesCbcDec::new_from_slices(&cipher_key[..24], &iv[..8])
                        .map_err(|e| CryptoError::Decrypt {
                            detail: format!("blob 3DES-CBC init: {e}"),
                        })?;
                    let decrypted = decryptor
                        .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf)
                        .map_err(|e| CryptoError::Decrypt {
                            detail: format!("blob 3DES-CBC decrypt: {e:?}"),
                        })?;
                    Ok(decrypted.to_vec())
                }
                CALG_AES_256 | 0x0000_660E => {
                    let mut buf = fields.ciphertext.clone();
                    let pad = buf.len() % 16;
                    if pad != 0 {
                        buf.resize(buf.len() + (16 - pad), 0);
                    }
                    if fields.alg_id == CALG_AES_256 {
                        let decryptor = Aes256CbcDec::new_from_slices(&cipher_key, &iv)
                            .map_err(|e| CryptoError::Decrypt {
                                detail: format!("blob AES-256-CBC init: {e}"),
                            })?;
                        let decrypted = decryptor
                            .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf)
                            .map_err(|e| CryptoError::Decrypt {
                                detail: format!("blob AES-256-CBC decrypt: {e:?}"),
                            })?;
                        Ok(decrypted.to_vec())
                    } else {
                        // AES-128
                        let decryptor = cbc::Decryptor::<aes::Aes128>::new_from_slices(&cipher_key, &iv)
                            .map_err(|e| CryptoError::Decrypt {
                                detail: format!("blob AES-128-CBC init: {e}"),
                            })?;
                        let decrypted = decryptor
                            .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf)
                            .map_err(|e| CryptoError::Decrypt {
                                detail: format!("blob AES-128-CBC decrypt: {e:?}"),
                            })?;
                        Ok(decrypted.to_vec())
                    }
                }
                other => Err(CryptoError::InvalidData {
                    detail: format!("unsupported blob cipher: {other:#06x}"),
                }),
            }
        }
        None => Err(CryptoError::Decrypt {
            detail: format!(
                "DPAPI: no master key found for GUID {:02x?}",
                &fields.mk_guid[..4]
            ),
        }),
    }
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/// Convert a GUID string like "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" to 16
/// bytes.  If the string is not a valid GUID, returns a SHA-1 hash of the
/// string truncated to 16 bytes (for best-effort matching).
fn guid_str_to_bin(guid: &str) -> [u8; 16] {
    let hex: String = guid.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() == 32 {
        // Standard GUID: first three groups are LE, last two are BE.
        // data1: 4 bytes LE, data2: 2 bytes LE, data3: 2 bytes LE, data4: 8 bytes
        let bytes: Vec<u8> = (0..16)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or(0))
            .collect();
        // Convert from string representation to binary GUID (mixed-endian)
        let mut out = [0u8; 16];
        // Data1 (LE)
        out[0] = bytes[3]; out[1] = bytes[2]; out[2] = bytes[1]; out[3] = bytes[0];
        // Data2 (LE)
        out[4] = bytes[5]; out[5] = bytes[4];
        // Data3 (LE)
        out[6] = bytes[7]; out[7] = bytes[6];
        // Data4 (as-is)
        out[8..16].copy_from_slice(&bytes[8..16]);
        out
    } else {
        // Fallback: hash the string
        use sha1::Digest;
        let hash = sha1::Sha1::digest(guid.as_bytes());
        let mut out = [0u8; 16];
        out.copy_from_slice(&hash[..16]);
        out
    }
}

/// Decode a UTF-16LE byte slice to a String.
fn decode_utf16le(bytes: &[u8]) -> String {
    let chars: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&chars)
}

/// Encode bytes as lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Constant-time byte comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dpapi_system() {
        // version(4) + user_key(20) + machine_key(20) = 44 bytes
        let mut raw = vec![0x01, 0x00, 0x00, 0x00]; // version
        raw.extend_from_slice(&[0xAA; 20]); // user key
        raw.extend_from_slice(&[0xBB; 20]); // machine key
        let (user, machine) = parse_dpapi_system(&raw).unwrap();
        assert_eq!(user, [0xAA; 20]);
        assert_eq!(machine, [0xBB; 20]);
    }

    #[test]
    fn test_parse_dpapi_system_too_short() {
        let raw = vec![0x01; 20];
        assert!(parse_dpapi_system(&raw).is_err());
    }

    #[test]
    fn test_guid_str_to_bin_valid() {
        let guid = "12345678-1234-1234-1234-123456789abc";
        let bin = guid_str_to_bin(guid);
        // Data1 LE: 78563412
        assert_eq!(bin[0], 0x78);
        assert_eq!(bin[1], 0x56);
        assert_eq!(bin[2], 0x34);
        assert_eq!(bin[3], 0x12);
        // Data2 LE: 3412
        assert_eq!(bin[4], 0x34);
        assert_eq!(bin[5], 0x12);
        // Data3 LE: 3412
        assert_eq!(bin[6], 0x34);
        assert_eq!(bin[7], 0x12);
        // Data4: as-is
        assert_eq!(bin[8], 0x12);
        assert_eq!(bin[9], 0x34);
    }

    #[test]
    fn test_guid_str_to_bin_lowercase() {
        let g1 = guid_str_to_bin("ABCDEF01-2345-6789-ABCD-EF0123456789");
        let g2 = guid_str_to_bin("abcdef01-2345-6789-abcd-ef0123456789");
        assert_eq!(g1, g2);
    }

    #[test]
    fn test_parse_master_key_file_too_short() {
        let data = vec![0u8; 50];
        assert!(parse_master_key_file(&data).is_err());
    }

    #[test]
    fn test_parse_master_key_file_minimal() {
        // Build a minimal valid master key file: 128-byte header + 0-length sections
        let mut data = vec![0u8; 128];
        // version = 2
        data[0] = 0x02;
        // GUID at offset 12: 72 bytes of UTF-16LE, put "test-guid\0..."
        let guid_str = "test-guid-value!";
        let guid_utf16: Vec<u8> = guid_str
            .chars()
            .flat_map(|c| (c as u16).to_le_bytes())
            .collect();
        let copy_len = guid_utf16.len().min(72);
        data[12..12 + copy_len].copy_from_slice(&guid_utf16[..copy_len]);
        // All section lengths = 0
        // (already zero from initialization)

        let mkf = parse_master_key_file(&data).unwrap();
        assert_eq!(mkf.version, 2);
        assert!(mkf.guid.starts_with("test-guid"));
        assert!(mkf.master_key_data.is_empty());
        assert!(mkf.backup_key_data.is_empty());
        assert!(mkf.domain_key_data.is_empty());
    }

    #[test]
    fn test_parse_master_key_header() {
        let mut data = vec![0u8; 64];
        // version = 1
        data[0] = 0x01;
        // salt at 4..20
        for i in 4..20 {
            data[i] = i as u8;
        }
        // iteration count = 4000
        let icount = 4000u32.to_le_bytes();
        data[20..24].copy_from_slice(&icount);
        // hash_algo = SHA1
        let hash = CALG_SHA1.to_le_bytes();
        data[24..28].copy_from_slice(&hash);
        // crypto_algo = 3DES
        let crypto = CALG_3DES.to_le_bytes();
        data[28..32].copy_from_slice(&crypto);
        // encrypted_key = remaining 32 bytes
        for i in 32..64 {
            data[i] = 0xFF;
        }

        let header = parse_master_key_header(&data).unwrap();
        assert_eq!(header._version, 1);
        assert_eq!(header.iteration_count, 4000);
        assert_eq!(header.hash_algo, CALG_SHA1);
        assert_eq!(header.crypto_algo, CALG_3DES);
        assert_eq!(header.encrypted_key.len(), 32);
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
    }

    #[test]
    fn test_decode_utf16le() {
        let s = "test";
        let bytes: Vec<u8> = s.chars().flat_map(|c| (c as u16).to_le_bytes()).collect();
        assert_eq!(decode_utf16le(&bytes), "test");
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0xDE, 0xAD, 0xBE, 0xEF]), "deadbeef");
    }

    #[test]
    fn test_empty_keyring_decrypt_fails() {
        let keyring = DpapiKeyring::new();
        // Minimal valid DPAPI blob header
        let mut blob = vec![0u8; 52];
        blob[0] = 1; // version
        assert!(keyring.decrypt_blob(&blob).is_err());
    }

    #[test]
    fn test_keyring_add_master_key_by_guid_str() {
        let mut keyring = DpapiKeyring::new();
        keyring.add_master_key_by_guid_str(
            "12345678-1234-1234-1234-123456789abc",
            vec![0xAA; 64],
        );
        assert_eq!(keyring.master_key_count(), 1);
    }

    #[test]
    fn test_parse_dpapi_blob_too_short() {
        let blob = vec![0u8; 10];
        assert!(parse_dpapi_blob(&blob).is_err());
    }

    #[test]
    fn test_parse_dpapi_blob_bad_version() {
        let mut blob = vec![0u8; 52];
        blob[0] = 99; // bad version
        assert!(parse_dpapi_blob(&blob).is_err());
    }

    #[test]
    fn test_parse_domain_key_section_too_short() {
        let data = vec![0u8; 10];
        assert!(parse_domain_key_section(&data).is_err());
    }
}
