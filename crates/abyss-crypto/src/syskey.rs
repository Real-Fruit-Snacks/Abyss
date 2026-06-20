//! SYSKEY (boot key) derivation from the SYSTEM registry hive.
//!
//! The SYSKEY is a 16-byte key used to encrypt credentials stored in the SAM
//! hive.  It is derived by reading the class names of four registry keys under
//! `ControlSet001\Control\Lsa`: JD, Skew1, GBG, and Data.  Each class name is
//! a UTF-16LE-encoded hexadecimal string whose bytes, when concatenated and
//! permuted through a fixed table, produce the 16-byte SYSKEY.

use crate::error::CryptoError;
use abyss_registry::RegistryHive;

/// Fixed permutation table applied to the 16 concatenated class-name bytes.
const SYSKEY_PERM: [usize; 16] = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7];

/// Derive the 16-byte SYSKEY from the SYSTEM registry hive.
///
/// Algorithm:
/// 1. Read `Select\Default` DWORD to determine the current control set number.
/// 2. For each of the four LSA sub-keys (JD, Skew1, GBG, Data) under
///    `ControlSetXXX\Control\Lsa`, read the class name bytes.
/// 3. The class name is a UTF-16LE hex string — decode each 2-byte UTF-16LE
///    code unit to an ASCII character, then parse pairs as hex bytes.
/// 4. Concatenate the four 4-byte results to get a 16-byte scrambled key.
/// 5. Apply `SYSKEY_PERM` to produce the final SYSKEY.
pub fn derive_syskey(system: &mut RegistryHive) -> Result<[u8; 16], CryptoError> {
    // Step 1: determine current control set.
    let select_key = system.open_key("Select").map_err(|_| CryptoError::KeyNotFound {
        key: "Select".to_string(),
    })?;
    let default_val = system.read_value(&select_key, "Default").map_err(|_| {
        CryptoError::ValueNotFound {
            name: "Select\\Default".to_string(),
        }
    })?;
    let control_set_num = default_val.as_u32().map_err(|e| CryptoError::InvalidData {
        detail: format!("Select\\Default: {e}"),
    })?;

    let cs_name = format!("ControlSet{:03}", control_set_num);
    log::debug!("SYSKEY: using {cs_name}");

    // Step 2-3: read and decode class names for each LSA sub-key.
    let lsa_subkeys = ["JD", "Skew1", "GBG", "Data"];
    let mut scrambled = [0u8; 16];
    let mut pos = 0usize;

    for subkey_name in &lsa_subkeys {
        let path = format!("{cs_name}\\Control\\Lsa\\{subkey_name}");
        let key = system.open_key(&path).map_err(|_| CryptoError::KeyNotFound {
            key: path.clone(),
        })?;

        let class_bytes = system
            .read_class_name(&key)
            .map_err(|e| CryptoError::InvalidData {
                detail: format!("class name for {path}: {e}"),
            })?
            .ok_or_else(|| CryptoError::InvalidData {
                detail: format!("no class name for {path}"),
            })?;

        // class_bytes is UTF-16LE: each character is 2 bytes.
        // Decode to a hex string then parse pairs as bytes.
        let hex_str = decode_utf16le_ascii(&class_bytes).ok_or_else(|| CryptoError::InvalidData {
            detail: format!("invalid UTF-16LE class name for {path}"),
        })?;

        let key_bytes = hex_decode(&hex_str).ok_or_else(|| CryptoError::InvalidData {
            detail: format!("invalid hex class name '{hex_str}' for {path}"),
        })?;

        if key_bytes.len() != 4 {
            return Err(CryptoError::InvalidData {
                detail: format!(
                    "expected 4 bytes from class name for {path}, got {}",
                    key_bytes.len()
                ),
            });
        }

        scrambled[pos..pos + 4].copy_from_slice(&key_bytes);
        pos += 4;
    }

    // Step 5: apply permutation.
    let mut syskey = [0u8; 16];
    for (i, &src) in SYSKEY_PERM.iter().enumerate() {
        syskey[i] = scrambled[src];
    }

    log::debug!("SYSKEY derived: {}", hex_fmt(&syskey));
    Ok(syskey)
}

/// Decode a UTF-16LE byte slice as an ASCII string.
///
/// Each pair of bytes is a UTF-16LE code unit.  We only handle the ASCII
/// range (code units 0x00–0x7F) since class names are hex digits.
fn decode_utf16le_ascii(bytes: &[u8]) -> Option<String> {
    if bytes.len() % 2 != 0 {
        return None;
    }
    let mut s = String::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks_exact(2) {
        let cu = u16::from_le_bytes([chunk[0], chunk[1]]);
        if cu > 0x7F {
            return None;
        }
        s.push(cu as u8 as char);
    }
    Some(s)
}

/// Decode a hex string into bytes.  Returns `None` on invalid input.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16).ok()?;
        out.push(byte);
    }
    Some(out)
}

/// Format a byte slice as a lowercase hex string (for debug logging).
fn hex_fmt(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_utf16le_ascii() {
        // "3a2b" as UTF-16LE
        let bytes: Vec<u8> = "3a2b".chars().flat_map(|c| (c as u16).to_le_bytes()).collect();
        assert_eq!(decode_utf16le_ascii(&bytes), Some("3a2b".to_string()));
    }

    #[test]
    fn test_hex_decode() {
        assert_eq!(hex_decode("deadbeef"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
        assert_eq!(hex_decode("00"), Some(vec![0x00]));
        assert_eq!(hex_decode("zz"), None);
        assert_eq!(hex_decode("abc"), None); // odd length
    }

    #[test]
    fn test_permutation_identity() {
        // With scrambled = [0,1,2,...,15], permutation selects SYSKEY_PERM[i] as value at i.
        let scrambled: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let mut syskey = [0u8; 16];
        for (i, &src) in SYSKEY_PERM.iter().enumerate() {
            syskey[i] = scrambled[src];
        }
        // syskey[0] = scrambled[8] = 8, syskey[1] = scrambled[5] = 5, etc.
        assert_eq!(syskey[0], 8);
        assert_eq!(syskey[1], 5);
        assert_eq!(syskey[2], 4);
    }
}
