//! GPP (Group Policy Preferences) cpassword decryption.
//!
//! MS14-025: Microsoft published the AES-256-CBC key used to encrypt
//! Group Policy Preferences passwords. This makes all cpassword values
//! trivially decryptable.

use crate::error::CryptoError;

/// The well-known AES-256 key published by Microsoft (MS14-025).
const GPP_AES_KEY: [u8; 32] = [
    0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9,
    0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
    0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90,
    0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b,
];

/// Decrypt a GPP cpassword string.
///
/// The cpassword is base64-encoded (with padding characters sometimes missing).
/// After base64 decoding, it's AES-256-CBC encrypted with a fixed IV of all zeros.
///
/// Returns the decrypted password as a UTF-16LE decoded string.
pub fn decrypt_gpp_password(cpassword: &str) -> Result<String, CryptoError> {
    if cpassword.is_empty() {
        return Ok(String::new());
    }

    // Fix base64 padding — GPP sometimes omits trailing '='
    let mut padded = cpassword.to_string();
    let remainder = padded.len() % 4;
    if remainder != 0 {
        for _ in 0..(4 - remainder) {
            padded.push('=');
        }
    }

    // Base64 decode
    let decoded = base64_decode(&padded)?;

    if decoded.is_empty() {
        return Ok(String::new());
    }

    // AES-256-CBC decrypt with zero IV
    let iv = [0u8; 16];

    use aes::Aes256;
    use cbc::cipher::{BlockDecryptMut, KeyIvInit};
    type Aes256CbcDec = cbc::Decryptor<Aes256>;

    // Ensure data is padded to block size
    let aligned_len = ((decoded.len() + 15) / 16) * 16;
    let mut buf = vec![0u8; aligned_len];
    buf[..decoded.len()].copy_from_slice(&decoded);

    let decryptor = Aes256CbcDec::new_from_slices(&GPP_AES_KEY, &iv)
        .map_err(|e| CryptoError::InvalidData {
            detail: format!("GPP AES init: {}", e),
        })?;

    let decrypted = decryptor
        .decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buf)
        .map_err(|e| CryptoError::InvalidData {
            detail: format!("GPP AES decrypt: {:?}", e),
        })?;

    // Result is UTF-16LE encoded
    decode_utf16le(decrypted)
}

/// Simple base64 decoder (no external dependency).
fn base64_decode(input: &str) -> Result<Vec<u8>, CryptoError> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut output = Vec::with_capacity(input.len() * 3 / 4);
    let bytes: Vec<u8> = input
        .bytes()
        .filter(|b| *b != b'\n' && *b != b'\r' && *b != b' ')
        .collect();

    for chunk in bytes.chunks(4) {
        if chunk.len() < 2 {
            break;
        }

        let mut vals = [0u8; 4];
        let mut count = 0;
        for (i, &b) in chunk.iter().enumerate() {
            if b == b'=' {
                break;
            }
            vals[i] = match TABLE.iter().position(|&c| c == b) {
                Some(pos) => pos as u8,
                None => {
                    return Err(CryptoError::InvalidData {
                        detail: format!("invalid base64 character: {}", b as char),
                    })
                }
            };
            count = i + 1;
        }

        if count >= 2 {
            output.push((vals[0] << 2) | (vals[1] >> 4));
        }
        if count >= 3 {
            output.push((vals[1] << 4) | (vals[2] >> 2));
        }
        if count >= 4 {
            output.push((vals[2] << 6) | vals[3]);
        }
    }

    Ok(output)
}

/// Decode UTF-16LE bytes to a String.
fn decode_utf16le(data: &[u8]) -> Result<String, CryptoError> {
    if data.len() % 2 != 0 {
        // Trim trailing byte if odd
        let trimmed = &data[..data.len() - 1];
        return decode_utf16le(trimmed);
    }
    let chars: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&chars).map_err(|_| CryptoError::InvalidData {
        detail: "GPP password: invalid UTF-16LE".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_cpassword() {
        let result = decrypt_gpp_password("").unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn test_known_vector() {
        // Well-known test vector from public GPP research.
        // cpassword: j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
        // Actual decrypted value verified against the MS14-025 AES key.
        let result = decrypt_gpp_password("j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw").unwrap();
        assert_eq!(result, "Local*P4ssword!");
    }

    #[test]
    fn test_missing_padding() {
        // Verify padding logic handles inputs whose length is not a multiple of 4.
        // "j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw" is 43 chars (len%4 == 3),
        // so it needs 1 '=' of padding to be valid base64.
        let no_pad = "j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw";
        assert_eq!(no_pad.len() % 4, 3); // needs 1 '=' padding

        // The full cpassword (with implicit padding added) should decrypt correctly.
        let result = decrypt_gpp_password(no_pad).unwrap();
        assert_eq!(result, "Local*P4ssword!");
    }
}
