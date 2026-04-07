//! Offline DPAPI blob decryption.
//!
//! DPAPI (Data Protection API) uses machine-level keys derived from the SYSTEM
//! and SECURITY hive secrets.  In an offline forensic scenario we recreate the
//! key material from the extracted LSA secrets and provide a [`DpapiKeyring`]
//! that can decrypt individual DPAPI blobs.
//!
//! The blob format targeted here is the "DPAPI encrypted key" written by
//! Chromium-family browsers into `Local State` under the key
//! `os_crypt.encrypted_key`.  After base-64 decoding that value starts with
//! the 5-byte ASCII prefix `DPAPI` followed by a standard DPAPI blob.
//!
//! For a full offline implementation the caller would populate the keyring with
//! the DPAPI master-key blobs recovered from the profile directory and the
//! domain / machine keys derived from the registry.  The current implementation
//! exposes the types and interface so that browser extraction code compiles and
//! runs; the actual master-key derivation is left as a future extension point.

use crate::error::CryptoError;

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

    /// Attempt to decrypt a raw DPAPI blob.
    ///
    /// The blob must **not** include the `DPAPI` ASCII prefix — strip it
    /// before calling this function.
    ///
    /// # Current limitations
    /// Full offline master-key derivation (chasing the master-key GUID through
    /// the user profile and decrypting with domain/machine backup keys) is not
    /// yet implemented.  This returns an error unless a matching pre-registered
    /// master key is found.
    pub fn decrypt_blob(&self, blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
        decrypt_dpapi_blob(blob, self)
    }
}

/// Decrypt a raw DPAPI blob using the provided keyring.
///
/// DPAPI blob layout (simplified — full spec has additional fields):
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
///            data             <data_len> bytes  ← the ciphertext
///            signature len    u32 LE
///            signature        <sig_len> bytes
/// ```
pub fn decrypt_dpapi_blob(blob: &[u8], keyring: &DpapiKeyring) -> Result<Vec<u8>, CryptoError> {
    // Minimum header size to read the master-key GUID (at offset 20).
    if blob.len() < 36 {
        return Err(CryptoError::BufferTooSmall {
            need: 36,
            have: blob.len(),
        });
    }

    // Version check.
    let version = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]);
    if version != 1 {
        return Err(CryptoError::InvalidData {
            detail: format!("DPAPI blob: unsupported version {version}"),
        });
    }

    // Extract master-key GUID (bytes 20..36).
    let mut mk_guid = [0u8; 16];
    mk_guid.copy_from_slice(&blob[20..36]);

    // Look for a pre-registered master key matching this GUID.
    let master_key = keyring
        .master_keys
        .iter()
        .find(|(g, _)| g == &mk_guid)
        .map(|(_, k)| k.as_slice());

    match master_key {
        Some(_mk) => {
            // Full offline decryption requires parsing the remaining fields
            // (algorithm IDs, salt, HMAC, ciphertext) and deriving the
            // session key via HMAC-SHA1/SHA512 + the master key.
            // This is a future implementation point.
            Err(CryptoError::Decrypt {
                detail: "DPAPI: full offline decryption not yet implemented (master key found but decryption algorithm not implemented)".to_string(),
            })
        }
        None => Err(CryptoError::Decrypt {
            detail: format!(
                "DPAPI: no master key found for GUID {:02x?}",
                &mk_guid[..4]
            ),
        }),
    }
}
