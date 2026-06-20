//! abyss-crypto: Windows credential crypto for Abyss.
//!
//! Provides SYSKEY derivation from the SYSTEM hive and SAM hash extraction
//! from the SAM hive using the derived SYSKEY.

pub mod cached_creds;
pub mod dpapi;
pub mod error;
pub mod gpp;
pub mod lsa;
pub mod ntds;
pub mod sam;
pub mod syskey;

pub use cached_creds::{CachedCredential, extract_cached_creds};
pub use dpapi::{
    DpapiKeyring, MasterKeyFile, decrypt_dpapi_blob, decrypt_master_key_with_hash,
    decrypt_master_key_with_system, parse_dpapi_system, parse_master_key_file,
};
pub use error::CryptoError;
pub use gpp::decrypt_gpp_password;
pub use lsa::{LsaSecret, derive_lsa_key, extract_lsa_secrets};
pub use ntds::{decrypt_ntds_hash, decrypt_ntds_hash_history, decrypt_pek};
pub use sam::{SamEntry, extract_sam_hashes};
pub use syskey::derive_syskey;
