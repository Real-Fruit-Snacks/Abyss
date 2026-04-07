//! abyss-crypto: Windows credential crypto for Abyss.
//!
//! Provides SYSKEY derivation from the SYSTEM hive and SAM hash extraction
//! from the SAM hive using the derived SYSKEY.

pub mod cached_creds;
pub mod dpapi;
pub mod error;
pub mod lsa;
pub mod sam;
pub mod syskey;

pub use cached_creds::{CachedCredential, extract_cached_creds};
pub use dpapi::{DpapiKeyring, decrypt_dpapi_blob};
pub use error::CryptoError;
pub use lsa::{LsaSecret, derive_lsa_key, extract_lsa_secrets};
pub use sam::{SamEntry, extract_sam_hashes};
pub use syskey::derive_syskey;
