//! abyss-crypto: Windows credential crypto for Abyss.
//!
//! Provides SYSKEY derivation from the SYSTEM hive and SAM hash extraction
//! from the SAM hive using the derived SYSKEY.

pub mod error;
pub mod sam;
pub mod syskey;

pub use error::CryptoError;
pub use sam::{SamEntry, extract_sam_hashes};
pub use syskey::derive_syskey;
