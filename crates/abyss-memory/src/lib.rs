//! abyss-memory: Memory dump parser for credential extraction.
//!
//! Parses Windows minidump files (.dmp) and extracts credential structures
//! from LSASS process memory (MSV1_0/NTLM, Wdigest, Kerberos, TSPKG).

pub mod error;
pub mod lsass;
pub mod minidump;

pub use error::MemoryError;
pub use lsass::LsassCredential;
pub use minidump::{Architecture, MinidumpReader, Module};
