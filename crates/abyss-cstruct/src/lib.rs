//! abyss-cstruct: Binary struct parsing utilities.
//!
//! Provides traits and helpers for zero-copy parsing of binary data structures
//! from disk images, registry hives, and other forensic artifacts.

pub mod error;
pub mod read;

pub use error::ParseError;
