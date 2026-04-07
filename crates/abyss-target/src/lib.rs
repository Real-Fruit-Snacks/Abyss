//! abyss-target: Target abstraction layer.
//!
//! Opens disk images and presents a unified interface for filesystem access,
//! OS detection, and artifact extraction.

pub mod error;

pub use error::TargetError;
