//! abyss-target: Target abstraction layer.
//!
//! Opens disk images and presents a unified interface for filesystem access,
//! OS detection, and artifact extraction.

pub mod detect;
pub mod error;
pub mod extractor;
pub mod extractors;
pub mod filesystem;
pub mod shell;
pub mod target;

pub use error::TargetError;
pub use target::Target;
