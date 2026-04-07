//! abyss-output: Output formatting and finding types.

pub mod collector;
pub mod error;
pub mod finding;
pub mod hashcat;
pub mod html;
pub mod json;
pub mod text;

pub use collector::Collector;
pub use error::OutputError;
pub use finding::Finding;
