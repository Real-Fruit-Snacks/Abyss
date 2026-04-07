//! abyss-ese: Extensible Storage Engine (ESE/JET) database parser.
//!
//! Parses NTDS.dit and other ESE databases used by Windows.

pub mod database;
pub mod error;
pub mod header;
pub mod page;

pub use database::EseDatabase;
pub use error::EseError;
