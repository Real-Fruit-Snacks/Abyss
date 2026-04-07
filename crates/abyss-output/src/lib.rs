pub mod finding;
pub mod collector;
pub mod text;
pub mod json;

pub use finding::Finding;
pub use collector::Collector;
pub use text::TextFormatter;
pub use json::JsonFormatter;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum OutputError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialize(#[from] serde_json::Error),
}
