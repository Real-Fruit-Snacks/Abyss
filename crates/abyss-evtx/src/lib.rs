use thiserror::Error;

#[derive(Debug, Error)]
pub enum EvtxError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid EVTX signature")]
    InvalidSignature,
    #[error("parse error: {0}")]
    Parse(String),
}
