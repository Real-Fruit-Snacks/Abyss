//! Concrete credential extractor implementations.

pub mod browser;
pub mod cached_creds;
pub mod dpapi;
pub mod lsa;
pub mod sam;

pub use browser::BrowserExtractor;
pub use cached_creds::CachedCredsExtractor;
pub use dpapi::DpapiExtractor;
pub use lsa::LsaExtractor;
pub use sam::SamExtractor;
