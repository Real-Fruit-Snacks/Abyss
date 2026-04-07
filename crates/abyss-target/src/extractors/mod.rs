//! Concrete credential extractor implementations.

pub mod browser;
pub mod cached_creds;
pub mod cloud;
pub mod dpapi;
pub mod firefox;
pub mod linux;
pub mod lsa;
pub mod ntds;
pub mod persistence;
pub mod sam;
pub mod ssh;

pub use browser::BrowserExtractor;
pub use cached_creds::CachedCredsExtractor;
pub use cloud::CloudExtractor;
pub use dpapi::DpapiExtractor;
pub use firefox::FirefoxExtractor;
pub use linux::LinuxCredsExtractor;
pub use lsa::LsaExtractor;
pub use ntds::NtdsExtractor;
pub use persistence::PersistenceExtractor;
pub use sam::SamExtractor;
pub use ssh::SshExtractor;
