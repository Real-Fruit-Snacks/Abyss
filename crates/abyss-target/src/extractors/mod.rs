//! Concrete credential extractor implementations.

pub mod browser;
pub mod cached_creds;
pub mod certs;
pub mod cloud;
pub mod credmgr;
pub mod dpapi;
pub mod firefox;
pub mod gpp;
pub mod linux;
pub mod lsa;
pub mod ntds;
pub mod persistence;
pub mod sam;
pub mod ssh;

pub use browser::BrowserExtractor;
pub use cached_creds::CachedCredsExtractor;
pub use certs::CertExtractor;
pub use cloud::CloudExtractor;
pub use credmgr::CredMgrExtractor;
pub use dpapi::DpapiExtractor;
pub use firefox::FirefoxExtractor;
pub use gpp::GppExtractor;
pub use linux::LinuxCredsExtractor;
pub use lsa::LsaExtractor;
pub use ntds::NtdsExtractor;
pub use persistence::PersistenceExtractor;
pub use sam::SamExtractor;
pub use ssh::SshExtractor;
