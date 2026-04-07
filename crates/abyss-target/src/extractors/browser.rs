//! Browser credential extractor.
//!
//! Requires a populated [`DpapiKeyring`] in the context (set by
//! [`DpapiExtractor`]).  For each browser entry stored in
//! `ctx.browser_data` it calls [`abyss_browser::chromium::extract_chromium_credentials`]
//! and emits a [`BrowserCredentialFinding`] for every decrypted credential.

use abyss_browser::chromium::extract_chromium_credentials;
use abyss_output::collector::Collector;
use abyss_output::finding::{BrowserCredentialFinding, Finding};

use crate::error::TargetError;
use crate::extractor::{ExtractionContext, Extractor};

pub struct BrowserExtractor;

impl Extractor for BrowserExtractor {
    fn name(&self) -> &'static str {
        "Browser"
    }

    fn is_compatible(&self, ctx: &ExtractionContext) -> bool {
        ctx.dpapi_keyring.is_some() && !ctx.browser_data.is_empty()
    }

    fn extract(
        &self,
        ctx: &mut ExtractionContext,
        collector: &mut Collector,
    ) -> Result<(), TargetError> {
        let keyring = ctx.dpapi_keyring.as_ref().unwrap();

        for (browser_name, local_state, login_data) in &ctx.browser_data {
            let credentials =
                extract_chromium_credentials(local_state, login_data, browser_name, keyring);

            for cred in credentials {
                collector.add(Finding::BrowserCredential(BrowserCredentialFinding {
                    browser: cred.browser,
                    url: cred.url,
                    username: cred.username,
                    password: cred.password,
                }));
            }
        }

        Ok(())
    }
}
