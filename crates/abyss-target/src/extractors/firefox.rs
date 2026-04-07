//! Firefox credential extractor.
//!
//! For each Firefox profile stored in `ctx.firefox_profiles` it calls
//! [`abyss_browser::firefox::extract_firefox_credentials`] and emits a
//! [`BrowserCredentialFinding`] for every decrypted credential.

use abyss_browser::firefox::{FirefoxProfile, extract_firefox_credentials};
use abyss_output::collector::Collector;
use abyss_output::finding::{BrowserCredentialFinding, Finding};

use crate::error::TargetError;
use crate::extractor::{ExtractionContext, Extractor};

pub struct FirefoxExtractor;

impl Extractor for FirefoxExtractor {
    fn name(&self) -> &'static str {
        "Firefox"
    }

    fn is_compatible(&self, ctx: &ExtractionContext) -> bool {
        !ctx.firefox_profiles.is_empty()
    }

    fn extract(
        &self,
        ctx: &mut ExtractionContext,
        collector: &mut Collector,
    ) -> Result<(), TargetError> {
        for (user, key4_db, logins_json) in &ctx.firefox_profiles {
            let profile = FirefoxProfile {
                user: user.clone(),
                profile_path: format!("<{}>", user),
                key4_db: key4_db.clone(),
                logins_json: logins_json.clone(),
            };

            let credentials = extract_firefox_credentials(&profile);

            for cred in credentials {
                collector.add(Finding::BrowserCredential(BrowserCredentialFinding {
                    browser: "Firefox".to_string(),
                    url: cred.url,
                    username: cred.username,
                    password: cred.password,
                }));
            }
        }

        Ok(())
    }
}
