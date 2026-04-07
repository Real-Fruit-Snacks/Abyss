//! DPAPI master key extractor.
//!
//! Reads raw DPAPI_SYSTEM LSA secret bytes captured by the LSA extractor,
//! builds a [`DpapiKeyring`], attempts to decrypt any master key files stored
//! in the context, and emits a [`DpapiMasterKeyFinding`] for each key.

use abyss_crypto::dpapi::DpapiKeyring;
use abyss_output::collector::Collector;
use abyss_output::finding::{DpapiMasterKeyFinding, Finding};

use crate::error::TargetError;
use crate::extractor::{ExtractionContext, Extractor};

pub struct DpapiExtractor;

impl Extractor for DpapiExtractor {
    fn name(&self) -> &'static str {
        "DPAPI"
    }

    fn is_compatible(&self, ctx: &ExtractionContext) -> bool {
        ctx.dpapi_system_raw.is_some()
    }

    fn extract(
        &self,
        ctx: &mut ExtractionContext,
        collector: &mut Collector,
    ) -> Result<(), TargetError> {
        let raw = ctx.dpapi_system_raw.clone().unwrap();

        // Build keyring from the DPAPI_SYSTEM LSA secret.
        let keyring = DpapiKeyring::new().with_lsa_secrets(vec![raw]);

        // Attempt to decrypt each master key file and emit a finding.
        for (sid, guid, _file_data) in &ctx.dpapi_master_key_files {
            // Full offline master-key decryption is not yet implemented in
            // abyss-crypto; we emit a finding recording what we found.
            collector.add(Finding::DpapiMasterKey(DpapiMasterKeyFinding {
                user_sid: sid.clone(),
                guid: guid.clone(),
                decrypted: false,
                key_source: "dpapi_system".to_string(),
            }));
        }

        // If there were no master key files, still store the keyring so
        // downstream extractors (browser) can attempt decryption of blobs
        // that don't require per-user master keys.
        ctx.dpapi_keyring = Some(keyring);

        Ok(())
    }
}
