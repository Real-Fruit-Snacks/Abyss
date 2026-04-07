//! Cached domain credential extractor.

use abyss_crypto::extract_cached_creds;
use abyss_output::collector::Collector;
use abyss_output::finding::{CachedCredentialFinding, Finding, hex_encode};

use crate::error::TargetError;
use crate::extractor::{ExtractionContext, Extractor};

pub struct CachedCredsExtractor;

impl Extractor for CachedCredsExtractor {
    fn name(&self) -> &'static str {
        "CachedCreds"
    }

    fn is_compatible(&self, ctx: &ExtractionContext) -> bool {
        ctx.security_hive.is_some() && ctx.nlkm.is_some()
    }

    fn extract(
        &self,
        ctx: &mut ExtractionContext,
        collector: &mut Collector,
    ) -> Result<(), TargetError> {
        let nlkm = ctx.nlkm.clone().ok_or_else(|| TargetError::OpenFailed {
            detail: "NL$KM not available".to_string(),
        })?;

        // Take the SECURITY hive out to avoid simultaneous borrows.
        let mut security = ctx.security_hive.take().ok_or_else(|| TargetError::OpenFailed {
            detail: "SECURITY hive not available".to_string(),
        })?;

        let creds = extract_cached_creds(&mut security, &nlkm).map_err(|e| TargetError::OpenFailed {
            detail: format!("cached creds extraction: {e}"),
        })?;

        ctx.security_hive = Some(security);

        for cred in creds {
            collector.add(Finding::CachedCredential(CachedCredentialFinding {
                username: cred.username,
                domain: cred.domain,
                hash: hex_encode(&cred.nt_hash),
                iteration_count: cred.iteration_count,
            }));
        }

        Ok(())
    }
}
