//! SAM hash extractor.

use abyss_crypto::{derive_syskey, extract_sam_hashes};
use abyss_output::collector::Collector;
use abyss_output::finding::{Finding, SamHashFinding, hex_encode};

use crate::error::TargetError;
use crate::extractor::{ExtractionContext, Extractor};

pub struct SamExtractor;

impl Extractor for SamExtractor {
    fn name(&self) -> &'static str {
        "SAM"
    }

    fn is_compatible(&self, ctx: &ExtractionContext) -> bool {
        ctx.system_hive.is_some() && ctx.sam_hive.is_some()
    }

    fn extract(
        &self,
        ctx: &mut ExtractionContext,
        collector: &mut Collector,
    ) -> Result<(), TargetError> {
        // Derive SYSKEY if not already cached.
        if ctx.syskey.is_none() {
            let system = ctx.system_hive.as_mut().ok_or_else(|| TargetError::OpenFailed {
                detail: "SYSTEM hive not available".to_string(),
            })?;
            let syskey = derive_syskey(system).map_err(|e| TargetError::OpenFailed {
                detail: format!("SYSKEY derivation: {e}"),
            })?;
            ctx.syskey = Some(syskey);
        }

        let syskey = ctx.syskey.as_ref().unwrap();

        // Take the SAM hive out to avoid simultaneous borrows.
        let mut sam = ctx.sam_hive.take().ok_or_else(|| TargetError::OpenFailed {
            detail: "SAM hive not available".to_string(),
        })?;

        let entries = extract_sam_hashes(&mut sam, syskey).map_err(|e| TargetError::OpenFailed {
            detail: format!("SAM extraction: {e}"),
        })?;

        ctx.sam_hive = Some(sam);

        for entry in entries {
            collector.add(Finding::SamHash(SamHashFinding {
                username: entry.username,
                rid: entry.rid,
                nt_hash: if entry.ntlm.is_empty() {
                    "aad3b435b51404eeaad3b435b51404ee".to_string()
                } else {
                    hex_encode(&entry.ntlm)
                },
                lm_hash: if entry.lm.is_empty() {
                    "aad3b435b51404eeaad3b435b51404ee".to_string()
                } else {
                    hex_encode(&entry.lm)
                },
                account_flags: 0,
            }));
        }

        Ok(())
    }
}
