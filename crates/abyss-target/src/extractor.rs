//! Extractor trait and ExtractionContext for the credential extraction pipeline.

use abyss_output::collector::Collector;
use abyss_registry::RegistryHive;

use crate::error::TargetError;

/// Context holding opened registry hives and derived cryptographic keys.
///
/// Fields are populated incrementally as the pipeline progresses.
/// Extractors receive a `&mut ExtractionContext` and pull what they need.
pub struct ExtractionContext {
    pub system_hive: Option<RegistryHive>,
    pub sam_hive: Option<RegistryHive>,
    pub security_hive: Option<RegistryHive>,
    pub syskey: Option<[u8; 16]>,
    pub lsa_key: Option<Vec<u8>>,
    pub nlkm: Option<Vec<u8>>,
}

impl ExtractionContext {
    pub fn new() -> Self {
        Self {
            system_hive: None,
            sam_hive: None,
            security_hive: None,
            syskey: None,
            lsa_key: None,
            nlkm: None,
        }
    }
}

impl Default for ExtractionContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait implemented by each credential extractor.
pub trait Extractor {
    /// Human-readable name for logging.
    fn name(&self) -> &'static str;

    /// Returns true if this extractor can run given the current context.
    fn is_compatible(&self, ctx: &ExtractionContext) -> bool;

    /// Run extraction, emitting findings into `collector`.
    fn extract(
        &self,
        ctx: &mut ExtractionContext,
        collector: &mut Collector,
    ) -> Result<(), TargetError>;
}
