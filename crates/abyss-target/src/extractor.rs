//! Extractor trait and ExtractionContext for the credential extraction pipeline.

use std::collections::HashMap;

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
    /// DPAPI_SYSTEM raw bytes (from LSA secrets).
    pub dpapi_system_raw: Option<Vec<u8>>,
    /// Decrypted DPAPI keyring.
    pub dpapi_keyring: Option<abyss_crypto::dpapi::DpapiKeyring>,
    /// Raw DPAPI master key files: (SID, GUID, file_data).
    pub dpapi_master_key_files: Vec<(String, String, Vec<u8>)>,
    /// Browser data: (browser_name, local_state_bytes, login_data_bytes).
    pub browser_data: Vec<(String, Vec<u8>, Vec<u8>)>,
    /// Firefox profile data: (user, key4_db_bytes, logins_json_bytes).
    pub firefox_profiles: Vec<(String, Vec<u8>, Vec<u8>)>,
    /// Raw NTDS.dit file bytes (ESE database from Domain Controllers).
    pub ntds_dit: Option<Vec<u8>>,
    /// Raw file bytes read from the filesystem, keyed by path.
    /// Populated by Target::build_extraction_context for SSH/Linux extractors.
    pub filesystem_files: HashMap<String, Vec<u8>>,
    /// Usernames discovered from directory listing (e.g. home dirs).
    pub discovered_users: Vec<String>,
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
            dpapi_system_raw: None,
            dpapi_keyring: None,
            dpapi_master_key_files: Vec::new(),
            browser_data: Vec::new(),
            firefox_profiles: Vec::new(),
            ntds_dit: None,
            filesystem_files: HashMap::new(),
            discovered_users: Vec::new(),
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
