use serde::Serialize;

/// All extraction results flow through this enum.
/// Phase 1 starts with TargetInfo only. Other variants added in later phases.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum Finding {
    TargetInfo(TargetInfoFinding),
    SamHash(SamHashFinding),
    LsaSecret(LsaSecretFinding),
    CachedCredential(CachedCredentialFinding),
    DpapiMasterKey(DpapiMasterKeyFinding),
    BrowserCredential(BrowserCredentialFinding),
    SshPrivateKey(SshKeyFinding),
    SshAuthorizedKey(SshAuthKeyFinding),
    ShadowEntry(ShadowEntryFinding),
    ServiceCredential(ServiceCredentialFinding),
    PersistenceEntry(PersistenceEntryFinding),
    NtdsHash(NtdsHashFinding),
    CloudCredential(CloudCredentialFinding),
    MemoryCredential(MemoryCredentialFinding),
    GppPassword(GppPasswordFinding),
    CredentialManager(CredentialManagerFinding),
    Certificate(CertificateFinding),
}

#[derive(Debug, Clone, Serialize)]
pub struct SamHashFinding {
    pub username: String,
    pub rid: u32,
    pub nt_hash: String,
    pub lm_hash: String,
    pub account_flags: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct LsaSecretFinding {
    pub name: String,
    pub secret_type: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CachedCredentialFinding {
    pub username: String,
    pub domain: String,
    pub hash: String,
    pub iteration_count: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct DpapiMasterKeyFinding {
    pub user_sid: String,
    pub guid: String,
    pub decrypted: bool,
    pub key_source: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BrowserCredentialFinding {
    pub browser: String,
    pub url: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SshKeyFinding {
    pub user: String,
    pub path: String,
    pub key_type: String,
    pub fingerprint: String,
    pub encrypted: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SshAuthKeyFinding {
    pub user: String,
    pub key_type: String,
    pub fingerprint: String,
    pub comment: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ShadowEntryFinding {
    pub username: String,
    pub hash: String,
    pub hash_algorithm: String,
    pub uid: u32,
    pub shell: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServiceCredentialFinding {
    pub service: String,
    pub path: String,
    pub username: String,
    pub credential: String,
    pub credential_type: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PersistenceEntryFinding {
    pub mechanism: String,
    pub name: String,
    pub path: String,
    pub trigger: String,
    pub user_context: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct NtdsHashFinding {
    pub domain: String,
    pub username: String,
    pub rid: u32,
    pub nt_hash: String,
    pub lm_hash: String,
    pub enabled: bool,
    pub history: Vec<String>,  // NT hash history entries (hex-encoded)
}

#[derive(Debug, Clone, Serialize)]
pub struct CloudCredentialFinding {
    pub provider: String,
    pub credential_type: String,
    pub identifier: Option<String>,
    pub secret_preview: String,
    pub source_path: String,
    pub user: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemoryCredentialFinding {
    pub provider: String,
    pub domain: String,
    pub username: String,
    pub password: Option<String>,
    pub nt_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GppPasswordFinding {
    pub username: String,
    pub password: String,
    pub changed: Option<String>,  // timestamp from XML
    pub source_path: String,      // path to the XML file
    pub policy_type: String,      // "Groups", "Services", "Drives", "DataSources", "ScheduledTasks"
}

#[derive(Debug, Clone, Serialize)]
pub struct CredentialManagerFinding {
    pub target: String,
    pub username: String,
    pub password: Option<String>,
    pub credential_type: String,
    pub user: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CertificateFinding {
    pub subject: String,
    pub issuer: String,
    pub thumbprint: String,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub key_usage: Option<String>,
    pub has_private_key: bool,
    pub private_key_exportable: bool,
    pub source_path: String,
    pub user: Option<String>,
}

/// Encode a byte slice as a lowercase hex string.
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetInfoFinding {
    pub os: String,
    pub hostname: Option<String>,
    pub version: Option<String>,
    pub architecture: Option<String>,
    pub domain: Option<String>,
    pub volumes: Vec<VolumeInfo>,
    pub filesystems: Vec<FilesystemInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VolumeInfo {
    pub index: usize,
    pub partition_type: String,
    pub offset: u64,
    pub size: u64,
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FilesystemInfo {
    pub fs_type: String,
    pub label: Option<String>,
    pub total_size: u64,
    pub mount_point: Option<String>,
}

impl Finding {
    pub fn type_name(&self) -> &'static str {
        match self {
            Finding::TargetInfo(_) => "target_info",
            Finding::SamHash(_) => "sam_hash",
            Finding::LsaSecret(_) => "lsa_secret",
            Finding::CachedCredential(_) => "cached_credential",
            Finding::DpapiMasterKey(_) => "dpapi_master_key",
            Finding::BrowserCredential(_) => "browser_credential",
            Finding::SshPrivateKey(_) => "ssh_private_key",
            Finding::SshAuthorizedKey(_) => "ssh_authorized_key",
            Finding::ShadowEntry(_) => "shadow_entry",
            Finding::ServiceCredential(_) => "service_credential",
            Finding::PersistenceEntry(_) => "persistence_entry",
            Finding::NtdsHash(_) => "ntds_hash",
            Finding::CloudCredential(_) => "cloud_credential",
            Finding::MemoryCredential(_) => "memory_credential",
            Finding::GppPassword(_) => "gpp_password",
            Finding::CredentialManager(_) => "credential_manager",
            Finding::Certificate(_) => "certificate",
        }
    }
}
