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
        }
    }
}
