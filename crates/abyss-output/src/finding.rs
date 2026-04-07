use serde::Serialize;

/// All extraction results flow through this enum.
/// Phase 1 starts with TargetInfo only. Other variants added in later phases.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum Finding {
    TargetInfo(TargetInfoFinding),
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
        }
    }
}
