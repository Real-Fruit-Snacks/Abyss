use serde::{Deserialize, Serialize};

/// A single forensic finding produced by any analysis module.
/// Phase 1 only has TargetInfo; more variants are added in later phases.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Finding {
    /// Basic information about the analysis target (image, dump, database).
    TargetInfo {
        /// Human-readable label for this target
        label: String,
        /// Type of target (e.g. "raw disk image", "memory dump", "NTDS database")
        target_type: String,
        /// File path or source description
        source: String,
        /// Size in bytes, if known
        size_bytes: Option<u64>,
        /// Additional key-value metadata
        #[serde(default)]
        metadata: std::collections::HashMap<String, String>,
    },
}

impl Finding {
    /// Short human-readable title for this finding.
    pub fn title(&self) -> &str {
        match self {
            Finding::TargetInfo { .. } => "Target Information",
        }
    }

    /// Category tag for grouping findings.
    pub fn category(&self) -> &str {
        match self {
            Finding::TargetInfo { .. } => "info",
        }
    }
}
