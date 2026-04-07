use anyhow::Result;
use clap::Args;
use abyss_output::{Collector, Finding};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Args)]
pub struct InfoArgs {
    /// Path to the target file (image, dump, or database)
    #[arg(value_name = "TARGET")]
    pub path: PathBuf,
}

pub fn run(args: InfoArgs, use_json: bool) -> Result<()> {
    let mut collector = Collector::new();

    let size_bytes = std::fs::metadata(&args.path).ok().map(|m| m.len());

    // Detect target type by extension heuristic
    let target_type = detect_type(&args.path);

    collector.add(Finding::TargetInfo {
        label: args.path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into()),
        target_type,
        source: args.path.display().to_string(),
        size_bytes,
        metadata: HashMap::new(),
    });

    collector.emit(use_json)?;
    Ok(())
}

fn detect_type(path: &std::path::Path) -> String {
    match path.extension().and_then(|e| e.to_str()) {
        Some("raw") | Some("img") | Some("dd") => "raw disk image",
        Some("vmdk") => "VMware disk image",
        Some("vhd") | Some("vhdx") => "Hyper-V disk image",
        Some("dmp") | Some("mem") => "memory dump",
        Some("dit") => "NTDS database",
        Some("evtx") => "Windows event log",
        _ => "unknown",
    }
    .into()
}
