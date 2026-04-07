use anyhow::Result;
use clap::Args;
use abyss_output::{Collector, Finding};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Args)]
pub struct ImageArgs {
    /// Path to the disk image file
    #[arg(value_name = "IMAGE")]
    pub path: PathBuf,

    /// Offset into the image where the partition starts (bytes)
    #[arg(long, default_value = "0")]
    pub offset: u64,
}

pub fn run(args: ImageArgs, use_json: bool) -> Result<()> {
    let mut collector = Collector::new();

    // Gather basic target metadata
    let size_bytes = std::fs::metadata(&args.path).ok().map(|m| m.len());
    let mut metadata = HashMap::new();
    if args.offset > 0 {
        metadata.insert("partition_offset".into(), format!("{:#x}", args.offset));
    }

    collector.add(Finding::TargetInfo {
        label: args.path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "unknown".into()),
        target_type: "raw disk image".into(),
        source: args.path.display().to_string(),
        size_bytes,
        metadata,
    });

    collector.emit(use_json)?;
    Ok(())
}
