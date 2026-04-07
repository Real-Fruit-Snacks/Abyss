use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
pub struct ShellArgs {
    /// Path to the target to open in the shell
    #[arg(value_name = "TARGET")]
    pub path: Option<PathBuf>,
}

pub fn run(_args: ShellArgs, _use_json: bool) -> Result<()> {
    // Phase 1 stub — interactive shell is a future-phase feature
    eprintln!("Interactive shell is not yet implemented (planned for a future phase).");
    std::process::exit(1);
}
