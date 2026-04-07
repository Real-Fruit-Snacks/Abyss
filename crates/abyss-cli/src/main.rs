mod banner;
mod commands;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "abyss",
    version = env!("CARGO_PKG_VERSION"),
    about = "Offline offensive analysis of disk images, memory dumps, and AD databases",
    long_about = None,
    after_help = "Use 'abyss <COMMAND> --help' for more information on a specific command.",
)]
struct Cli {
    /// Output findings as JSONL instead of human-readable text
    #[arg(long, global = true)]
    json: bool,

    /// Increase verbosity (can be repeated)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyse a raw disk image or forensic image format
    Image(commands::image::ImageArgs),
    /// Display quick info about a target without full analysis
    Info(commands::info::InfoArgs),
    /// Open an interactive shell for manual exploration
    Shell(commands::shell::ShellArgs),
}

fn main() -> Result<()> {
    banner::print_banner();

    let cli = Cli::parse();

    // Initialise logging based on verbosity
    let log_level = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();

    match cli.command {
        Commands::Image(args) => commands::image::run(args, cli.json),
        Commands::Info(args) => commands::info::run(args, cli.json),
        Commands::Shell(args) => commands::shell::run(args, cli.json),
    }
}
