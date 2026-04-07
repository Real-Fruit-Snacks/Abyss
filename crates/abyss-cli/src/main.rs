mod image;
mod info;
mod memory;
mod shell;

use abyss_output::collector::OutputFormat;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "abyss",
    about = "Offensive disk/memory/AD analysis framework",
    version,
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output format: text, json
    #[arg(short, long, default_value = "text", global = true)]
    output: String,

    /// Suppress banner and progress output
    #[arg(short, long, global = true)]
    quiet: bool,

    /// Verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze a disk image and extract findings
    Image {
        /// Path to disk image
        path: String,

        /// Extract credentials only
        #[arg(long)]
        creds: bool,

        /// Extract SSH/WireGuard/VPN keys only
        #[arg(long)]
        keys: bool,

        /// Extract persistence mechanisms only
        #[arg(long)]
        persist: bool,

        /// Extract everything (default)
        #[arg(long)]
        all: bool,
    },

    /// Display target metadata
    Info {
        /// Path to disk image
        path: String,
    },

    /// Analyze a memory dump and extract credentials
    Memory {
        /// Path to memory dump
        path: String,
    },

    /// Interactive filesystem shell
    Shell {
        /// Path to disk image
        path: String,
    },
}

fn main() {
    let cli = Cli::parse();

    if !cli.quiet {
        print_banner();
    }

    if cli.verbose {
        env_logger::Builder::from_env(
            env_logger::Env::default().default_filter_or("debug"),
        )
        .init();
    } else {
        env_logger::Builder::from_env(
            env_logger::Env::default().default_filter_or("warn"),
        )
        .init();
    }

    let output_format = match cli.output.as_str() {
        "text" => OutputFormat::Text,
        "json" => OutputFormat::Json,
        "hashcat" => OutputFormat::Hashcat,
        other => {
            eprintln!("Error: unknown output format '{}' (valid: text, json, hashcat)", other);
            std::process::exit(1);
        }
    };

    let exit_code = match cli.command {
        Commands::Image { ref path, creds, keys, persist, all } => {
            image::run(path, creds, keys, persist, all, output_format)
        }
        Commands::Memory { ref path } => {
            memory::run(path, output_format)
        }
        Commands::Info { ref path } => {
            info::run(path, output_format)
        }
        Commands::Shell { ref path } => {
            shell::run(path)
        }
    };

    std::process::exit(exit_code);
}

fn print_banner() {
    use colored::Colorize;
    eprintln!(
        "{}",
        r#"
    ___    __
   /   |  / /_  __  __________
  / /| | / __ \/ / / / ___/ ___/
 / ___ |/ /_/ / /_/ (__  |__  )
/_/  |_/_.___/\__, /____/____/
             /____/
"#
        .bright_blue()
    );
}
