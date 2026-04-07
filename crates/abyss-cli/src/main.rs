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
        "json" => OutputFormat::Json,
        _ => OutputFormat::Text,
    };

    let exit_code = match cli.command {
        Commands::Image { ref path, .. } => {
            eprintln!("abyss image: not yet implemented (target: {})", path);
            let _ = output_format;
            2
        }
        Commands::Info { ref path } => {
            eprintln!("abyss info: not yet implemented (target: {})", path);
            let _ = output_format;
            2
        }
        Commands::Shell { ref path } => {
            eprintln!("abyss shell: not yet implemented (target: {})", path);
            2
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
