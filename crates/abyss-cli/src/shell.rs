//! Interactive filesystem shell for Abyss targets.
//!
//! Uses rustyline for readline support with history and Ctrl+C/Ctrl+D handling.

use std::path::Path;

use abyss_target::shell::{execute_command, ShellResult};
use abyss_target::Target;
use colored::Colorize;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;

/// Run the interactive shell against the disk image at `path`.
///
/// Returns an exit code: 0 on clean exit, 1 on error.
pub fn run(path: &str) -> i32 {
    let target = match Target::open(Path::new(path)) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{} {}", "error:".bright_red(), e);
            return 1;
        }
    };

    let mut target = target;

    // Build prompt from hostname or fallback to "abyss"
    let host = target
        .hostname
        .clone()
        .unwrap_or_else(|| "abyss".to_string());

    eprintln!(
        "{} Opened target: {}",
        "[+]".bright_green(),
        path
    );
    eprintln!(
        "{} Type {} for available commands.",
        "[*]".bright_blue(),
        "help".bright_yellow()
    );

    let mut rl = match DefaultEditor::new() {
        Ok(editor) => editor,
        Err(e) => {
            eprintln!("{} Failed to initialize editor: {}", "error:".bright_red(), e);
            return 1;
        }
    };

    loop {
        let prompt = format!("{}{}{}{}",
            host.bright_cyan(),
            ":".white(),
            "/ ".white(),
            "> ".bright_white(),
        );

        match rl.readline(&prompt) {
            Ok(line) => {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    let _ = rl.add_history_entry(trimmed);
                }
                match execute_command(&mut target, trimmed) {
                    ShellResult::Output(out) => {
                        if !out.is_empty() {
                            print!("{}", out);
                        }
                    }
                    ShellResult::Exit => {
                        eprintln!("{}", "Goodbye.".bright_blue());
                        return 0;
                    }
                    ShellResult::Error(msg) => {
                        eprintln!("{} {}", "error:".bright_red(), msg);
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                // Ctrl+C — clear current line, keep going
                eprintln!("(Use 'exit' or Ctrl+D to quit)");
            }
            Err(ReadlineError::Eof) => {
                // Ctrl+D — exit cleanly
                eprintln!("{}", "Goodbye.".bright_blue());
                return 0;
            }
            Err(e) => {
                eprintln!("{} readline error: {}", "error:".bright_red(), e);
                return 1;
            }
        }
    }
}
