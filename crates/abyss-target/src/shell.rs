//! Interactive shell command execution for Abyss targets.
//!
//! Provides `execute_command` which dispatches shell input to filesystem
//! operations on a `Target`.

use std::fs;
use std::io::Write;

use sha2::Digest as Sha2Digest;

use crate::target::Target;

/// Result of executing a shell command.
pub enum ShellResult {
    /// Textual output to display to the user.
    Output(String),
    /// Signal to exit the shell.
    Exit,
    /// An error message.
    Error(String),
}

/// Execute a single shell command against `target`.
///
/// Parses `input`, dispatches to the appropriate handler, and returns a
/// `ShellResult`.
pub fn execute_command(target: &mut Target, input: &str) -> ShellResult {
    let input = input.trim();
    if input.is_empty() {
        return ShellResult::Output(String::new());
    }

    let parts: Vec<&str> = input.splitn(3, ' ').collect();
    let cmd = parts[0];

    match cmd {
        "help" => cmd_help(),
        "exit" | "quit" => ShellResult::Exit,
        "info" => cmd_info(target),
        "volumes" => cmd_volumes(target),
        "ls" => {
            let path = parts.get(1).copied().unwrap_or("/");
            cmd_ls(target, path)
        }
        "cat" => match parts.get(1) {
            Some(path) => cmd_cat(target, path),
            None => ShellResult::Error("usage: cat <path>".to_string()),
        },
        "hexdump" => match parts.get(1) {
            Some(path) => cmd_hexdump(target, path),
            None => ShellResult::Error("usage: hexdump <path>".to_string()),
        },
        "hash" => match parts.get(1) {
            Some(path) => cmd_hash(target, path),
            None => ShellResult::Error("usage: hash <path>".to_string()),
        },
        "save" => {
            let src = parts.get(1);
            let dst = parts.get(2);
            match (src, dst) {
                (Some(src), Some(dst)) => cmd_save(target, src, dst),
                _ => ShellResult::Error("usage: save <src> <dst>".to_string()),
            }
        }
        _ => ShellResult::Error(format!("unknown command: '{}'. Type 'help' for help.", cmd)),
    }
}

fn cmd_help() -> ShellResult {
    ShellResult::Output(
        r#"Available commands:
  help              Show this help message
  info              Display target information (OS, hostname, domain)
  volumes           List partitions/volumes
  ls [path]         List directory contents (default: /)
  cat <path>        Print file contents as text
  hexdump <path>    Hex dump first 512 bytes of file
  hash <path>       Compute MD5 and SHA-256 of file
  save <src> <dst>  Extract file from image to local filesystem
  exit / quit       Exit the shell"#
            .to_string(),
    )
}

fn cmd_info(target: &Target) -> ShellResult {
    let mut out = String::new();
    out.push_str(&format!("OS:       {}\n", target.os));
    out.push_str(&format!(
        "Hostname: {}\n",
        target.hostname.as_deref().unwrap_or("(unknown)")
    ));
    out.push_str(&format!(
        "Domain:   {}\n",
        target.domain.as_deref().unwrap_or("(unknown)")
    ));
    out.push_str(&format!(
        "Version:  {}\n",
        target.version.as_deref().unwrap_or("(unknown)")
    ));
    out.push_str(&format!(
        "Filesystem: {}\n",
        target.filesystem_type().unwrap_or("none")
    ));
    ShellResult::Output(out)
}

fn cmd_volumes(target: &Target) -> ShellResult {
    if target.partitions.is_empty() {
        return ShellResult::Output("No partitions found.".to_string());
    }
    let mut out = String::new();
    out.push_str(&format!(
        "{:<6} {:<20} {:<16} {:<16} {}\n",
        "Index", "Type", "Offset", "Size", "Label"
    ));
    out.push_str(&"-".repeat(72));
    out.push('\n');
    for p in &target.partitions {
        out.push_str(&format!(
            "{:<6} {:<20} {:<16} {:<16} {}\n",
            p.index,
            p.partition_type,
            p.offset,
            p.size,
            p.label.as_deref().unwrap_or("")
        ));
    }
    ShellResult::Output(out)
}

fn cmd_ls(target: &mut Target, path: &str) -> ShellResult {
    if !target.has_filesystem() {
        return ShellResult::Error("No filesystem available.".to_string());
    }

    match target.list_directory_by_path(path) {
        Ok(entries) => {
            if entries.is_empty() {
                return ShellResult::Output("(empty directory)".to_string());
            }
            let mut out = String::new();
            for (name, is_dir, _idx) in &entries {
                if *is_dir {
                    out.push_str(&format!("{}/\n", name));
                } else {
                    out.push_str(&format!("{}\n", name));
                }
            }
            ShellResult::Output(out)
        }
        Err(e) => ShellResult::Error(format!("ls: {}", e)),
    }
}

fn cmd_cat(target: &mut Target, path: &str) -> ShellResult {
    if !target.has_filesystem() {
        return ShellResult::Error("No filesystem available.".to_string());
    }

    match target.read_file(path) {
        Ok(data) => match std::str::from_utf8(&data) {
            Ok(text) => ShellResult::Output(text.to_string()),
            Err(_) => ShellResult::Error(format!(
                "cat: '{}' appears to be binary. Use 'hexdump {}' instead.",
                path, path
            )),
        },
        Err(e) => ShellResult::Error(format!("cat: {}: {}", path, e)),
    }
}

fn cmd_hexdump(target: &mut Target, path: &str) -> ShellResult {
    if !target.has_filesystem() {
        return ShellResult::Error("No filesystem available.".to_string());
    }

    let data = match target.read_file(path) {
        Ok(d) => d,
        Err(e) => return ShellResult::Error(format!("hexdump: {}: {}", path, e)),
    };

    let limit = data.len().min(512);
    let slice = &data[..limit];
    let mut out = String::new();

    for (i, chunk) in slice.chunks(16).enumerate() {
        let offset = i * 16;
        // Hex bytes
        let hex_part: String = chunk
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        // ASCII part
        let ascii_part: String = chunk
            .iter()
            .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
            .collect();
        out.push_str(&format!(
            "{:08x}  {:<48}  |{}|\n",
            offset, hex_part, ascii_part
        ));
    }

    if data.len() > 512 {
        out.push_str(&format!(
            "... ({} bytes total, showing first 512)\n",
            data.len()
        ));
    }

    ShellResult::Output(out)
}

fn cmd_hash(target: &mut Target, path: &str) -> ShellResult {
    if !target.has_filesystem() {
        return ShellResult::Error("No filesystem available.".to_string());
    }

    let data = match target.read_file(path) {
        Ok(d) => d,
        Err(e) => return ShellResult::Error(format!("hash: {}: {}", path, e)),
    };

    let md5_result = format!("{:x}", md5::compute(&data));

    let sha256_result = {
        let mut h = sha2::Sha256::new();
        Sha2Digest::update(&mut h, &data);
        let bytes = Sha2Digest::finalize(h);
        bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>()
    };

    ShellResult::Output(format!(
        "MD5:    {}\nSHA256: {}\n",
        md5_result, sha256_result
    ))
}

fn cmd_save(target: &mut Target, src: &str, dst: &str) -> ShellResult {
    if !target.has_filesystem() {
        return ShellResult::Error("No filesystem available.".to_string());
    }

    let data = match target.read_file(src) {
        Ok(d) => d,
        Err(e) => return ShellResult::Error(format!("save: {}: {}", src, e)),
    };

    match fs::File::create(dst) {
        Ok(mut f) => match f.write_all(&data) {
            Ok(_) => ShellResult::Output(format!(
                "Saved {} bytes to '{}'.\n",
                data.len(),
                dst
            )),
            Err(e) => ShellResult::Error(format!("save: write failed: {}", e)),
        },
        Err(e) => ShellResult::Error(format!("save: cannot create '{}': {}", dst, e)),
    }
}
