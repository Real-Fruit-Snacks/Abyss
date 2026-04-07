use crate::finding::Finding;
use crate::OutputError;
use colored::Colorize;
use std::io::Write;

pub fn emit_text(findings: &[Finding], writer: &mut dyn Write) -> Result<(), OutputError> {
    for finding in findings {
        match finding {
            Finding::TargetInfo(info) => {
                writeln!(writer, "{}", "=== Target Info ===".bold().cyan())?;
                writeln!(writer, "  {} {}", "OS:".bold(), info.os)?;
                if let Some(ref hostname) = info.hostname {
                    writeln!(writer, "  {} {}", "Hostname:".bold(), hostname)?;
                }
                if let Some(ref version) = info.version {
                    writeln!(writer, "  {} {}", "Version:".bold(), version)?;
                }
                if let Some(ref arch) = info.architecture {
                    writeln!(writer, "  {} {}", "Architecture:".bold(), arch)?;
                }
                if let Some(ref domain) = info.domain {
                    writeln!(writer, "  {} {}", "Domain:".bold(), domain)?;
                }
                if !info.volumes.is_empty() {
                    writeln!(writer, "\n  {}", "Volumes:".bold())?;
                    for vol in &info.volumes {
                        writeln!(
                            writer,
                            "    [{}] {} offset={:#x} size={} {}",
                            vol.index,
                            vol.partition_type,
                            vol.offset,
                            format_size(vol.size),
                            vol.label.as_deref().unwrap_or("")
                        )?;
                    }
                }
                if !info.filesystems.is_empty() {
                    writeln!(writer, "\n  {}", "Filesystems:".bold())?;
                    for fs in &info.filesystems {
                        writeln!(
                            writer,
                            "    {} size={} {}",
                            fs.fs_type,
                            format_size(fs.total_size),
                            fs.label.as_deref().unwrap_or("")
                        )?;
                    }
                }
                writeln!(writer)?;
            }
            Finding::SamHash(h) => {
                writeln!(
                    writer,
                    "{} {}:{} nt={} lm={}",
                    "[SAM]".bold().yellow(),
                    h.username,
                    h.rid,
                    h.nt_hash,
                    h.lm_hash
                )?;
            }
            Finding::LsaSecret(s) => {
                writeln!(
                    writer,
                    "{} [{}] {}: {}",
                    "[LSA]".bold().red(),
                    s.secret_type,
                    s.name,
                    s.value
                )?;
            }
            Finding::CachedCredential(c) => {
                writeln!(
                    writer,
                    "{} {}\\{} iter={} hash={}",
                    "[DCC2]".bold().magenta(),
                    c.domain,
                    c.username,
                    c.iteration_count,
                    c.hash
                )?;
            }
            Finding::DpapiMasterKey(d) => {
                let decrypted_label = if d.decrypted {
                    "decrypted".green().to_string()
                } else {
                    "not decrypted".red().to_string()
                };
                writeln!(
                    writer,
                    "{} sid={} guid={} status={} source={}",
                    "[DPAPI]".bold().blue(),
                    d.user_sid,
                    d.guid,
                    decrypted_label,
                    d.key_source
                )?;
            }
            Finding::BrowserCredential(b) => {
                writeln!(
                    writer,
                    "{} [{}] {} {} {}",
                    "[BROWSER]".bold().green(),
                    b.browser,
                    b.url,
                    b.username,
                    b.password
                )?;
            }
            Finding::SshPrivateKey(k) => {
                let enc = if k.encrypted { "encrypted" } else { "plaintext" };
                writeln!(
                    writer,
                    "{} {} type={} {} {}",
                    "[SSH-KEY]".bold().cyan(),
                    k.path,
                    k.key_type,
                    enc,
                    k.fingerprint
                )?;
            }
            Finding::SshAuthorizedKey(k) => {
                writeln!(
                    writer,
                    "{} user={} type={} comment={}",
                    "[SSH-AUTH]".bold().cyan(),
                    k.user,
                    k.key_type,
                    k.comment
                )?;
            }
            Finding::ShadowEntry(s) => {
                writeln!(
                    writer,
                    "{} {}:{} algo={}",
                    "[SHADOW]".bold().yellow(),
                    s.username,
                    s.hash,
                    s.hash_algorithm
                )?;
            }
            Finding::ServiceCredential(c) => {
                writeln!(
                    writer,
                    "{} [{}] {} path={} {}",
                    "[SERVICE]".bold().red(),
                    c.service,
                    c.credential,
                    c.path,
                    c.credential_type
                )?;
            }
            Finding::PersistenceEntry(p) => {
                writeln!(writer, "  {} [{}] {}: {} (trigger={}, user={})",
                    "[PERSIST]".bold().yellow(),
                    p.mechanism, p.name, p.path, p.trigger, p.user_context)?;
            }
        }
    }
    Ok(())
}

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    const TB: u64 = 1024 * GB;

    if bytes >= TB {
        format!("{:.1} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
