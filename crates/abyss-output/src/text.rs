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
            Finding::NtdsHash(h) => {
                let status = if h.enabled { "active" } else { "disabled" };
                writeln!(
                    writer,
                    "{} {}\\{}:{} nt={} lm={} ({})",
                    "[NTDS]".bold().yellow(),
                    h.domain,
                    h.username,
                    h.rid,
                    h.nt_hash,
                    h.lm_hash,
                    status
                )?;
                if !h.history.is_empty() {
                    writeln!(
                        writer,
                        "  {} history ({}):",
                        "[NTDS-HIST]".bold().yellow(),
                        h.history.len()
                    )?;
                    for (i, hist_hash) in h.history.iter().enumerate() {
                        writeln!(writer, "    [{}] {}", i + 1, hist_hash)?;
                    }
                }
            }
            Finding::CloudCredential(c) => {
                let user_str = c.user.as_deref().unwrap_or("");
                let id_str = c.identifier.as_deref().unwrap_or("");
                writeln!(
                    writer,
                    "{} {}/{}: {} ({}) from {}",
                    "[CLOUD]".bold().magenta(),
                    c.provider,
                    c.credential_type,
                    id_str,
                    user_str,
                    c.source_path
                )?;
            }
            Finding::MemoryCredential(m) => {
                let hash_str = m.nt_hash.as_deref().unwrap_or("(none)");
                let pass_str = m.password.as_deref().unwrap_or("");
                writeln!(
                    writer,
                    "{} [{}] {}\\{} nt={} {}",
                    "[MEMORY]".bold().red(),
                    m.provider,
                    m.domain,
                    m.username,
                    hash_str,
                    if pass_str.is_empty() {
                        String::new()
                    } else {
                        format!("pass={}", pass_str)
                    }
                )?;
            }
            Finding::GppPassword(g) => {
                writeln!(
                    writer,
                    "{} [{}] {}:{} (from {})",
                    "[GPP]".bold().yellow(),
                    g.policy_type,
                    g.username,
                    g.password,
                    g.source_path
                )?;
            }
            Finding::CredentialManager(c) => {
                let pass_str = c.password.as_deref().unwrap_or("(encrypted)");
                writeln!(
                    writer,
                    "{} {}: {} / {} ({})",
                    "[CREDMGR]".bold().green(),
                    c.target,
                    c.username,
                    pass_str,
                    c.user
                )?;
            }
            Finding::Certificate(cert) => {
                let pk_label = if cert.has_private_key {
                    "has_private_key".green().to_string()
                } else {
                    "no_private_key".dimmed().to_string()
                };
                let user_str = cert.user.as_deref().unwrap_or("");
                writeln!(
                    writer,
                    "{} {} ({}) thumbprint={} [{}] ({})",
                    "[CERT]".bold().cyan(),
                    cert.subject,
                    cert.issuer,
                    cert.thumbprint,
                    pk_label,
                    user_str
                )?;
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
