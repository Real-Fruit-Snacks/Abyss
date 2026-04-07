use std::io::Write;
use crate::error::OutputError;
use crate::finding::Finding;

pub fn emit_html(writer: &mut dyn Write, findings: &[Finding]) -> Result<(), OutputError> {
    write!(writer, r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Abyss Analysis Report</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace; margin: 0; padding: 20px; background: #0d1117; color: #c9d1d9; }}
h1 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }}
h2 {{ color: #79c0ff; margin-top: 30px; }}
table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
th {{ background: #161b22; color: #58a6ff; text-align: left; padding: 8px 12px; border: 1px solid #30363d; }}
td {{ padding: 8px 12px; border: 1px solid #30363d; word-break: break-all; }}
tr:nth-child(even) {{ background: #161b22; }}
tr:hover {{ background: #1f2937; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; }}
.badge-cred {{ background: #da3633; color: white; }}
.badge-key {{ background: #d29922; color: white; }}
.badge-persist {{ background: #8957e5; color: white; }}
.badge-info {{ background: #388bfd; color: white; }}
.badge-cloud {{ background: #3fb950; color: white; }}
.summary {{ display: flex; gap: 20px; flex-wrap: wrap; margin: 20px 0; }}
.summary-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 15px 20px; min-width: 120px; }}
.summary-card .count {{ font-size: 28px; font-weight: bold; color: #58a6ff; }}
.summary-card .label {{ font-size: 13px; color: #8b949e; }}
.mono {{ font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 13px; }}
.timestamp {{ color: #8b949e; font-size: 12px; }}
</style>
</head>
<body>
<h1>Abyss Analysis Report</h1>
"#)?;

    emit_summary(writer, findings)?;
    emit_target_info(writer, findings)?;

    emit_finding_table(writer, "SAM Hashes", findings, "sam_hash")?;
    emit_finding_table(writer, "NTDS Domain Hashes", findings, "ntds_hash")?;
    emit_finding_table(writer, "LSA Secrets", findings, "lsa_secret")?;
    emit_finding_table(writer, "Cached Domain Credentials", findings, "cached_credential")?;
    emit_finding_table(writer, "Browser Credentials", findings, "browser_credential")?;
    emit_finding_table(writer, "Credential Manager", findings, "credential_manager")?;
    emit_finding_table(writer, "GPP Passwords", findings, "gpp_password")?;
    emit_finding_table(writer, "SSH Keys", findings, "ssh_private_key")?;
    emit_finding_table(writer, "SSH Authorized Keys", findings, "ssh_authorized_key")?;
    emit_finding_table(writer, "Shadow Entries", findings, "shadow_entry")?;
    emit_finding_table(writer, "Cloud Credentials", findings, "cloud_credential")?;
    emit_finding_table(writer, "Certificates", findings, "certificate")?;
    emit_finding_table(writer, "Service Credentials", findings, "service_credential")?;
    emit_finding_table(writer, "Persistence Mechanisms", findings, "persistence_entry")?;
    emit_finding_table(writer, "Memory Credentials", findings, "memory_credential")?;
    emit_finding_table(writer, "DPAPI Master Keys", findings, "dpapi_master_key")?;

    write!(writer, "</body></html>")?;
    Ok(())
}

fn emit_summary(writer: &mut dyn Write, findings: &[Finding]) -> Result<(), OutputError> {
    let creds = findings.iter().filter(|f| matches!(f,
        Finding::SamHash(_) | Finding::NtdsHash(_) | Finding::LsaSecret(_) |
        Finding::CachedCredential(_) | Finding::BrowserCredential(_) |
        Finding::ShadowEntry(_) | Finding::CredentialManager(_) | Finding::GppPassword(_)
    )).count();
    let keys = findings.iter().filter(|f| matches!(f,
        Finding::SshPrivateKey(_) | Finding::SshAuthorizedKey(_) | Finding::Certificate(_) |
        Finding::CloudCredential(_)
    )).count();
    let persist = findings.iter().filter(|f| matches!(f, Finding::PersistenceEntry(_))).count();

    write!(writer, r#"<div class="summary">
<div class="summary-card"><div class="count">{total}</div><div class="label">Total Findings</div></div>
<div class="summary-card"><div class="count">{creds}</div><div class="label">Credentials</div></div>
<div class="summary-card"><div class="count">{keys}</div><div class="label">Keys &amp; Certs</div></div>
<div class="summary-card"><div class="count">{persist}</div><div class="label">Persistence</div></div>
</div>
"#, total = findings.len(), creds = creds, keys = keys, persist = persist)?;
    Ok(())
}

fn emit_target_info(writer: &mut dyn Write, findings: &[Finding]) -> Result<(), OutputError> {
    for finding in findings {
        if let Finding::TargetInfo(info) = finding {
            write!(writer, "<h2>Target Information</h2>\n<table>\n")?;
            write!(writer, "<tr><th>Field</th><th>Value</th></tr>\n")?;
            write!(writer, "<tr><td>OS</td><td class=\"mono\">{}</td></tr>\n", html_escape(&info.os))?;
            if let Some(ref h) = info.hostname {
                write!(writer, "<tr><td>Hostname</td><td class=\"mono\">{}</td></tr>\n", html_escape(h))?;
            }
            if let Some(ref v) = info.version {
                write!(writer, "<tr><td>Version</td><td class=\"mono\">{}</td></tr>\n", html_escape(v))?;
            }
            if let Some(ref a) = info.architecture {
                write!(writer, "<tr><td>Architecture</td><td class=\"mono\">{}</td></tr>\n", html_escape(a))?;
            }
            if let Some(ref d) = info.domain {
                write!(writer, "<tr><td>Domain</td><td class=\"mono\">{}</td></tr>\n", html_escape(d))?;
            }
            write!(writer, "</table>\n")?;

            if !info.volumes.is_empty() {
                write!(writer, "<h2>Volumes</h2>\n<table>\n")?;
                write!(writer, "<tr><th>Index</th><th>Type</th><th>Offset</th><th>Size</th><th>Label</th></tr>\n")?;
                for vol in &info.volumes {
                    write!(writer,
                        "<tr><td class=\"mono\">{}</td><td class=\"mono\">{}</td><td class=\"mono\">{:#x}</td><td class=\"mono\">{}</td><td class=\"mono\">{}</td></tr>\n",
                        vol.index,
                        html_escape(&vol.partition_type),
                        vol.offset,
                        vol.size,
                        html_escape(vol.label.as_deref().unwrap_or(""))
                    )?;
                }
                write!(writer, "</table>\n")?;
            }

            if !info.filesystems.is_empty() {
                write!(writer, "<h2>Filesystems</h2>\n<table>\n")?;
                write!(writer, "<tr><th>Type</th><th>Size</th><th>Label</th><th>Mount Point</th></tr>\n")?;
                for fs in &info.filesystems {
                    write!(writer,
                        "<tr><td class=\"mono\">{}</td><td class=\"mono\">{}</td><td class=\"mono\">{}</td><td class=\"mono\">{}</td></tr>\n",
                        html_escape(&fs.fs_type),
                        fs.total_size,
                        html_escape(fs.label.as_deref().unwrap_or("")),
                        html_escape(fs.mount_point.as_deref().unwrap_or(""))
                    )?;
                }
                write!(writer, "</table>\n")?;
            }
        }
    }
    Ok(())
}

fn emit_finding_table(
    writer: &mut dyn Write,
    title: &str,
    findings: &[Finding],
    type_name: &str,
) -> Result<(), OutputError> {
    let matching: Vec<&Finding> = findings.iter().filter(|f| f.type_name() == type_name).collect();
    if matching.is_empty() {
        return Ok(());
    }

    write!(writer, "<h2>{} ({})</h2>\n<table>\n", html_escape(title), matching.len())?;

    // Derive column headers from first finding's JSON keys
    let first_json = serde_json::to_value(matching[0])?;
    if let serde_json::Value::Object(map) = &first_json {
        write!(writer, "<tr>")?;
        for key in map.keys() {
            if key != "type" {
                write!(writer, "<th>{}</th>", html_escape(key))?;
            }
        }
        write!(writer, "</tr>\n")?;
    }

    // Emit a row per finding
    for finding in &matching {
        let json = serde_json::to_value(finding)?;
        if let serde_json::Value::Object(map) = &json {
            write!(writer, "<tr>")?;
            for (key, value) in map {
                if key != "type" {
                    let cell = match value {
                        serde_json::Value::String(s) => s.clone(),
                        serde_json::Value::Null => String::new(),
                        serde_json::Value::Bool(b) => b.to_string(),
                        serde_json::Value::Number(n) => n.to_string(),
                        other => other.to_string(),
                    };
                    write!(writer, "<td class=\"mono\">{}</td>", html_escape(&cell))?;
                }
            }
            write!(writer, "</tr>\n")?;
        }
    }

    write!(writer, "</table>\n")?;
    Ok(())
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Finding, SamHashFinding, BrowserCredentialFinding, PersistenceEntryFinding};

    #[test]
    fn test_emit_html_empty() {
        let mut buf = Vec::new();
        emit_html(&mut buf, &[]).unwrap();
        let html = String::from_utf8(buf).unwrap();
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("Abyss Analysis Report"));
        assert!(html.contains("</html>"));
    }

    #[test]
    fn test_emit_html_with_findings() {
        let findings = vec![
            Finding::SamHash(SamHashFinding {
                username: "Administrator".to_string(),
                rid: 500,
                nt_hash: "aad3b435b51404eeaad3b435b51404ee".to_string(),
                lm_hash: "aad3b435b51404eeaad3b435b51404ee".to_string(),
                account_flags: 0,
            }),
            Finding::BrowserCredential(BrowserCredentialFinding {
                browser: "Chrome".to_string(),
                url: "https://example.com".to_string(),
                username: "user@example.com".to_string(),
                password: "secret<>&\"".to_string(),
            }),
            Finding::PersistenceEntry(PersistenceEntryFinding {
                mechanism: "registry_run".to_string(),
                name: "Updater".to_string(),
                path: "C:\\malware.exe".to_string(),
                trigger: "logon".to_string(),
                user_context: "SYSTEM".to_string(),
            }),
        ];

        let mut buf = Vec::new();
        emit_html(&mut buf, &findings).unwrap();
        let html = String::from_utf8(buf).unwrap();

        assert!(html.contains("SAM Hashes"));
        assert!(html.contains("Administrator"));
        assert!(html.contains("Browser Credentials"));
        // HTML escaping applied
        assert!(html.contains("secret&lt;&gt;&amp;&quot;"));
        assert!(html.contains("Persistence Mechanisms"));
        // Summary counts
        assert!(html.contains("<div class=\"count\">3</div>"));
    }
}
