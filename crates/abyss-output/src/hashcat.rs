use crate::finding::Finding;
use crate::OutputError;
use std::io::Write;

/// Emit hashcat-compatible lines for credential findings.
///
/// SamHash      -> mode 1000: `username:rid:lm_hash:nt_hash:::`
/// CachedCredential -> mode 2100: `$DCC2$iterations#username#hash`
/// Other finding types are silently skipped.
pub fn emit_hashcat(findings: &[Finding], writer: &mut dyn Write) -> Result<(), OutputError> {
    for finding in findings {
        match finding {
            Finding::SamHash(h) => {
                writeln!(
                    writer,
                    "{}:{}:{}:{}:::",
                    h.username, h.rid, h.lm_hash, h.nt_hash
                )?;
            }
            Finding::CachedCredential(c) => {
                writeln!(
                    writer,
                    "$DCC2${}#{}#{}",
                    c.iteration_count, c.username, c.hash
                )?;
            }
            Finding::ShadowEntry(s) => {
                // hashcat auto-detects mode from the hash prefix ($6$, $5$, $1$, etc.)
                writeln!(writer, "{}", s.hash)?;
            }
            Finding::NtdsHash(h) => {
                // Mode 1000: domain\username:rid:lm_hash:nt_hash:::
                writeln!(
                    writer,
                    "{}\\{}:{}:{}:{}:::",
                    h.domain, h.username, h.rid, h.lm_hash, h.nt_hash
                )?;
                // History entries: one line per hash, mode 1000
                for (i, hist_hash) in h.history.iter().enumerate() {
                    writeln!(
                        writer,
                        "{}\\{}_history_{}:{}:{}:{}:::",
                        h.domain, h.username, i + 1, h.rid, h.lm_hash, hist_hash
                    )?;
                }
            }
            Finding::MemoryCredential(m) => {
                // Mode 1000: NT hash
                if let Some(ref nt_hash) = m.nt_hash {
                    writeln!(
                        writer,
                        "{}\\{}:::{}:::",
                        m.domain, m.username, nt_hash
                    )?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}
