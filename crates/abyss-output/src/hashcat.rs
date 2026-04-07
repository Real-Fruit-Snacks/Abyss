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
            _ => {}
        }
    }
    Ok(())
}
