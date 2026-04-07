use crate::finding::Finding;
use crate::OutputError;
use std::io::Write;

pub fn emit_json(findings: &[Finding], writer: &mut dyn Write) -> Result<(), OutputError> {
    for finding in findings {
        let json = serde_json::to_string(finding)?;
        writeln!(writer, "{}", json)?;
    }
    Ok(())
}
