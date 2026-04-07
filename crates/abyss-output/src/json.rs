use crate::finding::Finding;
use crate::OutputError;
use std::io::Write;

/// Formats findings as JSONL (one JSON object per line).
pub struct JsonFormatter;

impl JsonFormatter {
    pub fn new() -> Self {
        JsonFormatter
    }

    /// Write all findings to the given writer, one JSON object per line.
    pub fn write_all<W: Write>(&self, writer: &mut W, findings: &[Finding]) -> Result<(), OutputError> {
        for finding in findings {
            let line = serde_json::to_string(finding)?;
            writeln!(writer, "{}", line)?;
        }
        Ok(())
    }
}

impl Default for JsonFormatter {
    fn default() -> Self {
        JsonFormatter::new()
    }
}
