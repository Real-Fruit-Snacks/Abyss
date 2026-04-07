use crate::finding::Finding;
use crate::OutputError;
use colored::Colorize;
use std::io::Write;

/// Formats findings as colored, human-readable text.
pub struct TextFormatter;

impl TextFormatter {
    pub fn new() -> Self {
        TextFormatter
    }

    /// Write all findings to the given writer.
    pub fn write_all<W: Write>(&self, writer: &mut W, findings: &[Finding]) -> Result<(), OutputError> {
        for finding in findings {
            self.write_finding(writer, finding)?;
        }
        Ok(())
    }

    fn write_finding<W: Write>(&self, writer: &mut W, finding: &Finding) -> Result<(), OutputError> {
        match finding {
            Finding::TargetInfo {
                label,
                target_type,
                source,
                size_bytes,
                metadata,
            } => {
                writeln!(writer, "{}", finding.title().bold().cyan())?;
                writeln!(writer, "  {}: {}", "Label".bold(), label)?;
                writeln!(writer, "  {}: {}", "Type".bold(), target_type)?;
                writeln!(writer, "  {}: {}", "Source".bold(), source)?;
                if let Some(size) = size_bytes {
                    writeln!(writer, "  {}: {} bytes ({:.2} MB)",
                        "Size".bold(),
                        size,
                        *size as f64 / 1_048_576.0
                    )?;
                }
                for (key, value) in metadata {
                    writeln!(writer, "  {}: {}", key.bold(), value)?;
                }
                writeln!(writer)?;
            }
        }
        Ok(())
    }
}

impl Default for TextFormatter {
    fn default() -> Self {
        TextFormatter::new()
    }
}
