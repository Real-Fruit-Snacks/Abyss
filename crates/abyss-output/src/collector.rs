use crate::finding::Finding;
use crate::{JsonFormatter, OutputError, TextFormatter};
use std::io::Write;

/// Accumulates findings during analysis, then emits them via a formatter.
#[derive(Debug, Default)]
pub struct Collector {
    findings: Vec<Finding>,
}

impl Collector {
    /// Create an empty collector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a finding to the collection.
    pub fn add(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    /// Return a slice of all collected findings.
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// True if no findings have been collected.
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    /// Number of findings collected.
    pub fn count(&self) -> usize {
        self.findings.len()
    }

    /// Emit all findings using the text formatter to the given writer.
    pub fn emit_text<W: Write>(&self, writer: &mut W) -> Result<(), OutputError> {
        let fmt = TextFormatter::new();
        fmt.write_all(writer, &self.findings)
    }

    /// Emit all findings using the JSON (JSONL) formatter to the given writer.
    pub fn emit_json<W: Write>(&self, writer: &mut W) -> Result<(), OutputError> {
        let fmt = JsonFormatter::new();
        fmt.write_all(writer, &self.findings)
    }

    /// Emit findings to stdout. Format is determined by `use_json`.
    pub fn emit(&self, use_json: bool) -> Result<(), OutputError> {
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        if use_json {
            self.emit_json(&mut lock)
        } else {
            self.emit_text(&mut lock)
        }
    }
}
