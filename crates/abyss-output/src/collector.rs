use crate::finding::Finding;
use crate::OutputError;
use std::io::Write;

/// Output format selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
    Hashcat,
}

/// Collects findings and emits them in the selected format.
pub struct Collector {
    findings: Vec<Finding>,
    format: OutputFormat,
}

impl Collector {
    pub fn new(format: OutputFormat) -> Self {
        Self {
            findings: Vec::new(),
            format,
        }
    }

    pub fn add(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    pub fn count(&self) -> usize {
        self.findings.len()
    }

    pub fn emit(&self, writer: &mut dyn Write) -> Result<(), OutputError> {
        match self.format {
            OutputFormat::Text => crate::text::emit_text(&self.findings, writer),
            OutputFormat::Json => crate::json::emit_json(&self.findings, writer),
            OutputFormat::Hashcat => crate::hashcat::emit_hashcat(&self.findings, writer),
        }
    }
}
