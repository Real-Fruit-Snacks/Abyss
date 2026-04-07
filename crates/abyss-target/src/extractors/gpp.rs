//! GPP (Group Policy Preferences) cpassword extractor.
//!
//! Scans filesystem_files for XML files containing "cpassword" attributes,
//! decrypts them using the well-known MS14-025 AES key, and emits findings.

use abyss_output::collector::Collector;
use abyss_output::finding::{Finding, GppPasswordFinding};

use crate::error::TargetError;
use crate::extractor::{ExtractionContext, Extractor};

pub struct GppExtractor;

impl Extractor for GppExtractor {
    fn name(&self) -> &'static str {
        "GPP"
    }

    fn is_compatible(&self, _ctx: &ExtractionContext) -> bool {
        true // Always try — will scan filesystem_files for XML
    }

    fn extract(
        &self,
        ctx: &mut ExtractionContext,
        collector: &mut Collector,
    ) -> Result<(), TargetError> {
        // Collect paths first to avoid borrow conflict
        let paths: Vec<String> = ctx
            .filesystem_files
            .keys()
            .filter(|p| {
                let lower = p.to_lowercase();
                lower.ends_with(".xml")
            })
            .cloned()
            .collect();

        for path in paths {
            if let Some(data) = ctx.filesystem_files.get(&path) {
                if let Ok(text) = std::str::from_utf8(data) {
                    if text.contains("cpassword") {
                        parse_gpp_xml(text, &path, collector);
                    }
                }
            }
        }

        Ok(())
    }
}

fn parse_gpp_xml(xml: &str, path: &str, collector: &mut Collector) {
    let mut pos = 0;
    while let Some(idx) = xml[pos..].find("cpassword=\"") {
        let start = pos + idx + 11; // skip past cpassword="
        if let Some(end_idx) = xml[start..].find('"') {
            let cpassword = &xml[start..start + end_idx];
            if cpassword.is_empty() {
                pos = start + end_idx + 1;
                continue;
            }

            // Look for userName/name/runAs attributes in the same XML element
            let element_start = xml[..start].rfind('<').unwrap_or(0);
            let element_end = xml[start..]
                .find('>')
                .map(|i| start + i)
                .unwrap_or(xml.len());
            let element = &xml[element_start..element_end];

            let username = extract_xml_attr(element, "userName")
                .or_else(|| extract_xml_attr(element, "name"))
                .or_else(|| extract_xml_attr(element, "runAs"))
                .unwrap_or("")
                .to_string();

            let changed = extract_xml_attr(element, "changed").map(|s| s.to_string());

            let policy_type = if path.contains("Groups") {
                "Groups"
            } else if path.contains("Services") {
                "Services"
            } else if path.contains("Drives") {
                "Drives"
            } else if path.contains("DataSources") {
                "DataSources"
            } else if path.contains("ScheduledTasks") {
                "ScheduledTasks"
            } else {
                "Unknown"
            };

            match abyss_crypto::gpp::decrypt_gpp_password(cpassword) {
                Ok(password) => {
                    collector.add(Finding::GppPassword(GppPasswordFinding {
                        username,
                        password,
                        changed,
                        source_path: path.to_string(),
                        policy_type: policy_type.to_string(),
                    }));
                }
                Err(e) => {
                    log::warn!("Failed to decrypt GPP cpassword in {}: {}", path, e);
                }
            }

            pos = start + end_idx + 1;
        } else {
            break;
        }
    }
}

fn extract_xml_attr<'a>(element: &'a str, attr_name: &str) -> Option<&'a str> {
    let pattern = format!("{}=\"", attr_name);
    if let Some(idx) = element.find(&pattern) {
        let start = idx + pattern.len();
        if let Some(end) = element[start..].find('"') {
            return Some(&element[start..start + end]);
        }
    }
    None
}
