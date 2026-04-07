//! Certificate extractor.
//!
//! Scans filesystem_files for DER-encoded X.509 certificates from the Windows
//! certificate store (`SystemCertificates/My/Certificates/`). Performs minimal
//! DER parsing to extract subject and issuer Common Names. Also notes private
//! key containers found under `Crypto/RSA/`.

use abyss_output::collector::Collector;
use abyss_output::finding::{CertificateFinding, Finding};
use sha2::Digest as Sha2Digest;

use crate::error::TargetError;
use crate::extractor::{ExtractionContext, Extractor};

pub struct CertExtractor;

impl Extractor for CertExtractor {
    fn name(&self) -> &'static str {
        "Certificates"
    }

    fn is_compatible(&self, _ctx: &ExtractionContext) -> bool {
        true
    }

    fn extract(
        &self,
        ctx: &mut ExtractionContext,
        collector: &mut Collector,
    ) -> Result<(), TargetError> {
        // Collect private key container paths for cross-referencing
        let mut private_key_paths: Vec<String> = Vec::new();
        for path in ctx.filesystem_files.keys() {
            if path.contains("Crypto/RSA/") || path.contains("Crypto\\RSA\\") {
                log::info!("Found private key container: {}", path);
                private_key_paths.push(path.clone());
            }
        }

        // Snapshot paths and data for certificates to avoid borrow issues
        let cert_entries: Vec<(String, Vec<u8>)> = ctx
            .filesystem_files
            .iter()
            .filter(|(path, data)| is_certificate_path(path) && is_der_certificate(data))
            .map(|(path, data)| (path.clone(), data.clone()))
            .collect();

        for (path, data) in &cert_entries {
            if let Some(mut cert) = parse_der_certificate_basic(data, path) {
                // Check if a private key exists for this user
                if let Some(ref user) = cert.user {
                    let has_pk = private_key_paths.iter().any(|pk_path| {
                        pk_path.contains(&format!("Users/{}", user))
                            || pk_path.contains(&format!("Users\\{}", user))
                    });
                    cert.has_private_key = has_pk;
                }
                // Machine-level private keys
                if !cert.has_private_key {
                    cert.has_private_key = private_key_paths
                        .iter()
                        .any(|p| p.contains("MachineKeys"));
                }
                collector.add(Finding::Certificate(cert));
            }
        }

        Ok(())
    }
}

/// Check if a path looks like a Windows certificate store path or PFX file.
fn is_certificate_path(path: &str) -> bool {
    path.contains("SystemCertificates/My/Certificates/")
        || path.contains("SystemCertificates\\My\\Certificates\\")
        || path.to_lowercase().ends_with(".pfx")
        || path.to_lowercase().ends_with(".p12")
        || path.to_lowercase().ends_with(".cer")
        || path.to_lowercase().ends_with(".der")
}

/// Check if data starts with ASN.1 SEQUENCE tag (0x30), indicating DER encoding.
fn is_der_certificate(data: &[u8]) -> bool {
    data.len() >= 10 && data[0] == 0x30
}

/// Compute SHA-256 fingerprint of the full certificate DER data.
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    Sha2Digest::update(&mut hasher, data);
    let result = Sha2Digest::finalize(hasher);
    result.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Extract username from a Windows-style path like `Users/<user>/AppData/...`.
fn extract_user_from_path(path: &str) -> Option<String> {
    // Normalise separators
    let normalized = path.replace('\\', "/");
    // Look for Users/<username>/
    if let Some(idx) = normalized.find("Users/") {
        let after = &normalized[idx + 6..];
        if let Some(slash) = after.find('/') {
            let user = &after[..slash];
            if !user.is_empty() {
                return Some(user.to_string());
            }
        }
    }
    None
}

/// Minimal DER parser: extract subject and issuer Common Name from an X.509 certificate.
///
/// X.509 structure: SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
/// tbsCertificate: SEQUENCE { version, serialNumber, signature, issuer, validity, subject, ... }
///
/// Rather than fully parsing ASN.1, we scan for OID 2.5.4.3 (Common Name = 55 04 03)
/// occurrences. In standard X.509 ordering, the first CN belongs to the issuer and
/// the second to the subject.
fn parse_der_certificate_basic(data: &[u8], path: &str) -> Option<CertificateFinding> {
    if data.len() < 10 || data[0] != 0x30 {
        return None;
    }

    let thumbprint = sha256_hex(data);

    let issuer = find_cn_in_der(data, true).unwrap_or_else(|| "Unknown".to_string());
    let subject = find_cn_in_der(data, false).unwrap_or_else(|| "Unknown".to_string());

    let user = extract_user_from_path(path);

    Some(CertificateFinding {
        subject,
        issuer,
        thumbprint,
        not_before: None,
        not_after: None,
        key_usage: None,
        has_private_key: false,
        private_key_exportable: false,
        source_path: path.to_string(),
        user,
    })
}

/// Find Common Name (OID 2.5.4.3 = 55 04 03) in DER data.
///
/// If `first` is true, return the first occurrence (issuer in standard X.509 ordering).
/// If `first` is false, return the second occurrence (subject).
fn find_cn_in_der(data: &[u8], first: bool) -> Option<String> {
    let cn_oid: [u8; 3] = [0x55, 0x04, 0x03];
    let mut count = 0;

    for i in 0..data.len().saturating_sub(5) {
        if data[i..i + 3] == cn_oid {
            // Next should be a string type tag + length + value
            let string_offset = i + 3;
            if string_offset + 2 < data.len() {
                let tag = data[string_offset];
                // UTF8String (0x0C), PrintableString (0x13), IA5String (0x16), T61String (0x14)
                if tag == 0x0C || tag == 0x13 || tag == 0x16 || tag == 0x14 {
                    let len = data[string_offset + 1] as usize;
                    let start = string_offset + 2;
                    if start + len <= data.len() {
                        let cn = String::from_utf8_lossy(&data[start..start + len]).to_string();
                        count += 1;
                        if first && count == 1 {
                            return Some(cn);
                        }
                        if !first && count == 2 {
                            return Some(cn);
                        }
                    }
                }
            }
        }
    }

    // If only one CN found and we wanted the second (subject), return it as a fallback
    // since self-signed certificates have the same issuer and subject CN.
    if !first && count == 1 {
        return find_cn_in_der(data, true);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extractor_name() {
        let ext = CertExtractor;
        assert_eq!(ext.name(), "Certificates");
    }

    #[test]
    fn test_is_certificate_path() {
        assert!(is_certificate_path(
            "Users/admin/AppData/Roaming/Microsoft/SystemCertificates/My/Certificates/AABBCCDD"
        ));
        assert!(is_certificate_path("some/path/cert.pfx"));
        assert!(is_certificate_path("some/path/cert.p12"));
        assert!(is_certificate_path("some/path/cert.cer"));
        assert!(is_certificate_path("some/path/cert.der"));
        assert!(!is_certificate_path("some/random/file.txt"));
    }

    #[test]
    fn test_is_der_certificate() {
        // Valid: starts with 0x30 and is long enough
        let valid = [0x30, 0x82, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(is_der_certificate(&valid));

        // Invalid: too short
        let short = [0x30, 0x01];
        assert!(!is_der_certificate(&short));

        // Invalid: wrong tag
        let wrong_tag = [0x31, 0x82, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(!is_der_certificate(&wrong_tag));
    }

    #[test]
    fn test_extract_user_from_path() {
        assert_eq!(
            extract_user_from_path(
                "Users/admin/AppData/Roaming/Microsoft/SystemCertificates/My/Certificates/AABB"
            ),
            Some("admin".to_string())
        );
        assert_eq!(
            extract_user_from_path("Users\\john\\AppData\\Roaming\\file"),
            Some("john".to_string())
        );
        assert_eq!(extract_user_from_path("etc/shadow"), None);
    }

    #[test]
    fn test_find_cn_in_der() {
        // Build a minimal DER snippet with two CN entries:
        // OID 2.5.4.3 followed by UTF8String "Issuer" then OID 2.5.4.3 followed by UTF8String "Subject"
        let mut data: Vec<u8> = vec![0x30, 0x82, 0x00, 0x40]; // SEQUENCE header (fake)

        // First CN (issuer): OID 55 04 03, then UTF8String tag 0x0C, len 6, "Issuer"
        data.extend_from_slice(&[0x55, 0x04, 0x03, 0x0C, 0x06]);
        data.extend_from_slice(b"Issuer");

        // Some padding
        data.extend_from_slice(&[0x00; 10]);

        // Second CN (subject): OID 55 04 03, then PrintableString tag 0x13, len 7, "Subject"
        data.extend_from_slice(&[0x55, 0x04, 0x03, 0x13, 0x07]);
        data.extend_from_slice(b"Subject");

        // Pad to minimum length
        data.extend_from_slice(&[0x00; 20]);

        assert_eq!(find_cn_in_der(&data, true), Some("Issuer".to_string()));
        assert_eq!(find_cn_in_der(&data, false), Some("Subject".to_string()));
    }

    #[test]
    fn test_find_cn_single_self_signed() {
        // Self-signed: only one CN occurrence. Both issuer and subject should return it.
        let mut data: Vec<u8> = vec![0x30, 0x82, 0x00, 0x20];
        data.extend_from_slice(&[0x55, 0x04, 0x03, 0x0C, 0x04]);
        data.extend_from_slice(b"Self");
        data.extend_from_slice(&[0x00; 20]);

        assert_eq!(find_cn_in_der(&data, true), Some("Self".to_string()));
        // For subject (second), falls back to first CN for self-signed certs
        assert_eq!(find_cn_in_der(&data, false), Some("Self".to_string()));
    }

    #[test]
    fn test_certificate_finding_construction() {
        let finding = CertificateFinding {
            subject: "test.example.com".to_string(),
            issuer: "Example CA".to_string(),
            thumbprint: "abcdef1234567890".to_string(),
            not_before: None,
            not_after: None,
            key_usage: Some("Code Signing".to_string()),
            has_private_key: true,
            private_key_exportable: false,
            source_path: "Users/admin/AppData/cert".to_string(),
            user: Some("admin".to_string()),
        };
        assert_eq!(finding.subject, "test.example.com");
        assert!(finding.has_private_key);
        assert!(!finding.private_key_exportable);
    }
}
