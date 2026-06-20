//! Windows Credential Manager extractor.
//!
//! Scans `Users/<user>/AppData/Local/Microsoft/Credentials/` for DPAPI-encrypted
//! credential blobs.  Each file is a raw DPAPI blob; after decryption the plaintext
//! contains a CREDENTIAL structure with target name, username, and credential bytes.

use abyss_output::collector::Collector;
use abyss_output::finding::{CredentialManagerFinding, Finding};

use crate::error::TargetError;
use crate::extractor::{ExtractionContext, Extractor};

pub struct CredMgrExtractor;

impl Extractor for CredMgrExtractor {
    fn name(&self) -> &'static str {
        "Credential Manager"
    }

    fn is_compatible(&self, ctx: &ExtractionContext) -> bool {
        ctx.dpapi_keyring.is_some()
    }

    fn extract(
        &self,
        ctx: &mut ExtractionContext,
        collector: &mut Collector,
    ) -> Result<(), TargetError> {
        let keyring = match &ctx.dpapi_keyring {
            Some(k) => k.clone(),
            None => return Ok(()),
        };

        // Collect matching paths to avoid borrow conflict with ctx
        let cred_files: Vec<(String, Vec<u8>)> = ctx
            .filesystem_files
            .iter()
            .filter(|(path, _)| {
                path.contains("Microsoft/Credentials/") || path.contains("Microsoft\\Credentials\\")
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        for (path, data) in &cred_files {
            let user = extract_user_from_path(path);

            // Try DPAPI decryption
            match keyring.decrypt_blob(data) {
                Ok(plaintext) => {
                    if let Some(cred) = parse_credential(&plaintext, &user) {
                        collector.add(Finding::CredentialManager(cred));
                    }
                }
                Err(e) => {
                    log::debug!("Failed to decrypt credential {}: {}", path, e);
                }
            }
        }

        Ok(())
    }
}

/// Extract the username from a filesystem path like "Users/user/..." or "home/user/...".
fn extract_user_from_path(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').collect();
    for (i, part) in parts.iter().enumerate() {
        if (*part == "Users" || *part == "home") && i + 1 < parts.len() {
            return parts[i + 1].to_string();
        }
    }
    "unknown".to_string()
}

/// Map the credential type integer to a human-readable string.
fn credential_type_name(cred_type: u32) -> &'static str {
    match cred_type {
        1 => "generic",
        2 => "domain_password",
        3 => "domain_certificate",
        4 => "domain_visible_password",
        _ => "unknown",
    }
}

/// Parse the decrypted CREDENTIAL structure from a DPAPI plaintext.
///
/// The decrypted blob contains a CREDENTIAL structure with the following layout
/// (all offsets are from the start of the structure):
///
/// ```text
/// [flags:4][credential_type:4][last_written:8]
/// [credential_blob_size_inner:4][persist:4][attribute_count:4][_reserved:4]
/// [target_name: ptr_size][target_name_size:4]
/// [comment: ptr_size][comment_size:4]
/// [target_alias: ptr_size][target_alias_size:4]
/// [username: ptr_size][username_size:4]
/// [credential_blob: ptr_size][credential_blob_size:4]
/// [attributes: ptr_size][attributes_size:4]
/// ```
///
/// Rather than hard-coding exact pointer-width-dependent offsets, we use a
/// heuristic approach: scan for UTF-16LE strings in the plaintext that look
/// like target names, usernames, and passwords based on the credential type
/// header.
fn parse_credential(plaintext: &[u8], user: &str) -> Option<CredentialManagerFinding> {
    // Need at least the fixed header: flags(4) + cred_type(4) + last_written(8) = 16 bytes
    if plaintext.len() < 16 {
        return None;
    }

    let cred_type = u32::from_le_bytes([
        plaintext[4], plaintext[5], plaintext[6], plaintext[7],
    ]);

    // Validate credential type (1-4 are defined)
    if cred_type == 0 || cred_type > 10 {
        return None;
    }

    // Try structured parsing first with known offsets.
    // The CREDENTIAL structure after DPAPI decryption uses fixed-size fields
    // with inlined data (not pointers).  Typical layout (observed in practice):
    //
    // Offset  0: flags (4)
    // Offset  4: credential_type (4)
    // Offset  8: last_written (8)
    // Offset 16: credential_blob_size (4)
    // Offset 20: persist (4)
    // Offset 24: attribute_count (4)
    // Offset 28: _reserved (4)
    // Offset 32: target_name (UTF-16LE, null-terminated, variable)
    //
    // Since target_name is variable-length and followed by other variable-length
    // fields, we scan for embedded UTF-16LE strings.

    let target = find_utf16le_string(plaintext, 32);
    let target_str = target.unwrap_or_default();

    // If we couldn't find a reasonable target, try a broader scan
    if target_str.is_empty() && plaintext.len() < 48 {
        return None;
    }

    // Search for username and credential blob by scanning for UTF-16LE strings
    // after the target name.  We collect all non-empty UTF-16LE segments.
    let segments = extract_utf16le_segments(plaintext);

    // Heuristic: the first meaningful segment is typically the target,
    // followed by optional comment, optional alias, then username, then password.
    let (found_target, found_username, found_password) = match segments.len() {
        0 => return None,
        1 => (segments[0].clone(), String::new(), None),
        2 => (segments[0].clone(), segments[1].clone(), None),
        3 => (segments[0].clone(), segments[1].clone(), Some(segments[2].clone())),
        _ => {
            // With 4+ segments: target, comment, username, password (or target, alias, username, password)
            // We take the first as target, second-to-last as username, last as password
            let t = segments[0].clone();
            let u = segments[segments.len() - 2].clone();
            let p = Some(segments[segments.len() - 1].clone());
            (t, u, p)
        }
    };

    // Use the structured target if we got one, otherwise use the segment-based one
    let final_target = if !target_str.is_empty() {
        target_str
    } else {
        found_target
    };

    if final_target.is_empty() && found_username.is_empty() {
        return None;
    }

    // Filter out passwords that look like binary garbage
    let clean_password = found_password.and_then(|p| {
        if p.is_empty() {
            None
        } else if p.chars().all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()) {
            Some(p)
        } else if p.chars().filter(|c| c.is_control() && *c != '\t' && *c != '\n').count() * 3
            > p.len()
        {
            // Too many control characters — likely binary data, not a password
            None
        } else {
            Some(p)
        }
    });

    Some(CredentialManagerFinding {
        target: final_target,
        username: found_username,
        password: clean_password,
        credential_type: credential_type_name(cred_type).to_string(),
        user: user.to_string(),
    })
}

/// Try to read a UTF-16LE string starting at `offset` in `data`.
/// Returns None if offset is out of bounds or the string is empty.
fn find_utf16le_string(data: &[u8], offset: usize) -> Option<String> {
    if offset >= data.len() {
        return None;
    }
    let remaining = &data[offset..];
    // Read UTF-16LE chars until we hit a null or run out of data
    let mut chars = Vec::new();
    for chunk in remaining.chunks_exact(2) {
        let ch = u16::from_le_bytes([chunk[0], chunk[1]]);
        if ch == 0 {
            break;
        }
        chars.push(ch);
    }
    if chars.is_empty() {
        return None;
    }
    Some(String::from_utf16_lossy(&chars))
}

/// Extract all non-empty UTF-16LE string segments from a byte buffer.
///
/// Scans through the buffer looking for runs of valid UTF-16LE characters
/// (printable ASCII range plus common extended chars) separated by nulls.
/// Only returns strings of 2+ characters to filter noise.
fn extract_utf16le_segments(data: &[u8]) -> Vec<String> {
    let mut segments = Vec::new();
    let mut i = 0;

    while i + 1 < data.len() {
        let ch = u16::from_le_bytes([data[i], data[i + 1]]);

        // Check if this looks like the start of a UTF-16LE string
        if ch >= 0x20 && ch < 0xFFFE {
            let start = i;
            let mut chars = Vec::new();
            let mut j = i;
            while j + 1 < data.len() {
                let c = u16::from_le_bytes([data[j], data[j + 1]]);
                if c == 0 {
                    break;
                }
                chars.push(c);
                j += 2;
            }
            if chars.len() >= 2 {
                let s = String::from_utf16_lossy(&chars);
                // Only keep strings with mostly printable characters
                let printable = s.chars().filter(|c| !c.is_control()).count();
                if printable * 2 >= s.len() {
                    segments.push(s);
                }
            }
            i = if j + 1 < data.len() { j + 2 } else { j };
            let _ = start; // suppress unused warning
        } else {
            i += 2;
        }
    }

    segments
}

#[cfg(test)]
mod tests {
    use super::*;
    use abyss_output::collector::{Collector, OutputFormat};
    use crate::extractor::ExtractionContext;

    #[test]
    fn test_name() {
        let extractor = CredMgrExtractor;
        assert_eq!(extractor.name(), "Credential Manager");
    }

    #[test]
    fn test_is_compatible_requires_keyring() {
        let extractor = CredMgrExtractor;
        let ctx = ExtractionContext::new();
        assert!(!extractor.is_compatible(&ctx));
    }

    #[test]
    fn test_is_compatible_with_keyring() {
        let extractor = CredMgrExtractor;
        let mut ctx = ExtractionContext::new();
        ctx.dpapi_keyring = Some(abyss_crypto::dpapi::DpapiKeyring::new());
        assert!(extractor.is_compatible(&ctx));
    }

    #[test]
    fn test_extract_user_from_path() {
        assert_eq!(
            extract_user_from_path("Users/Admin/AppData/Local/Microsoft/Credentials/abc123"),
            "Admin"
        );
        assert_eq!(
            extract_user_from_path("some/other/path"),
            "unknown"
        );
    }

    #[test]
    fn test_credential_type_name() {
        assert_eq!(credential_type_name(1), "generic");
        assert_eq!(credential_type_name(2), "domain_password");
        assert_eq!(credential_type_name(3), "domain_certificate");
        assert_eq!(credential_type_name(4), "domain_visible_password");
        assert_eq!(credential_type_name(99), "unknown");
    }

    #[test]
    fn test_parse_credential_from_synthetic() {
        // Build a synthetic decrypted credential structure:
        // flags(4) + cred_type(4) + last_written(8) + blob_size(4) + persist(4)
        // + attr_count(4) + reserved(4) = 32 bytes header
        // Then target name as UTF-16LE, null-terminated
        // Then username as UTF-16LE, null-terminated
        // Then password as UTF-16LE, null-terminated

        let mut buf = Vec::new();

        // flags = 0
        buf.extend_from_slice(&0u32.to_le_bytes());
        // credential_type = 1 (generic)
        buf.extend_from_slice(&1u32.to_le_bytes());
        // last_written = 0
        buf.extend_from_slice(&0u64.to_le_bytes());
        // credential_blob_size = 0
        buf.extend_from_slice(&0u32.to_le_bytes());
        // persist = 2
        buf.extend_from_slice(&2u32.to_le_bytes());
        // attribute_count = 0
        buf.extend_from_slice(&0u32.to_le_bytes());
        // reserved = 0
        buf.extend_from_slice(&0u32.to_le_bytes());

        // Target name: "MicrosoftAccount:user@outlook.com" as UTF-16LE + null
        let target = "MicrosoftAccount:user@outlook.com";
        for ch in target.encode_utf16() {
            buf.extend_from_slice(&ch.to_le_bytes());
        }
        buf.extend_from_slice(&0u16.to_le_bytes()); // null terminator

        // Username: "user@outlook.com" as UTF-16LE + null
        let username = "user@outlook.com";
        for ch in username.encode_utf16() {
            buf.extend_from_slice(&ch.to_le_bytes());
        }
        buf.extend_from_slice(&0u16.to_le_bytes());

        // Password: "MyP@ssw0rd!" as UTF-16LE + null
        let password = "MyP@ssw0rd!";
        for ch in password.encode_utf16() {
            buf.extend_from_slice(&ch.to_le_bytes());
        }
        buf.extend_from_slice(&0u16.to_le_bytes());

        let result = parse_credential(&buf, "TestUser");
        assert!(result.is_some(), "Expected Some credential from synthetic data");
        let cred = result.unwrap();
        assert_eq!(cred.credential_type, "generic");
        assert_eq!(cred.user, "TestUser");
        assert_eq!(cred.target, "MicrosoftAccount:user@outlook.com");
        assert_eq!(cred.username, "user@outlook.com");
        assert_eq!(cred.password, Some("MyP@ssw0rd!".to_string()));
    }

    #[test]
    fn test_parse_credential_too_short() {
        let buf = vec![0u8; 10];
        assert!(parse_credential(&buf, "user").is_none());
    }

    #[test]
    fn test_finding_type_name() {
        let finding = Finding::CredentialManager(CredentialManagerFinding {
            target: "test".to_string(),
            username: "user".to_string(),
            password: None,
            credential_type: "generic".to_string(),
            user: "Admin".to_string(),
        });
        assert_eq!(finding.type_name(), "credential_manager");
    }

    #[test]
    fn test_extract_no_keyring_returns_ok() {
        let extractor = CredMgrExtractor;
        let mut ctx = ExtractionContext::new();
        let mut collector = Collector::new(OutputFormat::Text);
        // No keyring — should return Ok immediately
        assert!(extractor.extract(&mut ctx, &mut collector).is_ok());
    }
}
