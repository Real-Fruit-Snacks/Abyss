//! SSH key extractor.
//!
//! Scans known SSH key paths from the filesystem_files map populated by
//! Target::build_extraction_context. Emits SshPrivateKey and SshAuthorizedKey findings.

use abyss_output::collector::Collector;
use abyss_output::finding::{Finding, SshAuthKeyFinding, SshKeyFinding};

use crate::error::TargetError;
use crate::extractor::{ExtractionContext, Extractor};

pub struct SshExtractor;

/// Known private key filenames to look for inside .ssh directories.
const PRIVATE_KEY_NAMES: &[&str] = &["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"];

impl Extractor for SshExtractor {
    fn name(&self) -> &'static str {
        "SSH"
    }

    fn is_compatible(&self, _ctx: &ExtractionContext) -> bool {
        // SSH keys exist on both Windows and Linux targets.
        true
    }

    fn extract(
        &self,
        ctx: &mut ExtractionContext,
        collector: &mut Collector,
    ) -> Result<(), TargetError> {
        // Build the set of users to scan from discovered_users plus common fallbacks.
        let mut users: Vec<String> = ctx.discovered_users.clone();
        for common in &["Administrator", "admin", "user", "root", "ubuntu", "ec2-user"] {
            let s = common.to_string();
            if !users.contains(&s) {
                users.push(s);
            }
        }

        for user in &users {
            // Try Windows path: Users/<user>/.ssh/<key>
            // Try Linux path: home/<user>/.ssh/<key> and root/.ssh/<key>
            let ssh_prefixes: Vec<String> = if user == "root" {
                vec![
                    format!("root/.ssh"),
                    format!("home/root/.ssh"),
                ]
            } else {
                vec![
                    format!("Users/{}/.ssh", user),
                    format!("home/{}/.ssh", user),
                ]
            };

            for prefix in &ssh_prefixes {
                // Check private keys
                for key_name in PRIVATE_KEY_NAMES {
                    let path = format!("{}/{}", prefix, key_name);
                    if let Some(data) = ctx.filesystem_files.get(&path) {
                        let content = String::from_utf8_lossy(data);
                        let (key_type, encrypted) = parse_private_key_header(&content);
                        let fingerprint = derive_fingerprint(data);
                        collector.add(Finding::SshPrivateKey(SshKeyFinding {
                            user: user.clone(),
                            path: path.clone(),
                            key_type,
                            fingerprint,
                            encrypted,
                        }));
                    }
                }

                // Check authorized_keys
                let auth_path = format!("{}/authorized_keys", prefix);
                if let Some(data) = ctx.filesystem_files.get(&auth_path) {
                    let content = String::from_utf8_lossy(data);
                    for line in content.lines() {
                        let line = line.trim();
                        if line.is_empty() || line.starts_with('#') {
                            continue;
                        }
                        if let Some((key_type, fingerprint, comment)) = parse_authorized_key_line(line) {
                            collector.add(Finding::SshAuthorizedKey(SshAuthKeyFinding {
                                user: user.clone(),
                                key_type,
                                fingerprint,
                                comment,
                            }));
                        }
                    }
                }
            }
        }

        // Also scan /etc/ssh/ for host keys
        let host_key_names = &[
            "ssh_host_rsa_key",
            "ssh_host_ed25519_key",
            "ssh_host_ecdsa_key",
        ];
        for key_name in host_key_names {
            let path = format!("etc/ssh/{}", key_name);
            if let Some(data) = ctx.filesystem_files.get(&path) {
                let content = String::from_utf8_lossy(data);
                let (key_type, encrypted) = parse_private_key_header(&content);
                let fingerprint = derive_fingerprint(data);
                collector.add(Finding::SshPrivateKey(SshKeyFinding {
                    user: "root".to_string(),
                    path: path.clone(),
                    key_type,
                    fingerprint,
                    encrypted,
                }));
            }
        }

        Ok(())
    }
}

/// Detect key type and encryption from PEM header content.
fn parse_private_key_header(content: &str) -> (String, bool) {
    let encrypted = content.contains("ENCRYPTED") || content.contains("Proc-Type: 4,ENCRYPTED");

    // OpenSSH format: "-----BEGIN OPENSSH PRIVATE KEY-----"
    if content.contains("BEGIN OPENSSH PRIVATE KEY") {
        // Detect type from the key body (b64 decoded would have type, but we can guess from name context)
        // Check for algorithm marker in the ascii-armored blob (rough heuristic)
        let key_type = if content.contains("ed25519") {
            "Ed25519"
        } else if content.contains("ecdsa") {
            "ECDSA"
        } else {
            "RSA"
        };
        return (key_type.to_string(), encrypted);
    }

    if content.contains("BEGIN RSA PRIVATE KEY") {
        return ("RSA".to_string(), encrypted);
    }
    if content.contains("BEGIN EC PRIVATE KEY") {
        return ("ECDSA".to_string(), encrypted);
    }
    if content.contains("BEGIN DSA PRIVATE KEY") {
        return ("DSA".to_string(), encrypted);
    }

    ("Unknown".to_string(), encrypted)
}

/// Parse a single authorized_keys line. Returns (key_type, fingerprint, comment).
fn parse_authorized_key_line(line: &str) -> Option<(String, String, String)> {
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return None;
    }
    let key_type = parts[0].to_string();
    // Validate it looks like an SSH key type
    if !key_type.starts_with("ssh-") && !key_type.starts_with("ecdsa-") && !key_type.starts_with("sk-") {
        return None;
    }
    let key_data = parts[1].as_bytes();
    let fingerprint = derive_fingerprint(key_data);
    let comment = if parts.len() >= 3 {
        parts[2].to_string()
    } else {
        String::new()
    };
    Some((key_type, fingerprint, comment))
}

/// Produce a short hex fingerprint from raw bytes (first 8 bytes of SHA-256-like fold).
/// This is a lightweight stand-in; real fingerprinting requires base64 decode + SHA-256.
/// Exported for use by the linux extractor.
pub fn derive_fingerprint_pub(data: &[u8]) -> String {
    derive_fingerprint(data)
}

fn derive_fingerprint(data: &[u8]) -> String {
    // Simple FNV-1a hash folded to 8 bytes for display purposes.
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in data {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{:016x}", hash)
}
