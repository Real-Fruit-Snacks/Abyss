//! Linux credential extractor.
//!
//! Reads /etc/shadow, /etc/passwd, and common service credential files
//! from the filesystem_files map, emitting ShadowEntry and ServiceCredential findings.

use abyss_output::collector::Collector;
use abyss_output::finding::{Finding, ServiceCredentialFinding, ShadowEntryFinding};

use crate::error::TargetError;
use crate::extractor::{ExtractionContext, Extractor};

pub struct LinuxCredsExtractor;

impl Extractor for LinuxCredsExtractor {
    fn name(&self) -> &'static str {
        "LinuxCreds"
    }

    fn is_compatible(&self, _ctx: &ExtractionContext) -> bool {
        // Always attempt; filesystem_files map is empty if no Linux fs was found.
        true
    }

    fn extract(
        &self,
        ctx: &mut ExtractionContext,
        collector: &mut Collector,
    ) -> Result<(), TargetError> {
        // Build UID map from /etc/passwd: username -> (uid, shell)
        let uid_map = parse_passwd(ctx.filesystem_files.get("etc/passwd").map(|v| v.as_slice()));

        // Parse /etc/shadow
        if let Some(shadow_data) = ctx.filesystem_files.get("etc/shadow") {
            let content = String::from_utf8_lossy(shadow_data);
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let parts: Vec<&str> = line.splitn(9, ':').collect();
                if parts.len() < 2 {
                    continue;
                }
                let username = parts[0];
                let hash = parts[1];

                // Skip accounts with no hash or locked accounts
                if hash.is_empty() || hash == "*" || hash == "!" || hash == "!!" || hash == "x" {
                    continue;
                }

                let hash_algorithm = detect_hash_algorithm(hash);
                let (uid, shell) = uid_map
                    .get(username)
                    .cloned()
                    .unwrap_or((0, "/bin/sh".to_string()));

                collector.add(Finding::ShadowEntry(ShadowEntryFinding {
                    username: username.to_string(),
                    hash: hash.to_string(),
                    hash_algorithm,
                    uid,
                    shell,
                }));
            }
        }

        // Service credential files: (service_name, path, credential_type, parser_fn)
        let service_files: &[(&str, &str, &str)] = &[
            ("AWS", "root/.aws/credentials", "aws_credentials"),
            ("git", "root/.git-credentials", "plaintext_url"),
            ("netrc", "root/.netrc", "netrc"),
            ("Docker", "root/.docker/config.json", "docker_config"),
            ("VNC", "root/.vnc/passwd", "vnc_passwd"),
        ];

        for &(service, path, cred_type) in service_files {
            if let Some(data) = ctx.filesystem_files.get(path) {
                parse_service_file(service, path, cred_type, data, collector);
            }
        }

        // Per-user service files
        let user_service_files: &[(&str, &str, &str)] = &[
            ("AWS", ".aws/credentials", "aws_credentials"),
            ("git", ".git-credentials", "plaintext_url"),
            ("netrc", ".netrc", "netrc"),
            ("Docker", ".docker/config.json", "docker_config"),
        ];

        for user in &ctx.discovered_users {
            let home = if user == "root" {
                "root".to_string()
            } else {
                format!("home/{}", user)
            };

            for &(service, rel_path, cred_type) in user_service_files {
                let full_path = format!("{}/{}", home, rel_path);
                if let Some(data) = ctx.filesystem_files.get(&full_path) {
                    parse_service_file(service, &full_path, cred_type, data, collector);
                }
            }
        }

        // WireGuard configs: /etc/wireguard/*.conf (pre-populated in filesystem_files)
        for (path, data) in &ctx.filesystem_files {
            if path.starts_with("etc/wireguard/") && path.ends_with(".conf") {
                parse_service_file("WireGuard", path, "wireguard_conf", data, collector);
            }
        }

        Ok(())
    }
}

/// Detect hash algorithm from /etc/shadow hash field prefix.
fn detect_hash_algorithm(hash: &str) -> String {
    if hash.starts_with("$6$") {
        "SHA-512".to_string()
    } else if hash.starts_with("$5$") {
        "SHA-256".to_string()
    } else if hash.starts_with("$2b$") || hash.starts_with("$2y$") || hash.starts_with("$2a$") {
        "bcrypt".to_string()
    } else if hash.starts_with("$1$") {
        "MD5".to_string()
    } else if hash.starts_with("$y$") || hash.starts_with("$7$") {
        "yescrypt".to_string()
    } else {
        "DES".to_string()
    }
}

/// Parse /etc/passwd into a map of username -> (uid, shell).
fn parse_passwd(data: Option<&[u8]>) -> std::collections::HashMap<String, (u32, String)> {
    let mut map = std::collections::HashMap::new();
    let data = match data {
        Some(d) => d,
        None => return map,
    };
    let content = String::from_utf8_lossy(data);
    for line in content.lines() {
        let parts: Vec<&str> = line.splitn(7, ':').collect();
        if parts.len() < 7 {
            continue;
        }
        let username = parts[0].to_string();
        let uid: u32 = parts[2].parse().unwrap_or(0);
        let shell = parts[6].to_string();
        map.insert(username, (uid, shell));
    }
    map
}

/// Parse a service credential file and emit findings.
fn parse_service_file(
    service: &str,
    path: &str,
    cred_type: &str,
    data: &[u8],
    collector: &mut Collector,
) {
    let content = String::from_utf8_lossy(data);

    match cred_type {
        "aws_credentials" => {
            // INI-style: aws_access_key_id = AKIA...
            let mut access_key = String::new();
            let mut secret_key = String::new();
            for line in content.lines() {
                let line = line.trim();
                if let Some(v) = line.strip_prefix("aws_access_key_id") {
                    access_key = v.trim().trim_start_matches('=').trim().to_string();
                } else if let Some(v) = line.strip_prefix("aws_secret_access_key") {
                    secret_key = v.trim().trim_start_matches('=').trim().to_string();
                }
            }
            if !access_key.is_empty() {
                collector.add(Finding::ServiceCredential(ServiceCredentialFinding {
                    service: service.to_string(),
                    path: path.to_string(),
                    username: access_key,
                    credential: secret_key,
                    credential_type: "aws_secret_access_key".to_string(),
                }));
            }
        }
        "plaintext_url" => {
            // https://user:password@host
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                collector.add(Finding::ServiceCredential(ServiceCredentialFinding {
                    service: service.to_string(),
                    path: path.to_string(),
                    username: String::new(),
                    credential: line.to_string(),
                    credential_type: "url_with_credentials".to_string(),
                }));
            }
        }
        "netrc" => {
            // machine host login user password pass (whitespace-tokenized)
            let mut machine = String::new();
            let mut login = String::new();
            let mut password = String::new();
            let tokens: Vec<&str> = content.split_whitespace().collect();
            let mut i = 0;
            while i < tokens.len() {
                match tokens[i] {
                    "machine" => {
                        if !machine.is_empty() && !login.is_empty() {
                            collector.add(Finding::ServiceCredential(ServiceCredentialFinding {
                                service: service.to_string(),
                                path: path.to_string(),
                                username: login.clone(),
                                credential: password.clone(),
                                credential_type: format!("netrc:{}", machine),
                            }));
                        }
                        machine = tokens.get(i + 1).unwrap_or(&"").to_string();
                        login.clear();
                        password.clear();
                        i += 2;
                    }
                    "login" => {
                        login = tokens.get(i + 1).unwrap_or(&"").to_string();
                        i += 2;
                    }
                    "password" => {
                        password = tokens.get(i + 1).unwrap_or(&"").to_string();
                        i += 2;
                    }
                    _ => { i += 1; }
                }
            }
            if !machine.is_empty() && !login.is_empty() {
                collector.add(Finding::ServiceCredential(ServiceCredentialFinding {
                    service: service.to_string(),
                    path: path.to_string(),
                    username: login,
                    credential: password,
                    credential_type: format!("netrc:{}", machine),
                }));
            }
        }
        "docker_config" => {
            // JSON: {"auths": {"registry": {"auth": "base64(user:pass)"}}}
            // Simple string search without pulling in a JSON parser.
            if content.contains("\"auth\"") {
                collector.add(Finding::ServiceCredential(ServiceCredentialFinding {
                    service: service.to_string(),
                    path: path.to_string(),
                    username: String::new(),
                    credential: content.trim().to_string(),
                    credential_type: "docker_auth_json".to_string(),
                }));
            }
        }
        "vnc_passwd" => {
            // VNC stores an 8-byte DES-encrypted password blob.
            collector.add(Finding::ServiceCredential(ServiceCredentialFinding {
                service: service.to_string(),
                path: path.to_string(),
                username: String::new(),
                credential: crate::extractors::ssh::derive_fingerprint_pub(data),
                credential_type: "vnc_des_blob".to_string(),
            }));
        }
        "wireguard_conf" => {
            // Look for PrivateKey = <base64>
            for line in content.lines() {
                let line = line.trim();
                if let Some(v) = line.strip_prefix("PrivateKey") {
                    let key = v.trim_start_matches('=').trim().to_string();
                    collector.add(Finding::ServiceCredential(ServiceCredentialFinding {
                        service: service.to_string(),
                        path: path.to_string(),
                        username: String::new(),
                        credential: key,
                        credential_type: "wireguard_private_key".to_string(),
                    }));
                }
            }
        }
        _ => {}
    }
}
