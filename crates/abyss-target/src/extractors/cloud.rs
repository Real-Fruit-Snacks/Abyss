//! Cloud credential extractor.
//!
//! Scans filesystem_files for credentials from AWS, Azure, GCP, GitHub, Docker,
//! Kubernetes, Terraform, and environment variables in shell rc files.

use abyss_output::collector::Collector;
use abyss_output::finding::{CloudCredentialFinding, Finding};

use crate::error::TargetError;
use crate::extractor::{ExtractionContext, Extractor};

/// Environment variable names that indicate cloud/service credentials.
const CREDENTIAL_ENV_VARS: &[(&str, &str, &str)] = &[
    ("AWS_ACCESS_KEY_ID", "aws", "access_key_id"),
    ("AWS_SECRET_ACCESS_KEY", "aws", "secret_access_key"),
    ("AWS_SESSION_TOKEN", "aws", "session_token"),
    ("AZURE_CLIENT_SECRET", "azure", "client_secret"),
    ("AZURE_CLIENT_ID", "azure", "client_id"),
    ("AZURE_TENANT_ID", "azure", "tenant_id"),
    ("GOOGLE_APPLICATION_CREDENTIALS", "gcp", "credentials_path"),
    ("GITHUB_TOKEN", "github", "token"),
    ("GITLAB_TOKEN", "gitlab", "token"),
    ("GITLAB_PRIVATE_TOKEN", "gitlab", "token"),
    ("DIGITALOCEAN_TOKEN", "digitalocean", "token"),
    ("HEROKU_API_KEY", "heroku", "api_key"),
    ("SLACK_TOKEN", "slack", "token"),
    ("SLACK_BOT_TOKEN", "slack", "bot_token"),
    ("STRIPE_SECRET_KEY", "stripe", "secret_key"),
    ("TWILIO_AUTH_TOKEN", "twilio", "auth_token"),
    ("SENDGRID_API_KEY", "sendgrid", "api_key"),
    ("DATABASE_URL", "database", "connection_string"),
    ("REDIS_URL", "redis", "connection_string"),
    ("MONGODB_URI", "database", "connection_string"),
];

pub struct CloudExtractor;

impl Extractor for CloudExtractor {
    fn name(&self) -> &'static str {
        "CloudCredentials"
    }

    fn is_compatible(&self, ctx: &ExtractionContext) -> bool {
        !ctx.filesystem_files.is_empty() || !ctx.discovered_users.is_empty()
    }

    fn extract(
        &self,
        ctx: &mut ExtractionContext,
        collector: &mut Collector,
    ) -> Result<(), TargetError> {
        // Collect paths first to avoid borrow conflict with ctx
        let paths: Vec<(String, Vec<u8>)> = ctx
            .filesystem_files
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        for (path, data) in &paths {
            let text = match std::str::from_utf8(data) {
                Ok(t) => t,
                Err(_) => continue,
            };

            let user = extract_user_from_path(path);

            if path.contains(".aws/credentials") {
                parse_aws_credentials(text, path, &user, collector);
            } else if path.contains(".aws/config") {
                parse_aws_config(text, path, &user, collector);
            } else if path.contains(".azure/") {
                parse_azure_credentials(text, path, &user, collector);
            } else if path.contains("gcloud/") || path.contains("application_default_credentials") {
                parse_gcp_credentials(text, path, &user, collector);
            } else if path.contains("gh/hosts.yml") || path.contains(".config/hub") {
                parse_github_token(text, path, &user, collector);
            } else if path.contains(".docker/config.json") {
                parse_docker_config(text, path, &user, collector);
            } else if path.contains(".kube/config") {
                parse_kube_config(text, path, &user, collector);
            } else if path.contains("credentials.tfrc.json") {
                parse_terraform_credentials(text, path, &user, collector);
            } else if path.ends_with(".env")
                || path.ends_with(".bashrc")
                || path.ends_with(".bash_profile")
                || path.ends_with(".profile")
                || path.ends_with(".zshrc")
            {
                parse_shell_env_vars(text, path, &user, collector);
            } else if path.ends_with(".git-credentials")
                || path.ends_with(".config/git/credentials")
            {
                parse_git_credentials(text, path, &user, collector);
            } else if path.ends_with(".npmrc") {
                parse_npmrc(text, path, &user, collector);
            } else if path == "var/run/secrets/kubernetes.io/serviceaccount/token" {
                parse_k8s_service_account_token(text, path, &user, collector);
            }
        }

        Ok(())
    }
}

/// Preview a secret value: first 8 chars + "..." for safety.
fn preview_secret(secret: &str) -> String {
    if secret.len() <= 8 {
        "***".to_string()
    } else {
        format!("{}...", &secret[..8])
    }
}

/// Extract the username from a filesystem path like "home/user/..." or "Users/user/...".
fn extract_user_from_path(path: &str) -> Option<String> {
    let parts: Vec<&str> = path.split('/').collect();
    for (i, part) in parts.iter().enumerate() {
        if (*part == "home" || *part == "Users") && i + 1 < parts.len() {
            return Some(parts[i + 1].to_string());
        }
    }
    if parts.first() == Some(&"root") {
        return Some("root".to_string());
    }
    None
}

/// Emit a CloudCredential finding.
fn emit(
    provider: &str,
    credential_type: &str,
    identifier: Option<String>,
    secret: &str,
    source_path: &str,
    user: &Option<String>,
    collector: &mut Collector,
) {
    collector.add(Finding::CloudCredential(CloudCredentialFinding {
        provider: provider.to_string(),
        credential_type: credential_type.to_string(),
        identifier,
        secret_preview: preview_secret(secret),
        source_path: source_path.to_string(),
        user: user.clone(),
    }));
}

// ---------------------------------------------------------------------------
// AWS
// ---------------------------------------------------------------------------

/// Parse AWS credentials INI file.
fn parse_aws_credentials(text: &str, path: &str, user: &Option<String>, collector: &mut Collector) {
    let mut current_profile = String::new();
    let mut access_key = String::new();
    let mut secret_key = String::new();
    let mut session_token = String::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            // Flush previous profile
            flush_aws_profile(
                &current_profile,
                &access_key,
                &secret_key,
                &session_token,
                path,
                user,
                collector,
            );
            current_profile = line[1..line.len() - 1].trim().to_string();
            access_key.clear();
            secret_key.clear();
            session_token.clear();
            continue;
        }

        if let Some((key, value)) = parse_ini_line(line) {
            match key {
                "aws_access_key_id" => access_key = value.to_string(),
                "aws_secret_access_key" => secret_key = value.to_string(),
                "aws_session_token" => session_token = value.to_string(),
                _ => {}
            }
        }
    }

    // Flush last profile
    flush_aws_profile(
        &current_profile,
        &access_key,
        &secret_key,
        &session_token,
        path,
        user,
        collector,
    );
}

fn flush_aws_profile(
    profile: &str,
    access_key: &str,
    secret_key: &str,
    session_token: &str,
    path: &str,
    user: &Option<String>,
    collector: &mut Collector,
) {
    if !access_key.is_empty() && !secret_key.is_empty() {
        let id = if profile.is_empty() {
            access_key.to_string()
        } else {
            format!("{}:{}", profile, access_key)
        };
        emit("aws", "access_key", Some(id), secret_key, path, user, collector);
    }
    if !session_token.is_empty() {
        emit(
            "aws",
            "session_token",
            Some(access_key.to_string()),
            session_token,
            path,
            user,
            collector,
        );
    }
}

/// Parse AWS config file for SSO/role credentials.
fn parse_aws_config(text: &str, path: &str, user: &Option<String>, collector: &mut Collector) {
    let mut current_profile = String::new();
    let mut sso_account = String::new();
    let mut role_arn = String::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            // Flush previous
            if !sso_account.is_empty() {
                emit(
                    "aws",
                    "sso_config",
                    Some(format!("{}:{}", current_profile, sso_account)),
                    &sso_account,
                    path,
                    user,
                    collector,
                );
            }
            if !role_arn.is_empty() {
                emit(
                    "aws",
                    "role_arn",
                    Some(format!("{}:{}", current_profile, role_arn)),
                    &role_arn,
                    path,
                    user,
                    collector,
                );
            }
            current_profile = line[1..line.len() - 1].trim().to_string();
            sso_account.clear();
            role_arn.clear();
            continue;
        }

        if let Some((key, value)) = parse_ini_line(line) {
            match key {
                "sso_account_id" => sso_account = value.to_string(),
                "role_arn" => role_arn = value.to_string(),
                _ => {}
            }
        }
    }

    if !sso_account.is_empty() {
        emit(
            "aws",
            "sso_config",
            Some(format!("{}:{}", current_profile, sso_account)),
            &sso_account,
            path,
            user,
            collector,
        );
    }
    if !role_arn.is_empty() {
        emit(
            "aws",
            "role_arn",
            Some(format!("{}:{}", current_profile, role_arn)),
            &role_arn,
            path,
            user,
            collector,
        );
    }
}

/// Parse a simple INI key=value line. Returns (key, value) with trimmed whitespace.
fn parse_ini_line(line: &str) -> Option<(&str, &str)> {
    let eq_pos = line.find('=')?;
    let key = line[..eq_pos].trim();
    let value = line[eq_pos + 1..].trim();
    Some((key, value))
}

// ---------------------------------------------------------------------------
// Azure
// ---------------------------------------------------------------------------

/// Parse Azure credential files (accessTokens.json, msal_token_cache.json, azureProfile.json).
fn parse_azure_credentials(text: &str, path: &str, user: &Option<String>, collector: &mut Collector) {
    if path.contains("accessTokens.json") {
        // JSON array of token objects
        if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(text) {
            for obj in &arr {
                if let Some(token) = obj.get("accessToken").and_then(|v| v.as_str()) {
                    let token_type = obj
                        .get("tokenType")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Bearer");
                    emit(
                        "azure",
                        "access_token",
                        Some(token_type.to_string()),
                        token,
                        path,
                        user,
                        collector,
                    );
                }
            }
        }
    } else if path.contains("msal_token_cache.json") {
        // MSAL cache: {"AccessToken": {"key": {"secret": "..."}}}
        if let Ok(root) = serde_json::from_str::<serde_json::Value>(text) {
            if let Some(tokens) = root.get("AccessToken").and_then(|v| v.as_object()) {
                for (_key, entry) in tokens {
                    if let Some(secret) = entry.get("secret").and_then(|v| v.as_str()) {
                        let realm = entry
                            .get("realm")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        emit(
                            "azure",
                            "msal_token",
                            Some(realm.to_string()),
                            secret,
                            path,
                            user,
                            collector,
                        );
                    }
                }
            }
        }
    } else if path.contains("azureProfile.json") {
        // Subscription info
        if let Ok(root) = serde_json::from_str::<serde_json::Value>(text) {
            if let Some(subs) = root.get("subscriptions").and_then(|v| v.as_array()) {
                for sub in subs {
                    let name = sub.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let id = sub.get("id").and_then(|v| v.as_str()).unwrap_or("");
                    if !id.is_empty() {
                        emit(
                            "azure",
                            "subscription",
                            Some(format!("{}:{}", name, id)),
                            id,
                            path,
                            user,
                            collector,
                        );
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// GCP
// ---------------------------------------------------------------------------

/// Parse GCP application default credentials or service account JSON.
fn parse_gcp_credentials(text: &str, path: &str, user: &Option<String>, collector: &mut Collector) {
    if let Ok(root) = serde_json::from_str::<serde_json::Value>(text) {
        let cred_type = root.get("type").and_then(|v| v.as_str()).unwrap_or("unknown");

        match cred_type {
            "service_account" => {
                let project = root
                    .get("project_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let email = root
                    .get("client_email")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let has_key = root.get("private_key").is_some();
                let key_preview = if has_key {
                    root.get("private_key")
                        .and_then(|v| v.as_str())
                        .map(preview_secret)
                        .unwrap_or_else(|| "***".to_string())
                } else {
                    "no_key".to_string()
                };

                collector.add(Finding::CloudCredential(CloudCredentialFinding {
                    provider: "gcp".to_string(),
                    credential_type: "service_account".to_string(),
                    identifier: Some(format!("{}:{}", project, email)),
                    secret_preview: key_preview,
                    source_path: path.to_string(),
                    user: user.clone(),
                }));
            }
            "authorized_user" => {
                let client_id = root
                    .get("client_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let refresh_token = root
                    .get("refresh_token")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if !refresh_token.is_empty() {
                    emit(
                        "gcp",
                        "refresh_token",
                        Some(client_id.to_string()),
                        refresh_token,
                        path,
                        user,
                        collector,
                    );
                }
            }
            _ => {
                // Unknown type but still a credential file
                if let Some(token) = root.get("access_token").and_then(|v| v.as_str()) {
                    emit("gcp", "access_token", None, token, path, user, collector);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// GitHub / Hub
// ---------------------------------------------------------------------------

/// Parse GitHub CLI hosts.yml or hub config for oauth tokens.
fn parse_github_token(text: &str, path: &str, user: &Option<String>, collector: &mut Collector) {
    for line in text.lines() {
        let line = line.trim();

        // gh CLI: "oauth_token: ghp_xxx" or "token: ghp_xxx"
        if let Some(token) = line.strip_prefix("oauth_token:") {
            let token = token.trim();
            if !token.is_empty() {
                emit("github", "oauth_token", None, token, path, user, collector);
            }
        } else if let Some(rest) = line.strip_prefix("token:") {
            let token = rest.trim();
            if !token.is_empty() {
                emit("github", "token", None, token, path, user, collector);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Docker
// ---------------------------------------------------------------------------

/// Parse Docker config.json for registry auth credentials.
fn parse_docker_config(text: &str, path: &str, user: &Option<String>, collector: &mut Collector) {
    if let Ok(root) = serde_json::from_str::<serde_json::Value>(text) {
        if let Some(auths) = root.get("auths").and_then(|v| v.as_object()) {
            for (registry, entry) in auths {
                if let Some(auth_b64) = entry.get("auth").and_then(|v| v.as_str()) {
                    let decoded = base64_decode_simple(auth_b64);
                    let secret = if decoded.contains(':') {
                        // user:pass format
                        decoded.clone()
                    } else {
                        auth_b64.to_string()
                    };
                    emit(
                        "docker",
                        "registry_auth",
                        Some(registry.clone()),
                        &secret,
                        path,
                        user,
                        collector,
                    );
                }
            }
        }
    }
}

/// Simple base64 decoder (standard alphabet, no padding required).
fn base64_decode_simple(input: &str) -> String {
    const DECODE_TABLE: [u8; 128] = {
        let mut table = [255u8; 128];
        let mut i = 0u8;
        while i < 26 {
            table[(b'A' + i) as usize] = i;
            table[(b'a' + i) as usize] = i + 26;
            i += 1;
        }
        let mut d = 0u8;
        while d < 10 {
            table[(b'0' + d) as usize] = d + 52;
            d += 1;
        }
        table[b'+' as usize] = 62;
        table[b'/' as usize] = 63;
        table
    };

    let lookup = |byte: u8| -> u8 {
        if (byte as usize) < 128 {
            DECODE_TABLE[byte as usize]
        } else {
            255
        }
    };

    let bytes: Vec<u8> = input.bytes().filter(|&b| b != b'=' && b != b'\n' && b != b'\r').collect();
    let mut output = Vec::with_capacity(bytes.len() * 3 / 4);

    let mut i = 0;
    while i + 4 <= bytes.len() {
        let a = lookup(bytes[i]);
        let b = lookup(bytes[i + 1]);
        let c = lookup(bytes[i + 2]);
        let d = lookup(bytes[i + 3]);
        if a == 255 || b == 255 {
            break;
        }
        output.push((a << 2) | (b >> 4));
        if c != 255 {
            output.push((b << 4) | (c >> 2));
            if d != 255 {
                output.push((c << 6) | d);
            }
        }
        i += 4;
    }

    // Handle remaining 2 or 3 bytes (partial block after padding removal)
    let remaining = bytes.len() - i;
    if remaining >= 2 {
        let a = lookup(bytes[i]);
        let b = lookup(bytes[i + 1]);
        if a != 255 && b != 255 {
            output.push((a << 2) | (b >> 4));
            if remaining >= 3 {
                let c = lookup(bytes[i + 2]);
                if c != 255 {
                    output.push((b << 4) | (c >> 2));
                }
            }
        }
    }

    String::from_utf8(output).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Kubernetes
// ---------------------------------------------------------------------------

/// Parse kubeconfig for tokens, passwords, and certificate data.
fn parse_kube_config(text: &str, path: &str, user: &Option<String>, collector: &mut Collector) {
    for line in text.lines() {
        let trimmed = line.trim();

        if let Some(value) = extract_yaml_value(trimmed, "token:") {
            if !value.is_empty() {
                emit("kubernetes", "token", None, value, path, user, collector);
            }
        } else if let Some(value) = extract_yaml_value(trimmed, "password:") {
            if !value.is_empty() {
                emit("kubernetes", "password", None, value, path, user, collector);
            }
        } else if let Some(value) = extract_yaml_value(trimmed, "client-certificate-data:") {
            if !value.is_empty() {
                emit(
                    "kubernetes",
                    "client_certificate",
                    None,
                    value,
                    path,
                    user,
                    collector,
                );
            }
        } else if let Some(value) = extract_yaml_value(trimmed, "client-key-data:") {
            if !value.is_empty() {
                emit(
                    "kubernetes",
                    "client_key",
                    None,
                    value,
                    path,
                    user,
                    collector,
                );
            }
        }
    }
}

/// Extract a value from a simple "key: value" YAML line.
fn extract_yaml_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(key)?;
    Some(rest.trim())
}

// ---------------------------------------------------------------------------
// Terraform
// ---------------------------------------------------------------------------

/// Parse Terraform credentials.tfrc.json for API tokens.
fn parse_terraform_credentials(
    text: &str,
    path: &str,
    user: &Option<String>,
    collector: &mut Collector,
) {
    if let Ok(root) = serde_json::from_str::<serde_json::Value>(text) {
        if let Some(creds) = root.get("credentials").and_then(|v| v.as_object()) {
            for (host, entry) in creds {
                if let Some(token) = entry.get("token").and_then(|v| v.as_str()) {
                    emit(
                        "terraform",
                        "api_token",
                        Some(host.clone()),
                        token,
                        path,
                        user,
                        collector,
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Shell environment variables
// ---------------------------------------------------------------------------

/// Scan shell rc files and .env files for credential environment variables.
fn parse_shell_env_vars(text: &str, path: &str, user: &Option<String>, collector: &mut Collector) {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Strip "export " prefix if present
        let assignment = if let Some(rest) = line.strip_prefix("export ") {
            rest.trim()
        } else {
            line
        };

        // Look for KEY=VALUE
        if let Some(eq_pos) = assignment.find('=') {
            let key = assignment[..eq_pos].trim();
            let value = assignment[eq_pos + 1..].trim();
            // Strip surrounding quotes
            let value = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .or_else(|| {
                    value
                        .strip_prefix('\'')
                        .and_then(|v| v.strip_suffix('\''))
                })
                .unwrap_or(value);

            if value.is_empty() {
                continue;
            }

            for &(env_key, provider, cred_type) in CREDENTIAL_ENV_VARS {
                if key == env_key {
                    emit(provider, cred_type, Some(env_key.to_string()), value, path, user, collector);
                    break;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Git credentials
// ---------------------------------------------------------------------------

/// Parse `.git-credentials` file. Each line is a URL with embedded credentials:
/// `https://user:ghp_xxxxxxxxxxxx@github.com`
fn parse_git_credentials(text: &str, path: &str, user: &Option<String>, collector: &mut Collector) {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Extract scheme://user:token@host
        if let Some(at_pos) = line.rfind('@') {
            let creds_part = &line[..at_pos];
            let host = &line[at_pos + 1..];
            // Find the last ':' before '@' to split user:token
            if let Some(colon_pos) = creds_part.rfind(':') {
                let token = &creds_part[colon_pos + 1..];
                // Strip scheme://user prefix to get just the username
                let user_part = &creds_part[..colon_pos];
                let git_user = user_part.split("//").last().unwrap_or(user_part);
                if !token.is_empty() {
                    emit(
                        "git",
                        "credential",
                        Some(format!("{}@{}", git_user, host)),
                        token,
                        path,
                        user,
                        collector,
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// npmrc
// ---------------------------------------------------------------------------

/// Parse `.npmrc` for `_authToken=` entries.
/// Example: `//registry.npmjs.org/:_authToken=npm_xxxxxxxxxxxx`
fn parse_npmrc(text: &str, path: &str, user: &Option<String>, collector: &mut Collector) {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(token_pos) = line.find("_authToken=") {
            let registry = &line[..token_pos];
            let token = &line[token_pos + "_authToken=".len()..];
            // Strip surrounding quotes if present
            let token = token
                .strip_prefix('"').and_then(|t| t.strip_suffix('"'))
                .or_else(|| token.strip_prefix('\'').and_then(|t| t.strip_suffix('\'')))
                .unwrap_or(token);
            if !token.is_empty() {
                emit(
                    "npm",
                    "auth_token",
                    Some(registry.trim_end_matches('/').to_string()),
                    token,
                    path,
                    user,
                    collector,
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Kubernetes service account token
// ---------------------------------------------------------------------------

/// Parse a raw Kubernetes service account bearer token.
fn parse_k8s_service_account_token(text: &str, path: &str, user: &Option<String>, collector: &mut Collector) {
    let token = text.trim();
    if !token.is_empty() {
        emit(
            "kubernetes",
            "service_account_token",
            None,
            token,
            path,
            user,
            collector,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abyss_output::collector::{Collector, OutputFormat};

    #[test]
    fn test_preview_secret_short() {
        assert_eq!(preview_secret("abc"), "***");
        assert_eq!(preview_secret("12345678"), "***");
    }

    #[test]
    fn test_preview_secret_long() {
        assert_eq!(preview_secret("AKIAIOSFODNN7EXAMPLE"), "AKIAIOSF...");
        let result = preview_secret("AKIAIOSFODNN7EXAMPLE");
        assert!(result.starts_with("AKIAIOSF"));
        assert!(result.ends_with("..."));
    }

    #[test]
    fn test_extract_user_from_path_home() {
        assert_eq!(
            extract_user_from_path("home/alice/.aws/credentials"),
            Some("alice".to_string())
        );
    }

    #[test]
    fn test_extract_user_from_path_users() {
        assert_eq!(
            extract_user_from_path("Users/bob/.aws/credentials"),
            Some("bob".to_string())
        );
    }

    #[test]
    fn test_extract_user_from_path_root() {
        assert_eq!(
            extract_user_from_path("root/.aws/credentials"),
            Some("root".to_string())
        );
    }

    #[test]
    fn test_extract_user_from_path_none() {
        assert_eq!(extract_user_from_path("etc/shadow"), None);
    }

    #[test]
    fn test_parse_aws_credentials() {
        let mut collector = Collector::new(OutputFormat::Text);
        let text = "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n";
        parse_aws_credentials(text, "home/user/.aws/credentials", &Some("user".to_string()), &mut collector);
        let findings = collector.findings();
        assert_eq!(findings.len(), 1);
        match &findings[0] {
            Finding::CloudCredential(c) => {
                assert_eq!(c.provider, "aws");
                assert_eq!(c.credential_type, "access_key");
                assert!(c.identifier.as_ref().unwrap().contains("AKIAIOSFODNN7EXAMPLE"));
                assert_eq!(c.secret_preview, "wJalrXUt...");
                assert_eq!(c.user, Some("user".to_string()));
            }
            _ => panic!("Expected CloudCredential"),
        }
    }

    #[test]
    fn test_parse_docker_config() {
        let mut collector = Collector::new(OutputFormat::Text);
        // "user:pass" base64-encoded is "dXNlcjpwYXNz"
        let text = r#"{"auths":{"https://index.docker.io/v1/":{"auth":"dXNlcjpwYXNz"}}}"#;
        parse_docker_config(text, "home/user/.docker/config.json", &Some("user".to_string()), &mut collector);
        let findings = collector.findings();
        assert_eq!(findings.len(), 1);
        match &findings[0] {
            Finding::CloudCredential(c) => {
                assert_eq!(c.provider, "docker");
                assert_eq!(c.credential_type, "registry_auth");
                assert_eq!(
                    c.identifier.as_ref().unwrap(),
                    "https://index.docker.io/v1/"
                );
                // Decoded "user:pass" -> preview is "user:pas..."
                assert_eq!(c.secret_preview, "user:pas...");
            }
            _ => panic!("Expected CloudCredential"),
        }
    }

    #[test]
    fn test_parse_shell_env_vars() {
        let mut collector = Collector::new(OutputFormat::Text);
        let text = "export AWS_SECRET_ACCESS_KEY=\"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\nexport GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n# comment\nIRRELEVANT=foo\n";
        parse_shell_env_vars(text, "home/user/.bashrc", &Some("user".to_string()), &mut collector);
        let findings = collector.findings();
        assert_eq!(findings.len(), 2);
        let providers: Vec<&str> = findings
            .iter()
            .map(|f| match f {
                Finding::CloudCredential(c) => c.provider.as_str(),
                _ => "",
            })
            .collect();
        assert!(providers.contains(&"aws"));
        assert!(providers.contains(&"github"));
    }

    #[test]
    fn test_parse_github_token() {
        let mut collector = Collector::new(OutputFormat::Text);
        let text = "github.com:\n    oauth_token: ghp_abcdefghijklmnopqrstuvwxyz123456\n";
        parse_github_token(text, "home/user/.config/gh/hosts.yml", &Some("user".to_string()), &mut collector);
        let findings = collector.findings();
        assert_eq!(findings.len(), 1);
        match &findings[0] {
            Finding::CloudCredential(c) => {
                assert_eq!(c.provider, "github");
                assert_eq!(c.credential_type, "oauth_token");
                assert_eq!(c.secret_preview, "ghp_abcd...");
            }
            _ => panic!("Expected CloudCredential"),
        }
    }

    #[test]
    fn test_parse_gcp_service_account() {
        let mut collector = Collector::new(OutputFormat::Text);
        let text = r#"{"type":"service_account","project_id":"my-project","private_key_id":"abc123","private_key":"-----BEGIN RSA PRIVATE KEY-----\nMIIE...","client_email":"svc@my-project.iam.gserviceaccount.com"}"#;
        parse_gcp_credentials(text, "home/user/.config/gcloud/application_default_credentials.json", &Some("user".to_string()), &mut collector);
        let findings = collector.findings();
        assert_eq!(findings.len(), 1);
        match &findings[0] {
            Finding::CloudCredential(c) => {
                assert_eq!(c.provider, "gcp");
                assert_eq!(c.credential_type, "service_account");
                assert!(c
                    .identifier
                    .as_ref()
                    .unwrap()
                    .contains("my-project"));
                assert!(c.secret_preview.starts_with("-----BEG"));
            }
            _ => panic!("Expected CloudCredential"),
        }
    }

    #[test]
    fn test_base64_decode_simple() {
        assert_eq!(base64_decode_simple("dXNlcjpwYXNz"), "user:pass");
        assert_eq!(base64_decode_simple("aGVsbG8="), "hello");
        assert_eq!(base64_decode_simple(""), "");
    }

    #[test]
    fn test_cloud_extractor_name() {
        let ext = CloudExtractor;
        assert_eq!(ext.name(), "CloudCredentials");
    }

    #[test]
    fn test_cloud_extractor_is_compatible() {
        let ext = CloudExtractor;

        // Empty context -> not compatible
        let ctx = ExtractionContext::new();
        assert!(!ext.is_compatible(&ctx));

        // With a user -> compatible
        let mut ctx2 = ExtractionContext::new();
        ctx2.discovered_users.push("alice".to_string());
        assert!(ext.is_compatible(&ctx2));

        // With filesystem files -> compatible
        let mut ctx3 = ExtractionContext::new();
        ctx3.filesystem_files
            .insert("etc/shadow".to_string(), vec![]);
        assert!(ext.is_compatible(&ctx3));
    }
}
