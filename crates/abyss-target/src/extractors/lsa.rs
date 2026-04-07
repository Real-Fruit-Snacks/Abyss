//! LSA secrets extractor.

use abyss_crypto::{derive_lsa_key, derive_syskey, extract_lsa_secrets};
use abyss_output::collector::Collector;
use abyss_output::finding::{Finding, LsaSecretFinding, hex_encode};

use crate::error::TargetError;
use crate::extractor::{ExtractionContext, Extractor};

pub struct LsaExtractor;

impl Extractor for LsaExtractor {
    fn name(&self) -> &'static str {
        "LSA"
    }

    fn is_compatible(&self, ctx: &ExtractionContext) -> bool {
        ctx.system_hive.is_some() && ctx.security_hive.is_some()
    }

    fn extract(
        &self,
        ctx: &mut ExtractionContext,
        collector: &mut Collector,
    ) -> Result<(), TargetError> {
        // Derive SYSKEY if not already cached.
        if ctx.syskey.is_none() {
            let system = ctx.system_hive.as_mut().ok_or_else(|| TargetError::OpenFailed {
                detail: "SYSTEM hive not available".to_string(),
            })?;
            let syskey = derive_syskey(system).map_err(|e| TargetError::OpenFailed {
                detail: format!("SYSKEY derivation: {e}"),
            })?;
            ctx.syskey = Some(syskey);
        }

        let syskey = *ctx.syskey.as_ref().unwrap();

        // Take the SECURITY hive out to avoid simultaneous borrows.
        let mut security = ctx.security_hive.take().ok_or_else(|| TargetError::OpenFailed {
            detail: "SECURITY hive not available".to_string(),
        })?;

        // Derive LSA key if not already cached.
        if ctx.lsa_key.is_none() {
            let lsa_key = derive_lsa_key(&mut security, &syskey).map_err(|e| TargetError::OpenFailed {
                detail: format!("LSA key derivation: {e}"),
            })?;
            ctx.lsa_key = Some(lsa_key);
        }

        let lsa_key = ctx.lsa_key.clone().unwrap();

        let secrets = extract_lsa_secrets(&mut security, &lsa_key).map_err(|e| TargetError::OpenFailed {
            detail: format!("LSA extraction: {e}"),
        })?;

        // Capture NL$KM for cached creds before putting hive back.
        for secret in &secrets {
            if secret.name == "NL$KM" {
                ctx.nlkm = Some(secret.current_value.clone());
            }
        }

        ctx.security_hive = Some(security);

        for secret in secrets {
            let (secret_type, value) = interpret_secret(&secret.name, &secret.current_value);
            collector.add(Finding::LsaSecret(LsaSecretFinding {
                name: secret.name,
                secret_type,
                value,
            }));
        }

        Ok(())
    }
}

/// Classify an LSA secret by name and return (type_label, display_value).
fn interpret_secret(name: &str, value: &[u8]) -> (String, String) {
    if name == "DPAPI_SYSTEM" {
        ("dpapi_system".to_string(), hex_encode(value))
    } else if name == "$MACHINE.ACC" {
        ("machine_account".to_string(), hex_encode(value))
    } else if name == "DefaultPassword" {
        // May be UTF-16LE plaintext.
        let display = decode_utf16le_lossy(value);
        ("default_password".to_string(), display)
    } else if name.starts_with("_SC_") {
        // Service credential — often UTF-16LE password.
        let display = decode_utf16le_lossy(value);
        ("service_credential".to_string(), display)
    } else if name == "NL$KM" {
        ("nlkm".to_string(), hex_encode(value))
    } else {
        ("raw".to_string(), hex_encode(value))
    }
}

/// Attempt to decode bytes as UTF-16LE; fall back to hex if it fails.
fn decode_utf16le_lossy(bytes: &[u8]) -> String {
    if bytes.len() % 2 != 0 || bytes.is_empty() {
        return hex_encode(bytes);
    }
    let chars: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let s = String::from_utf16_lossy(&chars);
    // If the result contains only printable characters, return it; otherwise hex.
    if s.chars().all(|c| !c.is_control() || c == '\n' || c == '\r') {
        s.trim_end_matches('\0').to_string()
    } else {
        hex_encode(bytes)
    }
}
