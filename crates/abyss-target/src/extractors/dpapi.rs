//! DPAPI master key extractor.
//!
//! Reads raw DPAPI_SYSTEM LSA secret bytes captured by the LSA extractor,
//! parses master key files from the user profile directories, derives the
//! actual master keys using DPAPI_SYSTEM (machine-level) or NT hashes
//! (user-level), and builds a [`DpapiKeyring`] for downstream extractors.
//!
//! Emits a [`DpapiMasterKeyFinding`] for each master key file processed,
//! indicating whether decryption succeeded and which key source was used.

use abyss_crypto::dpapi::{
    DpapiKeyring, decrypt_master_key_with_hash, decrypt_master_key_with_system,
    parse_dpapi_system, parse_master_key_file,
};
use abyss_output::collector::Collector;
use abyss_output::finding::{DpapiMasterKeyFinding, Finding};

use crate::error::TargetError;
use crate::extractor::{ExtractionContext, Extractor};

pub struct DpapiExtractor;

impl Extractor for DpapiExtractor {
    fn name(&self) -> &'static str {
        "DPAPI"
    }

    fn is_compatible(&self, ctx: &ExtractionContext) -> bool {
        ctx.dpapi_system_raw.is_some()
    }

    fn extract(
        &self,
        ctx: &mut ExtractionContext,
        collector: &mut Collector,
    ) -> Result<(), TargetError> {
        let raw = ctx.dpapi_system_raw.clone().ok_or_else(|| TargetError::OpenFailed {
            detail: "DPAPI_SYSTEM LSA secret not available".to_string(),
        })?;

        // Parse DPAPI_SYSTEM into user and machine keys.
        let (dpapi_user_key, dpapi_machine_key) = match parse_dpapi_system(&raw) {
            Ok(keys) => keys,
            Err(e) => {
                log::warn!("DPAPI: failed to parse DPAPI_SYSTEM: {e}");
                // Build an empty keyring so downstream extractors can still run.
                ctx.dpapi_keyring = Some(DpapiKeyring::new().with_lsa_secrets(vec![raw]));
                return Ok(());
            }
        };

        log::info!(
            "DPAPI_SYSTEM parsed: user_key={}, machine_key={}",
            hex_fmt(&dpapi_user_key[..4]),
            hex_fmt(&dpapi_machine_key[..4])
        );

        // Collect NT hashes from SAM extraction (if available) for user-level
        // master key decryption.  We need (SID, nt_hash) pairs but SID mapping
        // is not currently tracked; we'll try each hash against each key file.
        // For now, the DPAPI_SYSTEM path covers SYSTEM-context master keys.

        let mut keyring = DpapiKeyring::new().with_lsa_secrets(vec![raw]);
        let mut decrypted_count = 0u32;

        // Attempt to decrypt each master key file.
        for (sid, guid, file_data) in &ctx.dpapi_master_key_files {
            let mkf = match parse_master_key_file(file_data) {
                Ok(m) => m,
                Err(e) => {
                    log::debug!("DPAPI: failed to parse master key file {guid}: {e}");
                    collector.add(Finding::DpapiMasterKey(DpapiMasterKeyFinding {
                        user_sid: sid.clone(),
                        guid: guid.clone(),
                        decrypted: false,
                        key_source: "parse_error".to_string(),
                    }));
                    continue;
                }
            };

            // Try DPAPI_SYSTEM machine key first (most common for SYSTEM-context).
            if let Ok(master_key) = decrypt_master_key_with_system(&mkf, &dpapi_machine_key) {
                log::info!(
                    "DPAPI: decrypted master key {guid} with DPAPI_SYSTEM machine key ({} bytes)",
                    master_key.len()
                );
                keyring.add_master_key_by_guid_str(guid, master_key);
                decrypted_count += 1;
                collector.add(Finding::DpapiMasterKey(DpapiMasterKeyFinding {
                    user_sid: sid.clone(),
                    guid: guid.clone(),
                    decrypted: true,
                    key_source: "dpapi_system_machine".to_string(),
                }));
                continue;
            }

            // Try DPAPI_SYSTEM user key.
            if let Ok(master_key) = decrypt_master_key_with_system(&mkf, &dpapi_user_key) {
                log::info!(
                    "DPAPI: decrypted master key {guid} with DPAPI_SYSTEM user key ({} bytes)",
                    master_key.len()
                );
                keyring.add_master_key_by_guid_str(guid, master_key);
                decrypted_count += 1;
                collector.add(Finding::DpapiMasterKey(DpapiMasterKeyFinding {
                    user_sid: sid.clone(),
                    guid: guid.clone(),
                    decrypted: true,
                    key_source: "dpapi_system_user".to_string(),
                }));
                continue;
            }

            // Try NT hashes from extracted SAM entries (if any).
            let mut decrypted_with_hash = false;
            if let Some(sam_entries) = &ctx.sam_entries {
                for entry in sam_entries {
                    if entry.ntlm.len() == 16 {
                        let mut nt_hash = [0u8; 16];
                        nt_hash.copy_from_slice(&entry.ntlm);
                        if let Ok(master_key) =
                            decrypt_master_key_with_hash(&mkf, &nt_hash, sid)
                        {
                            log::info!(
                                "DPAPI: decrypted master key {guid} with NT hash of user {} ({} bytes)",
                                entry.username,
                                master_key.len()
                            );
                            keyring.add_master_key_by_guid_str(guid, master_key);
                            decrypted_count += 1;
                            collector.add(Finding::DpapiMasterKey(DpapiMasterKeyFinding {
                                user_sid: sid.clone(),
                                guid: guid.clone(),
                                decrypted: true,
                                key_source: format!("nt_hash:{}", entry.username),
                            }));
                            decrypted_with_hash = true;
                            break;
                        }
                    }
                }
            }

            if !decrypted_with_hash {
                log::debug!(
                    "DPAPI: could not decrypt master key {guid} for SID {sid}"
                );
                collector.add(Finding::DpapiMasterKey(DpapiMasterKeyFinding {
                    user_sid: sid.clone(),
                    guid: guid.clone(),
                    decrypted: false,
                    key_source: "none".to_string(),
                }));
            }
        }

        log::info!(
            "DPAPI: decrypted {decrypted_count}/{} master keys",
            ctx.dpapi_master_key_files.len()
        );

        ctx.dpapi_keyring = Some(keyring);

        Ok(())
    }
}

/// Format bytes as a lowercase hex string.
fn hex_fmt(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
