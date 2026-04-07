//! NTDS.dit hash extractor.
//!
//! Extracts domain user NT/LM hashes from an NTDS.dit ESE database found on
//! Windows Domain Controller disk images. Requires the SYSTEM hive for SYSKEY
//! derivation and the NTDS.dit file containing the datatable.

use abyss_crypto::{decrypt_ntds_hash, decrypt_ntds_hash_history, decrypt_pek, derive_syskey};
use abyss_ese::EseDatabase;
use abyss_output::collector::Collector;
use abyss_output::finding::{Finding, NtdsHashFinding, hex_encode};

use crate::error::TargetError;
use crate::extractor::{ExtractionContext, Extractor};

/// NTDS datatable column name for SAM Account Name.
const COL_SAM_ACCOUNT_NAME: &str = "ATTm590045";
/// NTDS datatable column name for encrypted NT hash (unicodePwd).
const COL_NT_HASH: &str = "ATTk590689";
/// NTDS datatable column name for encrypted LM hash (dBCSPwd).
const COL_LM_HASH: &str = "ATTk590690";
/// NTDS datatable column name for objectSid.
const COL_OBJECT_SID: &str = "ATTr589970";
/// NTDS datatable column name for userAccountControl.
const COL_USER_ACCOUNT_CONTROL: &str = "ATTq589922";
/// NTDS datatable column name for pekList.
const COL_PEK_LIST: &str = "ATTk589918";
/// NTDS datatable column name for SAM account type.
const COL_SAM_ACCOUNT_TYPE: &str = "ATTb590606";
/// NTDS datatable column name for ntPwdHistory (NT hash history).
const COL_NT_HASH_HISTORY: &str = "ATTk589918";
/// NTDS datatable column name for lmPwdHistory (LM hash history).
const COL_LM_HASH_HISTORY: &str = "ATTk589984";

/// SAM_NORMAL_USER_ACCOUNT value (805306368 decimal = 0x30000000).
const SAM_NORMAL_USER_ACCOUNT: u32 = 0x30000000;

/// ACCOUNTDISABLE flag in userAccountControl.
const UF_ACCOUNTDISABLE: u32 = 0x0002;

/// Empty/blank hash constant.
const EMPTY_HASH: &str = "aad3b435b51404eeaad3b435b51404ee";

pub struct NtdsExtractor;

impl Extractor for NtdsExtractor {
    fn name(&self) -> &'static str {
        "NTDS"
    }

    fn is_compatible(&self, ctx: &ExtractionContext) -> bool {
        ctx.system_hive.is_some() && ctx.ntds_dit.is_some()
    }

    fn extract(
        &self,
        ctx: &mut ExtractionContext,
        collector: &mut Collector,
    ) -> Result<(), TargetError> {
        // 1. Derive SYSKEY if not already cached.
        if ctx.syskey.is_none() {
            let system = ctx
                .system_hive
                .as_mut()
                .ok_or_else(|| TargetError::OpenFailed {
                    detail: "SYSTEM hive not available".to_string(),
                })?;
            let syskey = derive_syskey(system).map_err(|e| TargetError::OpenFailed {
                detail: format!("SYSKEY derivation: {e}"),
            })?;
            ctx.syskey = Some(syskey);
        }

        let syskey = ctx.syskey.as_ref().ok_or_else(|| TargetError::OpenFailed {
            detail: "SYSKEY not available after derivation".to_string(),
        })?;

        // 2. Open NTDS.dit as ESE database.
        let ntds_data = ctx.ntds_dit.take().ok_or_else(|| TargetError::OpenFailed {
            detail: "NTDS.dit not available".to_string(),
        })?;

        let cursor = std::io::Cursor::new(ntds_data.clone());
        let reader: Box<dyn abyss_cstruct::read::ReadSeek> = Box::new(cursor);
        let mut db = EseDatabase::open(reader).map_err(|e| TargetError::OpenFailed {
            detail: format!("NTDS.dit ESE open: {e}"),
        })?;

        // Put it back so other extractors could use it.
        ctx.ntds_dit = Some(ntds_data);

        // 3. Find the datatable.
        let table = db.find_table("datatable").map_err(|e| TargetError::OpenFailed {
            detail: format!("NTDS.dit datatable not found: {e}"),
        })?;

        // Resolve column IDs by name.
        let col_id = |name: &str| -> Option<u32> {
            table
                .columns
                .iter()
                .find(|c| c.name == name)
                .map(|c| c.id)
        };

        let sam_name_id = col_id(COL_SAM_ACCOUNT_NAME);
        let nt_hash_id = col_id(COL_NT_HASH);
        let lm_hash_id = col_id(COL_LM_HASH);
        let object_sid_id = col_id(COL_OBJECT_SID);
        let uac_id = col_id(COL_USER_ACCOUNT_CONTROL);
        let pek_list_id = col_id(COL_PEK_LIST);
        let sam_type_id = col_id(COL_SAM_ACCOUNT_TYPE);

        // We need at least the SAM account name and PEK list columns.
        let sam_name_id = match sam_name_id {
            Some(id) => id,
            None => {
                log::warn!("NTDS: SAM account name column not found in datatable");
                return Ok(());
            }
        };
        let pek_list_id = match pek_list_id {
            Some(id) => id,
            None => {
                log::warn!("NTDS: pekList column not found in datatable");
                return Ok(());
            }
        };

        // 4. Read all records.
        let records = db
            .read_table_records(&table)
            .map_err(|e| TargetError::OpenFailed {
                detail: format!("NTDS.dit read records: {e}"),
            })?;

        log::info!("NTDS: read {} datatable records", records.len());

        // 5. Find PEK record and decrypt PEK.
        let mut pek: Option<Vec<u8>> = None;
        for record in &records {
            if let Some(pek_data) = record.get(pek_list_id) {
                if pek_data.len() >= 28 {
                    match decrypt_pek(pek_data, syskey) {
                        Ok(p) => {
                            log::info!("NTDS: PEK decrypted successfully");
                            pek = Some(p);
                            break;
                        }
                        Err(e) => {
                            log::debug!("NTDS: PEK decryption attempt failed: {e}");
                        }
                    }
                }
            }
        }

        let pek = match pek {
            Some(p) => p,
            None => {
                log::warn!("NTDS: could not find or decrypt PEK");
                return Ok(());
            }
        };

        // Determine domain name from hostname or default.
        let domain = ctx
            .system_hive
            .as_mut()
            .and_then(|sys| {
                sys.open_key("ControlSet001\\Services\\Tcpip\\Parameters")
                    .ok()
                    .and_then(|key| sys.read_value(&key, "Domain").ok())
                    .map(|v| {
                        String::from_utf8_lossy(&v.data)
                            .trim_end_matches('\0')
                            .to_string()
                    })
                    .filter(|s| !s.is_empty())
            })
            .unwrap_or_else(|| "UNKNOWN".to_string());

        // 6. Iterate records and extract user hashes.
        let mut count = 0u32;
        for record in &records {
            // Check SAM account type if column exists.
            if let Some(type_id) = sam_type_id {
                match record.get_u32(type_id) {
                    Some(t) if t == SAM_NORMAL_USER_ACCOUNT => {}
                    Some(_) => continue, // Not a normal user account
                    None => continue,    // No account type — skip
                }
            }

            // Get SAM account name.
            let username = match record.get_string(sam_name_id) {
                Some(name) if !name.is_empty() => name,
                _ => match record.get_ascii(sam_name_id) {
                    Some(name) if !name.is_empty() => name,
                    _ => continue,
                },
            };

            // Skip the machine account PEK holder.
            if username == "$MACHINE.ACC" {
                continue;
            }

            // Extract objectSid and derive RID (last 4 bytes, LE).
            let rid = match object_sid_id.and_then(|id| record.get(id)) {
                Some(sid) if sid.len() >= 4 => {
                    let len = sid.len();
                    u32::from_le_bytes([sid[len - 4], sid[len - 3], sid[len - 2], sid[len - 1]])
                }
                _ => continue,
            };

            // userAccountControl flags.
            let uac = uac_id.and_then(|id| record.get_u32(id)).unwrap_or(0);
            let enabled = uac & UF_ACCOUNTDISABLE == 0;

            // Decrypt NT hash.
            let nt_hash = if let Some(nt_id) = nt_hash_id {
                match record.get(nt_id) {
                    Some(enc) if !enc.is_empty() => {
                        match decrypt_ntds_hash(enc, &pek, rid) {
                            Ok(h) if h.len() == 16 => hex_encode(&h),
                            Ok(_) => EMPTY_HASH.to_string(),
                            Err(e) => {
                                log::debug!(
                                    "NTDS: failed to decrypt NT hash for {}: {}",
                                    username,
                                    e
                                );
                                EMPTY_HASH.to_string()
                            }
                        }
                    }
                    _ => EMPTY_HASH.to_string(),
                }
            } else {
                EMPTY_HASH.to_string()
            };

            // Decrypt LM hash.
            let lm_hash = if let Some(lm_id) = lm_hash_id {
                match record.get(lm_id) {
                    Some(enc) if !enc.is_empty() => {
                        match decrypt_ntds_hash(enc, &pek, rid) {
                            Ok(h) if h.len() == 16 => hex_encode(&h),
                            Ok(_) => EMPTY_HASH.to_string(),
                            Err(e) => {
                                log::debug!(
                                    "NTDS: failed to decrypt LM hash for {}: {}",
                                    username,
                                    e
                                );
                                EMPTY_HASH.to_string()
                            }
                        }
                    }
                    _ => EMPTY_HASH.to_string(),
                }
            } else {
                EMPTY_HASH.to_string()
            };

            collector.add(Finding::NtdsHash(NtdsHashFinding {
                domain: domain.clone(),
                username,
                rid,
                nt_hash,
                lm_hash,
                enabled,
            }));
            count += 1;
        }

        log::info!("NTDS: extracted {} user hashes", count);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntds_extractor_name() {
        let ext = NtdsExtractor;
        assert_eq!(ext.name(), "NTDS");
    }

    #[test]
    fn test_ntds_extractor_incompatible_without_ntds() {
        let ctx = ExtractionContext::new();
        let ext = NtdsExtractor;
        assert!(!ext.is_compatible(&ctx));
    }
}
