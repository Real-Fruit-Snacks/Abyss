//! Windows persistence mechanism extractor.
//!
//! Scans the SYSTEM hive for auto-starting services, boot-execute entries,
//! and Image File Execution Options (IFEO) debugger hijacks.

use abyss_output::collector::Collector;
use abyss_output::finding::{Finding, PersistenceEntryFinding};

use crate::error::TargetError;
use crate::extractor::{ExtractionContext, Extractor};

pub struct PersistenceExtractor;

impl Extractor for PersistenceExtractor {
    fn name(&self) -> &'static str {
        "Persistence Mechanism Extractor"
    }

    fn is_compatible(&self, ctx: &ExtractionContext) -> bool {
        ctx.system_hive.is_some()
    }

    fn extract(
        &self,
        ctx: &mut ExtractionContext,
        collector: &mut Collector,
    ) -> Result<(), TargetError> {
        if let Some(ref mut hive) = ctx.system_hive {
            extract_services(hive, collector);
            extract_run_keys(hive, collector);
            extract_ifeo(hive, collector);
        }
        Ok(())
    }
}

fn extract_services(hive: &mut abyss_registry::RegistryHive, collector: &mut Collector) {
    let services_key = match hive.open_key("ControlSet001\\Services") {
        Ok(k) => k,
        Err(e) => {
            log::debug!("Could not open ControlSet001\\Services: {}", e);
            return;
        }
    };

    let names = match hive.subkey_names(&services_key) {
        Ok(n) => n,
        Err(e) => {
            log::debug!("Could not list Services subkeys: {}", e);
            return;
        }
    };

    for name in names {
        let svc_path = format!("ControlSet001\\Services\\{}", name);
        let svc_key = match hive.open_key(&svc_path) {
            Ok(k) => k,
            Err(e) => {
                log::debug!("Could not open {}: {}", svc_path, e);
                continue;
            }
        };

        // Read Start value (REG_DWORD); skip if missing or not auto-starting (<= 2).
        let start_val = match hive.read_value(&svc_key, "Start") {
            Ok(v) => v,
            Err(_) => continue,
        };
        let start = match start_val.as_u32() {
            Ok(v) => v,
            Err(_) => continue,
        };
        if start > 2 {
            continue;
        }

        let trigger = match start {
            0 => "Boot",
            1 => "System",
            2 => "Auto",
            _ => "Unknown",
        };

        // Read ImagePath; fall back to checking Parameters\ServiceDll.
        let image_path = match hive.read_value(&svc_key, "ImagePath") {
            Ok(v) => v.as_string().unwrap_or_default(),
            Err(_) => {
                // Try Parameters\ServiceDll
                let params_path = format!("ControlSet001\\Services\\{}\\Parameters", name);
                match hive.open_key(&params_path) {
                    Ok(params_key) => match hive.read_value(&params_key, "ServiceDll") {
                        Ok(v) => v.as_string().unwrap_or_default(),
                        Err(_) => String::new(),
                    },
                    Err(_) => String::new(),
                }
            }
        };

        if image_path.is_empty() {
            continue;
        }

        collector.add(Finding::PersistenceEntry(PersistenceEntryFinding {
            mechanism: "Service".to_string(),
            name: name.clone(),
            path: image_path,
            trigger: trigger.to_string(),
            user_context: "SYSTEM".to_string(),
        }));
    }
}

fn extract_run_keys(hive: &mut abyss_registry::RegistryHive, collector: &mut Collector) {
    let boot_exec_path = "ControlSet001\\Control\\Session Manager";
    let sm_key = match hive.open_key(boot_exec_path) {
        Ok(k) => k,
        Err(e) => {
            log::debug!("Could not open {}: {}", boot_exec_path, e);
            return;
        }
    };

    match hive.read_value(&sm_key, "BootExecute") {
        Ok(val) => {
            // BootExecute is REG_MULTI_SZ; decode as string for display.
            let raw = val.as_string().unwrap_or_else(|_| {
                // Fallback: treat raw bytes as UTF-16LE multi-string, join on space.
                String::from_utf8_lossy(&val.data).into_owned()
            });
            let trimmed = raw.trim().to_string();
            if !trimmed.is_empty() && trimmed != "autocheck autochk *" {
                collector.add(Finding::PersistenceEntry(PersistenceEntryFinding {
                    mechanism: "BootExecute".to_string(),
                    name: "BootExecute".to_string(),
                    path: trimmed,
                    trigger: "Boot".to_string(),
                    user_context: "SYSTEM".to_string(),
                }));
            }
        }
        Err(e) => {
            log::debug!("Could not read BootExecute: {}", e);
        }
    }
}

fn extract_ifeo(hive: &mut abyss_registry::RegistryHive, collector: &mut Collector) {
    let ifeo_path = "ControlSet001\\Control\\Session Manager\\Image File Execution Options";
    let ifeo_key = match hive.open_key(ifeo_path) {
        Ok(k) => k,
        Err(e) => {
            log::debug!("Could not open IFEO key: {}", e);
            return;
        }
    };

    let names = match hive.subkey_names(&ifeo_key) {
        Ok(n) => n,
        Err(e) => {
            log::debug!("Could not list IFEO subkeys: {}", e);
            return;
        }
    };

    for name in names {
        let entry_path = format!(
            "ControlSet001\\Control\\Session Manager\\Image File Execution Options\\{}",
            name
        );
        let entry_key = match hive.open_key(&entry_path) {
            Ok(k) => k,
            Err(e) => {
                log::debug!("Could not open IFEO entry {}: {}", name, e);
                continue;
            }
        };

        match hive.read_value(&entry_key, "Debugger") {
            Ok(val) => {
                let debugger = val.as_string().unwrap_or_default();
                if !debugger.is_empty() {
                    collector.add(Finding::PersistenceEntry(PersistenceEntryFinding {
                        mechanism: "IFEO".to_string(),
                        name: name.clone(),
                        path: debugger,
                        trigger: "ProcessLaunch".to_string(),
                        user_context: "inherit".to_string(),
                    }));
                }
            }
            Err(_) => {
                // No Debugger value — not a persistence entry, skip silently.
            }
        }
    }
}
