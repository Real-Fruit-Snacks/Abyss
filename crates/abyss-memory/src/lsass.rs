//! LSASS credential extraction from minidump memory.
//!
//! Extracts credentials by scanning for known byte patterns that identify
//! credential linked-list structures within LSASS process memory, then
//! walking the lists to read credential fields.

use abyss_cstruct::read::read_u64_le;
use log::{debug, warn};

use crate::minidump::{Architecture, MinidumpReader};
use crate::MemoryError;

/// A credential extracted from LSASS process memory.
#[derive(Debug, Clone)]
pub struct LsassCredential {
    pub provider: String,
    pub domain: String,
    pub username: String,
    pub password: Option<String>,
    pub nt_hash: Option<Vec<u8>>,
}

/// Signature entry for locating credential structures.
///
/// Each entry maps a Windows build range to a specific byte pattern and
/// the offset from the pattern match to the list head pointer.
#[derive(Debug, Clone)]
struct SignatureEntry {
    /// Minimum OS build number (inclusive).
    min_build: u32,
    /// Maximum OS build number (inclusive).
    max_build: u32,
    /// Byte pattern to search for.
    pattern: Vec<u8>,
    /// Offset from pattern match to the list head pointer (RIP-relative offset location).
    ptr_offset: i64,
    /// Offset from a logon session entry to the credentials sub-structure.
    cred_offset: usize,
    /// Offset to username UNICODE_STRING within a logon session entry.
    username_offset: usize,
    /// Offset to domain UNICODE_STRING within a logon session entry.
    domain_offset: usize,
}

/// Build the MSV1_0 (NTLM) signature table.
///
/// These patterns are based on known lsasrv.dll signatures for locating
/// the MSV1_0 `LogonSessionList`. Offsets vary by Windows build number.
fn msv_signatures() -> Vec<SignatureEntry> {
    vec![
        // Windows 7 SP1 / Server 2008 R2 (builds 7600-7601)
        SignatureEntry {
            min_build: 7600,
            max_build: 7601,
            pattern: vec![
                0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74,
            ],
            ptr_offset: -4,
            cred_offset: 0x60,
            username_offset: 0x30,
            domain_offset: 0x40,
        },
        // Windows 8 / Server 2012 (build 9200)
        SignatureEntry {
            min_build: 9200,
            max_build: 9200,
            pattern: vec![
                0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74,
            ],
            ptr_offset: -4,
            cred_offset: 0x60,
            username_offset: 0x30,
            domain_offset: 0x40,
        },
        // Windows 8.1 / Server 2012 R2 (build 9600)
        SignatureEntry {
            min_build: 9600,
            max_build: 9600,
            pattern: vec![
                0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74,
            ],
            ptr_offset: -4,
            cred_offset: 0x68,
            username_offset: 0x30,
            domain_offset: 0x40,
        },
        // Windows 10 1507 (build 10240)
        SignatureEntry {
            min_build: 10240,
            max_build: 10240,
            pattern: vec![
                0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74,
            ],
            ptr_offset: -4,
            cred_offset: 0x110,
            username_offset: 0x90,
            domain_offset: 0xa0,
        },
        // Windows 10 1511 (build 10586)
        SignatureEntry {
            min_build: 10586,
            max_build: 10586,
            pattern: vec![
                0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74,
            ],
            ptr_offset: -4,
            cred_offset: 0x110,
            username_offset: 0x90,
            domain_offset: 0xa0,
        },
        // Windows 10 1607+ / Server 2016+ (builds 14393-19045)
        SignatureEntry {
            min_build: 14393,
            max_build: 19045,
            // Pattern near LogonSessionList reference in lsasrv.dll
            pattern: vec![
                0x33, 0xff, 0x41, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc0, 0x74,
            ],
            ptr_offset: -4,
            cred_offset: 0x110,
            username_offset: 0x90,
            domain_offset: 0xa0,
        },
        // Windows 10 2004+ (builds 19041-22631)
        SignatureEntry {
            min_build: 19041,
            max_build: 22631,
            pattern: vec![
                0x33, 0xff, 0x45, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc9, 0x74,
            ],
            ptr_offset: -4,
            cred_offset: 0x118,
            username_offset: 0x90,
            domain_offset: 0xa0,
        },
        // Windows 11 (builds 22621+)
        SignatureEntry {
            min_build: 22621,
            max_build: 30000,
            pattern: vec![
                0x33, 0xff, 0x45, 0x89, 0x37, 0x4c, 0x8b, 0xf3, 0x45, 0x85, 0xc9, 0x74,
            ],
            ptr_offset: -4,
            cred_offset: 0x120,
            username_offset: 0x98,
            domain_offset: 0xa8,
        },
    ]
}

/// Build the Wdigest signature table.
fn wdigest_signatures() -> Vec<SignatureEntry> {
    vec![
        // Windows 7 SP1 / Server 2008 R2 (builds 7600-7601)
        SignatureEntry {
            min_build: 7600,
            max_build: 7601,
            // Pattern near l_LogSessList in wdigest.dll for Win7/2008R2
            pattern: vec![0x48, 0x3b, 0xda, 0x74],
            ptr_offset: -4,
            cred_offset: 0x30,
            username_offset: 0x30,
            domain_offset: 0x40,
        },
        // Windows 8 / Server 2012 (build 9200)
        SignatureEntry {
            min_build: 9200,
            max_build: 9200,
            pattern: vec![0x48, 0x3b, 0xda, 0x74],
            ptr_offset: -4,
            cred_offset: 0x30,
            username_offset: 0x30,
            domain_offset: 0x40,
        },
        // Windows 8.1 / Server 2012 R2 (build 9600)
        SignatureEntry {
            min_build: 9600,
            max_build: 9600,
            pattern: vec![0x48, 0x3b, 0xda, 0x74],
            ptr_offset: -4,
            cred_offset: 0x30,
            username_offset: 0x30,
            domain_offset: 0x40,
        },
        // Windows 10 / Server 2016+ (builds 10240-19045)
        SignatureEntry {
            min_build: 10240,
            max_build: 19045,
            // Pattern near l_LogSessList in wdigest.dll
            pattern: vec![
                0x48, 0x3b, 0xd9, 0x74,
            ],
            ptr_offset: 8,
            cred_offset: 0x30,
            username_offset: 0x30,
            domain_offset: 0x40,
        },
        // Windows 11 (builds 22621+)
        SignatureEntry {
            min_build: 22621,
            max_build: 30000,
            pattern: vec![
                0x48, 0x3b, 0xd9, 0x74,
            ],
            ptr_offset: 8,
            cred_offset: 0x30,
            username_offset: 0x30,
            domain_offset: 0x40,
        },
    ]
}

/// Extract credentials from an LSASS memory dump.
///
/// Scans for MSV1_0 (NTLM) and Wdigest credential structures, walking
/// their linked lists to extract usernames, domains, NT hashes, and
/// (when available) plaintext passwords.
pub fn extract_lsass_credentials(
    reader: &mut MinidumpReader,
) -> Result<Vec<LsassCredential>, MemoryError> {
    let mut credentials = Vec::new();

    // Only x64 dumps are fully supported; x86 has limited extraction coverage.
    if reader.arch == Architecture::X86 {
        warn!("x86 memory dumps have limited credential extraction support");
        return Ok(credentials);
    }
    if reader.arch != Architecture::X64 {
        warn!("LSASS extraction only supports x64 dumps; skipping");
        return Ok(credentials);
    }

    // Try MSV1_0 (NTLM hash extraction).
    match extract_msv(reader) {
        Ok(mut creds) => {
            debug!("MSV1_0: extracted {} credentials", creds.len());
            credentials.append(&mut creds);
        }
        Err(e) => {
            debug!("MSV1_0 extraction failed: {}", e);
        }
    }

    // Try Wdigest (plaintext password extraction).
    match extract_wdigest(reader) {
        Ok(mut creds) => {
            debug!("Wdigest: extracted {} credentials", creds.len());
            credentials.append(&mut creds);
        }
        Err(e) => {
            debug!("Wdigest extraction failed: {}", e);
        }
    }

    Ok(credentials)
}

/// Extract MSV1_0 (NTLM) credentials from lsasrv.dll structures.
fn extract_msv(reader: &mut MinidumpReader) -> Result<Vec<LsassCredential>, MemoryError> {
    let sigs = msv_signatures();
    let build = reader.os_build;

    // Find the matching signature for this build.
    let sig = sigs
        .iter()
        .find(|s| build >= s.min_build && build <= s.max_build)
        .ok_or_else(|| MemoryError::PatternNotFound {
            pattern: format!("MSV1_0 signature for build {}", build),
        })?;

    // Search for the pattern in lsasrv.dll.
    let hits = reader.search_pattern_in_module("lsasrv.dll", &sig.pattern)?;
    if hits.is_empty() {
        return Err(MemoryError::PatternNotFound {
            pattern: "MSV1_0 LogonSessionList pattern".into(),
        });
    }

    debug!("MSV1_0: found {} pattern hits in lsasrv.dll", hits.len());

    let mut credentials = Vec::new();

    for hit in &hits {
        // Read the RIP-relative offset to the list head.
        let offset_addr = (*hit as i64 + sig.ptr_offset) as u64;
        let rip_offset = match reader.read_virtual_u32(offset_addr) {
            Ok(v) => v as i32,
            Err(_) => continue,
        };

        // Calculate the absolute address of the list head.
        // RIP-relative: target = instruction_end + offset
        // instruction_end is approximately at the pattern match location.
        let list_head = (offset_addr as i64 + 4 + rip_offset as i64) as u64;

        debug!("MSV1_0: list head at {:#x}", list_head);

        // Walk the doubly-linked list.
        match walk_msv_list(reader, list_head, sig) {
            Ok(mut creds) => credentials.append(&mut creds),
            Err(e) => {
                debug!("MSV1_0: failed to walk list at {:#x}: {}", list_head, e);
                continue;
            }
        }
    }

    Ok(credentials)
}

/// Walk the MSV1_0 logon session linked list.
fn walk_msv_list(
    reader: &mut MinidumpReader,
    list_head: u64,
    sig: &SignatureEntry,
) -> Result<Vec<LsassCredential>, MemoryError> {
    let mut credentials = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Read the first flink pointer from the list head.
    let mut current = reader.read_virtual_u64(list_head)?;

    // Walk up to 256 entries to prevent infinite loops.
    for _ in 0..256 {
        if current == 0 || current == list_head || !seen.insert(current) {
            break;
        }

        // Read username and domain UNICODE_STRINGs.
        let username = match reader.read_unicode_string(current + sig.username_offset as u64) {
            Ok(s) => s,
            Err(_) => {
                // Try to advance to next entry.
                current = match reader.read_virtual_u64(current) {
                    Ok(v) => v,
                    Err(_) => break,
                };
                continue;
            }
        };

        let domain = reader
            .read_unicode_string(current + sig.domain_offset as u64)
            .unwrap_or_default();

        // Skip empty or machine account entries (trailing $).
        if username.is_empty() {
            current = match reader.read_virtual_u64(current) {
                Ok(v) => v,
                Err(_) => break,
            };
            continue;
        }

        // Try to read NT hash from the credentials sub-structure.
        let nt_hash = read_nt_hash(reader, current, sig.cred_offset);

        debug!(
            "MSV1_0 entry: {}\\{} nt_hash={}",
            domain,
            username,
            nt_hash.is_some()
        );

        credentials.push(LsassCredential {
            provider: "msv1_0".into(),
            domain,
            username,
            password: None,
            nt_hash,
        });

        // Follow flink to next entry.
        current = match reader.read_virtual_u64(current) {
            Ok(v) => v,
            Err(_) => break,
        };
    }

    Ok(credentials)
}

/// Read the NT hash from an MSV1_0 credential sub-structure.
fn read_nt_hash(
    reader: &mut MinidumpReader,
    entry_addr: u64,
    cred_offset: usize,
) -> Option<Vec<u8>> {
    // The credentials pointer is at cred_offset within the entry.
    let cred_ptr = reader.read_virtual_u64(entry_addr + cred_offset as u64).ok()?;
    if cred_ptr == 0 {
        return None;
    }

    // In the primary credentials structure, the NT hash is typically at
    // a fixed offset. The primary credential has:
    //   flink/blink (16 bytes on x64)
    //   AuthenticationPackageId (u32, 4 bytes)
    //   ... padding ...
    //   PrimaryCredentials (UNICODE_STRING for credential data)
    // The actual NT hash is within the "Primary" credential blob.
    //
    // For the raw NT hash, look at offset 0x18 (after list entry + auth id)
    // for the credential data pointer, then read 16 bytes of NT hash.
    let primary_ptr = reader.read_virtual_u64(cred_ptr + 0x18).ok()?;
    if primary_ptr == 0 {
        return None;
    }

    // NT hash is 16 bytes at a known offset within the primary credentials.
    // Offset varies: try common location (after LM hash length fields).
    // Layout: isNtOwfPassword (bool), isLmOwfPassword (bool), isShaOwfPassword (bool),
    //         padding, NtOwfPassword (16 bytes), LmOwfPassword (16 bytes)
    // Common offset for NT hash: 0x08
    let hash_data = reader.read_virtual(primary_ptr + 0x08, 16).ok()?;

    // Validate it's not all zeros (empty hash).
    if hash_data.iter().all(|&b| b == 0) {
        return None;
    }

    Some(hash_data)
}

/// Extract Wdigest credentials from wdigest.dll structures.
fn extract_wdigest(reader: &mut MinidumpReader) -> Result<Vec<LsassCredential>, MemoryError> {
    let sigs = wdigest_signatures();
    let build = reader.os_build;

    let sig = sigs
        .iter()
        .find(|s| build >= s.min_build && build <= s.max_build)
        .ok_or_else(|| MemoryError::PatternNotFound {
            pattern: format!("Wdigest signature for build {}", build),
        })?;

    // Search for the pattern in wdigest.dll.
    let hits = reader.search_pattern_in_module("wdigest.dll", &sig.pattern)?;
    if hits.is_empty() {
        return Err(MemoryError::PatternNotFound {
            pattern: "Wdigest l_LogSessList pattern".into(),
        });
    }

    debug!("Wdigest: found {} pattern hits in wdigest.dll", hits.len());

    let mut credentials = Vec::new();

    for hit in &hits {
        // Read RIP-relative offset to the list head pointer.
        let offset_addr = (*hit as i64 + sig.ptr_offset) as u64;
        let rip_offset = match reader.read_virtual_u32(offset_addr) {
            Ok(v) => v as i32,
            Err(_) => continue,
        };

        let list_head = (offset_addr as i64 + 4 + rip_offset as i64) as u64;

        debug!("Wdigest: list head at {:#x}", list_head);

        match walk_wdigest_list(reader, list_head, sig) {
            Ok(mut creds) => credentials.append(&mut creds),
            Err(e) => {
                debug!("Wdigest: failed to walk list at {:#x}: {}", list_head, e);
                continue;
            }
        }
    }

    Ok(credentials)
}

/// Walk the Wdigest logon session linked list.
fn walk_wdigest_list(
    reader: &mut MinidumpReader,
    list_head: u64,
    sig: &SignatureEntry,
) -> Result<Vec<LsassCredential>, MemoryError> {
    let mut credentials = Vec::new();
    let mut seen = std::collections::HashSet::new();

    let mut current = reader.read_virtual_u64(list_head)?;

    for _ in 0..256 {
        if current == 0 || current == list_head || !seen.insert(current) {
            break;
        }

        let username = match reader.read_unicode_string(current + sig.username_offset as u64) {
            Ok(s) => s,
            Err(_) => {
                current = match reader.read_virtual_u64(current) {
                    Ok(v) => v,
                    Err(_) => break,
                };
                continue;
            }
        };

        let domain = reader
            .read_unicode_string(current + sig.domain_offset as u64)
            .unwrap_or_default();

        if username.is_empty() {
            current = match reader.read_virtual_u64(current) {
                Ok(v) => v,
                Err(_) => break,
            };
            continue;
        }

        // Wdigest stores the password as a UNICODE_STRING at a known offset.
        // Password offset is typically domain_offset + 0x10 (size of UNICODE_STRING on x64).
        let password_offset = sig.domain_offset + 0x10;
        let password = reader
            .read_unicode_string(current + password_offset as u64)
            .ok()
            .filter(|p| !p.is_empty());

        debug!(
            "Wdigest entry: {}\\{} password={}",
            domain,
            username,
            password.is_some()
        );

        credentials.push(LsassCredential {
            provider: "wdigest".into(),
            domain,
            username,
            password,
            nt_hash: None,
        });

        current = match reader.read_virtual_u64(current) {
            Ok(v) => v,
            Err(_) => break,
        };
    }

    Ok(credentials)
}

/// Read a pointer value from virtual memory, handling architecture differences.
fn _read_pointer(reader: &mut MinidumpReader, address: u64) -> Result<u64, MemoryError> {
    match reader.arch {
        Architecture::X64 => {
            let data = reader.read_virtual(address, 8)?;
            Ok(read_u64_le(&data, 0)?)
        }
        Architecture::X86 => {
            let data = reader.read_virtual(address, 4)?;
            let val = abyss_cstruct::read::read_u32_le(&data, 0)?;
            Ok(val as u64)
        }
    }
}
