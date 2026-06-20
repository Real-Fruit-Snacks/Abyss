/// Comprehensive tests for abyss-output: Finding variants, Collector, hashcat formatter,
/// JSON serialization.
use abyss_output::collector::{Collector, OutputFormat};
use abyss_output::finding::{
    BrowserCredentialFinding, CachedCredentialFinding, DpapiMasterKeyFinding, FilesystemInfo,
    Finding, LsaSecretFinding, PersistenceEntryFinding, SamHashFinding, ServiceCredentialFinding,
    ShadowEntryFinding, SshAuthKeyFinding, SshKeyFinding, TargetInfoFinding, VolumeInfo, hex_encode,
};
use abyss_output::hashcat::emit_hashcat;
use abyss_output::json::emit_json;
use std::io::Cursor;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_sam_hash(username: &str, rid: u32, lm: &str, nt: &str) -> Finding {
    Finding::SamHash(SamHashFinding {
        username: username.to_string(),
        rid,
        nt_hash: nt.to_string(),
        lm_hash: lm.to_string(),
        account_flags: 0,
    })
}

fn make_cached(username: &str, domain: &str, hash: &str, iters: u32) -> Finding {
    Finding::CachedCredential(CachedCredentialFinding {
        username: username.to_string(),
        domain: domain.to_string(),
        hash: hash.to_string(),
        iteration_count: iters,
    })
}

fn make_shadow(username: &str, hash: &str, algo: &str) -> Finding {
    Finding::ShadowEntry(ShadowEntryFinding {
        username: username.to_string(),
        hash: hash.to_string(),
        hash_algorithm: algo.to_string(),
        uid: 0,
        shell: "/bin/bash".to_string(),
    })
}

// ---------------------------------------------------------------------------
// 1. Finding enum: construct every variant, verify type_name()
// ---------------------------------------------------------------------------

#[test]
fn finding_type_name_target_info() {
    let f = Finding::TargetInfo(TargetInfoFinding {
        os: "Windows 10".to_string(),
        hostname: None,
        version: None,
        architecture: None,
        domain: None,
        volumes: vec![],
        filesystems: vec![],
    });
    assert_eq!(f.type_name(), "target_info");
}

#[test]
fn finding_type_name_sam_hash() {
    assert_eq!(make_sam_hash("admin", 500, "aad3b435b51404eeaad3b435b51404ee", "31d6cfe0d16ae931b73c59d7e0c089c0").type_name(), "sam_hash");
}

#[test]
fn finding_type_name_lsa_secret() {
    let f = Finding::LsaSecret(LsaSecretFinding {
        name: "DPAPI_SYSTEM".to_string(),
        secret_type: "binary".to_string(),
        value: "deadbeef".to_string(),
    });
    assert_eq!(f.type_name(), "lsa_secret");
}

#[test]
fn finding_type_name_cached_credential() {
    assert_eq!(make_cached("alice", "CORP", "aabbcc", 10240).type_name(), "cached_credential");
}

#[test]
fn finding_type_name_dpapi_master_key() {
    let f = Finding::DpapiMasterKey(DpapiMasterKeyFinding {
        user_sid: "S-1-5-21-1234".to_string(),
        guid: "abc-def".to_string(),
        decrypted: true,
        key_source: "dpapi".to_string(),
    });
    assert_eq!(f.type_name(), "dpapi_master_key");
}

#[test]
fn finding_type_name_browser_credential() {
    let f = Finding::BrowserCredential(BrowserCredentialFinding {
        browser: "Chrome".to_string(),
        url: "https://example.com".to_string(),
        username: "user@example.com".to_string(),
        password: "hunter2".to_string(),
    });
    assert_eq!(f.type_name(), "browser_credential");
}

#[test]
fn finding_type_name_ssh_private_key() {
    let f = Finding::SshPrivateKey(SshKeyFinding {
        user: "alice".to_string(),
        path: "/home/alice/.ssh/id_rsa".to_string(),
        key_type: "RSA".to_string(),
        fingerprint: "deadbeef".to_string(),
        encrypted: false,
    });
    assert_eq!(f.type_name(), "ssh_private_key");
}

#[test]
fn finding_type_name_ssh_authorized_key() {
    let f = Finding::SshAuthorizedKey(SshAuthKeyFinding {
        user: "alice".to_string(),
        key_type: "ssh-ed25519".to_string(),
        fingerprint: "00112233".to_string(),
        comment: "alice@laptop".to_string(),
    });
    assert_eq!(f.type_name(), "ssh_authorized_key");
}

#[test]
fn finding_type_name_shadow_entry() {
    assert_eq!(make_shadow("root", "$6$salt$hash", "SHA-512").type_name(), "shadow_entry");
}

#[test]
fn finding_type_name_service_credential() {
    let f = Finding::ServiceCredential(ServiceCredentialFinding {
        service: "AWS".to_string(),
        path: "/root/.aws/credentials".to_string(),
        username: "AKIA...".to_string(),
        credential: "secret".to_string(),
        credential_type: "aws_secret_access_key".to_string(),
    });
    assert_eq!(f.type_name(), "service_credential");
}

#[test]
fn finding_type_name_persistence_entry() {
    let f = Finding::PersistenceEntry(PersistenceEntryFinding {
        mechanism: "registry_run".to_string(),
        name: "Updater".to_string(),
        path: "C:\\Windows\\malware.exe".to_string(),
        trigger: "logon".to_string(),
        user_context: "HKCU".to_string(),
    });
    assert_eq!(f.type_name(), "persistence_entry");
}

// ---------------------------------------------------------------------------
// 2. Hashcat formatter: SamHash -> mode 1000 line
// ---------------------------------------------------------------------------

#[test]
fn hashcat_sam_hash_format() {
    // Expected: username:rid:lm_hash:nt_hash:::
    let f = make_sam_hash(
        "Administrator",
        500,
        "aad3b435b51404eeaad3b435b51404ee",
        "31d6cfe0d16ae931b73c59d7e0c089c0",
    );
    let mut out = Vec::new();
    emit_hashcat(&[f], &mut out).unwrap();
    let s = String::from_utf8(out).unwrap();
    assert_eq!(
        s.trim(),
        "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"
    );
}

#[test]
fn hashcat_cached_credential_dcc2_format() {
    // Expected: $DCC2$iterations#username#hash
    let f = make_cached("jdoe", "CORP", "aabbccddeeff00112233445566778899", 10240);
    let mut out = Vec::new();
    emit_hashcat(&[f], &mut out).unwrap();
    let s = String::from_utf8(out).unwrap();
    assert_eq!(
        s.trim(),
        "$DCC2$10240#jdoe#aabbccddeeff00112233445566778899"
    );
}

#[test]
fn hashcat_shadow_entry_raw_hash() {
    let f = make_shadow("root", "$6$salt$longhashvalue", "SHA-512");
    let mut out = Vec::new();
    emit_hashcat(&[f], &mut out).unwrap();
    let s = String::from_utf8(out).unwrap();
    assert_eq!(s.trim(), "$6$salt$longhashvalue");
}

#[test]
fn hashcat_skips_non_credential_findings() {
    let f = Finding::LsaSecret(LsaSecretFinding {
        name: "DPAPI_SYSTEM".to_string(),
        secret_type: "binary".to_string(),
        value: "deadbeef".to_string(),
    });
    let mut out = Vec::new();
    emit_hashcat(&[f], &mut out).unwrap();
    assert!(out.is_empty(), "non-credential finding must produce no hashcat output");
}

#[test]
fn hashcat_multiple_findings_in_order() {
    let findings = vec![
        make_sam_hash("admin", 500, "aad3b435b51404eeaad3b435b51404ee", "31d6cfe0d16ae931b73c59d7e0c089c0"),
        make_cached("alice", "DOMAIN", "112233445566778899aabbccddeeff00", 10240),
    ];
    let mut out = Vec::new();
    emit_hashcat(&findings, &mut out).unwrap();
    let s = String::from_utf8(out).unwrap();
    let lines: Vec<&str> = s.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].starts_with("admin:500:"));
    assert!(lines[1].starts_with("$DCC2$"));
}

// ---------------------------------------------------------------------------
// 3. Collector: add() and count/is_empty/findings()
// ---------------------------------------------------------------------------

#[test]
fn collector_starts_empty() {
    let c = Collector::new(OutputFormat::Text);
    assert!(c.is_empty());
    assert_eq!(c.count(), 0);
    assert_eq!(c.findings().len(), 0);
}

#[test]
fn collector_add_increments_count() {
    let mut c = Collector::new(OutputFormat::Hashcat);
    c.add(make_sam_hash("user1", 1001, "aa", "bb"));
    assert_eq!(c.count(), 1);
    assert!(!c.is_empty());
    c.add(make_sam_hash("user2", 1002, "cc", "dd"));
    assert_eq!(c.count(), 2);
}

#[test]
fn collector_findings_slice_matches_added_order() {
    let mut c = Collector::new(OutputFormat::Text);
    c.add(make_sam_hash("first", 1, "aa", "bb"));
    c.add(make_shadow("root", "$6$x$y", "SHA-512"));
    let findings = c.findings();
    assert_eq!(findings.len(), 2);
    assert!(matches!(findings[0], Finding::SamHash(_)));
    assert!(matches!(findings[1], Finding::ShadowEntry(_)));
}

#[test]
fn collector_emit_hashcat_produces_output() {
    let mut c = Collector::new(OutputFormat::Hashcat);
    c.add(make_sam_hash("admin", 500, "lmhash", "nthash"));
    let mut buf = Vec::new();
    c.emit(&mut buf).unwrap();
    assert!(!buf.is_empty());
}

#[test]
fn collector_emit_json_produces_output() {
    let mut c = Collector::new(OutputFormat::Json);
    c.add(make_sam_hash("admin", 500, "lmhash", "nthash"));
    let mut buf = Vec::new();
    c.emit(&mut buf).unwrap();
    assert!(!buf.is_empty());
    let s = String::from_utf8(buf).unwrap();
    assert!(s.contains("admin"));
}

#[test]
fn collector_emit_text_produces_output() {
    let mut c = Collector::new(OutputFormat::Text);
    c.add(make_sam_hash("admin", 500, "lmhash", "nthash"));
    let mut buf = Vec::new();
    c.emit(&mut buf).unwrap();
    assert!(!buf.is_empty());
}

// ---------------------------------------------------------------------------
// 4. JSON serialization: emit_json and round-trip
// ---------------------------------------------------------------------------

#[test]
fn json_sam_hash_contains_expected_fields() {
    let f = make_sam_hash("Administrator", 500, "aad3b435b51404eeaad3b435b51404ee", "31d6cfe0d16ae931b73c59d7e0c089c0");
    let mut buf = Vec::new();
    emit_json(&[f], &mut buf).unwrap();
    let s = String::from_utf8(buf).unwrap();
    assert!(s.contains("\"SamHash\""), "serde tag must be present");
    assert!(s.contains("Administrator"));
    assert!(s.contains("500"));
    assert!(s.contains("aad3b435b51404eeaad3b435b51404ee"));
}

#[test]
fn json_each_finding_on_its_own_line() {
    let findings = vec![
        make_sam_hash("user1", 1001, "aa", "bb"),
        make_shadow("root", "$6$s$h", "SHA-512"),
    ];
    let mut buf = Vec::new();
    emit_json(&findings, &mut buf).unwrap();
    let s = String::from_utf8(buf).unwrap();
    assert_eq!(s.lines().count(), 2, "emit_json must write one JSON object per line");
}

#[test]
fn json_roundtrip_sam_hash() {
    // Structs only derive Serialize; verify via serde_json::Value round-trip.
    let original = SamHashFinding {
        username: "bob".to_string(),
        rid: 1002,
        nt_hash: "31d6cfe0d16ae931b73c59d7e0c089c0".to_string(),
        lm_hash: "aad3b435b51404eeaad3b435b51404ee".to_string(),
        account_flags: 0,
    };
    let json = serde_json::to_string(&original).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["username"], "bob");
    assert_eq!(v["rid"], 1002);
    assert_eq!(v["nt_hash"], "31d6cfe0d16ae931b73c59d7e0c089c0");
    assert_eq!(v["lm_hash"], "aad3b435b51404eeaad3b435b51404ee");
}

#[test]
fn json_roundtrip_lsa_secret() {
    let original = LsaSecretFinding {
        name: "DPAPI_SYSTEM".to_string(),
        secret_type: "binary".to_string(),
        value: "deadbeef01234567".to_string(),
    };
    let json = serde_json::to_string(&original).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["name"], "DPAPI_SYSTEM");
    assert_eq!(v["value"], "deadbeef01234567");
    assert_eq!(v["secret_type"], "binary");
}

#[test]
fn json_roundtrip_cached_credential() {
    let original = CachedCredentialFinding {
        username: "alice".to_string(),
        domain: "EXAMPLE".to_string(),
        hash: "aabbccddeeff".to_string(),
        iteration_count: 10240,
    };
    let json = serde_json::to_string(&original).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["username"], "alice");
    assert_eq!(v["domain"], "EXAMPLE");
    assert_eq!(v["iteration_count"], 10240);
    assert_eq!(v["hash"], "aabbccddeeff");
}

#[test]
fn json_roundtrip_target_info_with_volumes() {
    let original = TargetInfoFinding {
        os: "Linux".to_string(),
        hostname: Some("ubuntu".to_string()),
        version: Some("22.04".to_string()),
        architecture: Some("x86_64".to_string()),
        domain: None,
        volumes: vec![VolumeInfo {
            index: 0,
            partition_type: "NTFS".to_string(),
            offset: 4096,
            size: 1073741824,
            label: Some("System".to_string()),
        }],
        filesystems: vec![FilesystemInfo {
            fs_type: "ext4".to_string(),
            label: None,
            total_size: 10737418240,
            mount_point: Some("/".to_string()),
        }],
    };
    let json = serde_json::to_string(&original).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["os"], "Linux");
    assert_eq!(v["hostname"], "ubuntu");
    assert_eq!(v["volumes"][0]["partition_type"], "NTFS");
    assert_eq!(v["filesystems"][0]["mount_point"], "/");
}

// ---------------------------------------------------------------------------
// 5. hex_encode utility
// ---------------------------------------------------------------------------

#[test]
fn hex_encode_empty_slice() {
    assert_eq!(hex_encode(&[]), "");
}

#[test]
fn hex_encode_known_bytes() {
    assert_eq!(hex_encode(&[0xDE, 0xAD, 0xBE, 0xEF]), "deadbeef");
}

#[test]
fn hex_encode_single_byte() {
    assert_eq!(hex_encode(&[0x0A]), "0a");
    assert_eq!(hex_encode(&[0xFF]), "ff");
}

#[test]
fn hex_encode_all_zeros() {
    assert_eq!(hex_encode(&[0u8; 4]), "00000000");
}

// ---------------------------------------------------------------------------
// 6. Finding clone and Debug
// ---------------------------------------------------------------------------

#[test]
fn finding_clone_is_independent() {
    let f = make_sam_hash("original", 500, "aad3", "31d6");
    let cloned = f.clone();
    if let Finding::SamHash(ref h) = f {
        assert_eq!(h.username, "original");
    }
    if let Finding::SamHash(ref h) = cloned {
        assert_eq!(h.username, "original");
    }
}

#[test]
fn finding_debug_output_is_non_empty() {
    let f = make_sam_hash("user", 1000, "lm", "nt");
    let s = format!("{f:?}");
    assert!(!s.is_empty());
    assert!(s.contains("SamHash"));
}

// ---------------------------------------------------------------------------
// 7. Collector emit via Cursor (Write trait via std::io::Cursor)
// ---------------------------------------------------------------------------

#[test]
fn collector_emit_hashcat_via_cursor() {
    let mut c = Collector::new(OutputFormat::Hashcat);
    c.add(make_sam_hash("user", 1000, "lm", "nt"));
    let mut cursor = Cursor::new(Vec::<u8>::new());
    c.emit(&mut cursor).unwrap();
    let inner = cursor.into_inner();
    let s = String::from_utf8(inner).unwrap();
    assert!(s.contains("user:1000:lm:nt:::"));
}
