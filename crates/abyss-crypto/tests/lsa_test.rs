//! Integration tests for LSA secret and cached credential structs.

use abyss_crypto::{CachedCredential, LsaSecret};

#[test]
fn test_lsa_secret_struct_construction() {
    let secret = LsaSecret {
        name: "$MACHINE.ACC".to_string(),
        current_value: vec![0xDE, 0xAD, 0xBE, 0xEF],
        old_value: Some(vec![0x00, 0x11, 0x22, 0x33]),
    };

    assert_eq!(secret.name, "$MACHINE.ACC");
    assert_eq!(secret.current_value, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(secret.old_value, Some(vec![0x00, 0x11, 0x22, 0x33]));
}

#[test]
fn test_lsa_secret_no_old_value() {
    let secret = LsaSecret {
        name: "DefaultPassword".to_string(),
        current_value: b"hunter2".to_vec(),
        old_value: None,
    };

    assert_eq!(secret.name, "DefaultPassword");
    assert_eq!(secret.current_value, b"hunter2");
    assert!(secret.old_value.is_none());
}

#[test]
fn test_cached_credential_struct_construction() {
    let nt_hash = [
        0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31,
        0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0,
    ];

    let cred = CachedCredential {
        username: "jdoe".to_string(),
        domain: "CORP".to_string(),
        nt_hash,
        iteration_count: 10240,
    };

    assert_eq!(cred.username, "jdoe");
    assert_eq!(cred.domain, "CORP");
    assert_eq!(cred.nt_hash, nt_hash);
    assert_eq!(cred.iteration_count, 10240);
}

#[test]
fn test_cached_credential_empty_fields() {
    let cred = CachedCredential {
        username: String::new(),
        domain: String::new(),
        nt_hash: [0u8; 16],
        iteration_count: 0,
    };

    assert!(cred.username.is_empty());
    assert!(cred.domain.is_empty());
    assert_eq!(cred.nt_hash, [0u8; 16]);
    assert_eq!(cred.iteration_count, 0);
}

#[test]
fn test_lsa_secret_clone() {
    let secret = LsaSecret {
        name: "DPAPI_SYSTEM".to_string(),
        current_value: vec![1, 2, 3],
        old_value: None,
    };
    let cloned = secret.clone();
    assert_eq!(cloned.name, secret.name);
    assert_eq!(cloned.current_value, secret.current_value);
}

#[test]
fn test_cached_credential_clone() {
    let cred = CachedCredential {
        username: "alice".to_string(),
        domain: "EXAMPLE".to_string(),
        nt_hash: [0xAB; 16],
        iteration_count: 10240,
    };
    let cloned = cred.clone();
    assert_eq!(cloned.username, cred.username);
    assert_eq!(cloned.nt_hash, cred.nt_hash);
}
