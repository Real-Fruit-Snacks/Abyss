//! Tests for new Finding variants.

use abyss_output::finding::{
    Finding, ServiceCredentialFinding, ShadowEntryFinding, SshAuthKeyFinding, SshKeyFinding,
};

#[test]
fn ssh_private_key_finding_type_name() {
    let f = Finding::SshPrivateKey(SshKeyFinding {
        user: "alice".to_string(),
        path: "home/alice/.ssh/id_rsa".to_string(),
        key_type: "RSA".to_string(),
        fingerprint: "deadbeef01234567".to_string(),
        encrypted: false,
    });
    assert_eq!(f.type_name(), "ssh_private_key");
}

#[test]
fn ssh_authorized_key_finding_type_name() {
    let f = Finding::SshAuthorizedKey(SshAuthKeyFinding {
        user: "alice".to_string(),
        key_type: "ssh-ed25519".to_string(),
        fingerprint: "aabbccdd00112233".to_string(),
        comment: "alice@laptop".to_string(),
    });
    assert_eq!(f.type_name(), "ssh_authorized_key");
}

#[test]
fn shadow_entry_finding_type_name() {
    let f = Finding::ShadowEntry(ShadowEntryFinding {
        username: "root".to_string(),
        hash: "$6$salt$hash".to_string(),
        hash_algorithm: "SHA-512".to_string(),
        uid: 0,
        shell: "/bin/bash".to_string(),
    });
    assert_eq!(f.type_name(), "shadow_entry");
}

#[test]
fn service_credential_finding_type_name() {
    let f = Finding::ServiceCredential(ServiceCredentialFinding {
        service: "AWS".to_string(),
        path: "root/.aws/credentials".to_string(),
        username: "AKIAIOSFODNN7EXAMPLE".to_string(),
        credential: "secret".to_string(),
        credential_type: "aws_secret_access_key".to_string(),
    });
    assert_eq!(f.type_name(), "service_credential");
}

#[test]
fn ssh_key_finding_encrypted_flag() {
    let plain = Finding::SshPrivateKey(SshKeyFinding {
        user: "bob".to_string(),
        path: "home/bob/.ssh/id_ed25519".to_string(),
        key_type: "Ed25519".to_string(),
        fingerprint: "0011223344556677".to_string(),
        encrypted: false,
    });
    let enc = Finding::SshPrivateKey(SshKeyFinding {
        user: "bob".to_string(),
        path: "home/bob/.ssh/id_ed25519".to_string(),
        key_type: "Ed25519".to_string(),
        fingerprint: "0011223344556677".to_string(),
        encrypted: true,
    });

    if let Finding::SshPrivateKey(ref k) = plain {
        assert!(!k.encrypted);
    }
    if let Finding::SshPrivateKey(ref k) = enc {
        assert!(k.encrypted);
    }
}

#[test]
fn shadow_entry_serializes_to_json() {
    let f = Finding::ShadowEntry(ShadowEntryFinding {
        username: "testuser".to_string(),
        hash: "$1$salt$hash".to_string(),
        hash_algorithm: "MD5".to_string(),
        uid: 1001,
        shell: "/bin/sh".to_string(),
    });
    let json = serde_json::to_string(&f).expect("serialize");
    // serde uses the variant name as the tag value: "ShadowEntry"
    assert!(json.contains("ShadowEntry"));
    assert!(json.contains("testuser"));
    assert!(json.contains("MD5"));
}
