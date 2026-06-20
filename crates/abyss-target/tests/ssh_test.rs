//! Tests for SshExtractor and LinuxCredsExtractor.

use abyss_target::extractors::{LinuxCredsExtractor, SshExtractor};
use abyss_target::extractor::{ExtractionContext, Extractor};

#[test]
fn ssh_extractor_name() {
    assert_eq!(SshExtractor.name(), "SSH");
}

#[test]
fn ssh_extractor_always_compatible() {
    let ctx = ExtractionContext::new();
    assert!(SshExtractor.is_compatible(&ctx));
}

#[test]
fn linux_creds_extractor_name() {
    assert_eq!(LinuxCredsExtractor.name(), "LinuxCreds");
}

#[test]
fn linux_creds_extractor_always_compatible() {
    let ctx = ExtractionContext::new();
    assert!(LinuxCredsExtractor.is_compatible(&ctx));
}

#[test]
fn ssh_extractor_emits_private_key_finding() {
    use abyss_output::collector::{Collector, OutputFormat};
    use abyss_output::finding::Finding;

    let mut ctx = ExtractionContext::new();
    // Simulate a filesystem with an RSA private key for a user
    ctx.discovered_users.push("alice".to_string());
    ctx.filesystem_files.insert(
        "home/alice/.ssh/id_rsa".to_string(),
        b"-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n".to_vec(),
    );

    let mut collector = Collector::new(OutputFormat::Text);
    SshExtractor.extract(&mut ctx, &mut collector).unwrap();

    let findings = collector.findings();
    let has_ssh_key = findings.iter().any(|f| matches!(f, Finding::SshPrivateKey(_)));
    assert!(has_ssh_key, "expected at least one SshPrivateKey finding");
}

#[test]
fn ssh_extractor_emits_authorized_key_finding() {
    use abyss_output::collector::{Collector, OutputFormat};
    use abyss_output::finding::Finding;

    let mut ctx = ExtractionContext::new();
    ctx.discovered_users.push("bob".to_string());
    ctx.filesystem_files.insert(
        "home/bob/.ssh/authorized_keys".to_string(),
        b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... bob@laptop\n".to_vec(),
    );

    let mut collector = Collector::new(OutputFormat::Text);
    SshExtractor.extract(&mut ctx, &mut collector).unwrap();

    let findings = collector.findings();
    let has_auth_key = findings.iter().any(|f| matches!(f, Finding::SshAuthorizedKey(_)));
    assert!(has_auth_key, "expected at least one SshAuthorizedKey finding");
}

#[test]
fn linux_creds_extractor_emits_shadow_entry() {
    use abyss_output::collector::{Collector, OutputFormat};
    use abyss_output::finding::Finding;

    let shadow = b"root:$6$salt$hashhashhashhashhashhashhashhashhashhashhashhashhashhashhashhash:19000:0:99999:7:::\nalice:$6$salt2$hash2:19000:0:99999:7:::\n";
    let passwd = b"root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n";

    let mut ctx = ExtractionContext::new();
    ctx.filesystem_files.insert("etc/shadow".to_string(), shadow.to_vec());
    ctx.filesystem_files.insert("etc/passwd".to_string(), passwd.to_vec());

    let mut collector = Collector::new(OutputFormat::Text);
    LinuxCredsExtractor.extract(&mut ctx, &mut collector).unwrap();

    let findings = collector.findings();
    let shadow_entries: Vec<_> = findings.iter().filter(|f| matches!(f, Finding::ShadowEntry(_))).collect();
    assert_eq!(shadow_entries.len(), 2, "expected 2 shadow entries");

    if let Finding::ShadowEntry(e) = shadow_entries[0] {
        assert_eq!(e.username, "root");
        assert_eq!(e.hash_algorithm, "SHA-512");
        assert_eq!(e.uid, 0);
    }
}

#[test]
fn linux_creds_extractor_skips_locked_accounts() {
    use abyss_output::collector::{Collector, OutputFormat};
    use abyss_output::finding::Finding;

    let shadow = b"nologin:!:19000:0:99999:7:::\ndaemon:*:19000:0:99999:7:::\n";

    let mut ctx = ExtractionContext::new();
    ctx.filesystem_files.insert("etc/shadow".to_string(), shadow.to_vec());

    let mut collector = Collector::new(OutputFormat::Text);
    LinuxCredsExtractor.extract(&mut ctx, &mut collector).unwrap();

    let findings = collector.findings();
    let shadow_entries: Vec<_> = findings.iter().filter(|f| matches!(f, Finding::ShadowEntry(_))).collect();
    assert_eq!(shadow_entries.len(), 0, "locked/disabled accounts should be skipped");
}

#[test]
fn linux_creds_extractor_emits_aws_credential() {
    use abyss_output::collector::{Collector, OutputFormat};
    use abyss_output::finding::Finding;

    let aws_creds = b"[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n";

    let mut ctx = ExtractionContext::new();
    ctx.filesystem_files.insert("root/.aws/credentials".to_string(), aws_creds.to_vec());

    let mut collector = Collector::new(OutputFormat::Text);
    LinuxCredsExtractor.extract(&mut ctx, &mut collector).unwrap();

    let findings = collector.findings();
    let svc = findings.iter().find(|f| matches!(f, Finding::ServiceCredential(_)));
    assert!(svc.is_some(), "expected a ServiceCredential finding for AWS");
    if let Some(Finding::ServiceCredential(c)) = svc {
        assert_eq!(c.service, "AWS");
        assert_eq!(c.username, "AKIAIOSFODNN7EXAMPLE");
    }
}
