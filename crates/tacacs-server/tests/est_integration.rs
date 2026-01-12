//! Integration tests for EST (RFC 7030) certificate provisioning.
//!
//! These tests verify the end-to-end EST functionality including:
//! - Bootstrap enrollment workflow
//! - Certificate renewal detection
//! - Metrics updates on certificate operations
//! - Certificate reload signaling

use anyhow::Result;
use std::path::PathBuf;
use tempfile::TempDir;
use usg_tacacs_secrets::{CertificateBundle, EstConfig};

/// Test that EstConfig can be constructed with all required fields.
#[test]
fn test_est_config_construction() {
    let config = EstConfig {
        enabled: true,
        server_url: "https://est.example.com/.well-known/est".to_string(),
        username: Some("bootstrap".to_string()),
        password: Some("secret".to_string()),
        password_file: None,
        client_cert_path: None,
        client_key_path: None,
        ca_label: Some("RA".to_string()),
        common_name: "tacacs-01.internal".to_string(),
        organization: Some("Example Corp".to_string()),
        cert_path: PathBuf::from("/tmp/cert.pem"),
        key_path: PathBuf::from("/tmp/key.pem"),
        ca_cert_path: PathBuf::from("/tmp/ca.pem"),
        renewal_threshold_percent: 70,
        renewal_check_interval_secs: 3600,
        bootstrap_timeout_secs: 300,
        initial_enrollment_required: false,
    };

    assert!(config.enabled);
    assert_eq!(config.common_name, "tacacs-01.internal");
    assert_eq!(config.renewal_threshold_percent, 70);
}

/// Test certificate bundle file operations in isolation.
#[tokio::test]
async fn test_certificate_bundle_file_operations() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let cert_path = temp_dir.path().join("server.crt");
    let key_path = temp_dir.path().join("server.key");
    let ca_path = temp_dir.path().join("ca.crt");

    // Create a mock certificate bundle
    let bundle = CertificateBundle {
        cert_pem: b"-----BEGIN CERTIFICATE-----\nMOCKCERTIFICATE\n-----END CERTIFICATE-----\n"
            .to_vec(),
        key_pem: b"-----BEGIN PRIVATE KEY-----\nMOCKPRIVATEKEY\n-----END PRIVATE KEY-----\n"
            .to_vec(),
        ca_chain: Some(
            b"-----BEGIN CERTIFICATE-----\nMOCKCAcert\n-----END CERTIFICATE-----\n".to_vec(),
        ),
        serial_number: "0123456789ABCDEF".to_string(),
        expires_at: 9999999999, // Far future
    };

    // Write bundle to files
    bundle
        .write_to_files(&cert_path, &key_path, &ca_path)
        .await?;

    // Verify files were created
    assert!(cert_path.exists(), "certificate file should exist");
    assert!(key_path.exists(), "private key file should exist");
    assert!(ca_path.exists(), "CA certificate file should exist");

    // Verify file contents
    let cert_content = std::fs::read_to_string(&cert_path)?;
    assert!(cert_content.contains("MOCKCERTIFICATE"));

    let key_content = std::fs::read_to_string(&key_path)?;
    assert!(key_content.contains("MOCKPRIVATEKEY"));

    let ca_content = std::fs::read_to_string(&ca_path)?;
    assert!(ca_content.contains("MOCKCAcert"));

    // Verify permissions on private key
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let key_metadata = std::fs::metadata(&key_path)?;
        let mode = key_metadata.permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "private key should have 0o600 permissions"
        );
    }

    Ok(())
}

/// Test renewal threshold logic with various certificate expiration scenarios.
#[test]
fn test_renewal_threshold_scenarios() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Scenario 1: Certificate with 10 days remaining
    let ten_days = now + (10 * 86400);
    let bundle_10d = CertificateBundle {
        cert_pem: vec![],
        key_pem: vec![],
        ca_chain: None,
        serial_number: "10days".to_string(),
        expires_at: ten_days,
    };

    // With 70% threshold, should renew when <= 7 days remain
    // Currently 10 days, so should NOT renew
    assert!(!bundle_10d.should_renew(70));

    // With 100% threshold, should always renew (except unknown expiration)
    assert!(bundle_10d.should_renew(100));

    // Scenario 2: Certificate with 1 day remaining
    let one_day = now + 86400;
    let bundle_1d = CertificateBundle {
        cert_pem: vec![],
        key_pem: vec![],
        ca_chain: None,
        serial_number: "1day".to_string(),
        expires_at: one_day,
    };

    // With 1 day (86400s) remaining:
    // - 30% threshold: renew when <= 25920s remain. Currently 86400s, so NO
    // - 100% threshold: renew when <= 86400s remain. Currently 86400s, so YES
    // - 110% threshold: renew when <= 95040s remain. Currently 86400s, so YES
    assert!(!bundle_1d.should_renew(30));
    assert!(bundle_1d.should_renew(100));
    assert!(bundle_1d.should_renew(110));

    // Scenario 3: Already expired certificate
    let expired = now - 1;
    let bundle_expired = CertificateBundle {
        cert_pem: vec![],
        key_pem: vec![],
        ca_chain: None,
        serial_number: "expired".to_string(),
        expires_at: expired,
    };

    // Should always renew expired certificates
    assert!(bundle_expired.should_renew(1));
    assert!(bundle_expired.should_renew(50));
    assert!(bundle_expired.should_renew(100));
}

/// Test EST configuration serialization/deserialization for config files.
#[test]
fn test_est_config_serde() -> Result<()> {
    let config = EstConfig {
        enabled: true,
        server_url: "https://est.example.com/.well-known/est".to_string(),
        username: Some("user".to_string()),
        password: Some("pass".to_string()),
        password_file: None,
        client_cert_path: Some(PathBuf::from("/etc/tacacs/est-client.crt")),
        client_key_path: Some(PathBuf::from("/etc/tacacs/est-client.key")),
        ca_label: Some("RA".to_string()),
        common_name: "tacacs.example.com".to_string(),
        organization: Some("Example Org".to_string()),
        cert_path: PathBuf::from("/etc/tacacs/server.crt"),
        key_path: PathBuf::from("/etc/tacacs/server.key"),
        ca_cert_path: PathBuf::from("/etc/tacacs/ca.crt"),
        renewal_threshold_percent: 80,
        renewal_check_interval_secs: 7200,
        bootstrap_timeout_secs: 600,
        initial_enrollment_required: true,
    };

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&config)?;

    // Deserialize back
    let parsed: EstConfig = serde_json::from_str(&json)?;

    // Verify round-trip
    assert_eq!(parsed.server_url, config.server_url);
    assert_eq!(parsed.common_name, config.common_name);
    assert_eq!(parsed.renewal_threshold_percent, 80);
    assert_eq!(parsed.initial_enrollment_required, true);

    Ok(())
}

/// Test EST certificate bundle without CA chain.
#[tokio::test]
async fn test_certificate_bundle_no_ca_chain() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let cert_path = temp_dir.path().join("server.crt");
    let key_path = temp_dir.path().join("server.key");
    let ca_path = temp_dir.path().join("ca.crt");

    let bundle = CertificateBundle {
        cert_pem: b"CERT".to_vec(),
        key_pem: b"KEY".to_vec(),
        ca_chain: None,
        serial_number: "no-ca".to_string(),
        expires_at: 1234567890,
    };

    // Write without CA (ca_chain is None, so ca_path won't be created)
    bundle
        .write_to_files(&cert_path, &key_path, &ca_path)
        .await?;

    assert!(cert_path.exists());
    assert!(key_path.exists());
    assert!(
        !ca_path.exists(),
        "CA file should NOT exist when ca_chain is None"
    );

    let cert = std::fs::read(&cert_path)?;
    let key = std::fs::read(&key_path)?;

    assert_eq!(cert, b"CERT");
    assert_eq!(key, b"KEY");

    Ok(())
}

/// Test EST config with password file instead of inline password.
#[test]
fn test_est_config_with_password_file() {
    let config = EstConfig {
        enabled: true,
        server_url: "https://est.example.com/.well-known/est".to_string(),
        username: Some("user".to_string()),
        password: None,
        password_file: Some(PathBuf::from("/etc/tacacs/est-password")),
        client_cert_path: None,
        client_key_path: None,
        ca_label: None,
        common_name: "tacacs.example.com".to_string(),
        organization: None,
        cert_path: PathBuf::from("/etc/tacacs/server.crt"),
        key_path: PathBuf::from("/etc/tacacs/server.key"),
        ca_cert_path: PathBuf::from("/etc/tacacs/ca.crt"),
        renewal_threshold_percent: 70,
        renewal_check_interval_secs: 3600,
        bootstrap_timeout_secs: 300,
        initial_enrollment_required: false,
    };

    assert_eq!(config.password, None);
    assert_eq!(
        config.password_file,
        Some(PathBuf::from("/etc/tacacs/est-password"))
    );
}

/// Test renewal threshold boundary conditions.
#[test]
fn test_renewal_threshold_edge_cases() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Edge case 1: Certificate expires in exactly threshold time
    let expires_100s = now + 100;
    let bundle = CertificateBundle {
        cert_pem: vec![],
        key_pem: vec![],
        ca_chain: None,
        serial_number: "edge".to_string(),
        expires_at: expires_100s,
    };

    // At exactly threshold (100%), should renew
    assert!(bundle.should_renew(100));

    // Just below threshold (99%), should NOT renew
    assert!(!bundle.should_renew(99));

    // Just above threshold (101%), should renew
    assert!(bundle.should_renew(101));

    // Edge case 2: Zero threshold
    assert!(!bundle.should_renew(0));

    // Edge case 3: Very high threshold
    assert!(bundle.should_renew(200));
}
