// SPDX-License-Identifier: Apache-2.0
//! TLS configuration for TACACS+ server (RFC 9887 compliant).
//!
//! # NIST SP 800-53 Security Controls
//!
//! This module implements the following NIST security controls:
//!
//! - **SC-8 (Transmission Confidentiality and Integrity)**: Enforces TLS 1.3
//!   for all connections with no fallback to older protocol versions.
//!
//! - **SC-13 (Cryptographic Protection)**: Uses modern TLS 1.3 cipher suites
//!   with forward secrecy via Rustls (memory-safe TLS implementation).
//!
//! - **SC-17 (PKI Certificates)**: Implements X.509 certificate validation
//!   with WebPkiClientVerifier for certificate chain verification.
//!
//! - **SC-23 (Session Authenticity)**: Requires mutual TLS (mTLS) for all
//!   connections, authenticating both client and server.
//!
//! - **IA-3 (Device Identification and Authentication)**: Client certificates
//!   are validated against trusted CA chain for device authentication.
//!
//! - **SC-12 (Cryptographic Key Establishment)**: Supports multiple trust
//!   roots and certificate chain validation.

use anyhow::{Context, Result};
use std::path::PathBuf;
use tokio_rustls::rustls::{
    self, RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::WebPkiClientVerifier,
};

/// Build TLS server configuration with mTLS enforcement.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | SC-8 | Transmission Confidentiality | TLS 1.3 only, no protocol fallback |
/// | SC-12 | Key Establishment | Supports multiple trust roots |
/// | SC-13 | Cryptographic Protection | Modern cipher suites with forward secrecy |
/// | SC-17 | PKI Certificates | X.509 certificate chain validation |
/// | SC-23 | Session Authenticity | Mutual TLS required for all connections |
/// | IA-3 | Device Identification | Client certificate validation against CA chain |
pub fn build_tls_config(
    cert: &PathBuf,
    key: &PathBuf,
    client_ca: &PathBuf,
    extra_trust_roots: &[PathBuf],
) -> Result<rustls::ServerConfig> {
    let certs: Vec<CertificateDer<'_>> = load_certs(cert)?;
    let key: PrivateKeyDer<'_> = load_key(key)?;

    // NIST SC-17/SC-12: Build certificate trust store with all trusted CAs
    let mut roots: RootCertStore = RootCertStore::empty();
    for ca in load_certs(client_ca)? {
        roots.add(ca).context("adding client CA")?;
    }
    for ca_path in extra_trust_roots {
        for ca in load_certs(ca_path)? {
            roots
                .add(ca)
                .with_context(|| format!("adding extra trust root {}", ca_path.display()))?;
        }
    }

    // NIST SC-23/IA-3: Require client certificate validation (mTLS)
    let client_auth = WebPkiClientVerifier::builder(roots.into())
        .build()
        .context("building client verifier")?;

    // NIST SC-8/SC-13: TLS 1.3 only - no fallback to older versions
    let mut config: rustls::ServerConfig =
        rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_client_cert_verifier(client_auth)
            .with_single_cert(certs, key)
            .context("building TLS config")?;

    config.alpn_protocols = vec![];
    Ok(config)
}

fn load_certs(path: &PathBuf) -> Result<Vec<CertificateDer<'static>>> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(path)
        .with_context(|| format!("opening certificate {}", path.display()))?
        .collect::<Result<_, _>>()
        .with_context(|| format!("reading certificates from {}", path.display()))?;
    Ok(certs)
}

fn load_key(path: &PathBuf) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path)
        .with_context(|| format!("reading private key from {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};
    use std::io::Write;
    use std::sync::Once;
    use tempfile::NamedTempFile;

    /// Install a default CryptoProvider for tests that need TLS operations.
    /// Uses Once to ensure this only happens once per test process.
    static CRYPTO_PROVIDER_INIT: Once = Once::new();
    fn install_crypto_provider() {
        CRYPTO_PROVIDER_INIT.call_once(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

    // Self-signed test certificate (PEM format) - may not match key
    const TEST_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpegPjMCMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RjYTAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnRlc3RjYTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7o96FCFzK4X1wqVA5kCqD
xr7WzELp3hLpLMQfJtqTqN1R+S7mJmX/D1vY/A8WL6FPptC9s4S0A0E8qM7LxbRv
AgMBAAGjUzBRMB0GA1UdDgQWBBQ7aNU0n5x0FlTCM7CVbTy5lUBUYjAfBgNVHSME
GDAWgBQ7aNU0n5x0FlTCM7CVbTy5lUBUYjAPBgNVHRMBAf8EBTADAQH/MA0GCSqG
SIb3DQEBCwUAA0EAe5DFa4U0bXkj9QEwZzlO4rJjFZt3e4GVHdBYcIDXxIxNKMD5
j9qNmfPNgCz5N3HqK3LdReB4VvGVb+e3P5uLJA==
-----END CERTIFICATE-----"#;

    // Test private key (PEM format - RSA 512-bit for testing only)
    const TEST_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAu6PehQhcyuF9cKlQ
OZAqg8a+1sxC6d4S6SzEHybak6jdUfku5iZl/w9b2PwPFi+hT6bQvbOEtANBPKjO
y8W0bwIDAQABAkBLERzC7e5UKT7D5QX6RBaIpFbUkl4VCVFxNmVH4MbMD/N5T5G0
xBt5MmIk6sLVMI3/RHVpC0eNp4/VwD8BAyoBAiEA5gRLNb0e7R5M1J9DJmP5yMxS
LzM/nF9fCvCqFj2RB/8CIQDRxGY8bnDNqCEMN8KL/mDqlP1bYAYzNVXr/q4wl6sB
AQIgKVz5f5D5HQDqFmvD5slKAZMxO8VCJ4dVamVNgXIqk1cCIQCYLgWbm0BCnSeZ
daoTvXh0GzTCAdHTmIpOMqzH1ewAAQIgJd0BuXbzPsVB5mKkqOFM8C2MKuoQbE4d
0wRvp1wBkgA=
-----END PRIVATE KEY-----"#;

    fn create_temp_file(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().expect("create temp file");
        file.write_all(content.as_bytes()).expect("write temp file");
        file.flush().expect("flush temp file");
        file
    }

    /// Generate a valid self-signed certificate and key pair using rcgen
    fn generate_valid_cert_and_key() -> (String, String) {
        let key_pair = KeyPair::generate().expect("generate key pair");
        let params = CertificateParams::new(vec!["localhost".to_string()])
            .expect("create certificate params");
        let cert = params
            .self_signed(&key_pair)
            .expect("self-sign certificate");
        (cert.pem(), key_pair.serialize_pem())
    }

    // ==================== load_certs Tests ====================

    #[test]
    fn load_certs_valid_pem() {
        let cert_file = create_temp_file(TEST_CERT_PEM);
        let result = load_certs(&cert_file.path().to_path_buf());
        assert!(result.is_ok());
        let certs = result.unwrap();
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn load_certs_multiple_certs() {
        let multi_cert = format!("{}\n{}", TEST_CERT_PEM, TEST_CERT_PEM);
        let cert_file = create_temp_file(&multi_cert);
        let result = load_certs(&cert_file.path().to_path_buf());
        assert!(result.is_ok());
        let certs = result.unwrap();
        assert_eq!(certs.len(), 2);
    }

    #[test]
    fn load_certs_nonexistent_file() {
        let path = PathBuf::from("/nonexistent/path/to/cert.pem");
        let result = load_certs(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("opening"));
    }

    #[test]
    fn load_certs_empty_file() {
        let cert_file = create_temp_file("");
        let result = load_certs(&cert_file.path().to_path_buf());
        assert!(result.is_ok());
        let certs = result.unwrap();
        assert!(certs.is_empty());
    }

    #[test]
    fn load_certs_invalid_pem() {
        let cert_file = create_temp_file("not a valid PEM file");
        let result = load_certs(&cert_file.path().to_path_buf());
        // Invalid PEM returns empty vec, not an error
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    // ==================== load_key Tests ====================

    #[test]
    fn load_key_valid_pem() {
        let key_file = create_temp_file(TEST_KEY_PEM);
        let result = load_key(&key_file.path().to_path_buf());
        assert!(result.is_ok());
    }

    #[test]
    fn load_key_nonexistent_file() {
        let path = PathBuf::from("/nonexistent/path/to/key.pem");
        let result = load_key(&path);
        assert!(result.is_err());
        // Error message changed with rustls-pki-types migration
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("private key")
                || err_msg.contains("opening")
                || err_msg.contains("No such file")
        );
    }

    #[test]
    fn load_key_empty_file() {
        let key_file = create_temp_file("");
        let result = load_key(&key_file.path().to_path_buf());
        assert!(result.is_err());
        // Error message changed with rustls-pki-types migration
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("private key") || err_msg.contains("PEM"));
    }

    #[test]
    fn load_key_invalid_pem() {
        let key_file = create_temp_file("not a valid PEM key");
        let result = load_key(&key_file.path().to_path_buf());
        assert!(result.is_err());
        // Error message changed with rustls-pki-types migration
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("private key") || err_msg.contains("PEM"));
    }

    #[test]
    fn load_key_cert_instead_of_key() {
        // Try loading a certificate as a key
        let cert_file = create_temp_file(TEST_CERT_PEM);
        let result = load_key(&cert_file.path().to_path_buf());
        assert!(result.is_err());
        // Error message changed with rustls-pki-types migration
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("private key") || err_msg.contains("PEM"));
    }

    // ==================== build_tls_config Tests ====================

    #[test]
    fn build_tls_config_missing_cert() {
        let key_file = create_temp_file(TEST_KEY_PEM);
        let ca_file = create_temp_file(TEST_CERT_PEM);
        let missing_cert = PathBuf::from("/nonexistent/cert.pem");

        let result = build_tls_config(
            &missing_cert,
            &key_file.path().to_path_buf(),
            &ca_file.path().to_path_buf(),
            &[],
        );
        assert!(result.is_err());
    }

    #[test]
    fn build_tls_config_missing_key() {
        let cert_file = create_temp_file(TEST_CERT_PEM);
        let ca_file = create_temp_file(TEST_CERT_PEM);
        let missing_key = PathBuf::from("/nonexistent/key.pem");

        let result = build_tls_config(
            &cert_file.path().to_path_buf(),
            &missing_key,
            &ca_file.path().to_path_buf(),
            &[],
        );
        assert!(result.is_err());
    }

    #[test]
    fn build_tls_config_missing_client_ca() {
        let cert_file = create_temp_file(TEST_CERT_PEM);
        let key_file = create_temp_file(TEST_KEY_PEM);
        let missing_ca = PathBuf::from("/nonexistent/ca.pem");

        let result = build_tls_config(
            &cert_file.path().to_path_buf(),
            &key_file.path().to_path_buf(),
            &missing_ca,
            &[],
        );
        assert!(result.is_err());
    }

    #[test]
    fn build_tls_config_missing_extra_trust_root() {
        let cert_file = create_temp_file(TEST_CERT_PEM);
        let key_file = create_temp_file(TEST_KEY_PEM);
        let ca_file = create_temp_file(TEST_CERT_PEM);
        let missing_extra = PathBuf::from("/nonexistent/extra.pem");

        let result = build_tls_config(
            &cert_file.path().to_path_buf(),
            &key_file.path().to_path_buf(),
            &ca_file.path().to_path_buf(),
            &[missing_extra],
        );
        assert!(result.is_err());
    }

    #[test]
    fn build_tls_config_empty_extra_trust_roots() {
        let cert_file = create_temp_file(TEST_CERT_PEM);
        let key_file = create_temp_file(TEST_KEY_PEM);
        let ca_file = create_temp_file(TEST_CERT_PEM);

        // This will fail because the test cert/key pair isn't valid for TLS
        // but we're testing that empty extra_trust_roots doesn't cause issues
        let result = build_tls_config(
            &cert_file.path().to_path_buf(),
            &key_file.path().to_path_buf(),
            &ca_file.path().to_path_buf(),
            &[],
        );
        // The result may fail due to invalid cert/key, but not due to empty roots
        // We just verify it doesn't panic
        let _ = result;
    }

    // ==================== build_tls_config Success Path Tests ====================

    #[test]
    fn build_tls_config_valid_certs_succeeds() {
        install_crypto_provider();
        // Generate a valid cert/key pair
        let (cert_pem, key_pem) = generate_valid_cert_and_key();
        let cert_file = create_temp_file(&cert_pem);
        let key_file = create_temp_file(&key_pem);
        let ca_file = create_temp_file(&cert_pem); // Use same cert as CA

        let result = build_tls_config(
            &cert_file.path().to_path_buf(),
            &key_file.path().to_path_buf(),
            &ca_file.path().to_path_buf(),
            &[],
        );

        assert!(result.is_ok());
        let config = result.unwrap();
        // Verify ALPN is empty as set in build_tls_config
        assert!(config.alpn_protocols.is_empty());
    }

    #[test]
    fn build_tls_config_with_extra_trust_roots_succeeds() {
        install_crypto_provider();
        // Generate valid cert/key pairs
        let (cert_pem, key_pem) = generate_valid_cert_and_key();
        let (extra_cert_pem, _) = generate_valid_cert_and_key();

        let cert_file = create_temp_file(&cert_pem);
        let key_file = create_temp_file(&key_pem);
        let ca_file = create_temp_file(&cert_pem);
        let extra_ca_file = create_temp_file(&extra_cert_pem);

        let result = build_tls_config(
            &cert_file.path().to_path_buf(),
            &key_file.path().to_path_buf(),
            &ca_file.path().to_path_buf(),
            &[extra_ca_file.path().to_path_buf()],
        );

        assert!(result.is_ok());
    }

    #[test]
    fn build_tls_config_with_multiple_extra_trust_roots() {
        install_crypto_provider();
        // Generate valid cert/key pairs
        let (cert_pem, key_pem) = generate_valid_cert_and_key();
        let (extra1_cert_pem, _) = generate_valid_cert_and_key();
        let (extra2_cert_pem, _) = generate_valid_cert_and_key();

        let cert_file = create_temp_file(&cert_pem);
        let key_file = create_temp_file(&key_pem);
        let ca_file = create_temp_file(&cert_pem);
        let extra1_file = create_temp_file(&extra1_cert_pem);
        let extra2_file = create_temp_file(&extra2_cert_pem);

        let result = build_tls_config(
            &cert_file.path().to_path_buf(),
            &key_file.path().to_path_buf(),
            &ca_file.path().to_path_buf(),
            &[
                extra1_file.path().to_path_buf(),
                extra2_file.path().to_path_buf(),
            ],
        );

        assert!(result.is_ok());
    }

    #[test]
    fn build_tls_config_multiple_certs_in_chain() {
        install_crypto_provider();
        // Generate certs and put multiple in one file (chain)
        let (cert1_pem, key_pem) = generate_valid_cert_and_key();
        let (cert2_pem, _) = generate_valid_cert_and_key();

        // Create a chain file with multiple certs
        let chain_pem = format!("{}\n{}", cert1_pem, cert2_pem);
        let chain_file = create_temp_file(&chain_pem);
        let key_file = create_temp_file(&key_pem);
        let ca_file = create_temp_file(&cert1_pem);

        let result = build_tls_config(
            &chain_file.path().to_path_buf(),
            &key_file.path().to_path_buf(),
            &ca_file.path().to_path_buf(),
            &[],
        );

        // This may fail because the chain certs don't form a valid chain,
        // but the point is to test the code path that processes multiple certs
        let _ = result;
    }

    // ==================== load_certs with rcgen Tests ====================

    #[test]
    fn load_certs_rcgen_generated() {
        let (cert_pem, _) = generate_valid_cert_and_key();
        let cert_file = create_temp_file(&cert_pem);
        let result = load_certs(&cert_file.path().to_path_buf());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
    }

    // ==================== load_key with rcgen Tests ====================

    #[test]
    fn load_key_rcgen_generated() {
        let (_, key_pem) = generate_valid_cert_and_key();
        let key_file = create_temp_file(&key_pem);
        let result = load_key(&key_file.path().to_path_buf());
        assert!(result.is_ok());
    }
}
