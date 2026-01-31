// SPDX-License-Identifier: Apache-2.0
//! TLS client configuration for TACACS+ (RFC 9887 compliant).
//!
//! # NIST SP 800-53 Rev. 5 Security Controls
//!
//! **Control Implementation Matrix**
//!
//! This module implements controls documented in
//! [../../../docs/NIST-CONTROLS-MAPPING.md](../../../docs/NIST-CONTROLS-MAPPING.md).
//!
//! | Control | Family | Status | Validated | Primary Functions |
//! |---------|--------|--------|-----------|-------------------|
//! | IA-3 | Identification and Authentication | Implemented | 2026-01-31 | See functions below |
//! | SC-13 | System and Communications Protection | Implemented | 2026-01-31 | See functions below |
//! | SC-17 | System and Communications Protection | Implemented | 2026-01-31 | See functions below |
//! | SC-23 | System and Communications Protection | Implemented | 2026-01-31 | See functions below |
//! | SC-8 | System and Communications Protection | Implemented | 2026-01-31 | See functions below |
//!
//! <details>
//! <summary><b>Validation Metadata (JSON)</b></summary>
//!
//! ```json
//! {
//!   "nist_framework": "NIST SP 800-53 Rev. 5",
//!   "software_version": "0.77.1",
//!   "last_validation": "2026-01-31",
//!   "control_families": [
//!     "IA",
//!     "SC"
//!   ],
//!   "total_controls": 5,
//!   "file_path": "crates/tacacs-client-tls/src/tls.rs"
//! }
//! ```
//!
//! </details>
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
//!   for server certificate verification.
//!
//! - **SC-23 (Session Authenticity)**: Supports mutual TLS (mTLS) for
//!   client authentication when configured.
//!
//! - **IA-3 (Device Identification and Authentication)**: Client certificates
//!   can be provided for device authentication.

use anyhow::{Context, Result, bail};
use std::path::Path;
use std::sync::Arc;
use tokio_rustls::rustls::{
    self, RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
};

/// TLS client configuration builder for TACACS+ connections.
///
/// # Example
///
/// ```ignore
/// let config = TlsClientConfig::builder()
///     .with_server_ca("./certs/ca.pem")?
///     .with_client_cert("./certs/client.pem", "./certs/client-key.pem")?
///     .build()?;
/// ```
#[derive(Debug)]
pub struct TlsClientConfigBuilder {
    root_certs: RootCertStore,
    client_cert: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
}

impl TlsClientConfigBuilder {
    /// Create a new TLS client configuration builder.
    pub fn new() -> Self {
        Self {
            root_certs: RootCertStore::empty(),
            client_cert: None,
        }
    }

    /// Add a CA certificate for server verification.
    ///
    /// Multiple CAs can be added by calling this method multiple times.
    ///
    /// # NIST Controls
    /// - **SC-17 (PKI Certificates)**: Server certificate chain validation
    pub fn with_server_ca<P: AsRef<Path>>(mut self, ca_path: P) -> Result<Self> {
        let certs = load_certs(ca_path.as_ref())?;
        for cert in certs {
            self.root_certs.add(cert).context("adding server CA")?;
        }
        Ok(self)
    }

    /// Set the client certificate and key for mutual TLS (mTLS).
    ///
    /// This is optional but recommended for device authentication.
    ///
    /// # NIST Controls
    /// - **SC-23 (Session Authenticity)**: Client authentication via certificate
    /// - **IA-3 (Device Identification)**: Device authentication to server
    pub fn with_client_cert<P: AsRef<Path>>(mut self, cert_path: P, key_path: P) -> Result<Self> {
        let certs = load_certs(cert_path.as_ref())?;
        let key = load_key(key_path.as_ref())?;
        self.client_cert = Some((certs, key));
        Ok(self)
    }

    /// Build the TLS client configuration.
    ///
    /// # NIST Controls
    /// - **SC-8 (Transmission Confidentiality)**: TLS 1.3 only, no protocol fallback
    /// - **SC-13 (Cryptographic Protection)**: Modern cipher suites with forward secrecy
    pub fn build(self) -> Result<TlsClientConfig> {
        if self.root_certs.is_empty() {
            bail!("at least one server CA certificate is required");
        }

        // NIST SC-8/SC-13: TLS 1.3 only - no fallback to older versions
        let config_builder =
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(self.root_certs);

        let config = if let Some((certs, key)) = self.client_cert {
            config_builder
                .with_client_auth_cert(certs, key)
                .context("configuring client certificate")?
        } else {
            config_builder.with_no_client_auth()
        };

        Ok(TlsClientConfig {
            inner: Arc::new(config),
        })
    }
}

impl Default for TlsClientConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// TLS client configuration for TACACS+ connections.
///
/// This configuration enforces TLS 1.3 per RFC 9887 requirements.
#[derive(Clone, Debug)]
pub struct TlsClientConfig {
    pub(crate) inner: Arc<rustls::ClientConfig>,
}

impl TlsClientConfig {
    /// Create a new configuration builder.
    pub fn builder() -> TlsClientConfigBuilder {
        TlsClientConfigBuilder::new()
    }

    /// Create a TLS connector for establishing connections.
    pub(crate) fn connector(&self) -> tokio_rustls::TlsConnector {
        tokio_rustls::TlsConnector::from(self.inner.clone())
    }

    /// Parse a server name for TLS SNI.
    pub(crate) fn parse_server_name(name: &str) -> Result<ServerName<'static>> {
        ServerName::try_from(name.to_string())
            .map_err(|_| anyhow::anyhow!("invalid server name: {}", name))
    }
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(path)
        .with_context(|| format!("opening certificate {}", path.display()))?
        .collect::<Result<_, _>>()
        .with_context(|| format!("reading certificates from {}", path.display()))?;
    if certs.is_empty() {
        bail!("no certificates found in {}", path.display());
    }
    Ok(certs)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path)
        .with_context(|| format!("reading private key from {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn init_crypto_provider() {
        use std::sync::Once;
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

    fn create_temp_file(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().expect("create temp file");
        file.write_all(content.as_bytes()).expect("write temp file");
        file.flush().expect("flush temp file");
        file
    }

    fn generate_valid_cert_and_key() -> (String, String) {
        let key_pair = KeyPair::generate().expect("generate key pair");
        let params = CertificateParams::new(vec!["localhost".to_string()])
            .expect("create certificate params");
        let cert = params
            .self_signed(&key_pair)
            .expect("self-sign certificate");
        (cert.pem(), key_pair.serialize_pem())
    }

    #[test]
    fn builder_requires_server_ca() {
        let result = TlsClientConfigBuilder::new().build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("CA"));
    }

    #[test]
    fn builder_with_server_ca_succeeds() {
        init_crypto_provider();
        let (cert_pem, _) = generate_valid_cert_and_key();
        let ca_file = create_temp_file(&cert_pem);

        let result = TlsClientConfig::builder()
            .with_server_ca(ca_file.path())
            .unwrap()
            .build();

        assert!(result.is_ok());
    }

    #[test]
    fn builder_with_client_cert_succeeds() {
        init_crypto_provider();
        let (cert_pem, key_pem) = generate_valid_cert_and_key();
        let ca_file = create_temp_file(&cert_pem);
        let cert_file = create_temp_file(&cert_pem);
        let key_file = create_temp_file(&key_pem);

        let result = TlsClientConfig::builder()
            .with_server_ca(ca_file.path())
            .unwrap()
            .with_client_cert(cert_file.path(), key_file.path())
            .unwrap()
            .build();

        assert!(result.is_ok());
    }

    #[test]
    fn parse_server_name_valid() {
        let result = TlsClientConfig::parse_server_name("example.com");
        assert!(result.is_ok());
    }

    #[test]
    fn parse_server_name_localhost() {
        let result = TlsClientConfig::parse_server_name("localhost");
        assert!(result.is_ok());
    }

    #[test]
    fn load_certs_nonexistent_fails() {
        let result = load_certs(Path::new("/nonexistent/path.pem"));
        assert!(result.is_err());
    }

    #[test]
    fn load_key_nonexistent_fails() {
        let result = load_key(Path::new("/nonexistent/path.pem"));
        assert!(result.is_err());
    }

    #[test]
    fn load_certs_empty_file_fails() {
        let empty_file = create_temp_file("");
        let result = load_certs(empty_file.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no certificates"));
    }

    #[test]
    fn load_key_empty_file_fails() {
        let empty_file = create_temp_file("");
        let result = load_key(empty_file.path());
        assert!(result.is_err());
        // Error message changed with rustls-pki-types migration
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("private key") || err_msg.contains("PEM"));
    }
}
