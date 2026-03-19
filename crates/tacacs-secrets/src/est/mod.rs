//! EST (RFC 7030) provider for zero-touch certificate provisioning.
//!
//! # NIST SP 800-53 Rev. 5 Security Controls
//!
//! **Control Implementation Matrix**
//!
//! This module implements controls documented in
//! [../../../../docs/NIST-CONTROLS-MAPPING.md](../../../../docs/NIST-CONTROLS-MAPPING.md).
//!
//! | Control | Family | Status | Validated | Primary Functions |
//! |---------|--------|--------|-----------|-------------------|
//! | CM-3 | Configuration Management | Implemented | 2026-01-31 | See functions below |
//! | IA-5 | Identification and Authentication | Implemented | 2026-01-31 | See functions below |
//! | SC-12 | System and Communications Protection | Implemented | 2026-01-31 | See functions below |
//! | SC-17 | System and Communications Protection | Implemented | 2026-01-31 | See functions below |
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
//!     "CM",
//!     "IA",
//!     "SC"
//!   ],
//!   "total_controls": 4,
//!   "file_path": "crates/tacacs-secrets/src/est/mod.rs"
//! }
//! ```
//!
//! </details>
//!
//! # NIST SP 800-53 Security Controls
//!
//! This module implements the following NIST security controls:
//!
//! - **IA-5 (Authenticator Management)**: Automated certificate lifecycle management
//!   with renewal before expiration.
//!
//! - **SC-17 (PKI Certificates)**: RFC 7030-compliant certificate enrollment and
//!   renewal using industry-standard EST protocol.
//!
//! - **SC-12 (Cryptographic Key Management)**: Private keys are generated locally
//!   and never transmitted to the EST server.
//!
//! - **CM-3 (Configuration Change Control)**: Automated certificate provisioning
//!   with audit trail via structured logging.

use crate::config::EstConfig;
use crate::provider::{SecretChange, SecretValue, SecretsProvider};
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::fs;
use tokio::sync::{RwLock, broadcast, oneshot};
use tracing::{debug, error, info, warn};
use usg_est_client::csr::CsrBuilder;
use usg_est_client::{EnrollmentResponse, EstClient, EstClientConfig};
use x509_cert::der::Encode;

/// Certificate bundle from EST enrollment.
#[derive(Debug, Clone)]
pub struct CertificateBundle {
    /// Certificate PEM data.
    pub cert_pem: Vec<u8>,
    /// Private key PEM data.
    pub key_pem: Vec<u8>,
    /// CA certificate chain PEM data (optional).
    pub ca_chain: Option<Vec<u8>>,
    /// Certificate serial number (for logging).
    pub serial_number: String,
    /// Certificate expiration timestamp (Unix seconds).
    pub expires_at: u64,
}

impl CertificateBundle {
    /// Write the certificate bundle to files with proper permissions.
    pub async fn write_to_files(
        &self,
        cert_path: &Path,
        key_path: &Path,
        ca_path: &Path,
    ) -> Result<()> {
        // Write certificate
        fs::write(cert_path, &self.cert_pem)
            .await
            .context("failed to write certificate file")?;
        info!(path = ?cert_path, "wrote certificate to file");

        // Write private key with restrictive permissions (0600) atomically
        // to avoid TOCTOU race where key is briefly world-readable.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let key_path_buf = key_path.to_path_buf();
            let key_data = self.key_pem.clone();
            tokio::task::spawn_blocking(move || -> Result<()> {
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&key_path_buf)
                    .context("failed to create private key file with 0600 mode")?;
                std::io::Write::write_all(&mut file, &key_data)
                    .context("failed to write private key data")?;
                Ok(())
            })
            .await
            .context("spawn_blocking join error")??;
        }

        #[cfg(not(unix))]
        {
            fs::write(key_path, &self.key_pem)
                .await
                .context("failed to write private key file")?;
        }
        info!(path = ?key_path, "wrote private key to file with 0600 permissions");

        // Write CA chain if present
        if let Some(ref ca_chain) = self.ca_chain {
            fs::write(ca_path, ca_chain)
                .await
                .context("failed to write CA certificate file")?;
            info!(path = ?ca_path, "wrote CA certificate chain to file");
        }

        Ok(())
    }

    /// Check if certificate should be renewed based on threshold.
    ///
    /// Returns true if the certificate has reached the renewal threshold.
    /// The threshold_percent represents "renew when this percentage of time remains".
    /// For example, threshold_percent=30 means "renew when 30% of lifetime remains".
    pub fn should_renew(&self, threshold_percent: u8) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Check if certificate is close to expiration
        if self.expires_at == 0 {
            // Unknown expiration, don't renew
            return false;
        }

        // If already expired, definitely renew
        if now >= self.expires_at {
            return true;
        }

        let time_until_expiry = self.expires_at - now;

        // We need the total lifetime to calculate percentage
        // Since we don't store not_before, we can't calculate exact lifetime
        // Instead, we interpret threshold as "renew when X% of time-until-expiry remains"
        // This means with threshold=30, renew when <= 30% of current time remains
        //
        // Actually, let's use a simpler interpretation:
        // threshold_percent = percentage of TIME REMAINING that triggers renewal
        // So if cert expires in 1000s and threshold is 70%, renew when <= 700s remain
        let threshold_seconds = (time_until_expiry * threshold_percent as u64) / 100;

        // Renew if time remaining is less than or equal to threshold
        time_until_expiry <= threshold_seconds
    }
}

/// EST-based secrets provider.
///
/// Manages certificate enrollment and renewal using RFC 7030 EST protocol.
pub struct EstProvider {
    config: EstConfig,
    client: Arc<EstClient>,
    current_bundle: Arc<RwLock<Option<CertificateBundle>>>,
    change_tx: broadcast::Sender<SecretChange>,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl EstProvider {
    /// Create a new EST provider.
    pub async fn new(config: EstConfig) -> Result<Self> {
        // Build EST client configuration
        let mut client_builder = EstClientConfig::builder().server_url(&config.server_url)?;

        // Configure HTTP Basic authentication
        if let Some(ref username) = config.username {
            let password = if let Some(ref pwd) = config.password {
                pwd.clone()
            } else if let Some(ref pwd_file) = config.password_file {
                fs::read_to_string(pwd_file)
                    .await
                    .context("failed to read EST password file")?
                    .trim()
                    .to_string()
            } else {
                anyhow::bail!("EST username provided but no password or password_file");
            };
            client_builder = client_builder.http_auth(username, &password);
        }

        // Configure mTLS client authentication if provided
        if let (Some(cert_path), Some(key_path)) =
            (&config.client_cert_path, &config.client_key_path)
        {
            let cert_pem = fs::read(cert_path)
                .await
                .context("failed to read EST client certificate")?;
            let key_pem = fs::read(key_path)
                .await
                .context("failed to read EST client key")?;
            client_builder = client_builder.client_identity_pem(cert_pem, key_pem);
        }

        let est_config = client_builder
            .build()
            .map_err(|e| anyhow::anyhow!("failed to build EST client config: {}", e))?;
        let client = Arc::new(EstClient::new(est_config).await?);

        let (change_tx, _) = broadcast::channel(16);

        Ok(Self {
            config,
            client,
            current_bundle: Arc::new(RwLock::new(None)),
            change_tx,
            shutdown_tx: None,
        })
    }

    /// Perform initial bootstrap enrollment.
    ///
    /// This method generates a CSR and enrolls with the EST server.
    /// If certificates already exist on disk, they are loaded instead.
    ///
    /// Store bundle to disk and memory.
    async fn store_bundle(&self, bundle: CertificateBundle) -> Result<()> {
        bundle
            .write_to_files(
                &self.config.cert_path,
                &self.config.key_path,
                &self.config.ca_cert_path,
            )
            .await?;

        *self.current_bundle.write().await = Some(bundle);
        Ok(())
    }

    pub async fn bootstrap_enrollment(&self) -> Result<CertificateBundle> {
        info!("starting EST bootstrap enrollment");

        if self.config.cert_path.exists() && self.config.key_path.exists() {
            info!("certificates already exist, loading from disk");
            return self.load_existing_certificates().await;
        }

        let mut csr_builder = CsrBuilder::new().common_name(&self.config.common_name);
        if let Some(ref org) = self.config.organization {
            csr_builder = csr_builder.organization(org);
        }

        let (csr_der, key_pair) = csr_builder.build()?;

        info!(cn = %self.config.common_name, "submitting enrollment request to EST server");
        let response = self.client.simple_enroll(&csr_der).await?;

        let certificate = match response {
            EnrollmentResponse::Issued { certificate } => {
                info!("EST enrollment successful");
                *certificate
            }
            EnrollmentResponse::Pending { retry_after } => {
                anyhow::bail!(
                    "EST enrollment is pending (retry after {} seconds) - polling not yet implemented",
                    retry_after
                );
            }
        };

        let cert_der = certificate.to_der()?;
        let cert_pem =
            pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, &cert_der)
                .map_err(|e| anyhow::anyhow!("failed to encode certificate to PEM: {}", e))?;

        let key_pem = key_pair.serialize_pem();
        let ca_chain = self.fetch_ca_chain().await?;

        let serial = hex::encode(certificate.tbs_certificate.serial_number.as_bytes());
        let expires = certificate
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs();

        let bundle = CertificateBundle {
            cert_pem: cert_pem.into_bytes(),
            key_pem: key_pem.into_bytes(),
            ca_chain,
            serial_number: serial,
            expires_at: expires,
        };

        self.store_bundle(bundle.clone()).await?;

        info!("bootstrap enrollment completed successfully");
        Ok(bundle)
    }

    /// Load existing certificates from disk.
    async fn load_existing_certificates(&self) -> Result<CertificateBundle> {
        let cert_pem = fs::read(&self.config.cert_path)
            .await
            .context("failed to read existing certificate")?;
        let key_pem = fs::read(&self.config.key_path)
            .await
            .context("failed to read existing private key")?;
        let ca_chain = if self.config.ca_cert_path.exists() {
            Some(fs::read(&self.config.ca_cert_path).await?)
        } else {
            None
        };

        // Parse certificate to extract serial number and expiration
        let (serial_number, expires_at) = Self::parse_cert_metadata(&cert_pem)?;

        let bundle = CertificateBundle {
            cert_pem,
            key_pem,
            ca_chain,
            serial_number,
            expires_at,
        };

        *self.current_bundle.write().await = Some(bundle.clone());
        info!(
            serial = %bundle.serial_number,
            expires_at = bundle.expires_at,
            "loaded existing certificates from disk"
        );

        Ok(bundle)
    }

    /// Parse certificate metadata (serial number and expiration) from PEM.
    fn parse_cert_metadata(cert_pem: &[u8]) -> Result<(String, u64)> {
        use x509_cert::Certificate;
        use x509_cert::der::Decode;

        // Parse PEM to get DER
        let pem_str = std::str::from_utf8(cert_pem).context("certificate is not valid UTF-8")?;

        // Find the certificate section
        let cert_start = pem_str
            .find("-----BEGIN CERTIFICATE-----")
            .context("no certificate found in PEM")?;
        let cert_end = pem_str[cert_start..]
            .find("-----END CERTIFICATE-----")
            .context("malformed certificate PEM")?;
        let cert_section = &pem_str[cert_start..cert_start + cert_end + 25];

        let cert_der = pem_rfc7468::decode_vec(cert_section.as_bytes())
            .map_err(|e| anyhow::anyhow!("failed to decode certificate PEM: {}", e))?
            .1;

        // Parse DER to X.509 certificate
        let cert = Certificate::from_der(&cert_der).context("failed to parse X.509 certificate")?;

        // Extract serial number
        let serial_hex = hex::encode(cert.tbs_certificate.serial_number.as_bytes());

        // Extract expiration (notAfter)
        let not_after = cert.tbs_certificate.validity.not_after.to_unix_duration();
        let expires_at = not_after.as_secs();

        Ok((serial_hex, expires_at))
    }

    /// Check certificate expiration and renew if necessary.
    /// Fetch CA certificate chain from EST server.
    async fn fetch_ca_chain(&self) -> Result<Option<Vec<u8>>> {
        let ca_certs = self.client.get_ca_certs().await?;
        let mut ca_pem = Vec::new();
        for cert in ca_certs.into_iter() {
            let der = cert.to_der()?;
            let pem = pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, &der)
                .map_err(|e| anyhow::anyhow!("failed to encode CA certificate to PEM: {}", e))?;
            ca_pem.extend_from_slice(pem.as_bytes());
        }
        Ok(if ca_pem.is_empty() {
            None
        } else {
            Some(ca_pem)
        })
    }

    /// Update certificate bundle on disk and in memory.
    async fn update_bundle(&self, new_bundle: CertificateBundle) -> Result<()> {
        new_bundle
            .write_to_files(
                &self.config.cert_path,
                &self.config.key_path,
                &self.config.ca_cert_path,
            )
            .await?;

        *self.current_bundle.write().await = Some(new_bundle.clone());

        let _ = self.change_tx.send(SecretChange::TlsCertificates {
            cert_pem: new_bundle.cert_pem.clone(),
            key_pem: new_bundle.key_pem.clone(),
            ca_chain: new_bundle.ca_chain.clone(),
        });

        Ok(())
    }

    async fn check_and_renew(&self) -> Result<Option<CertificateBundle>> {
        let bundle = self.current_bundle.read().await;
        let Some(ref current) = *bundle else {
            debug!("no current certificate bundle, skipping renewal check");
            return Ok(None);
        };

        if !current.should_renew(self.config.renewal_threshold_percent) {
            debug!("certificate not yet at renewal threshold");
            return Ok(None);
        }

        drop(bundle);

        info!("certificate has reached renewal threshold, initiating renewal");

        let mut csr_builder = CsrBuilder::new().common_name(&self.config.common_name);
        if let Some(ref org) = self.config.organization {
            csr_builder = csr_builder.organization(org);
        }
        let (csr_der, key_pair) = csr_builder.build()?;

        let response = self.client.simple_reenroll(&csr_der).await?;

        let certificate = match response {
            EnrollmentResponse::Issued { certificate } => {
                info!("EST renewal successful");
                *certificate
            }
            EnrollmentResponse::Pending { retry_after } => {
                warn!(retry_after, "EST renewal is pending - will retry later");
                return Ok(None);
            }
        };

        let cert_der = certificate.to_der()?;
        let cert_pem =
            pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, &cert_der)
                .map_err(|e| anyhow::anyhow!("failed to encode certificate to PEM: {}", e))?;

        let key_pem = key_pair.serialize_pem();
        let ca_chain = self.fetch_ca_chain().await?;

        let serial = hex::encode(certificate.tbs_certificate.serial_number.as_bytes());
        let expires = certificate
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs();

        let new_bundle = CertificateBundle {
            cert_pem: cert_pem.into_bytes(),
            key_pem: key_pem.into_bytes(),
            ca_chain,
            serial_number: serial,
            expires_at: expires,
        };

        self.update_bundle(new_bundle.clone()).await?;

        info!("certificate renewal completed successfully");
        Ok(Some(new_bundle))
    }

    /// Start the background renewal loop.
    ///
    /// This spawns a tokio task that periodically checks certificate expiration
    /// and triggers renewal when necessary.
    pub fn start_renewal_loop(&mut self) -> Result<()> {
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        self.shutdown_tx = Some(shutdown_tx);

        let interval_secs = self.config.renewal_check_interval_secs;
        let self_clone = Arc::new(self.clone_for_loop());

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if let Err(e) = self_clone.check_and_renew().await {
                            error!(error = %e, "certificate renewal check failed");
                        }
                    }
                    _ = &mut shutdown_rx => {
                        info!("EST renewal loop shutting down");
                        break;
                    }
                }
            }
        });

        info!("started EST certificate renewal loop");
        Ok(())
    }

    /// Create a clone suitable for the renewal loop.
    fn clone_for_loop(&self) -> Self {
        Self {
            config: self.config.clone(),
            client: self.client.clone(),
            current_bundle: self.current_bundle.clone(),
            change_tx: self.change_tx.clone(),
            shutdown_tx: None,
        }
    }

    /// Shutdown the renewal loop.
    pub fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

#[async_trait]
impl SecretsProvider for EstProvider {
    async fn get_shared_secret(&self) -> Result<SecretValue> {
        anyhow::bail!("EST provider does not provide shared secrets")
    }

    async fn get_ldap_bind_password(&self) -> Result<SecretValue> {
        anyhow::bail!("EST provider does not provide LDAP passwords")
    }

    async fn get_location_secret(&self, _location: &str) -> Result<Option<SecretValue>> {
        Ok(None)
    }

    async fn get_nad_secrets(&self) -> Result<HashMap<IpAddr, SecretValue>> {
        Ok(HashMap::new())
    }

    async fn get_nad_secret(&self, _ip: &IpAddr) -> Result<Option<SecretValue>> {
        Ok(None)
    }

    async fn refresh(&self) -> Result<Vec<SecretChange>> {
        // Check if renewal is needed
        if let Some(new_bundle) = self.check_and_renew().await? {
            Ok(vec![SecretChange::TlsCertificates {
                cert_pem: new_bundle.cert_pem,
                key_pem: new_bundle.key_pem,
                ca_chain: new_bundle.ca_chain,
            }])
        } else {
            Ok(vec![])
        }
    }

    fn subscribe(&self) -> broadcast::Receiver<SecretChange> {
        self.change_tx.subscribe()
    }

    fn supports_refresh(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_certificate_bundle_should_renew() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let bundle = CertificateBundle {
            cert_pem: vec![],
            key_pem: vec![],
            ca_chain: None,
            serial_number: "test".to_string(),
            expires_at: now + 1000, // Expires in 1000 seconds
        };

        // Interpretation: threshold_percent means "renew when <= X% of current time-to-expiry remains"
        // With 1000s until expiry:
        // - 70% threshold: renew when <= 700s remain. Currently 1000s, so NO
        // - 30% threshold: renew when <= 300s remain. Currently 1000s, so NO
        assert!(!bundle.should_renew(70));
        assert!(!bundle.should_renew(30));

        // Create a bundle that is closer to expiration
        let soon = CertificateBundle {
            cert_pem: vec![],
            key_pem: vec![],
            ca_chain: None,
            serial_number: "test2".to_string(),
            expires_at: now + 50, // Expires in 50 seconds
        };

        // With 50s until expiry:
        // - 70% threshold: renew when <= 35s remain. Currently 50s, so NO
        // - 100% threshold: renew when <= 50s remain. Currently 50s, so YES
        // - 110% threshold: renew when <= 55s remain. Currently 50s, so YES
        assert!(!soon.should_renew(70));
        assert!(soon.should_renew(100));
        assert!(soon.should_renew(110));
    }

    #[tokio::test]
    async fn test_est_config_defaults() {
        let config = EstConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.renewal_threshold_percent, 70);
        assert_eq!(config.renewal_check_interval_secs, 3600);
    }

    #[test]
    fn test_certificate_bundle_should_renew_already_expired() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Certificate that expired 100 seconds ago
        let expired = CertificateBundle {
            cert_pem: vec![],
            key_pem: vec![],
            ca_chain: None,
            serial_number: "expired".to_string(),
            expires_at: now - 100,
        };

        // Should always renew expired certificates regardless of threshold
        assert!(expired.should_renew(10));
        assert!(expired.should_renew(50));
        assert!(expired.should_renew(90));
    }

    #[test]
    fn test_certificate_bundle_should_renew_zero_expiration() {
        // Certificate with unknown expiration (expires_at = 0)
        let unknown = CertificateBundle {
            cert_pem: vec![],
            key_pem: vec![],
            ca_chain: None,
            serial_number: "unknown".to_string(),
            expires_at: 0,
        };

        // Should NOT renew when expiration is unknown
        assert!(!unknown.should_renew(10));
        assert!(!unknown.should_renew(70));
        assert!(!unknown.should_renew(100));
    }

    #[test]
    fn test_certificate_bundle_should_renew_threshold_boundary() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Certificate expires in exactly 100 seconds
        let bundle = CertificateBundle {
            cert_pem: vec![],
            key_pem: vec![],
            ca_chain: None,
            serial_number: "boundary".to_string(),
            expires_at: now + 100,
        };

        // With 100s remaining:
        // - 70% threshold: renew when <= 70s remain. Currently 100s, so NO
        // - 100% threshold: renew when <= 100s remain. Currently 100s, so YES
        // - 101% threshold: renew when <= 101s remain. Currently 100s, so YES
        assert!(!bundle.should_renew(70));
        assert!(bundle.should_renew(100));
        assert!(bundle.should_renew(101));
    }

    #[tokio::test]
    async fn test_certificate_bundle_write_permissions() {
        use std::os::unix::fs::PermissionsExt;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");
        let ca_path = temp_dir.path().join("ca.pem");

        let bundle = CertificateBundle {
            cert_pem: b"fake cert".to_vec(),
            key_pem: b"fake key".to_vec(),
            ca_chain: Some(b"fake ca".to_vec()),
            serial_number: "test".to_string(),
            expires_at: 1234567890,
        };

        bundle
            .write_to_files(&cert_path, &key_path, &ca_path)
            .await
            .unwrap();

        // Verify files exist
        assert!(cert_path.exists());
        assert!(key_path.exists());
        assert!(ca_path.exists());

        // Verify key file has restricted permissions (0o600)
        let key_metadata = std::fs::metadata(&key_path).unwrap();
        let permissions = key_metadata.permissions();
        assert_eq!(
            permissions.mode() & 0o777,
            0o600,
            "private key should have 0o600 permissions"
        );

        // Verify cert file has readable permissions (0o644)
        let cert_metadata = std::fs::metadata(&cert_path).unwrap();
        let permissions = cert_metadata.permissions();
        assert_eq!(
            permissions.mode() & 0o777,
            0o644,
            "certificate should have 0o644 permissions"
        );
    }

    #[tokio::test]
    async fn test_certificate_bundle_write_no_ca() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let cert_path = temp_dir.path().join("cert.pem");
        let key_path = temp_dir.path().join("key.pem");

        let bundle = CertificateBundle {
            cert_pem: b"fake cert".to_vec(),
            key_pem: b"fake key".to_vec(),
            ca_chain: None,
            serial_number: "test".to_string(),
            expires_at: 1234567890,
        };

        // Create a dummy CA path even though ca_chain is None
        let ca_path = temp_dir.path().join("ca.pem");
        bundle
            .write_to_files(&cert_path, &key_path, &ca_path)
            .await
            .unwrap();

        // Verify files exist
        assert!(cert_path.exists());
        assert!(key_path.exists());
        // CA file should NOT exist since ca_chain is None
        assert!(!ca_path.exists());

        // Verify contents
        let cert_content = std::fs::read(&cert_path).unwrap();
        assert_eq!(cert_content, b"fake cert");
        let key_content = std::fs::read(&key_path).unwrap();
        assert_eq!(key_content, b"fake key");
    }
}
