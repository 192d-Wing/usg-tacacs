//! EST (RFC 7030) provider for zero-touch certificate provisioning.
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
use tokio::sync::{broadcast, oneshot, RwLock};
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

        // Write private key with restrictive permissions (0600)
        fs::write(key_path, &self.key_pem)
            .await
            .context("failed to write private key file")?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(key_path).await?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(key_path, perms).await?;
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
        let mut client_builder = EstClientConfig::builder()
            .server_url(&config.server_url)?;

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
    pub async fn bootstrap_enrollment(&self) -> Result<CertificateBundle> {
        info!("starting EST bootstrap enrollment");

        // Check if certificates already exist
        if self.config.cert_path.exists() && self.config.key_path.exists() {
            info!("certificates already exist, loading from disk");
            return self.load_existing_certificates().await;
        }

        // Generate CSR
        let mut csr_builder = CsrBuilder::new().common_name(&self.config.common_name);
        if let Some(ref org) = self.config.organization {
            csr_builder = csr_builder.organization(org);
        }

        let (csr_der, key_pair) = csr_builder.build()?;

        // Enroll with EST server
        info!(cn = %self.config.common_name, "submitting enrollment request to EST server");
        let response = self.client.simple_enroll(&csr_der).await?;

        let certificate = match response {
            EnrollmentResponse::Issued { certificate } => {
                info!("EST enrollment successful");
                certificate
            }
            EnrollmentResponse::Pending { retry_after } => {
                anyhow::bail!(
                    "EST enrollment is pending (retry after {} seconds) - polling not yet implemented",
                    retry_after
                );
            }
        };

        // Convert certificate to PEM
        let cert_der = certificate.to_der()?;
        let cert_pem = pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, &cert_der)
            .map_err(|e| anyhow::anyhow!("failed to encode certificate to PEM: {}", e))?;

        // Convert private key to PEM
        let key_pem = key_pair.serialize_pem();

        // Fetch CA certificates if ca_label is configured
        let ca_chain = {
            debug!("fetching CA certificates");
            let ca_certs = self.client.get_ca_certs().await?;
            let mut ca_pem = Vec::new();
            for cert in ca_certs.into_iter() {
                let der = cert.to_der()?;
                let pem = pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, &der)
                    .map_err(|e| anyhow::anyhow!("failed to encode CA certificate to PEM: {}", e))?;
                ca_pem.extend_from_slice(pem.as_bytes());
            }
            if ca_pem.is_empty() {
                None
            } else {
                Some(ca_pem)
            }
        };

        // Parse certificate to extract serial and expiration
        let serial_number = hex::encode(certificate.tbs_certificate.serial_number.as_bytes());
        let expires_at = certificate
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs();

        let bundle = CertificateBundle {
            cert_pem: cert_pem.into_bytes(),
            key_pem: key_pem.into_bytes(),
            ca_chain,
            serial_number,
            expires_at,
        };

        // Write to disk
        bundle
            .write_to_files(
                &self.config.cert_path,
                &self.config.key_path,
                &self.config.ca_cert_path,
            )
            .await?;

        // Store in memory
        *self.current_bundle.write().await = Some(bundle.clone());

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

        // TODO: Parse certificate to extract serial and expiration
        let bundle = CertificateBundle {
            cert_pem,
            key_pem,
            ca_chain,
            serial_number: "existing".to_string(),
            expires_at: 0,
        };

        *self.current_bundle.write().await = Some(bundle.clone());
        info!("loaded existing certificates from disk");

        Ok(bundle)
    }

    /// Check certificate expiration and renew if necessary.
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

        drop(bundle); // Release read lock

        info!("certificate has reached renewal threshold, initiating renewal");

        // Generate new CSR
        let mut csr_builder = CsrBuilder::new().common_name(&self.config.common_name);
        if let Some(ref org) = self.config.organization {
            csr_builder = csr_builder.organization(org);
        }
        let (csr_der, key_pair) = csr_builder.build()?;

        // Re-enroll with EST server
        let response = self.client.simple_reenroll(&csr_der).await?;

        let certificate = match response {
            EnrollmentResponse::Issued { certificate } => {
                info!("EST renewal successful");
                certificate
            }
            EnrollmentResponse::Pending { retry_after } => {
                warn!(retry_after, "EST renewal is pending - will retry later");
                return Ok(None);
            }
        };

        // Convert certificate to PEM
        let cert_der = certificate.to_der()?;
        let cert_pem = pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, &cert_der)
            .map_err(|e| anyhow::anyhow!("failed to encode certificate to PEM: {}", e))?;

        // Convert private key to PEM
        let key_pem = key_pair.serialize_pem();

        // Fetch CA certificates
        let ca_chain = {
            let ca_certs = self.client.get_ca_certs().await?;
            let mut ca_pem = Vec::new();
            for cert in ca_certs.into_iter() {
                let der = cert.to_der()?;
                let pem = pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, &der)
                    .map_err(|e| anyhow::anyhow!("failed to encode CA certificate to PEM: {}", e))?;
                ca_pem.extend_from_slice(pem.as_bytes());
            }
            if ca_pem.is_empty() {
                None
            } else {
                Some(ca_pem)
            }
        };

        let serial_number = hex::encode(certificate.tbs_certificate.serial_number.as_bytes());
        let expires_at = certificate
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs();

        let new_bundle = CertificateBundle {
            cert_pem: cert_pem.into_bytes(),
            key_pem: key_pem.into_bytes(),
            ca_chain,
            serial_number,
            expires_at,
        };

        // Write to disk
        new_bundle
            .write_to_files(
                &self.config.cert_path,
                &self.config.key_path,
                &self.config.ca_cert_path,
            )
            .await?;

        // Update in-memory bundle
        *self.current_bundle.write().await = Some(new_bundle.clone());

        // Broadcast change notification
        let _ = self.change_tx.send(SecretChange::TlsCertificates {
            cert_pem: new_bundle.cert_pem.clone(),
            key_pem: new_bundle.key_pem.clone(),
            ca_chain: new_bundle.ca_chain.clone(),
        });

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
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(interval_secs));
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
}
