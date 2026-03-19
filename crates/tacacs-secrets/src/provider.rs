//! SecretsProvider trait and implementations.

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{debug, info};
use zeroize::Zeroize;

/// A secret value with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretValue {
    /// The secret data.
    pub data: Vec<u8>,

    /// Lease ID if this secret has a lease (OpenBao).
    #[serde(default)]
    pub lease_id: Option<String>,

    /// Lease duration in seconds.
    #[serde(default)]
    pub lease_duration_secs: Option<u64>,

    /// Whether this secret is renewable.
    #[serde(default)]
    pub renewable: bool,
}

impl SecretValue {
    /// Create a new secret value from bytes.
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            lease_id: None,
            lease_duration_secs: None,
            renewable: false,
        }
    }

    /// Create a secret value from a string.
    pub fn from_string(s: String) -> Self {
        Self::new(s.into_bytes())
    }

    /// Get the secret as a string (UTF-8).
    pub fn as_string(&self) -> Result<String> {
        String::from_utf8(self.data.clone())
            .map_err(|e| anyhow::anyhow!("secret is not valid UTF-8: {}", e))
    }
}

/// NIST SC-12: Zeroize secret data when SecretValue is dropped.
impl Drop for SecretValue {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

/// Notification of a secret change.
#[derive(Debug, Clone)]
pub enum SecretChange {
    /// The shared secret was updated.
    SharedSecret(Vec<u8>),

    /// The LDAP bind password was updated.
    LdapBindPassword(String),

    /// A NAD secret was updated.
    NadSecret { ip: IpAddr, secret: Vec<u8> },

    /// TLS certificates were updated.
    TlsCertificates {
        cert_pem: Vec<u8>,
        key_pem: Vec<u8>,
        ca_chain: Option<Vec<u8>>,
    },
}

/// Trait for secrets providers.
///
/// Implementations provide access to secrets from various backends:
/// - File-based (for backward compatibility)
/// - OpenBao/Vault (for dynamic secrets)
#[async_trait]
pub trait SecretsProvider: Send + Sync {
    /// Fetch the TACACS+ shared secret.
    async fn get_shared_secret(&self) -> Result<SecretValue>;

    /// Fetch the LDAP bind password.
    async fn get_ldap_bind_password(&self) -> Result<SecretValue>;

    /// Fetch per-location shared secret override.
    /// Returns None if no location-specific secret exists.
    async fn get_location_secret(&self, location: &str) -> Result<Option<SecretValue>>;

    /// Fetch all NAD (Network Access Device) secrets.
    async fn get_nad_secrets(&self) -> Result<HashMap<IpAddr, SecretValue>>;

    /// Fetch a NAD secret for a specific IP.
    async fn get_nad_secret(&self, ip: &IpAddr) -> Result<Option<SecretValue>>;

    /// Refresh all secrets from the backend.
    /// Returns a list of secrets that changed.
    async fn refresh(&self) -> Result<Vec<SecretChange>>;

    /// Subscribe to secret change notifications.
    fn subscribe(&self) -> broadcast::Receiver<SecretChange>;

    /// Check if this provider supports dynamic refresh.
    fn supports_refresh(&self) -> bool;
}

/// File-based secrets provider for backward compatibility.
///
/// This provider reads secrets from files on disk, matching the existing
/// CLI-based configuration approach.
pub struct FileProvider {
    shared_secret: Option<Vec<u8>>,
    ldap_bind_password: Option<String>,
    nad_secrets: HashMap<IpAddr, Vec<u8>>,
    change_sender: broadcast::Sender<SecretChange>,
}

impl FileProvider {
    /// Create a new file-based provider.
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(16);
        Self {
            shared_secret: None,
            ldap_bind_password: None,
            nad_secrets: HashMap::new(),
            change_sender: tx,
        }
    }

    /// Create a provider with a pre-configured shared secret.
    pub fn with_shared_secret(mut self, secret: Vec<u8>) -> Self {
        self.shared_secret = Some(secret);
        self
    }

    /// Create a provider with a pre-configured LDAP bind password.
    pub fn with_ldap_bind_password(mut self, password: String) -> Self {
        self.ldap_bind_password = Some(password);
        self
    }

    /// Create a provider with pre-configured NAD secrets.
    pub fn with_nad_secrets(mut self, secrets: HashMap<IpAddr, Vec<u8>>) -> Self {
        self.nad_secrets = secrets;
        self
    }

    /// Load shared secret from a file.
    pub fn load_shared_secret_from_file(mut self, path: &PathBuf) -> Result<Self> {
        let content = std::fs::read(path)
            .map_err(|e| anyhow::anyhow!("failed to read shared secret from {:?}: {}", path, e))?;
        // Trim trailing newlines
        let secret = content.strip_suffix(b"\n").unwrap_or(&content).to_vec();
        self.shared_secret = Some(secret);
        info!(path = ?path, "loaded shared secret from file");
        Ok(self)
    }

    /// Load LDAP bind password from a file.
    pub fn load_ldap_password_from_file(mut self, path: &PathBuf) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read LDAP password from {:?}: {}", path, e))?;
        self.ldap_bind_password = Some(content.trim().to_string());
        info!(path = ?path, "loaded LDAP bind password from file");
        Ok(self)
    }
}

impl Default for FileProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecretsProvider for FileProvider {
    async fn get_shared_secret(&self) -> Result<SecretValue> {
        self.shared_secret
            .as_ref()
            .map(|s| SecretValue::new(s.clone()))
            .ok_or_else(|| anyhow::anyhow!("shared secret not configured"))
    }

    async fn get_ldap_bind_password(&self) -> Result<SecretValue> {
        self.ldap_bind_password
            .as_ref()
            .map(|s| SecretValue::from_string(s.clone()))
            .ok_or_else(|| anyhow::anyhow!("LDAP bind password not configured"))
    }

    async fn get_location_secret(&self, _location: &str) -> Result<Option<SecretValue>> {
        // File provider doesn't support per-location secrets
        Ok(None)
    }

    async fn get_nad_secrets(&self) -> Result<HashMap<IpAddr, SecretValue>> {
        Ok(self
            .nad_secrets
            .iter()
            .map(|(ip, secret)| (*ip, SecretValue::new(secret.clone())))
            .collect())
    }

    async fn get_nad_secret(&self, ip: &IpAddr) -> Result<Option<SecretValue>> {
        Ok(self
            .nad_secrets
            .get(ip)
            .map(|s| SecretValue::new(s.clone())))
    }

    async fn refresh(&self) -> Result<Vec<SecretChange>> {
        // File provider doesn't support refresh
        debug!("file provider does not support dynamic refresh");
        Ok(vec![])
    }

    fn subscribe(&self) -> broadcast::Receiver<SecretChange> {
        self.change_sender.subscribe()
    }

    fn supports_refresh(&self) -> bool {
        false
    }
}

/// Wrapper to hold a provider behind an Arc for sharing.
pub struct SharedSecretsProvider {
    inner: Arc<dyn SecretsProvider>,
}

impl SharedSecretsProvider {
    /// Create a new shared provider.
    pub fn new<P: SecretsProvider + 'static>(provider: P) -> Self {
        Self {
            inner: Arc::new(provider),
        }
    }

    /// Get a clone of the inner Arc.
    pub fn clone_inner(&self) -> Arc<dyn SecretsProvider> {
        self.inner.clone()
    }
}

impl Clone for SharedSecretsProvider {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

#[async_trait]
impl SecretsProvider for SharedSecretsProvider {
    async fn get_shared_secret(&self) -> Result<SecretValue> {
        self.inner.get_shared_secret().await
    }

    async fn get_ldap_bind_password(&self) -> Result<SecretValue> {
        self.inner.get_ldap_bind_password().await
    }

    async fn get_location_secret(&self, location: &str) -> Result<Option<SecretValue>> {
        self.inner.get_location_secret(location).await
    }

    async fn get_nad_secrets(&self) -> Result<HashMap<IpAddr, SecretValue>> {
        self.inner.get_nad_secrets().await
    }

    async fn get_nad_secret(&self, ip: &IpAddr) -> Result<Option<SecretValue>> {
        self.inner.get_nad_secret(ip).await
    }

    async fn refresh(&self) -> Result<Vec<SecretChange>> {
        self.inner.refresh().await
    }

    fn subscribe(&self) -> broadcast::Receiver<SecretChange> {
        self.inner.subscribe()
    }

    fn supports_refresh(&self) -> bool {
        self.inner.supports_refresh()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_file_provider_with_shared_secret() {
        let provider = FileProvider::new().with_shared_secret(b"test-secret".to_vec());

        let secret = provider.get_shared_secret().await.unwrap();
        assert_eq!(secret.data, b"test-secret");
        assert!(!provider.supports_refresh());
    }

    #[tokio::test]
    async fn test_file_provider_missing_secret() {
        let provider = FileProvider::new();

        let result = provider.get_shared_secret().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not configured"));
    }

    #[tokio::test]
    async fn test_file_provider_with_nad_secrets() {
        let mut nad_secrets = HashMap::new();
        nad_secrets.insert("10.1.1.1".parse().unwrap(), b"secret1".to_vec());
        nad_secrets.insert("10.1.1.2".parse().unwrap(), b"secret2".to_vec());

        let provider = FileProvider::new().with_nad_secrets(nad_secrets);

        let secrets = provider.get_nad_secrets().await.unwrap();
        assert_eq!(secrets.len(), 2);

        let ip: IpAddr = "10.1.1.1".parse().unwrap();
        let secret = provider.get_nad_secret(&ip).await.unwrap();
        assert!(secret.is_some());
        assert_eq!(secret.unwrap().data, b"secret1");
    }

    #[tokio::test]
    async fn test_secret_value_as_string() {
        let secret = SecretValue::from_string("hello".to_string());
        assert_eq!(secret.as_string().unwrap(), "hello");
    }

    #[tokio::test]
    async fn test_shared_provider() {
        let file_provider = FileProvider::new()
            .with_shared_secret(b"shared-test".to_vec())
            .with_ldap_bind_password("ldap-pass".to_string());

        let shared = SharedSecretsProvider::new(file_provider);
        let cloned = shared.clone();

        let secret = shared.get_shared_secret().await.unwrap();
        assert_eq!(secret.data, b"shared-test");

        let ldap = cloned.get_ldap_bind_password().await.unwrap();
        assert_eq!(ldap.as_string().unwrap(), "ldap-pass");
    }
}
