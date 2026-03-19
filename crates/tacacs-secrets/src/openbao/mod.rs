//! OpenBao/Vault client integration.
//!
//! This module provides a client for fetching secrets from OpenBao (or HashiCorp Vault).
//! It supports:
//! - AppRole authentication
//! - KV v2 secrets engine for shared secrets, LDAP passwords, etc.
//! - PKI secrets engine for automatic certificate issuance and renewal

mod auth;
mod client;
mod kv;
mod pki;

pub use auth::AppRoleAuth;
pub use client::OpenBaoClient;
pub use kv::KvClient;
pub use pki::{CertificateBundle, PkiClient};

use crate::config::OpenBaoConfig;
use crate::provider::{SecretChange, SecretValue, SecretsProvider};
use anyhow::{Result, ensure};
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};
use tracing::{debug, info, warn};

/// OpenBao-backed secrets provider.
///
/// This provider fetches secrets from OpenBao using the KV v2 secrets engine.
/// It supports automatic token renewal and secret refresh.
pub struct OpenBaoProvider {
    client: Arc<OpenBaoClient>,
    config: OpenBaoConfig,
    cache: Arc<RwLock<SecretsCache>>,
    change_sender: broadcast::Sender<SecretChange>,
}

/// In-memory cache of secrets.
#[derive(Default)]
struct SecretsCache {
    shared_secret: Option<SecretValue>,
    ldap_bind_password: Option<SecretValue>,
    location_secrets: HashMap<String, SecretValue>,
    nad_secrets: HashMap<IpAddr, SecretValue>,
}

/// Validate a path segment to prevent path traversal attacks.
///
/// # NIST Controls
/// - **SI-10 (Information Input Validation)**: Validates path segments before interpolation
/// - **AC-3 (Access Enforcement)**: Prevents unauthorized path traversal
fn validate_path_segment(segment: &str) -> Result<()> {
    ensure!(!segment.is_empty(), "path segment must not be empty");
    ensure!(!segment.contains(".."), "path segment must not contain '..'");
    ensure!(!segment.contains('/'), "path segment must not contain '/'");
    ensure!(!segment.contains('\\'), "path segment must not contain '\\\\'");
    Ok(())
}

impl OpenBaoProvider {
    /// Create a new OpenBao provider with the given configuration.
    pub async fn new(config: OpenBaoConfig) -> Result<Self> {
        let client = OpenBaoClient::new(&config).await?;
        let (tx, _) = broadcast::channel(16);

        let provider = Self {
            client: Arc::new(client),
            config,
            cache: Arc::new(RwLock::new(SecretsCache::default())),
            change_sender: tx,
        };

        // Initial fetch of secrets
        provider.refresh_internal(false).await?;

        Ok(provider)
    }

    async fn fetch_shared_secret(&self, notify: bool) -> Result<Option<SecretChange>> {
        let secret_path = format!("{}/shared-secret", self.config.secret_path);
        match self.client.kv().read(&secret_path).await {
            Ok(Some(value)) => {
                let secret = SecretValue::new(value);
                let mut cache = self.cache.write().await;
                let changed = cache
                    .shared_secret
                    .as_ref()
                    .map(|s| s.data != secret.data)
                    .unwrap_or(true);
                if changed {
                    info!("shared secret updated from OpenBao");
                    cache.shared_secret = Some(secret.clone());
                    if notify {
                        return Ok(Some(SecretChange::SharedSecret(secret.data.clone())));
                    }
                }
                cache.shared_secret = Some(secret);
                Ok(None)
            }
            Ok(None) => {
                debug!(path = %secret_path, "shared secret not found in OpenBao");
                Ok(None)
            }
            Err(e) => {
                tracing::error!(error = %e, path = %secret_path, "failed to fetch shared secret");
                Ok(None)
            }
        }
    }

    async fn fetch_ldap_password(&self, notify: bool) -> Result<Option<SecretChange>> {
        let ldap_path = format!("{}/ldap-bind", self.config.secret_path);
        match self.client.kv().read(&ldap_path).await {
            Ok(Some(value)) => {
                let password = String::from_utf8(value)
                    .map_err(|e| anyhow::anyhow!("invalid UTF-8: {}", e))?;
                let secret = SecretValue::from_string(password.clone());
                let mut cache = self.cache.write().await;
                let changed = cache
                    .ldap_bind_password
                    .as_ref()
                    .map(|s| s.data != secret.data)
                    .unwrap_or(true);
                if changed {
                    info!("LDAP bind password updated from OpenBao");
                    cache.ldap_bind_password = Some(secret.clone());
                    if notify {
                        return Ok(Some(SecretChange::LdapBindPassword(password)));
                    }
                }
                cache.ldap_bind_password = Some(secret);
                Ok(None)
            }
            Ok(None) => {
                debug!(path = %ldap_path, "LDAP bind password not found in OpenBao");
                Ok(None)
            }
            Err(e) => {
                tracing::error!(error = %e, path = %ldap_path, "failed to fetch LDAP bind password");
                Ok(None)
            }
        }
    }

    async fn fetch_location_secret(&self, location: &str) -> Result<()> {
        validate_path_segment(location)?;
        let location_path = format!(
            "{}/locations/{}/shared-secret",
            self.config.secret_path, location
        );
        match self.client.kv().read(&location_path).await {
            Ok(Some(value)) => {
                let secret = SecretValue::new(value);
                let mut cache = self.cache.write().await;
                cache.location_secrets.insert(location.to_string(), secret);
                debug!(location = %location, "loaded location-specific secret");
            }
            Ok(None) => {
                debug!(location = %location, "no location-specific secret found");
            }
            Err(e) => {
                tracing::error!(error = %e, location = %location, "failed to fetch location secret");
            }
        }
        Ok(())
    }

    async fn fetch_nad_secrets(
        &self,
        location: &str,
        notify: bool,
    ) -> Result<Vec<SecretChange>> {
        validate_path_segment(location)?;
        let mut changes = Vec::new();
        let nad_path = format!(
            "{}/locations/{}/nad-secrets",
            self.config.secret_path, location
        );
        match self
            .client
            .kv()
            .read_json::<HashMap<String, String>>(&nad_path)
            .await
        {
            Ok(Some(nad_map)) => {
                let mut cache = self.cache.write().await;
                for (ip_str, secret_str) in nad_map {
                    match ip_str.parse::<IpAddr>() {
                        Ok(ip) => {
                            let old_secret = cache.nad_secrets.get(&ip);
                            let new_data = secret_str.as_bytes().to_vec();
                            let changed = old_secret.map(|s| s.data != new_data).unwrap_or(true);
                            if changed && notify {
                                changes.push(SecretChange::NadSecret {
                                    ip,
                                    secret: new_data.clone(),
                                });
                            }
                            cache.nad_secrets.insert(ip, SecretValue::new(new_data));
                        }
                        Err(e) => {
                            warn!(ip = %ip_str, error = %e, "invalid IP in NAD secrets");
                        }
                    }
                }
                debug!(count = cache.nad_secrets.len(), "loaded NAD secrets");
            }
            Ok(None) => {
                debug!(location = %location, "no NAD secrets found");
            }
            Err(e) => {
                tracing::error!(error = %e, location = %location, "failed to fetch NAD secrets");
            }
        }
        Ok(changes)
    }

    /// Internal refresh that optionally notifies subscribers.
    async fn refresh_internal(&self, notify: bool) -> Result<Vec<SecretChange>> {
        let mut changes = Vec::new();

        if let Some(change) = self.fetch_shared_secret(notify).await? {
            changes.push(change);
        }

        if let Some(change) = self.fetch_ldap_password(notify).await? {
            changes.push(change);
        }

        if let Some(ref location) = self.config.location {
            self.fetch_location_secret(location).await?;
            let nad_changes = self.fetch_nad_secrets(location, notify).await?;
            changes.extend(nad_changes);
        }

        for change in &changes {
            if let Err(e) = self.change_sender.send(change.clone()) {
                debug!(error = %e, "no subscribers for secret change");
            }
        }

        Ok(changes)
    }

    /// Get the underlying client for PKI operations.
    pub fn client(&self) -> &OpenBaoClient {
        &self.client
    }
}

#[async_trait]
impl SecretsProvider for OpenBaoProvider {
    async fn get_shared_secret(&self) -> Result<SecretValue> {
        // First check for location-specific secret
        if let Some(ref location) = self.config.location {
            let cache = self.cache.read().await;
            if let Some(secret) = cache.location_secrets.get(location) {
                return Ok(secret.clone());
            }
        }

        // Fall back to global shared secret
        let cache = self.cache.read().await;
        cache
            .shared_secret
            .clone()
            .ok_or_else(|| anyhow::anyhow!("shared secret not available from OpenBao"))
    }

    async fn get_ldap_bind_password(&self) -> Result<SecretValue> {
        let cache = self.cache.read().await;
        cache
            .ldap_bind_password
            .clone()
            .ok_or_else(|| anyhow::anyhow!("LDAP bind password not available from OpenBao"))
    }

    async fn get_location_secret(&self, location: &str) -> Result<Option<SecretValue>> {
        let cache = self.cache.read().await;
        Ok(cache.location_secrets.get(location).cloned())
    }

    async fn get_nad_secrets(&self) -> Result<HashMap<IpAddr, SecretValue>> {
        let cache = self.cache.read().await;
        Ok(cache.nad_secrets.clone())
    }

    async fn get_nad_secret(&self, ip: &IpAddr) -> Result<Option<SecretValue>> {
        let cache = self.cache.read().await;
        Ok(cache.nad_secrets.get(ip).cloned())
    }

    async fn refresh(&self) -> Result<Vec<SecretChange>> {
        self.refresh_internal(true).await
    }

    fn subscribe(&self) -> broadcast::Receiver<SecretChange> {
        self.change_sender.subscribe()
    }

    fn supports_refresh(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    // Integration tests would go here, using wiremock to mock OpenBao responses
}
