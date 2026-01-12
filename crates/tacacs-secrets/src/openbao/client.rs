//! OpenBao HTTP client with retry logic.

use crate::config::OpenBaoConfig;
use crate::openbao::{AppRoleAuth, KvClient, PkiClient};
use anyhow::{Context, Result};
use backon::{BackoffBuilder, ExponentialBuilder};
use reqwest::{Client, ClientBuilder, StatusCode};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// OpenBao HTTP client.
///
/// Handles authentication, token management, and API requests to OpenBao.
pub struct OpenBaoClient {
    http: Client,
    address: String,
    auth: AppRoleAuth,
    token: Arc<RwLock<TokenState>>,
    kv: KvClient,
    pki: Option<PkiClient>,
    max_retries: u32,
}

/// Token state for authentication.
#[derive(Default)]
struct TokenState {
    token: Option<String>,
    expires_at: Option<std::time::Instant>,
    renewable: bool,
}

impl TokenState {
    fn is_valid(&self) -> bool {
        if let (Some(_token), Some(expires)) = (&self.token, self.expires_at) {
            // Consider token invalid if it expires in less than 30 seconds
            expires > std::time::Instant::now() + Duration::from_secs(30)
        } else {
            false
        }
    }
}

/// Generic OpenBao API response wrapper.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct ApiResponse<T> {
    pub data: Option<T>,
    pub warnings: Option<Vec<String>>,
    pub auth: Option<AuthInfo>,
    pub lease_id: Option<String>,
    pub lease_duration: Option<u64>,
    pub renewable: Option<bool>,
}

/// Authentication info from login response.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct AuthInfo {
    pub client_token: String,
    pub accessor: String,
    pub policies: Vec<String>,
    pub token_policies: Vec<String>,
    pub lease_duration: u64,
    pub renewable: bool,
}

impl OpenBaoClient {
    /// Create a new OpenBao client with the given configuration.
    pub async fn new(config: &OpenBaoConfig) -> Result<Self> {
        let mut builder = ClientBuilder::new()
            .timeout(Duration::from_millis(config.timeout_ms))
            .pool_max_idle_per_host(4);

        // Configure TLS if CA file is provided
        if let Some(ref ca_path) = config.ca_file {
            let ca_cert = std::fs::read(ca_path)
                .with_context(|| format!("failed to read CA file: {:?}", ca_path))?;
            let cert = reqwest::Certificate::from_pem(&ca_cert)
                .with_context(|| "failed to parse CA certificate")?;
            builder = builder.add_root_certificate(cert);
        }

        let http = builder.build().context("failed to build HTTP client")?;

        let auth = AppRoleAuth::new(config.role_id_file.clone(), config.secret_id_file.clone());

        let kv = KvClient::new(config.secret_path.clone());

        let client = Self {
            http,
            address: config.address.trim_end_matches('/').to_string(),
            auth,
            token: Arc::new(RwLock::new(TokenState::default())),
            kv,
            pki: None,
            max_retries: config.max_retries,
        };

        // Perform initial authentication
        client.authenticate().await?;

        info!(address = %client.address, "connected to OpenBao");

        Ok(client)
    }

    /// Configure PKI client for certificate management.
    pub fn with_pki(mut self, mount: String, role: String) -> Self {
        self.pki = Some(PkiClient::new(mount, role));
        self
    }

    /// Authenticate with OpenBao using AppRole.
    pub async fn authenticate(&self) -> Result<()> {
        let (role_id, secret_id) = self.auth.load_credentials()?;

        let url = format!("{}/v1/auth/approle/login", self.address);
        let body = serde_json::json!({
            "role_id": role_id,
            "secret_id": secret_id
        });

        let response = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .context("failed to send auth request")?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("authentication failed: {} - {}", status, text);
        }

        let api_response: ApiResponse<()> = response
            .json()
            .await
            .context("failed to parse auth response")?;

        let auth = api_response
            .auth
            .ok_or_else(|| anyhow::anyhow!("no auth info in response"))?;

        let mut state = self.token.write().await;
        state.token = Some(auth.client_token);
        state.expires_at =
            Some(std::time::Instant::now() + Duration::from_secs(auth.lease_duration));
        state.renewable = auth.renewable;

        debug!(
            policies = ?auth.policies,
            lease_duration_secs = auth.lease_duration,
            "authenticated with OpenBao"
        );

        Ok(())
    }

    /// Get a valid token, refreshing if necessary.
    pub async fn get_token(&self) -> Result<String> {
        // Check if current token is valid
        {
            let state = self.token.read().await;
            if state.is_valid() {
                return Ok(state.token.clone().unwrap());
            }
        }

        // Token is expired or missing, re-authenticate
        self.authenticate().await?;

        let state = self.token.read().await;
        state
            .token
            .clone()
            .ok_or_else(|| anyhow::anyhow!("no token after authentication"))
    }

    /// Make an authenticated GET request.
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<Option<T>> {
        self.request_with_retry(reqwest::Method::GET, path, None::<()>)
            .await
    }

    /// Make an authenticated POST request.
    pub async fn post<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<Option<T>> {
        self.request_with_retry(reqwest::Method::POST, path, Some(body))
            .await
    }

    /// Make a request with automatic retry on transient failures.
    async fn request_with_retry<B: Serialize, T: DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<B>,
    ) -> Result<Option<T>> {
        let mut backoff = ExponentialBuilder::default()
            .with_max_times(self.max_retries as usize)
            .with_max_delay(Duration::from_secs(60))
            .build();

        let mut attempts = 0;

        loop {
            attempts += 1;
            let result = self.do_request(&method, path, &body).await;

            match result {
                Ok(response) => return Ok(response),
                Err(e) => {
                    // Check if error is retryable
                    let is_retryable = e.to_string().contains("connection")
                        || e.to_string().contains("timeout")
                        || e.to_string().contains("503")
                        || e.to_string().contains("502");

                    if !is_retryable || attempts >= self.max_retries {
                        return Err(e);
                    }

                    if let Some(delay) = backoff.next() {
                        warn!(
                            error = %e,
                            attempt = attempts,
                            delay_ms = delay.as_millis(),
                            "retrying request after transient failure"
                        );
                        tokio::time::sleep(delay).await;
                    } else {
                        return Err(e);
                    }
                }
            }
        }
    }

    /// Execute a single request.
    async fn do_request<B: Serialize, T: DeserializeOwned>(
        &self,
        method: &reqwest::Method,
        path: &str,
        body: &Option<B>,
    ) -> Result<Option<T>> {
        let token = self.get_token().await?;
        let url = format!("{}/v1/{}", self.address, path.trim_start_matches('/'));

        let mut request = self
            .http
            .request(method.clone(), &url)
            .header("X-Vault-Token", &token);

        if let Some(b) = body {
            request = request.json(b);
        }

        let response = request.send().await.context("request failed")?;

        match response.status() {
            StatusCode::OK => {
                let api_response: ApiResponse<T> =
                    response.json().await.context("failed to parse response")?;
                Ok(api_response.data)
            }
            StatusCode::NO_CONTENT => Ok(None),
            StatusCode::NOT_FOUND => Ok(None),
            StatusCode::FORBIDDEN => {
                // Token might be invalid, clear it and return error
                let mut state = self.token.write().await;
                state.token = None;
                state.expires_at = None;
                anyhow::bail!("forbidden: token may be invalid or insufficient permissions")
            }
            status => {
                let text = response.text().await.unwrap_or_default();
                anyhow::bail!("request failed: {} - {}", status, text)
            }
        }
    }

    /// Get the KV client for secret operations.
    pub fn kv(&self) -> &KvClient {
        &self.kv
    }

    /// Get the PKI client if configured.
    pub fn pki(&self) -> Option<&PkiClient> {
        self.pki.as_ref()
    }

    /// Get the base address.
    pub fn address(&self) -> &str {
        &self.address
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_state_validity() {
        let mut state = TokenState::default();
        assert!(!state.is_valid());

        state.token = Some("test-token".to_string());
        state.expires_at = Some(std::time::Instant::now() + Duration::from_secs(300));
        assert!(state.is_valid());

        // Token expiring in 20 seconds should be considered invalid
        state.expires_at = Some(std::time::Instant::now() + Duration::from_secs(20));
        assert!(!state.is_valid());
    }
}
