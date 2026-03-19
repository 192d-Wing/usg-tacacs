// SPDX-License-Identifier: Apache-2.0

//! Configuration structures for secrets management.
//!
//! # NIST SP 800-53 Rev. 5 Security Controls
//!
//! **Control Implementation Matrix**
//!
//! This module implements controls documented in
//! [NIST-CONTROLS-MAPPING.md](../../../docs/NIST-CONTROLS-MAPPING.md).
//!
//! | Control | Family | Status | Validated | Primary Functions |
//! |---------|--------|--------|-----------|-------------------|
//! | CM-3 | Config Management | Implemented | 2026-01-26 | Configuration structures |
//! | IA-5 | Ident/Authentication | Implemented | 2026-01-26 | [`OpenBaoConfig`], [`EstConfig`] |
//! | SC-17 | Sys/Comm Protection | Implemented | 2026-01-26 | [`PkiConfig`], [`EstConfig`] |
//!
//! <details>
//! <summary><b>Validation Metadata (JSON)</b></summary>
//!
//! ```json
//! {
//!   "nist_framework": "NIST SP 800-53 Rev. 5",
//!   "software_version": "0.77.1",
//!   "last_validation": "2026-01-26",
//!   "control_families": ["CM", "IA", "SC"],
//!   "total_controls": 3,
//!   "file_path": "crates/tacacs-secrets/src/config.rs"
//! }
//! ```
//!
//! </details>
//!
//! ## Control Details
//!
//! ### CM-3: Configuration Change Control
//! - **Implementation:** Structured configuration for secrets providers with validation
//! - **Evidence:** Serde-based deserialization, type-safe configuration models
//! - **Reference:** [CM-3](../../../docs/NIST-CONTROLS-MAPPING.md#cm-3-configuration-change-control)
//!
//! ### IA-5: Authenticator Management
//! - **Implementation:** OpenBao AppRole credentials, EST authentication configuration
//! - **Evidence:** Role/secret ID file paths, secure credential storage patterns
//! - **Reference:** [IA-5](../../../docs/NIST-CONTROLS-MAPPING.md#ia-5-authenticator-management)
//!
//! ### SC-17: Public Key Infrastructure Certificates
//! - **Implementation:** PKI and EST configuration for automated certificate lifecycle
//! - **Evidence:** Certificate paths, EST server URLs, renewal thresholds
//! - **Reference:** [SC-17](../../../docs/NIST-CONTROLS-MAPPING.md#sc-17-public-key-infrastructure-certificates)

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Top-level secrets configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecretsConfig {
    /// OpenBao configuration (optional).
    #[serde(default)]
    pub openbao: Option<OpenBaoConfig>,

    /// PKI configuration for automatic certificate management (optional).
    #[serde(default)]
    pub pki: Option<PkiConfig>,

    /// EST configuration for zero-touch certificate provisioning (optional).
    #[serde(default)]
    pub est: Option<EstConfig>,
}

/// OpenBao/Vault client configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenBaoConfig {
    /// OpenBao server address (e.g., "https://openbao.internal:8200").
    pub address: String,

    /// Authentication method. Currently only "approle" is supported.
    #[serde(default = "default_auth_method")]
    pub auth_method: String,

    /// Path to file containing the AppRole role_id.
    pub role_id_file: PathBuf,

    /// Path to file containing the AppRole secret_id.
    pub secret_id_file: PathBuf,

    /// Optional CA certificate file for TLS verification.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,

    /// Secret refresh interval in seconds.
    #[serde(default = "default_refresh_interval")]
    pub refresh_interval_secs: u64,

    /// Location identifier for per-location secrets.
    #[serde(default)]
    pub location: Option<String>,

    /// Base path for TACACS secrets in OpenBao.
    #[serde(default = "default_secret_path")]
    pub secret_path: String,

    /// Connection timeout in milliseconds.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,

    /// Maximum retry attempts for transient failures.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
}

impl Default for OpenBaoConfig {
    fn default() -> Self {
        Self {
            address: "https://openbao.internal:8200".to_string(),
            auth_method: default_auth_method(),
            role_id_file: PathBuf::from("/etc/tacacs/openbao-role-id"),
            secret_id_file: PathBuf::from("/etc/tacacs/openbao-secret-id"),
            ca_file: None,
            refresh_interval_secs: default_refresh_interval(),
            location: None,
            secret_path: default_secret_path(),
            timeout_ms: default_timeout_ms(),
            max_retries: default_max_retries(),
        }
    }
}

/// PKI secrets engine configuration for automatic certificate management.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkiConfig {
    /// Whether PKI auto-renewal is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// PKI secrets engine mount point (default: "pki").
    #[serde(default = "default_pki_mount")]
    pub mount: String,

    /// PKI role name for certificate issuance.
    #[serde(default = "default_pki_role")]
    pub role: String,

    /// Common name for the certificate.
    pub common_name: Option<String>,

    /// Certificate TTL in hours (default: 720 = 30 days).
    #[serde(default = "default_pki_ttl_hours")]
    pub ttl_hours: u32,

    /// Path to write the certificate PEM file.
    pub cert_path: PathBuf,

    /// Path to write the private key PEM file.
    pub key_path: PathBuf,

    /// Renewal threshold as percentage of TTL (default: 70%).
    #[serde(default = "default_renewal_threshold")]
    pub renewal_threshold_percent: u8,

    /// Check interval for certificate renewal in seconds.
    #[serde(default = "default_renewal_check_interval")]
    pub renewal_check_interval_secs: u64,
}

impl Default for PkiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mount: default_pki_mount(),
            role: default_pki_role(),
            common_name: None,
            ttl_hours: default_pki_ttl_hours(),
            cert_path: PathBuf::from("/etc/tacacs/server.crt"),
            key_path: PathBuf::from("/etc/tacacs/server.key"),
            renewal_threshold_percent: default_renewal_threshold(),
            renewal_check_interval_secs: default_renewal_check_interval(),
        }
    }
}

/// EST (RFC 7030) configuration for zero-touch certificate provisioning.
///
/// # NIST SP 800-53 Security Controls
///
/// This configuration implements:
/// - **IA-5 (Authenticator Management)**: Automated certificate lifecycle management
/// - **SC-17 (PKI Certificates)**: RFC 7030-compliant certificate enrollment
/// - **CM-3 (Configuration Change Control)**: Automated, auditable cert provisioning
#[derive(Clone, Serialize, Deserialize)]
pub struct EstConfig {
    /// Whether EST provisioning is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// EST server URL (e.g., "https://est.example.com/.well-known/est").
    pub server_url: String,

    /// HTTP Basic Auth username for initial enrollment (optional).
    #[serde(default)]
    pub username: Option<String>,

    /// HTTP Basic Auth password for initial enrollment (optional).
    #[serde(default)]
    pub password: Option<String>,

    /// Path to file containing the password (alternative to password field).
    #[serde(default)]
    pub password_file: Option<PathBuf>,

    /// Client certificate path for mTLS authentication (optional).
    #[serde(default)]
    pub client_cert_path: Option<PathBuf>,

    /// Client private key path for mTLS authentication (optional).
    #[serde(default)]
    pub client_key_path: Option<PathBuf>,

    /// CA label for fetching the EST CA certificate (optional).
    #[serde(default)]
    pub ca_label: Option<String>,

    /// Common name for the certificate (e.g., "tacacs-01.internal").
    pub common_name: String,

    /// Organization name for the certificate (optional).
    #[serde(default)]
    pub organization: Option<String>,

    /// Path to write the enrolled certificate.
    #[serde(default = "default_est_cert_path")]
    pub cert_path: PathBuf,

    /// Path to write the generated private key.
    #[serde(default = "default_est_key_path")]
    pub key_path: PathBuf,

    /// Path to write the EST CA certificate.
    #[serde(default = "default_est_ca_cert_path")]
    pub ca_cert_path: PathBuf,

    /// Renewal threshold as percentage of certificate lifetime (default: 70%).
    #[serde(default = "default_renewal_threshold")]
    pub renewal_threshold_percent: u8,

    /// Check interval for certificate renewal in seconds (default: 3600 = 1 hour).
    #[serde(default = "default_renewal_check_interval")]
    pub renewal_check_interval_secs: u64,

    /// Bootstrap enrollment timeout in seconds (default: 300 = 5 minutes).
    #[serde(default = "default_est_bootstrap_timeout")]
    pub bootstrap_timeout_secs: u64,

    /// Whether initial enrollment is required for server startup (default: false).
    /// If true, server exits on enrollment failure. If false, server starts degraded.
    #[serde(default)]
    pub initial_enrollment_required: bool,
}

/// Custom Debug implementation that redacts password field.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | IA-5 | Authenticator Management | Prevents credential exposure in debug/log output |
impl std::fmt::Debug for EstConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EstConfig")
            .field("enabled", &self.enabled)
            .field("server_url", &self.server_url)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("password_file", &self.password_file)
            .field("client_cert_path", &self.client_cert_path)
            .field("client_key_path", &self.client_key_path)
            .field("ca_label", &self.ca_label)
            .field("common_name", &self.common_name)
            .field("organization", &self.organization)
            .field("cert_path", &self.cert_path)
            .field("key_path", &self.key_path)
            .field("ca_cert_path", &self.ca_cert_path)
            .field("renewal_threshold_percent", &self.renewal_threshold_percent)
            .field(
                "renewal_check_interval_secs",
                &self.renewal_check_interval_secs,
            )
            .field("bootstrap_timeout_secs", &self.bootstrap_timeout_secs)
            .field(
                "initial_enrollment_required",
                &self.initial_enrollment_required,
            )
            .finish()
    }
}

impl Default for EstConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server_url: String::new(),
            username: None,
            password: None,
            password_file: None,
            client_cert_path: None,
            client_key_path: None,
            ca_label: None,
            common_name: String::new(),
            organization: None,
            cert_path: default_est_cert_path(),
            key_path: default_est_key_path(),
            ca_cert_path: default_est_ca_cert_path(),
            renewal_threshold_percent: default_renewal_threshold(),
            renewal_check_interval_secs: default_renewal_check_interval(),
            bootstrap_timeout_secs: default_est_bootstrap_timeout(),
            initial_enrollment_required: false,
        }
    }
}

// Default value functions for serde
fn default_auth_method() -> String {
    "approle".to_string()
}

fn default_refresh_interval() -> u64 {
    300 // 5 minutes
}

fn default_secret_path() -> String {
    "secret/data/tacacs".to_string()
}

fn default_timeout_ms() -> u64 {
    5000 // 5 seconds
}

fn default_max_retries() -> u32 {
    5
}

fn default_pki_mount() -> String {
    "pki".to_string()
}

fn default_pki_role() -> String {
    "tacacs-server".to_string()
}

fn default_pki_ttl_hours() -> u32 {
    720 // 30 days
}

fn default_renewal_threshold() -> u8 {
    70
}

fn default_renewal_check_interval() -> u64 {
    3600 // 1 hour
}

fn default_est_cert_path() -> PathBuf {
    PathBuf::from("/etc/tacacs/server.crt")
}

fn default_est_key_path() -> PathBuf {
    PathBuf::from("/etc/tacacs/server.key")
}

fn default_est_ca_cert_path() -> PathBuf {
    PathBuf::from("/etc/tacacs/ca.crt")
}

fn default_est_bootstrap_timeout() -> u64 {
    300 // 5 minutes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_openbao_config() {
        let config = OpenBaoConfig::default();
        assert_eq!(config.auth_method, "approle");
        assert_eq!(config.refresh_interval_secs, 300);
        assert_eq!(config.max_retries, 5);
    }

    #[test]
    fn test_default_pki_config() {
        let config = PkiConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.mount, "pki");
        assert_eq!(config.role, "tacacs-server");
        assert_eq!(config.ttl_hours, 720);
        assert_eq!(config.renewal_threshold_percent, 70);
    }

    #[test]
    fn test_serialize_deserialize() {
        let config = SecretsConfig {
            openbao: Some(OpenBaoConfig {
                address: "https://vault.example.com:8200".to_string(),
                location: Some("NYC01".to_string()),
                ..Default::default()
            }),
            pki: Some(PkiConfig {
                enabled: true,
                common_name: Some("nyc01.tacacs.internal".to_string()),
                ..Default::default()
            }),
            est: None,
        };

        let json = serde_json::to_string(&config).unwrap();
        let parsed: SecretsConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(
            parsed.openbao.as_ref().unwrap().address,
            "https://vault.example.com:8200"
        );
        assert_eq!(
            parsed.openbao.as_ref().unwrap().location,
            Some("NYC01".to_string())
        );
        assert!(parsed.pki.as_ref().unwrap().enabled);
    }

    #[test]
    fn test_default_est_config() {
        let config = EstConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.cert_path, PathBuf::from("/etc/tacacs/server.crt"));
        assert_eq!(config.key_path, PathBuf::from("/etc/tacacs/server.key"));
        assert_eq!(config.ca_cert_path, PathBuf::from("/etc/tacacs/ca.crt"));
        assert_eq!(config.renewal_threshold_percent, 70);
        assert_eq!(config.renewal_check_interval_secs, 3600);
        assert_eq!(config.bootstrap_timeout_secs, 300);
        assert!(!config.initial_enrollment_required);
    }

    #[test]
    fn test_est_config_serialize_deserialize() {
        let config = SecretsConfig {
            openbao: None,
            pki: None,
            est: Some(EstConfig {
                enabled: true,
                server_url: "https://est.example.com/.well-known/est".to_string(),
                username: Some("bootstrap".to_string()),
                password: Some("secret123".to_string()),
                common_name: "tacacs-01.internal".to_string(),
                organization: Some("Example Corp".to_string()),
                ..Default::default()
            }),
        };

        let json = serde_json::to_string(&config).unwrap();
        let parsed: SecretsConfig = serde_json::from_str(&json).unwrap();

        let est = parsed.est.as_ref().unwrap();
        assert!(est.enabled);
        assert_eq!(est.server_url, "https://est.example.com/.well-known/est");
        assert_eq!(est.username, Some("bootstrap".to_string()));
        assert_eq!(est.common_name, "tacacs-01.internal");
        assert_eq!(est.organization, Some("Example Corp".to_string()));
    }
}
