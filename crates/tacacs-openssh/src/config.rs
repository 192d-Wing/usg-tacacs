// SPDX-License-Identifier: Apache-2.0
//! Configuration for TACACS+ OpenSSH integration.
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
//! | CM-6 | Configuration Management | Implemented | 2026-01-31 | See functions below |
//! | IA-3 | Identification and Authentication | Implemented | 2026-01-31 | See functions below |
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
//!   "total_controls": 3,
//!   "file_path": "crates/tacacs-openssh/src/config.rs"
//! }
//! ```
//!
//! </details>
//!
//! # NIST SP 800-53 Security Controls
//!
//! This module supports the following security controls:
//!
//! - **SC-17 (PKI Certificates)**: Configuration includes CA certificate paths
//!   for server verification and optional client certificates for mTLS.
//!
//! - **CM-6 (Configuration Settings)**: Supports configuration via file, CLI
//!   arguments, or environment variables for consistent deployment.
//!
//! - **IA-3 (Device Identification)**: Client certificate configuration enables
//!   device authentication to the TACACS+ server.

use clap::Parser;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Configuration for connecting to a TACACS+ server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// TACACS+ server hostname or IP address.
    pub server: String,

    /// TACACS+ server port (default: 300 for TLS).
    #[serde(default = "default_port")]
    pub port: u16,

    /// Path to the CA certificate for server verification.
    pub ca_cert: PathBuf,

    /// Path to the client certificate for mTLS (optional).
    #[serde(default)]
    pub client_cert: Option<PathBuf>,

    /// Path to the client private key for mTLS (optional).
    #[serde(default)]
    pub client_key: Option<PathBuf>,

    /// Connection timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_port() -> u16 {
    300
}

fn default_timeout() -> u64 {
    30
}

impl Config {
    /// Load configuration from a JSON file.
    pub fn from_file(path: &PathBuf) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read config file: {}", e))?;
        serde_json::from_str(&content)
            .map_err(|e| anyhow::anyhow!("failed to parse config file: {}", e))
    }

    /// Create configuration from command-line arguments.
    pub fn from_args(args: &CommonArgs) -> Self {
        Self {
            server: args.server.clone(),
            port: args.port,
            ca_cert: args.ca.clone(),
            client_cert: args.client_cert.clone(),
            client_key: args.client_key.clone(),
            timeout_secs: args.timeout,
        }
    }
}

/// Common command-line arguments for TACACS+ connection.
#[derive(Debug, Clone, Parser)]
pub struct CommonArgs {
    /// TACACS+ server hostname or IP address.
    #[arg(long, short = 's', env = "TACACS_SERVER")]
    pub server: String,

    /// TACACS+ server port.
    #[arg(long, short = 'p', default_value = "300", env = "TACACS_PORT")]
    pub port: u16,

    /// Path to the CA certificate for server verification.
    #[arg(long, env = "TACACS_CA_CERT")]
    pub ca: PathBuf,

    /// Path to the client certificate for mTLS (optional).
    #[arg(long, env = "TACACS_CLIENT_CERT")]
    pub client_cert: Option<PathBuf>,

    /// Path to the client private key for mTLS (optional).
    #[arg(long, env = "TACACS_CLIENT_KEY")]
    pub client_key: Option<PathBuf>,

    /// Connection timeout in seconds.
    #[arg(long, default_value = "30", env = "TACACS_TIMEOUT")]
    pub timeout: u64,

    /// Path to configuration file (overrides other options).
    #[arg(long, short = 'c', env = "TACACS_CONFIG")]
    pub config: Option<PathBuf>,
}

impl CommonArgs {
    /// Resolve configuration from either file or CLI arguments.
    pub fn resolve(&self) -> anyhow::Result<Config> {
        if let Some(config_path) = &self.config {
            Config::from_file(config_path)
        } else {
            Ok(Config::from_args(self))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_deserialize() {
        let json = r#"{
            "server": "tacacs.example.com",
            "port": 300,
            "ca_cert": "/etc/tacacs/ca.pem"
        }"#;

        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.server, "tacacs.example.com");
        assert_eq!(config.port, 300);
        assert!(config.client_cert.is_none());
    }

    #[test]
    fn config_defaults() {
        let json = r#"{
            "server": "localhost",
            "ca_cert": "/tmp/ca.pem"
        }"#;

        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.port, 300);
        assert_eq!(config.timeout_secs, 30);
    }

    #[test]
    fn config_with_mtls() {
        let json = r#"{
            "server": "tacacs.example.com",
            "ca_cert": "/etc/tacacs/ca.pem",
            "client_cert": "/etc/tacacs/client.pem",
            "client_key": "/etc/tacacs/client-key.pem"
        }"#;

        let config: Config = serde_json::from_str(json).unwrap();
        assert!(config.client_cert.is_some());
        assert!(config.client_key.is_some());
    }
}
