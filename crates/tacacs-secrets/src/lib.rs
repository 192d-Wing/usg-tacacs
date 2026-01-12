//! Secrets management for TACACS+ server.
//!
//! This crate provides a unified interface for secrets management, supporting:
//! - File-based secrets (backward compatibility)
//! - OpenBao/Vault integration for dynamic secrets
//! - PKI certificate management via OpenBao PKI secrets engine
//! - EST (RFC 7030) zero-touch certificate provisioning
//!
//! # Example
//!
//! ```no_run
//! use usg_tacacs_secrets::{SecretsProvider, OpenBaoProvider, OpenBaoConfig};
//!
//! # async fn example() -> anyhow::Result<()> {
//! let config = OpenBaoConfig {
//!     address: "https://openbao.internal:8200".to_string(),
//!     role_id_file: "/etc/tacacs/openbao-role-id".into(),
//!     secret_id_file: "/etc/tacacs/openbao-secret-id".into(),
//!     ..Default::default()
//! };
//!
//! let provider = OpenBaoProvider::new(config).await?;
//! let shared_secret = provider.get_shared_secret().await?;
//! # Ok(())
//! # }
//! ```

pub mod config;
pub mod est;
pub mod openbao;
pub mod provider;

// Re-exports for convenience
pub use config::{EstConfig, OpenBaoConfig, PkiConfig, SecretsConfig};
pub use est::{CertificateBundle, EstProvider};
pub use openbao::{OpenBaoClient, OpenBaoProvider};
pub use provider::{FileProvider, SecretChange, SecretValue, SecretsProvider};
