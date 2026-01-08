// SPDX-License-Identifier: Apache-2.0
//! TLS-only TACACS+ client library.
//!
//! This crate provides a secure TACACS+ client that uses TLS 1.3 exclusively
//! for transport security, per RFC 9887. Unlike legacy TACACS+, this client
//! does not use MD5 body obfuscation - all security is provided by the TLS layer.
//!
//! # Features
//!
//! - **TLS 1.3 Only**: Modern cryptography with forward secrecy
//! - **No MD5**: Eliminates weak MD5-based obfuscation
//! - **Mutual TLS**: Optional client certificate authentication
//! - **Full AAA Support**: Authentication, Authorization, and Accounting
//!
//! # Quick Start
//!
//! ```ignore
//! use usg_tacacs_client_tls::{TacacsClient, TlsClientConfig};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Configure TLS
//!     let tls_config = TlsClientConfig::builder()
//!         .with_server_ca("./certs/ca.pem")?
//!         .with_client_cert("./certs/client.pem", "./certs/client-key.pem")?
//!         .build()?;
//!
//!     // Connect to TACACS+ server
//!     let mut client = TacacsClient::connect(
//!         "192.168.1.1:300",
//!         "tacacs.example.com",
//!         tls_config
//!     ).await?;
//!
//!     // Authenticate user
//!     let result = client.authenticate_pap("alice", "password123").await?;
//!     println!("Authentication: {:?}", result);
//!
//!     // Authorize command
//!     let authz = client.authorize_command("alice", "show", &["version"]).await?;
//!     println!("Authorization: {:?}", authz);
//!
//!     // Record accounting
//!     client.accounting_start("alice", "shell", "task-001").await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Security Considerations
//!
//! ## TLS Configuration
//!
//! The client enforces TLS 1.3 only - no fallback to older TLS versions is
//! permitted. Server certificates must be validated against a trusted CA.
//!
//! ## Mutual TLS
//!
//! For highest security, configure client certificates for mutual TLS (mTLS)
//! authentication. This provides device-level authentication in addition to
//! user credentials.
//!
//! ## No MD5 Obfuscation
//!
//! Unlike legacy TACACS+ (RFC 8907), this client does not implement MD5-based
//! body obfuscation. The shared secret parameter used by legacy implementations
//! is not used - TLS provides all cryptographic protection.
//!
//! # NIST SP 800-53 Compliance
//!
//! This implementation supports the following security controls:
//!
//! - **SC-8**: Transmission Confidentiality (TLS 1.3 encryption)
//! - **SC-13**: Cryptographic Protection (modern cipher suites)
//! - **SC-17**: PKI Certificates (X.509 validation)
//! - **SC-23**: Session Authenticity (mutual TLS)
//! - **IA-2**: User Authentication (TACACS+ authentication)
//! - **IA-3**: Device Identification (client certificates)
//! - **AC-3**: Access Enforcement (authorization)
//! - **AU-2/AU-12**: Audit Events (accounting records)
//!
//! # Protocol Reference
//!
//! - RFC 8907: TACACS+ Protocol
//! - RFC 9887: TACACS+ TLS 1.3

mod acct;
mod authen;
mod author;
mod client;
mod tls;

// Re-export main types
pub use acct::AcctResult;
pub use authen::{AuthenResult, ACTION_ENABLE, ACTION_LOGIN, SERVICE_ENABLE, SERVICE_LOGIN};
pub use author::AuthorResult;
pub use client::{Session, TacacsClient, DEFAULT_PORT};
pub use tls::{TlsClientConfig, TlsClientConfigBuilder};

// Re-export accounting flags for custom accounting
pub use usg_tacacs_proto::{ACCT_FLAG_START, ACCT_FLAG_STOP, ACCT_FLAG_WATCHDOG};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_are_exported() {
        assert_eq!(DEFAULT_PORT, 300);
        assert_eq!(ACTION_LOGIN, 0x01);
        assert_eq!(ACTION_ENABLE, 0x02);
        assert_eq!(SERVICE_LOGIN, 0x01);
        assert_eq!(SERVICE_ENABLE, 0x02);
    }

    #[test]
    fn accounting_flags_exported() {
        assert_eq!(ACCT_FLAG_START, 0x02);
        assert_eq!(ACCT_FLAG_STOP, 0x04);
        assert_eq!(ACCT_FLAG_WATCHDOG, 0x08);
    }
}
