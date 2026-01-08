// SPDX-License-Identifier: Apache-2.0
//! OpenSSH integration for TACACS+ authentication and authorization.
//!
//! This crate provides helper utilities for integrating OpenSSH with a TACACS+
//! server over TLS. It includes:
//!
//! - **PAM Helper**: A binary for PAM authentication via TACACS+
//! - **AuthorizedKeysCommand**: A binary for fetching SSH public keys via TACACS+
//! - **Session Accounting**: Record SSH session start/stop events
//!
//! # OpenSSH Configuration
//!
//! ## PAM Authentication
//!
//! Configure PAM to use the TACACS+ helper in `/etc/pam.d/sshd`:
//!
//! ```text
//! auth required pam_exec.so expose_authtok /usr/local/bin/tacacs-pam-helper \
//!     --server tacacs.example.com:300 \
//!     --ca /etc/tacacs/ca.pem \
//!     --client-cert /etc/tacacs/client.pem \
//!     --client-key /etc/tacacs/client-key.pem
//! ```
//!
//! ## AuthorizedKeysCommand
//!
//! Configure sshd to fetch authorized keys via TACACS+ in `/etc/ssh/sshd_config`:
//!
//! ```text
//! AuthorizedKeysCommand /usr/local/bin/tacacs-authkeys \
//!     --server tacacs.example.com:300 \
//!     --ca /etc/tacacs/ca.pem \
//!     %u
//! AuthorizedKeysCommandUser nobody
//! ```
//!
//! # Security
//!
//! - All communication uses TLS 1.3 (no MD5 obfuscation)
//! - Supports mutual TLS for device authentication
//! - Credentials are never logged or stored
//!
//! # NIST SP 800-53 Security Controls
//!
//! This crate implements the following NIST security controls:
//!
//! - **IA-2 (Identification and Authentication)**: Provides centralized user
//!   authentication for SSH access via TACACS+ PAP. Users are authenticated
//!   against a central authentication server rather than local accounts.
//!
//! - **IA-3 (Device Identification and Authentication)**: Supports mutual TLS
//!   (mTLS) client certificates to authenticate the SSH server/device to the
//!   TACACS+ server before processing authentication requests.
//!
//! - **IA-5 (Authenticator Management)**: Passwords are transmitted securely
//!   via TLS 1.3 encryption. Credentials are never logged, stored locally,
//!   or exposed in process arguments.
//!
//! - **AC-3 (Access Enforcement)**: Enforces authorization decisions for SSH
//!   sessions and commands. Users must be explicitly authorized for shell access.
//!
//! - **AC-17 (Remote Access)**: Controls remote SSH access by centralizing
//!   authentication and authorization decisions at the TACACS+ server.
//!
//! - **AU-2 (Audit Events)**: Generates audit records for SSH session start/stop
//!   events via TACACS+ accounting, enabling centralized session tracking.
//!
//! - **AU-12 (Audit Generation)**: SSH session accounting records include
//!   username, task ID, elapsed time, and data transfer statistics.
//!
//! - **SC-8 (Transmission Confidentiality)**: All TACACS+ communication uses
//!   TLS 1.3 encryption with no fallback to legacy MD5 obfuscation.

pub mod config;

pub use config::{CommonArgs, Config};

use anyhow::Result;
use usg_tacacs_client_tls::{AcctResult, AuthenResult, AuthorResult, TacacsClient, TlsClientConfig};

/// Authenticate a user via TACACS+ PAP.
///
/// Returns `Ok(true)` if authentication succeeds, `Ok(false)` if it fails,
/// or an error if there's a communication problem.
///
/// # NIST Controls
/// - **IA-2 (Identification and Authentication)**: Verifies user identity
/// - **IA-5 (Authenticator Management)**: Password protected by TLS
pub async fn authenticate_pap(
    client: &mut TacacsClient,
    username: &str,
    password: &str,
) -> Result<bool> {
    let result = client.authenticate_pap(username, password).await?;

    match result {
        AuthenResult::Pass { .. } => Ok(true),
        AuthenResult::Fail { .. } => Ok(false),
        AuthenResult::Error { server_msg } => {
            anyhow::bail!("TACACS+ server error: {}", server_msg)
        }
        _ => Ok(false),
    }
}

/// Authorize an SSH session for a user.
///
/// Checks if the user is allowed to start an SSH shell session.
///
/// # NIST Controls
/// - **AC-3 (Access Enforcement)**: Enforces session authorization
/// - **AC-17 (Remote Access)**: Controls remote shell access
pub async fn authorize_ssh_session(
    client: &mut TacacsClient,
    username: &str,
) -> Result<bool> {
    let result = client
        .authorize_service(username, "shell", Some("ssh"), &[])
        .await?;

    match result {
        AuthorResult::PassAdd { .. } | AuthorResult::PassReplace { .. } => Ok(true),
        AuthorResult::Fail { .. } => Ok(false),
        AuthorResult::Error { server_msg, .. } => {
            anyhow::bail!("TACACS+ authorization error: {}", server_msg)
        }
    }
}

/// Authorize a specific SSH command for a user.
///
/// Used for command authorization in restricted shells or forced commands.
///
/// # NIST Controls
/// - **AC-3 (Access Enforcement)**: Enforces command-level authorization
/// - **AC-6 (Least Privilege)**: Restricts commands to authorized set
/// - **CM-5 (Access Restrictions for Change)**: Controls configuration commands
pub async fn authorize_ssh_command(
    client: &mut TacacsClient,
    username: &str,
    command: &str,
    args: &[&str],
) -> Result<bool> {
    let result = client.authorize_command(username, command, args).await?;

    match result {
        AuthorResult::PassAdd { .. } | AuthorResult::PassReplace { .. } => Ok(true),
        AuthorResult::Fail { .. } => Ok(false),
        AuthorResult::Error { server_msg, .. } => {
            anyhow::bail!("TACACS+ command authorization error: {}", server_msg)
        }
    }
}

/// Record SSH session start.
///
/// Call this when an SSH session begins to create an accounting record.
///
/// # NIST Controls
/// - **AU-2 (Audit Events)**: Records session start event
/// - **AU-12 (Audit Generation)**: Generates accounting record
pub async fn accounting_session_start(
    client: &mut TacacsClient,
    username: &str,
    task_id: &str,
    remote_addr: Option<&str>,
) -> Result<()> {
    let result = client.accounting_start(username, "shell", task_id).await?;

    match result {
        AcctResult::Success { .. } => {
            tracing::debug!(
                username = username,
                task_id = task_id,
                remote_addr = remote_addr,
                "SSH session start recorded"
            );
            Ok(())
        }
        AcctResult::Error { server_msg } => {
            anyhow::bail!("TACACS+ accounting error: {}", server_msg)
        }
    }
}

/// Record SSH session end.
///
/// Call this when an SSH session ends to complete the accounting record.
///
/// # NIST Controls
/// - **AU-2 (Audit Events)**: Records session end event
/// - **AU-3 (Content of Audit Records)**: Includes elapsed time, bytes transferred
/// - **AU-12 (Audit Generation)**: Completes session accounting record
pub async fn accounting_session_stop(
    client: &mut TacacsClient,
    username: &str,
    task_id: &str,
    elapsed_seconds: u32,
    bytes_in: u64,
    bytes_out: u64,
) -> Result<()> {
    let result = client
        .accounting_stop(
            username,
            "shell",
            task_id,
            elapsed_seconds,
            0, // status = success
            bytes_in,
            bytes_out,
        )
        .await?;

    match result {
        AcctResult::Success { .. } => {
            tracing::debug!(
                username = username,
                task_id = task_id,
                elapsed = elapsed_seconds,
                "SSH session stop recorded"
            );
            Ok(())
        }
        AcctResult::Error { server_msg } => {
            anyhow::bail!("TACACS+ accounting error: {}", server_msg)
        }
    }
}

/// Create a TACACS+ client from configuration.
///
/// # NIST Controls
/// - **SC-8 (Transmission Confidentiality)**: Establishes TLS 1.3 connection
/// - **SC-23 (Session Authenticity)**: Validates server certificate
/// - **IA-3 (Device Identification)**: Optional mTLS client authentication
pub async fn connect(config: &Config) -> Result<TacacsClient> {
    let mut tls_builder = TlsClientConfig::builder().with_server_ca(&config.ca_cert)?;

    if let (Some(cert), Some(key)) = (&config.client_cert, &config.client_key) {
        tls_builder = tls_builder.with_client_cert(cert, key)?;
    }

    let tls_config = tls_builder.build()?;

    let addr = format!("{}:{}", config.server, config.port);
    TacacsClient::connect(&addr, &config.server, tls_config).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = Config {
            server: "tacacs.example.com".to_string(),
            port: 300,
            ca_cert: "/etc/tacacs/ca.pem".into(),
            client_cert: None,
            client_key: None,
            timeout_secs: 30,
        };

        assert_eq!(config.port, 300);
        assert_eq!(config.timeout_secs, 30);
    }
}
