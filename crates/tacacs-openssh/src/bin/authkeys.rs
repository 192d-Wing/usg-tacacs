// SPDX-License-Identifier: Apache-2.0
//! AuthorizedKeysCommand helper for TACACS+ over TLS.
//!
//! This binary is designed to be used as OpenSSH's AuthorizedKeysCommand.
//! It queries a TACACS+ server for a user's authorized SSH public keys.
//!
//! # OpenSSH Configuration
//!
//! Add to `/etc/ssh/sshd_config`:
//!
//! ```text
//! AuthorizedKeysCommand /usr/local/bin/tacacs-authkeys \
//!     --server tacacs.example.com \
//!     --ca /etc/tacacs/ca.pem \
//!     %u
//! AuthorizedKeysCommandUser nobody
//! ```
//!
//! # How It Works
//!
//! 1. OpenSSH calls this command with the username as an argument
//! 2. This helper authenticates to TACACS+ server (connection only, no user auth)
//! 3. Sends an authorization request for "service=sshd" with attribute "keys"
//! 4. Server returns authorized_keys data in response arguments
//! 5. Keys are printed to stdout in OpenSSH authorized_keys format
//!
//! # TACACS+ Server Configuration
//!
//! The TACACS+ server policy should be configured to return SSH keys in
//! authorization responses. Example response attributes:
//!
//! ```text
//! ssh-key=ssh-rsa AAAA... user@host
//! ssh-key=ssh-ed25519 AAAA... user@host2
//! ```
//!
//! # Exit Codes
//!
//! - 0: Success (keys printed to stdout, may be empty)
//! - 1: Error (connection failed, authorization error, etc.)
//!
//! # NIST SP 800-53 Security Controls
//!
//! This helper implements the following security controls:
//!
//! - **IA-2 (Identification and Authentication)**: Enables centralized SSH
//!   key management through TACACS+, ensuring consistent authentication
//!   policy across all managed hosts.
//!
//! - **IA-5(2) (PKI-Based Authentication)**: Retrieves and validates SSH
//!   public keys from central authority rather than local files, supporting
//!   centralized key lifecycle management.
//!
//! - **AC-3 (Access Enforcement)**: Uses TACACS+ authorization to determine
//!   which public keys are valid for a given user, enforcing access policy.
//!
//! - **AC-17 (Remote Access)**: Controls SSH remote access by centralizing
//!   authorized key distribution, enabling rapid key revocation.
//!
//! - **CM-3 (Configuration Change Control)**: Centralized key management
//!   eliminates local authorized_keys file modifications, improving change
//!   control and auditability.
//!
//! - **SC-8 (Transmission Confidentiality)**: All communication with the
//!   TACACS+ server uses TLS 1.3 encryption.

use anyhow::{Context, Result};
use clap::Parser;
use std::process::ExitCode;
use tracing::{debug, error, info};
use usg_tacacs_client_tls::AuthorResult;
use usg_tacacs_openssh::connect;

/// AuthorizedKeysCommand helper for TACACS+
#[derive(Parser, Debug)]
#[command(name = "tacacs-authkeys")]
#[command(about = "Fetch SSH authorized keys via TACACS+ authorization")]
#[command(version)]
struct Args {
    #[command(flatten)]
    common: usg_tacacs_openssh::config::CommonArgs,

    /// Username to fetch keys for (typically passed as %u by sshd).
    #[arg(required = true)]
    username: String,

    /// Service name for authorization request.
    #[arg(long, default_value = "sshd")]
    service: String,

    /// Enable debug logging to stderr.
    #[arg(long, short = 'd')]
    debug: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    // Initialize logging (to stderr so it doesn't interfere with key output)
    if args.debug {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    match run(&args).await {
        Ok(keys) => {
            let count = keys.len();
            // Print keys to stdout for sshd
            for key in keys {
                println!("{}", key);
            }
            info!(username = %args.username, count = count, "returned authorized keys");
            ExitCode::SUCCESS
        }
        Err(e) => {
            error!("failed to fetch authorized keys: {:#}", e);
            ExitCode::FAILURE
        }
    }
}

/// Fetch SSH authorized keys from TACACS+ server.
///
/// # NIST Controls
/// - **IA-2**: Centralized key retrieval for user identification
/// - **AC-3**: Authorization-based key access control
/// - **SC-8**: TLS-encrypted communication with server
async fn run(args: &Args) -> Result<Vec<String>> {
    debug!(username = %args.username, service = %args.service, "fetching SSH keys");

    // NIST SC-8: Configuration includes TLS parameters for secure communication
    let config = args.common.resolve()?;

    // NIST SC-8, SC-17: TLS connection with certificate verification
    let mut client = connect(&config)
        .await
        .context("failed to connect to TACACS+ server")?;

    // NIST AC-3, IA-5(2): Authorization request for SSH public keys
    // The server is expected to return keys in ssh-key=<key> attributes
    let result = client
        .authorize_service(
            &args.username,
            &args.service,
            Some("publickey"),
            &[("request", "keys")],
        )
        .await
        .context("authorization request failed")?;

    // Extract keys from response
    let keys = match result {
        AuthorResult::PassAdd { args, .. } | AuthorResult::PassReplace { args, .. } => {
            extract_ssh_keys(&args)
        }
        AuthorResult::Fail { server_msg, .. } => {
            debug!(
                username = %args.username,
                msg = %server_msg,
                "authorization denied, no keys returned"
            );
            Vec::new()
        }
        AuthorResult::Error { server_msg, .. } => {
            anyhow::bail!("TACACS+ server error: {}", server_msg);
        }
    };

    debug!(username = %args.username, count = keys.len(), "extracted SSH keys");

    Ok(keys)
}

/// Extract SSH public keys from TACACS+ authorization response arguments.
///
/// Looks for arguments in the format:
/// - `ssh-key=<key>`
/// - `authorized-key=<key>`
/// - `pubkey=<key>`
///
/// # NIST Controls
/// - **IA-5(2)**: Validates SSH key format before returning
fn extract_ssh_keys(args: &[String]) -> Vec<String> {
    let mut keys = Vec::new();

    for arg in args {
        // Check for various key attribute formats
        let key = if let Some(k) = arg.strip_prefix("ssh-key=") {
            Some(k)
        } else if let Some(k) = arg.strip_prefix("authorized-key=") {
            Some(k)
        } else { arg.strip_prefix("pubkey=").map(|k| k) };

        if let Some(k) = key {
            let k = k.trim();
            if !k.is_empty() && is_valid_ssh_key(k) {
                keys.push(k.to_string());
            }
        }
    }

    keys
}

/// Basic validation that a string looks like an SSH public key.
///
/// # NIST Controls
/// - **IA-5(2)**: Input validation for PKI-based authenticators
fn is_valid_ssh_key(key: &str) -> bool {
    // SSH keys start with key type
    let valid_prefixes = [
        "ssh-rsa",
        "ssh-ed25519",
        "ssh-dss",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519",
        "sk-ecdsa-sha2-nistp256",
    ];

    valid_prefixes.iter().any(|prefix| key.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_ssh_keys_from_args() {
        let args = vec![
            "service=sshd".to_string(),
            "ssh-key=ssh-rsa AAAA... user@host".to_string(),
            "ssh-key=ssh-ed25519 AAAA... user@host2".to_string(),
            "other=value".to_string(),
        ];

        let keys = extract_ssh_keys(&args);
        assert_eq!(keys.len(), 2);
        assert!(keys[0].starts_with("ssh-rsa"));
        assert!(keys[1].starts_with("ssh-ed25519"));
    }

    #[test]
    fn extract_authorized_key_format() {
        let args = vec!["authorized-key=ssh-ed25519 AAAA... user".to_string()];

        let keys = extract_ssh_keys(&args);
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn extract_ignores_invalid_keys() {
        let args = vec![
            "ssh-key=invalid-key".to_string(),
            "ssh-key=".to_string(),
            "ssh-key=ssh-rsa VALID".to_string(),
        ];

        let keys = extract_ssh_keys(&args);
        assert_eq!(keys.len(), 1);
        assert!(keys[0].starts_with("ssh-rsa"));
    }

    #[test]
    fn is_valid_ssh_key_rsa() {
        assert!(is_valid_ssh_key("ssh-rsa AAAA..."));
    }

    #[test]
    fn is_valid_ssh_key_ed25519() {
        assert!(is_valid_ssh_key("ssh-ed25519 AAAA..."));
    }

    #[test]
    fn is_valid_ssh_key_ecdsa() {
        assert!(is_valid_ssh_key("ecdsa-sha2-nistp256 AAAA..."));
    }

    #[test]
    fn is_valid_ssh_key_sk() {
        assert!(is_valid_ssh_key("sk-ssh-ed25519 AAAA..."));
        assert!(is_valid_ssh_key("sk-ecdsa-sha2-nistp256 AAAA..."));
    }

    #[test]
    fn is_valid_ssh_key_invalid() {
        assert!(!is_valid_ssh_key("invalid"));
        assert!(!is_valid_ssh_key(""));
        assert!(!is_valid_ssh_key("not-a-key AAAA"));
    }
}
