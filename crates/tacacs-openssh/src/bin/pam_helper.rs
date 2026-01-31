// SPDX-License-Identifier: Apache-2.0
//! PAM authentication helper for TACACS+ over TLS.
//!
//! # NIST SP 800-53 Rev. 5 Security Controls
//!
//! **Control Implementation Matrix**
//!
//! This module implements controls documented in
//! [../../../../docs/NIST-CONTROLS-MAPPING.md](../../../../docs/NIST-CONTROLS-MAPPING.md).
//!
//! | Control | Family | Status | Validated | Primary Functions |
//! |---------|--------|--------|-----------|-------------------|
//! | AC-3 | Access Control | Implemented | 2026-01-31 | See functions below |
//! | IA-2 | Identification and Authentication | Implemented | 2026-01-31 | See functions below |
//! | IA-5 | Identification and Authentication | Implemented | 2026-01-31 | See functions below |
//! | IA-6 | Identification and Authentication | Implemented | 2026-01-31 | See functions below |
//! | SC-8 | System and Communications Protection | Implemented | 2026-01-31 | See functions below |
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
//!     "AC",
//!     "IA",
//!     "SC"
//!   ],
//!   "total_controls": 5,
//!   "file_path": "crates/tacacs-openssh/src/bin/pam_helper.rs"
//! }
//! ```
//!
//! </details>
//!
//! This binary is designed to be called by pam_exec.so to authenticate
//! users via a TACACS+ server. It reads the password from stdin (via
//! PAM's expose_authtok) and the username from the PAM_USER environment
//! variable.
//!
//! # PAM Configuration
//!
//! Add to `/etc/pam.d/sshd` or your target PAM service:
//!
//! ```text
//! auth required pam_exec.so expose_authtok /usr/local/bin/tacacs-pam-helper \
//!     --server tacacs.example.com \
//!     --ca /etc/tacacs/ca.pem
//! ```
//!
//! # Environment Variables
//!
//! - `PAM_USER`: Username being authenticated (set by PAM)
//! - `PAM_RHOST`: Remote host (optional, for accounting)
//! - `PAM_TTY`: TTY name (optional, for accounting)
//!
//! # Exit Codes
//!
//! - 0: Authentication successful (PAM_SUCCESS)
//! - 1: Authentication failed (PAM_AUTH_ERR)
//! - 2: Service unavailable (PAM_AUTHINFO_UNAVAIL)
//! - 3: User unknown (PAM_USER_UNKNOWN)
//!
//! # NIST SP 800-53 Security Controls
//!
//! This helper implements the following security controls:
//!
//! - **IA-2 (Identification and Authentication)**: Provides centralized
//!   authentication via TACACS+ rather than local password files.
//!
//! - **IA-5 (Authenticator Management)**: Passwords are read from stdin
//!   (PAM expose_authtok) and transmitted securely via TLS. Passwords are
//!   never logged, stored, or exposed in command-line arguments.
//!
//! - **IA-6 (Authenticator Feedback)**: Returns generic pass/fail status
//!   without revealing whether the username exists.
//!
//! - **AC-3 (Access Enforcement)**: Optional `--authorize` flag enforces
//!   session authorization after successful authentication.
//!
//! - **SC-8 (Transmission Confidentiality)**: All TACACS+ communication
//!   uses TLS 1.3 encryption.

use anyhow::{Context, Result};
use clap::Parser;
use std::io::{self, BufRead};
use std::process::ExitCode;
use tracing::{debug, error, info, warn};
use usg_tacacs_openssh::{authenticate_pap, authorize_ssh_session, connect};

/// PAM authentication helper for TACACS+
#[derive(Parser, Debug)]
#[command(name = "tacacs-pam-helper")]
#[command(about = "Authenticate users via TACACS+ for PAM")]
#[command(version)]
struct Args {
    #[command(flatten)]
    common: usg_tacacs_openssh::config::CommonArgs,

    /// Also perform authorization check after authentication.
    #[arg(long)]
    authorize: bool,

    /// Enable debug logging to stderr.
    #[arg(long, short = 'd')]
    debug: bool,
}

/// PAM-compatible exit codes.
mod exit_codes {
    pub const PAM_SUCCESS: u8 = 0;
    pub const PAM_AUTH_ERR: u8 = 1;
    pub const PAM_AUTHINFO_UNAVAIL: u8 = 2;
    #[allow(dead_code)]
    pub const PAM_USER_UNKNOWN: u8 = 3;
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    // Initialize logging
    if args.debug {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    match run(&args).await {
        Ok(true) => {
            info!("authentication successful");
            ExitCode::from(exit_codes::PAM_SUCCESS)
        }
        Ok(false) => {
            warn!("authentication failed");
            ExitCode::from(exit_codes::PAM_AUTH_ERR)
        }
        Err(e) => {
            error!("authentication error: {:#}", e);
            ExitCode::from(exit_codes::PAM_AUTHINFO_UNAVAIL)
        }
    }
}

async fn run(args: &Args) -> Result<bool> {
    // Get username from PAM environment
    let username = std::env::var("PAM_USER").context("PAM_USER environment variable not set")?;

    if username.is_empty() {
        anyhow::bail!("PAM_USER is empty");
    }

    debug!(username = %username, "authenticating user");

    // Read password from stdin (PAM expose_authtok)
    let password = read_password_from_stdin()?;

    if password.is_empty() {
        warn!(username = %username, "empty password provided");
        return Ok(false);
    }

    // Resolve configuration
    let config = args.common.resolve()?;

    // Connect to TACACS+ server
    let mut client = connect(&config)
        .await
        .context("failed to connect to TACACS+ server")?;

    // Authenticate
    let auth_result = authenticate_pap(&mut client, &username, &password).await?;

    if !auth_result {
        debug!(username = %username, "PAP authentication failed");
        return Ok(false);
    }

    debug!(username = %username, "PAP authentication succeeded");

    // Optional authorization check
    if args.authorize {
        let authz_result = authorize_ssh_session(&mut client, &username).await?;
        if !authz_result {
            warn!(username = %username, "SSH authorization denied");
            return Ok(false);
        }
        debug!(username = %username, "SSH authorization granted");
    }

    Ok(true)
}

/// Read password from stdin (for PAM expose_authtok).
///
/// PAM sends the password as the first line on stdin when using expose_authtok.
fn read_password_from_stdin() -> Result<String> {
    let stdin = io::stdin();
    let mut handle = stdin.lock();
    let mut password = String::new();

    handle
        .read_line(&mut password)
        .context("failed to read password from stdin")?;

    // Remove trailing newline
    if password.ends_with('\n') {
        password.pop();
    }
    if password.ends_with('\r') {
        password.pop();
    }

    Ok(password)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_are_correct() {
        assert_eq!(exit_codes::PAM_SUCCESS, 0);
        assert_eq!(exit_codes::PAM_AUTH_ERR, 1);
        assert_eq!(exit_codes::PAM_AUTHINFO_UNAVAIL, 2);
    }
}
