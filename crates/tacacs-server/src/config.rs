// SPDX-License-Identifier: Apache-2.0
//! Configuration management for TACACS+ server.
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
//! | AC-10 | Access Control | Implemented | 2026-01-31 | See functions below |
//! | AC-7 | Access Control | Implemented | 2026-01-31 | See functions below |
//! | CM-2 | Configuration Management | Implemented | 2026-01-31 | See functions below |
//! | CM-6 | Configuration Management | Implemented | 2026-01-31 | See functions below |
//! | IA-5 | Identification and Authentication | Implemented | 2026-01-31 | See functions below |
//! | SC-12 | System and Communications Protection | Implemented | 2026-01-31 | See functions below |
//! | SC-28 | System and Communications Protection | Implemented | 2026-01-31 | See functions below |
//! | SI-10 | System and Information Integrity | Implemented | 2026-01-31 | See functions below |
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
//!     "CM",
//!     "IA",
//!     "SC",
//!     "SI"
//!   ],
//!   "total_controls": 8,
//!   "file_path": "crates/tacacs-server/src/config.rs"
//! }
//! ```
//!
//! </details>
//!
//! # NIST SP 800-53 Security Controls
//!
//! This module implements the following NIST security controls:
//!
//! - **CM-2 (Baseline Configuration)**: Defines all configurable parameters
//!   with secure defaults and validation requirements.
//!
//! - **CM-6 (Configuration Settings)**: Enforces secure defaults:
//!   - Static credentials disabled by default
//!   - Minimum secret lengths enforced
//!   - Reasonable timeout defaults
//!
//! - **SI-10 (Information Input Validation)**: Validates all configuration
//!   inputs including paths, addresses, and security parameters.
//!
//! - **AC-7 (Unsuccessful Logon Attempts)**: Configurable brute-force
//!   protection parameters (attempt limits, backoff, lockout).
//!
//! - **SC-12 (Cryptographic Key Establishment)**: TLS certificate and
//!   key path configuration.

use clap::{Parser, ValueEnum};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

/// Log output format.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum LogFormat {
    /// Human-readable text format (default).
    #[default]
    Text,
    /// JSON structured logging for log aggregation (ELK, Loki).
    Json,
}

/// Command-line arguments for the TACACS+ server.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | CM-2/CM-6 | Baseline Configuration | All parameters support secure baseline configuration |
/// | SI-10 | Input Validation | Input validation via clap argument parsing |
#[derive(Parser, Debug)]
#[command(name = "usg-tacacs", version, about = "Rust TACACS+ server")]
pub struct Args {
    /// Validate a policy file and exit.
    #[arg(long)]
    pub check_policy: Option<PathBuf>,

    /// JSON schema to validate policy files against.
    #[arg(long)]
    pub schema: Option<PathBuf>,

    /// Path to the active policy.
    #[arg(long)]
    pub policy: Option<PathBuf>,

    /// Listen address for TACACS+ over TLS (mTLS required).
    #[arg(long)]
    pub listen_tls: Option<SocketAddr>,

    /// Listen address for legacy plaintext TACACS+.
    #[arg(long)]
    pub listen_legacy: Option<SocketAddr>,

    /// Listen address for HTTP health checks and Prometheus metrics (e.g., 127.0.0.1:8080).
    #[arg(long)]
    pub listen_http: Option<SocketAddr>,

    /// Log output format: text or json.
    #[arg(long, value_enum, default_value_t = LogFormat::Text)]
    pub log_format: LogFormat,

    /// Location identifier for metrics labels (e.g., NYC01, LAX01).
    #[arg(long)]
    pub location: Option<String>,

    /// Server certificate (PEM).
    #[arg(long)]
    pub tls_cert: Option<PathBuf>,

    /// Server private key (PEM).
    #[arg(long)]
    pub tls_key: Option<PathBuf>,

    /// Client CA bundle (PEM).
    #[arg(long)]
    pub client_ca: Option<PathBuf>,

    /// Additional trusted root CAs for client mTLS verification (PEM, repeatable).
    #[arg(long, value_name = "CA_PEM", num_args = 0..)]
    pub tls_trust_root: Vec<PathBuf>,

    /// Shared secret for TACACS+ body obfuscation (required for legacy, recommended otherwise).
    ///
    /// **Security Note**: Prefer --secret-file or TACACS_SECRET env var over CLI argument
    /// to avoid exposing secrets in process listings.
    #[arg(long, env = "TACACS_SECRET")]
    pub secret: Option<String>,

    /// Path to file containing the shared secret (recommended for production).
    ///
    /// File should have restrictive permissions (e.g., 0600) and contain only the secret.
    /// Takes precedence over --secret and TACACS_SECRET if specified.
    #[arg(long)]
    pub secret_file: Option<PathBuf>,

    /// Reject UNENCRYPTED TACACS+ packets when a secret is configured, even over TLS.
    #[arg(long)]
    pub forbid_unencrypted: bool,

    /// Separate PSK for TLS; must not match the TACACS+ obfuscation secret.
    #[arg(long)]
    pub tls_psk: Option<String>,

    /// Static user:password pairs for PAP/CHAP verification (repeatable).
    #[arg(long, value_parser = parse_user_password, value_name = "USER:PASS")]
    pub user_password: Vec<(String, String)>,

    /// Optional file containing user:password entries (one per line). Disabled unless --allow-static-credentials.
    #[arg(long)]
    pub user_password_file: Option<PathBuf>,

    /// Optional hashed user:argon2 entries (user:$argon2id$v=... format).
    #[arg(long, value_parser = parse_user_password, value_name = "USER:ARGON2")]
    pub user_password_hash: Vec<(String, String)>,

    /// Optional file containing user:argon2 entries (one per line). Disabled unless --allow-static-credentials.
    #[arg(long)]
    pub user_password_hash_file: Option<PathBuf>,

    /// Permit loading static credentials (inline or file). Defaults to false to encourage LDAPS.
    #[arg(long, default_value_t = false)]
    pub allow_static_credentials: bool,

    /// Maximum ASCII authentication attempts before failing the session (0 = unlimited).
    #[arg(long, default_value_t = 5)]
    pub ascii_attempt_limit: u8,

    /// Maximum username prompts for ASCII auth before failing the session (0 = unlimited).
    #[arg(long, default_value_t = 3)]
    pub ascii_user_attempt_limit: u8,

    /// Maximum password prompts for ASCII auth before failing the session (0 = unlimited).
    #[arg(long, default_value_t = 5)]
    pub ascii_pass_attempt_limit: u8,

    /// Base backoff (ms) before repeating ASCII username/password prompts (0 = no delay).
    #[arg(long, default_value_t = 0)]
    pub ascii_backoff_ms: u64,

    /// Maximum backoff (ms) for ASCII prompt retries (0 = no cap).
    #[arg(long, default_value_t = 5000)]
    pub ascii_backoff_max_ms: u64,

    /// Lock out ASCII auth after this many attempts (0 = no lockout).
    #[arg(long, default_value_t = 0)]
    pub ascii_lockout_limit: u8,

    /// Idle timeout (seconds) for single-connection sessions before closing (0 = disabled).
    #[arg(long, default_value_t = 300)]
    pub single_connect_idle_secs: u64,

    /// Expected keepalive activity interval (seconds) for single-connection sessions; 0 disables the timeout.
    #[arg(long, default_value_t = 120)]
    pub single_connect_keepalive_secs: u64,

    /// Maximum concurrent connections allowed per peer IP (0 = unlimited).
    #[arg(long, default_value_t = 50)]
    pub max_connections_per_ip: u32,

    /// Maximum total sessions across all IPs (0 = unlimited).
    /// Enforced by session registry for NIST AC-10 compliance.
    #[arg(long, default_value_t = 0)]
    pub max_sessions: usize,

    /// Maximum sessions per IP address (0 = unlimited).
    /// Enforced by session registry for NIST AC-10 compliance.
    #[arg(long, default_value_t = 0)]
    pub max_sessions_per_ip: usize,

    /// Allowed client certificate Common Names (exact match). If set, client CN must match one of these.
    #[arg(long, value_name = "CN", num_args = 0..)]
    pub tls_allowed_client_cn: Vec<String>,

    /// Allowed client certificate SAN entries (DNS/IP/URI exact match). If set, client SAN must match one of these.
    #[arg(long, value_name = "SAN", num_args = 0..)]
    pub tls_allowed_client_san: Vec<String>,

    /// LDAPS URL for LDAP authentication (must start with ldaps://). If unset, LDAP auth is disabled.
    #[arg(long)]
    pub ldaps_url: Option<String>,

    /// LDAP service account bind DN.
    #[arg(long)]
    pub ldap_bind_dn: Option<String>,

    /// LDAP service account password.
    ///
    /// **Security Note**: Prefer --ldap-bind-password-file or LDAP_BIND_PASSWORD env var
    /// over CLI argument to avoid exposing secrets in process listings.
    #[arg(long, env = "LDAP_BIND_PASSWORD")]
    pub ldap_bind_password: Option<String>,

    /// Path to file containing the LDAP bind password (recommended for production).
    ///
    /// File should have restrictive permissions (e.g., 0600) and contain only the password.
    /// Takes precedence over --ldap-bind-password and LDAP_BIND_PASSWORD if specified.
    #[arg(long)]
    pub ldap_bind_password_file: Option<PathBuf>,

    /// LDAP search base for locating user entries.
    #[arg(long)]
    pub ldap_search_base: Option<String>,

    /// LDAP attribute to match the TACACS+ username (default: uid).
    #[arg(long, default_value = "uid")]
    pub ldap_username_attr: String,

    /// LDAP connect/operation timeout in milliseconds.
    #[arg(long, default_value_t = 5000)]
    pub ldap_timeout_ms: u64,

    /// Optional CA file for LDAPS validation.
    #[arg(long)]
    pub ldap_ca_file: Option<PathBuf>,

    /// Optional LDAP group DNs required for authentication (match-any).
    #[arg(long, value_name = "GROUP_DN", num_args = 0..)]
    pub ldap_required_group: Vec<String>,

    /// LDAP attribute to read group membership from (default: memberOf).
    #[arg(long, default_value = "memberOf")]
    pub ldap_group_attr: String,

    /// Legacy TACACS+ per-NAD secrets (IP:SECRET). When set, only listed NADs may use legacy TACACS+.
    #[arg(long, value_parser = parse_nad_secret, value_name = "IP:SECRET", num_args = 0..)]
    pub legacy_nad_secret: Vec<(IpAddr, String)>,

    /// OpenTelemetry OTLP endpoint URL (e.g., http://jaeger:4317). Enables distributed tracing.
    #[arg(long)]
    pub otlp_endpoint: Option<String>,

    /// Service name for OpenTelemetry traces (default: tacacs-server).
    #[arg(long, default_value = "tacacs-server")]
    pub otel_service_name: String,

    /// Graceful shutdown drain timeout in seconds. After receiving SIGTERM,
    /// the server will stop accepting new connections and wait this long
    /// for existing connections to complete (default: 30).
    #[arg(long, default_value_t = 30)]
    pub shutdown_drain_timeout_secs: u64,

    /// Force shutdown timeout in seconds. After the drain timeout, any
    /// remaining connections will be forcefully closed after this additional
    /// timeout (default: 30, total max shutdown time = drain + force).
    #[arg(long, default_value_t = 30)]
    pub shutdown_force_timeout_secs: u64,

    // ==================== OpenBao Integration ====================
    /// Enable OpenBao/Vault integration for secrets management.
    #[arg(long, default_value_t = false)]
    pub openbao_enabled: bool,

    /// OpenBao server address (e.g., https://openbao.internal:8200).
    #[arg(long, default_value = "https://openbao.internal:8200")]
    pub openbao_address: String,

    /// OpenBao authentication method (currently only "approle" is supported).
    #[arg(long, default_value = "approle")]
    pub openbao_auth_method: String,

    /// Path to file containing the AppRole role_id.
    #[arg(long)]
    pub openbao_role_id_file: Option<PathBuf>,

    /// Path to file containing the AppRole secret_id.
    #[arg(long)]
    pub openbao_secret_id_file: Option<PathBuf>,

    /// Optional CA certificate file for OpenBao TLS verification.
    #[arg(long)]
    pub openbao_ca_file: Option<PathBuf>,

    /// Secret refresh interval in seconds (how often to poll OpenBao for secret changes).
    #[arg(long, default_value_t = 300)]
    pub openbao_refresh_interval_secs: u64,

    /// Base path for TACACS secrets in OpenBao KV v2 engine.
    #[arg(long, default_value = "secret/data/tacacs")]
    pub openbao_secret_path: String,

    /// Location identifier for per-location secrets in OpenBao (e.g., NYC01).
    #[arg(long)]
    pub openbao_location: Option<String>,

    // ==================== OpenBao PKI (Certificate Management) ====================
    /// Enable automatic TLS certificate management via OpenBao PKI secrets engine.
    #[arg(long, default_value_t = false)]
    pub openbao_pki_enabled: bool,

    /// OpenBao PKI secrets engine mount point.
    #[arg(long, default_value = "pki")]
    pub openbao_pki_mount: String,

    /// OpenBao PKI role name for certificate issuance.
    #[arg(long, default_value = "tacacs-server")]
    pub openbao_pki_role: String,

    /// Common name for the issued TLS certificate.
    #[arg(long)]
    pub openbao_pki_common_name: Option<String>,

    /// Certificate TTL in hours (default: 720 = 30 days).
    #[arg(long, default_value_t = 720)]
    pub openbao_pki_ttl_hours: u32,

    /// Renewal threshold as percentage of TTL (renew when this % of lifetime has elapsed).
    #[arg(long, default_value_t = 70)]
    pub openbao_pki_renewal_threshold: u8,

    // ==================== EST (RFC 7030) Zero-Touch Provisioning ====================
    /// Enable EST-based certificate provisioning for zero-touch deployment.
    #[arg(long, default_value_t = false, env = "EST_ENABLED")]
    pub est_enabled: bool,

    /// EST server URL (e.g., https://est.example.com/.well-known/est).
    #[arg(long, env = "EST_SERVER_URL")]
    pub est_server_url: Option<String>,

    /// HTTP Basic Auth username for EST enrollment.
    #[arg(long, env = "EST_USERNAME")]
    pub est_username: Option<String>,

    /// HTTP Basic Auth password for EST enrollment.
    ///
    /// **Security Note**: Prefer --est-password-file or EST_PASSWORD_FILE to avoid
    /// exposing credentials in process listings.
    #[arg(long, env = "EST_PASSWORD")]
    pub est_password: Option<String>,

    /// Path to file containing the EST password.
    #[arg(long, env = "EST_PASSWORD_FILE")]
    pub est_password_file: Option<PathBuf>,

    /// Client certificate for EST mTLS authentication (PEM).
    #[arg(long, env = "EST_CLIENT_CERT")]
    pub est_client_cert_path: Option<PathBuf>,

    /// Client private key for EST mTLS authentication (PEM).
    #[arg(long, env = "EST_CLIENT_KEY")]
    pub est_client_key_path: Option<PathBuf>,

    /// EST CA label for fetching the EST server's CA certificate.
    #[arg(long, env = "EST_CA_LABEL")]
    pub est_ca_label: Option<String>,

    /// Common name for the EST-enrolled certificate (e.g., tacacs-01.internal).
    #[arg(long, env = "EST_COMMON_NAME")]
    pub est_common_name: Option<String>,

    /// Organization name for the EST certificate.
    #[arg(long, env = "EST_ORGANIZATION")]
    pub est_organization: Option<String>,

    /// Path to write the EST-enrolled certificate (default: /etc/tacacs/server.crt).
    #[arg(long, default_value = "/etc/tacacs/server.crt", env = "EST_CERT_PATH")]
    pub est_cert_path: PathBuf,

    /// Path to write the EST-generated private key (default: /etc/tacacs/server.key).
    #[arg(long, default_value = "/etc/tacacs/server.key", env = "EST_KEY_PATH")]
    pub est_key_path: PathBuf,

    /// Path to write the EST CA certificate chain (default: /etc/tacacs/ca.crt).
    #[arg(long, default_value = "/etc/tacacs/ca.crt", env = "EST_CA_CERT_PATH")]
    pub est_ca_cert_path: PathBuf,

    /// EST certificate renewal threshold as percentage of remaining time (default: 70).
    /// Renew when <= this percentage of time until expiry remains.
    #[arg(long, default_value_t = 70, env = "EST_RENEWAL_THRESHOLD")]
    pub est_renewal_threshold_percent: u8,

    /// EST certificate renewal check interval in seconds (default: 3600 = 1 hour).
    #[arg(long, default_value_t = 3600, env = "EST_RENEWAL_CHECK_INTERVAL")]
    pub est_renewal_check_interval_secs: u64,

    /// EST bootstrap enrollment timeout in seconds (default: 300 = 5 minutes).
    #[arg(long, default_value_t = 300, env = "EST_BOOTSTRAP_TIMEOUT")]
    pub est_bootstrap_timeout_secs: u64,

    /// Whether EST initial enrollment is required for server startup.
    /// If true, server exits on enrollment failure. If false, server starts degraded.
    #[arg(long, default_value_t = false, env = "EST_INITIAL_ENROLLMENT_REQUIRED")]
    pub est_initial_enrollment_required: bool,

    // ==================== Management API Configuration ====================
    /// Enable the Management API server.
    #[arg(long, default_value_t = false)]
    pub api_enabled: bool,

    /// Listen address for the Management API (e.g., 127.0.0.1:8443).
    #[arg(long)]
    pub api_listen: Option<SocketAddr>,

    /// TLS certificate for the Management API (PEM).
    #[arg(long)]
    pub api_tls_cert: Option<PathBuf>,

    /// TLS private key for the Management API (PEM).
    #[arg(long)]
    pub api_tls_key: Option<PathBuf>,

    /// Client CA bundle for Management API mTLS (PEM).
    #[arg(long)]
    pub api_client_ca: Option<PathBuf>,

    /// JSON file containing RBAC configuration for the Management API.
    #[arg(long)]
    pub api_rbac_config: Option<PathBuf>,
}

#[derive(Clone, Debug, Default)]
pub struct StaticCreds {
    pub plain: HashMap<String, String>,
    pub argon: HashMap<String, String>,
}

/// Read a secret from a file, trimming whitespace.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | SC-28 | Protection of Information at Rest | Secrets stored in files with restrictive permissions (0600 recommended) |
///
/// # Errors
/// Returns an error if the file cannot be read or is empty.
pub fn read_secret_file(path: &PathBuf) -> std::io::Result<String> {
    let content = std::fs::read_to_string(path)?;
    let secret = content.trim().to_string();
    if secret.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "secret file is empty",
        ));
    }
    Ok(secret)
}

/// Resolve the TACACS+ shared secret from file, CLI argument, or environment variable.
///
/// Priority order (highest to lowest):
/// 1. --secret-file (file-based secret)
/// 2. --secret or TACACS_SECRET environment variable
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | SC-12 | Cryptographic Key Establishment | Secure secret provisioning via files with restrictive permissions |
#[allow(dead_code)]
pub fn resolve_tacacs_secret(args: &Args) -> std::result::Result<Option<String>, String> {
    // File-based secret takes precedence
    if let Some(path) = &args.secret_file {
        let secret = read_secret_file(path)
            .map_err(|e| format!("failed to read secret file {:?}: {}", path, e))?;
        return Ok(Some(secret));
    }
    // Fall back to CLI arg / env var (clap handles env)
    Ok(args.secret.clone())
}

/// Resolve the LDAP bind password from file, CLI argument, or environment variable.
///
/// Priority order (highest to lowest):
/// 1. --ldap-bind-password-file (file-based secret)
/// 2. --ldap-bind-password or LDAP_BIND_PASSWORD environment variable
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | SC-12 | Cryptographic Key Establishment | Secure secret provisioning via files with restrictive permissions |
#[allow(dead_code)]
pub fn resolve_ldap_bind_password(args: &Args) -> std::result::Result<Option<String>, String> {
    // File-based password takes precedence
    if let Some(path) = &args.ldap_bind_password_file {
        let password = read_secret_file(path)
            .map_err(|e| format!("failed to read LDAP bind password file {:?}: {}", path, e))?;
        return Ok(Some(password));
    }
    // Fall back to CLI arg / env var (clap handles env)
    Ok(args.ldap_bind_password.clone())
}

/// Build EST configuration from CLI arguments and environment variables.
///
/// Returns None if EST is not enabled. Validates required fields when enabled.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | SC-12 | Cryptographic Key Establishment | Secure credential provisioning for EST enrollment |
/// | IA-5 | Authenticator Management | Zero-touch certificate lifecycle configuration |
pub fn build_est_config(
    args: &Args,
) -> std::result::Result<Option<usg_tacacs_secrets::EstConfig>, String> {
    if !args.est_enabled {
        return Ok(None);
    }

    // Validate required fields
    let server_url = args
        .est_server_url
        .as_ref()
        .ok_or_else(|| "EST enabled but --est-server-url not provided".to_string())?;

    let common_name = args
        .est_common_name
        .as_ref()
        .ok_or_else(|| "EST enabled but --est-common-name not provided".to_string())?;

    // Resolve password from file or CLI/env
    let password = if let Some(ref pwd_file) = args.est_password_file {
        Some(
            read_secret_file(pwd_file)
                .map_err(|e| format!("failed to read EST password file {:?}: {}", pwd_file, e))?,
        )
    } else {
        args.est_password.clone()
    };

    let config = usg_tacacs_secrets::EstConfig {
        enabled: true,
        server_url: server_url.clone(),
        username: args.est_username.clone(),
        password,
        password_file: args.est_password_file.clone(),
        client_cert_path: args.est_client_cert_path.clone(),
        client_key_path: args.est_client_key_path.clone(),
        ca_label: args.est_ca_label.clone(),
        common_name: common_name.clone(),
        organization: args.est_organization.clone(),
        cert_path: args.est_cert_path.clone(),
        key_path: args.est_key_path.clone(),
        ca_cert_path: args.est_ca_cert_path.clone(),
        renewal_threshold_percent: args.est_renewal_threshold_percent,
        renewal_check_interval_secs: args.est_renewal_check_interval_secs,
        bootstrap_timeout_secs: args.est_bootstrap_timeout_secs,
        initial_enrollment_required: args.est_initial_enrollment_required,
    };

    Ok(Some(config))
}

pub fn credentials_map(args: &Args) -> std::result::Result<StaticCreds, String> {
    if !args.allow_static_credentials
        && (!args.user_password.is_empty()
            || args.user_password_file.is_some()
            || !args.user_password_hash.is_empty()
            || args.user_password_hash_file.is_some())
    {
        return Err(
            "static credentials are disabled; set --allow-static-credentials to enable them"
                .to_string(),
        );
    }

    if (!args.user_password.is_empty() && args.user_password_file.is_some())
        || (!args.user_password_hash.is_empty() && args.user_password_hash_file.is_some())
    {
        return Err(
            "specify either inline or file for user_password and user_password_hash, not both"
                .into(),
        );
    }

    let mut creds = StaticCreds::default();
    creds.plain.extend(args.user_password.clone());
    creds.argon.extend(args.user_password_hash.clone());

    if let Some(path) = args.user_password_file.as_ref() {
        load_user_pass_file(path, &mut creds.plain)
            .map_err(|e| format!("failed to read user_password_file {path:?}: {e}"))?;
    }

    if let Some(path) = args.user_password_hash_file.as_ref() {
        load_user_pass_file(path, &mut creds.argon)
            .map_err(|e| format!("failed to read user_password_hash_file {path:?}: {e}"))?;
    }

    Ok(creds)
}

fn load_user_pass_file(
    path: &PathBuf,
    target: &mut HashMap<String, String>,
) -> std::io::Result<()> {
    let data = std::fs::read_to_string(path)?;
    for (idx, line) in data.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, ':');
        let user = parts.next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("missing user on line {}", idx + 1),
            )
        })?;
        let pass = parts.next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("missing password on line {}", idx + 1),
            )
        })?;
        if user.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("user cannot be empty on line {}", idx + 1),
            ));
        }
        target.insert(user.to_string(), pass.to_string());
    }
    Ok(())
}

fn parse_user_password(s: &str) -> std::result::Result<(String, String), String> {
    let mut parts = s.splitn(2, ':');
    let user = parts
        .next()
        .ok_or_else(|| "missing user".to_string())?
        .to_string();
    let pass = parts
        .next()
        .ok_or_else(|| "missing password".to_string())?
        .to_string();
    if user.is_empty() {
        return Err("user cannot be empty".into());
    }
    Ok((user, pass))
}

/// Parse NAD secret in the format `IP:SECRET` or `[IPv6]:SECRET`.
///
/// Supports:
/// - IPv4: `192.168.1.1:secret`
/// - IPv6 (bracketed): `[2001:db8::1]:secret`
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | SI-10 | Information Input Validation | Validates IP address format and ensures secrets are non-empty |
fn parse_nad_secret(s: &str) -> std::result::Result<(IpAddr, String), String> {
    // Check for bracketed IPv6 notation: [IPv6]:secret
    if s.starts_with('[') {
        // Find the closing bracket
        let bracket_end = s
            .find(']')
            .ok_or_else(|| "missing closing bracket for IPv6 address".to_string())?;

        let ip_str = &s[1..bracket_end];
        let ip = ip_str
            .parse::<IpAddr>()
            .map_err(|e| format!("invalid IPv6 address: {e}"))?;

        // Expect `:secret` after the bracket
        let remainder = &s[bracket_end + 1..];
        if !remainder.starts_with(':') {
            return Err("expected ':' after closing bracket".to_string());
        }

        let secret = remainder[1..].to_string();
        if secret.is_empty() {
            return Err("secret cannot be empty".into());
        }
        return Ok((ip, secret));
    }

    // Standard IPv4 format: split on first colon
    let mut parts = s.splitn(2, ':');
    let ip = parts
        .next()
        .ok_or_else(|| "missing NAD IP".to_string())?
        .parse::<IpAddr>()
        .map_err(|e| format!("invalid IP: {e}"))?;
    let secret = parts
        .next()
        .ok_or_else(|| "missing secret".to_string())?
        .to_string();
    if secret.is_empty() {
        return Err("secret cannot be empty".into());
    }
    Ok((ip, secret))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // ==================== parse_user_password Tests ====================

    #[test]
    fn parse_user_password_valid() {
        let result = parse_user_password("admin:secret123");
        assert!(result.is_ok());
        let (user, pass) = result.unwrap();
        assert_eq!(user, "admin");
        assert_eq!(pass, "secret123");
    }

    #[test]
    fn parse_user_password_with_colon_in_password() {
        let result = parse_user_password("admin:secret:with:colons");
        assert!(result.is_ok());
        let (user, pass) = result.unwrap();
        assert_eq!(user, "admin");
        assert_eq!(pass, "secret:with:colons");
    }

    #[test]
    fn parse_user_password_empty_password() {
        let result = parse_user_password("admin:");
        assert!(result.is_ok());
        let (user, pass) = result.unwrap();
        assert_eq!(user, "admin");
        assert_eq!(pass, "");
    }

    #[test]
    fn parse_user_password_empty_user() {
        let result = parse_user_password(":password");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty"));
    }

    #[test]
    fn parse_user_password_missing_password() {
        let result = parse_user_password("admin");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing password"));
    }

    #[test]
    fn parse_user_password_special_characters() {
        let result = parse_user_password("user@domain.com:P@$$w0rd!#");
        assert!(result.is_ok());
        let (user, pass) = result.unwrap();
        assert_eq!(user, "user@domain.com");
        assert_eq!(pass, "P@$$w0rd!#");
    }

    // ==================== parse_nad_secret Tests ====================

    #[test]
    fn parse_nad_secret_ipv4() {
        let result = parse_nad_secret("192.168.1.1:mysecret");
        assert!(result.is_ok());
        let (ip, secret) = result.unwrap();
        assert_eq!(ip, "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(secret, "mysecret");
    }

    #[test]
    fn parse_nad_secret_ipv6_bracketed() {
        // IPv6 addresses require bracketed notation: [IPv6]:secret
        let result = parse_nad_secret("[2001:db8::1]:mysecret");
        assert!(result.is_ok());
        let (ip, secret) = result.unwrap();
        assert_eq!(ip, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(secret, "mysecret");
    }

    #[test]
    fn parse_nad_secret_ipv6_full_address() {
        let result = parse_nad_secret("[2001:db8:85a3:8d3:1319:8a2e:370:7348]:secret123");
        assert!(result.is_ok());
        let (ip, secret) = result.unwrap();
        assert_eq!(
            ip,
            "2001:db8:85a3:8d3:1319:8a2e:370:7348"
                .parse::<IpAddr>()
                .unwrap()
        );
        assert_eq!(secret, "secret123");
    }

    #[test]
    fn parse_nad_secret_ipv6_loopback() {
        let result = parse_nad_secret("[::1]:loopback-secret");
        assert!(result.is_ok());
        let (ip, secret) = result.unwrap();
        assert_eq!(ip, "::1".parse::<IpAddr>().unwrap());
        assert_eq!(secret, "loopback-secret");
    }

    #[test]
    fn parse_nad_secret_ipv6_secret_with_colons() {
        let result = parse_nad_secret("[2001:db8::1]:secret:with:colons");
        assert!(result.is_ok());
        let (ip, secret) = result.unwrap();
        assert_eq!(ip, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(secret, "secret:with:colons");
    }

    #[test]
    fn parse_nad_secret_ipv6_missing_closing_bracket() {
        let result = parse_nad_secret("[2001:db8::1:secret");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing closing bracket"));
    }

    #[test]
    fn parse_nad_secret_ipv6_missing_colon_after_bracket() {
        let result = parse_nad_secret("[2001:db8::1]secret");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expected ':'"));
    }

    #[test]
    fn parse_nad_secret_ipv6_empty_secret() {
        let result = parse_nad_secret("[2001:db8::1]:");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty"));
    }

    #[test]
    fn parse_nad_secret_ipv6_invalid_address() {
        let result = parse_nad_secret("[not-an-ipv6]:secret");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid IPv6"));
    }

    #[test]
    fn parse_nad_secret_ipv6_unbracketed_fails() {
        // Unbracketed IPv6 should fail because "2001" is not a valid IP
        let result = parse_nad_secret("2001:db8::1:secret");
        assert!(result.is_err());
    }

    #[test]
    fn parse_nad_secret_with_colon_in_secret() {
        let result = parse_nad_secret("10.0.0.1:secret:with:colons");
        assert!(result.is_ok());
        let (ip, secret) = result.unwrap();
        assert_eq!(ip, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(secret, "secret:with:colons");
    }

    #[test]
    fn parse_nad_secret_empty_secret() {
        let result = parse_nad_secret("192.168.1.1:");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty"));
    }

    #[test]
    fn parse_nad_secret_invalid_ip() {
        let result = parse_nad_secret("invalid:secret");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid IP"));
    }

    #[test]
    fn parse_nad_secret_missing_secret() {
        let result = parse_nad_secret("192.168.1.1");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing secret"));
    }

    // ==================== load_user_pass_file Tests ====================

    #[test]
    fn load_user_pass_file_valid() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "admin:password123").unwrap();
        writeln!(file, "user:secret456").unwrap();

        let mut target = HashMap::new();
        let result = load_user_pass_file(&file.path().to_path_buf(), &mut target);

        assert!(result.is_ok());
        assert_eq!(target.len(), 2);
        assert_eq!(target.get("admin"), Some(&"password123".to_string()));
        assert_eq!(target.get("user"), Some(&"secret456".to_string()));
    }

    #[test]
    fn load_user_pass_file_empty_lines_skipped() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "admin:password123").unwrap();
        writeln!(file).unwrap();
        writeln!(file, "   ").unwrap();
        writeln!(file, "user:secret456").unwrap();

        let mut target = HashMap::new();
        let result = load_user_pass_file(&file.path().to_path_buf(), &mut target);

        assert!(result.is_ok());
        assert_eq!(target.len(), 2);
    }

    #[test]
    fn load_user_pass_file_duplicate_overwrites() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "admin:password1").unwrap();
        writeln!(file, "admin:password2").unwrap();

        let mut target = HashMap::new();
        let result = load_user_pass_file(&file.path().to_path_buf(), &mut target);

        assert!(result.is_ok());
        assert_eq!(target.len(), 1);
        assert_eq!(target.get("admin"), Some(&"password2".to_string()));
    }

    #[test]
    fn load_user_pass_file_missing_password() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "admin").unwrap();

        let mut target = HashMap::new();
        let result = load_user_pass_file(&file.path().to_path_buf(), &mut target);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("missing password"));
    }

    #[test]
    fn load_user_pass_file_empty_user() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, ":password").unwrap();

        let mut target = HashMap::new();
        let result = load_user_pass_file(&file.path().to_path_buf(), &mut target);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn load_user_pass_file_with_whitespace_trimming() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "  admin:password  ").unwrap();

        let mut target = HashMap::new();
        let result = load_user_pass_file(&file.path().to_path_buf(), &mut target);

        assert!(result.is_ok());
        assert_eq!(target.get("admin"), Some(&"password".to_string()));
    }

    #[test]
    fn load_user_pass_file_nonexistent() {
        let mut target = HashMap::new();
        let result = load_user_pass_file(&PathBuf::from("/nonexistent/file"), &mut target);

        assert!(result.is_err());
    }

    // ==================== credentials_map Tests ====================

    #[test]
    fn credentials_map_empty_allowed() {
        let args = Args {
            check_policy: None,
            schema: None,
            policy: None,
            listen_tls: None,
            listen_legacy: None,
            listen_http: None,
            log_format: LogFormat::Text,
            location: None,
            tls_cert: None,
            tls_key: None,
            client_ca: None,
            tls_trust_root: Vec::new(),
            secret: None,
            secret_file: None,
            forbid_unencrypted: false,
            tls_psk: None,
            user_password: Vec::new(),
            user_password_file: None,
            user_password_hash: Vec::new(),
            user_password_hash_file: None,
            allow_static_credentials: true,
            ascii_attempt_limit: 5,
            ascii_user_attempt_limit: 3,
            ascii_pass_attempt_limit: 5,
            ascii_backoff_ms: 0,
            ascii_backoff_max_ms: 5000,
            ascii_lockout_limit: 0,
            single_connect_idle_secs: 300,
            single_connect_keepalive_secs: 120,
            max_connections_per_ip: 50,
            max_sessions: 0,
            max_sessions_per_ip: 0,
            tls_allowed_client_cn: Vec::new(),
            tls_allowed_client_san: Vec::new(),
            ldaps_url: None,
            ldap_bind_dn: None,
            ldap_bind_password: None,
            ldap_bind_password_file: None,
            ldap_search_base: None,
            ldap_username_attr: "uid".into(),
            ldap_timeout_ms: 5000,
            ldap_ca_file: None,
            ldap_required_group: Vec::new(),
            ldap_group_attr: "memberOf".into(),
            legacy_nad_secret: Vec::new(),
            otlp_endpoint: None,
            otel_service_name: "tacacs-server".into(),
            shutdown_drain_timeout_secs: 30,
            shutdown_force_timeout_secs: 30,
            openbao_enabled: false,
            openbao_address: "https://openbao.internal:8200".into(),
            openbao_auth_method: "approle".into(),
            openbao_role_id_file: None,
            openbao_secret_id_file: None,
            openbao_ca_file: None,
            openbao_refresh_interval_secs: 300,
            openbao_secret_path: "secret/data/tacacs".into(),
            openbao_location: None,
            openbao_pki_enabled: false,
            openbao_pki_mount: "pki".into(),
            openbao_pki_role: "tacacs-server".into(),
            openbao_pki_common_name: None,
            openbao_pki_ttl_hours: 720,
            openbao_pki_renewal_threshold: 70,
            api_enabled: false,
            api_listen: None,
            api_tls_cert: None,
            api_tls_key: None,
            api_client_ca: None,
            api_rbac_config: None,
            est_enabled: false,
            est_server_url: None,
            est_username: None,
            est_password: None,
            est_password_file: None,
            est_client_cert_path: None,
            est_client_key_path: None,
            est_ca_label: None,
            est_common_name: None,
            est_organization: None,
            est_cert_path: PathBuf::from("/etc/tacacs/server.crt"),
            est_key_path: PathBuf::from("/etc/tacacs/server.key"),
            est_ca_cert_path: PathBuf::from("/etc/tacacs/ca.crt"),
            est_renewal_threshold_percent: 70,
            est_renewal_check_interval_secs: 3600,
            est_bootstrap_timeout_secs: 300,
            est_initial_enrollment_required: false,
        };

        let result = credentials_map(&args);
        assert!(result.is_ok());
        let creds = result.unwrap();
        assert!(creds.plain.is_empty());
        assert!(creds.argon.is_empty());
    }

    #[test]
    fn credentials_map_inline_passwords() {
        let args = Args {
            check_policy: None,
            schema: None,
            policy: None,
            listen_tls: None,
            listen_legacy: None,
            listen_http: None,
            log_format: LogFormat::Text,
            location: None,
            tls_cert: None,
            tls_key: None,
            client_ca: None,
            tls_trust_root: Vec::new(),
            secret: None,
            secret_file: None,
            forbid_unencrypted: false,
            tls_psk: None,
            user_password: vec![
                ("admin".into(), "secret1".into()),
                ("user".into(), "secret2".into()),
            ],
            user_password_file: None,
            user_password_hash: Vec::new(),
            user_password_hash_file: None,
            allow_static_credentials: true,
            ascii_attempt_limit: 5,
            ascii_user_attempt_limit: 3,
            ascii_pass_attempt_limit: 5,
            ascii_backoff_ms: 0,
            ascii_backoff_max_ms: 5000,
            ascii_lockout_limit: 0,
            single_connect_idle_secs: 300,
            single_connect_keepalive_secs: 120,
            max_connections_per_ip: 50,
            max_sessions: 0,
            max_sessions_per_ip: 0,
            tls_allowed_client_cn: Vec::new(),
            tls_allowed_client_san: Vec::new(),
            ldaps_url: None,
            ldap_bind_dn: None,
            ldap_bind_password: None,
            ldap_bind_password_file: None,
            ldap_search_base: None,
            ldap_username_attr: "uid".into(),
            ldap_timeout_ms: 5000,
            ldap_ca_file: None,
            ldap_required_group: Vec::new(),
            ldap_group_attr: "memberOf".into(),
            legacy_nad_secret: Vec::new(),
            otlp_endpoint: None,
            otel_service_name: "tacacs-server".into(),
            shutdown_drain_timeout_secs: 30,
            shutdown_force_timeout_secs: 30,
            openbao_enabled: false,
            openbao_address: "https://openbao.internal:8200".into(),
            openbao_auth_method: "approle".into(),
            openbao_role_id_file: None,
            openbao_secret_id_file: None,
            openbao_ca_file: None,
            openbao_refresh_interval_secs: 300,
            openbao_secret_path: "secret/data/tacacs".into(),
            openbao_location: None,
            openbao_pki_enabled: false,
            openbao_pki_mount: "pki".into(),
            openbao_pki_role: "tacacs-server".into(),
            openbao_pki_common_name: None,
            openbao_pki_ttl_hours: 720,
            openbao_pki_renewal_threshold: 70,
            api_enabled: false,
            api_listen: None,
            api_tls_cert: None,
            api_tls_key: None,
            api_client_ca: None,
            api_rbac_config: None,
            est_enabled: false,
            est_server_url: None,
            est_username: None,
            est_password: None,
            est_password_file: None,
            est_client_cert_path: None,
            est_client_key_path: None,
            est_ca_label: None,
            est_common_name: None,
            est_organization: None,
            est_cert_path: PathBuf::from("/etc/tacacs/server.crt"),
            est_key_path: PathBuf::from("/etc/tacacs/server.key"),
            est_ca_cert_path: PathBuf::from("/etc/tacacs/ca.crt"),
            est_renewal_threshold_percent: 70,
            est_renewal_check_interval_secs: 3600,
            est_bootstrap_timeout_secs: 300,
            est_initial_enrollment_required: false,
        };

        let result = credentials_map(&args);
        assert!(result.is_ok());
        let creds = result.unwrap();
        assert_eq!(creds.plain.len(), 2);
        assert_eq!(creds.plain.get("admin"), Some(&"secret1".to_string()));
        assert_eq!(creds.plain.get("user"), Some(&"secret2".to_string()));
    }

    #[test]
    fn credentials_map_disabled_without_flag() {
        let args = Args {
            check_policy: None,
            schema: None,
            policy: None,
            listen_tls: None,
            listen_legacy: None,
            listen_http: None,
            log_format: LogFormat::Text,
            location: None,
            tls_cert: None,
            tls_key: None,
            client_ca: None,
            tls_trust_root: Vec::new(),
            secret: None,
            secret_file: None,
            forbid_unencrypted: false,
            tls_psk: None,
            user_password: vec![("admin".into(), "secret".into())],
            user_password_file: None,
            user_password_hash: Vec::new(),
            user_password_hash_file: None,
            allow_static_credentials: false, // Disabled
            ascii_attempt_limit: 5,
            ascii_user_attempt_limit: 3,
            ascii_pass_attempt_limit: 5,
            ascii_backoff_ms: 0,
            ascii_backoff_max_ms: 5000,
            ascii_lockout_limit: 0,
            single_connect_idle_secs: 300,
            single_connect_keepalive_secs: 120,
            max_connections_per_ip: 50,
            max_sessions: 0,
            max_sessions_per_ip: 0,
            tls_allowed_client_cn: Vec::new(),
            tls_allowed_client_san: Vec::new(),
            ldaps_url: None,
            ldap_bind_dn: None,
            ldap_bind_password: None,
            ldap_bind_password_file: None,
            ldap_search_base: None,
            ldap_username_attr: "uid".into(),
            ldap_timeout_ms: 5000,
            ldap_ca_file: None,
            ldap_required_group: Vec::new(),
            ldap_group_attr: "memberOf".into(),
            legacy_nad_secret: Vec::new(),
            otlp_endpoint: None,
            otel_service_name: "tacacs-server".into(),
            shutdown_drain_timeout_secs: 30,
            shutdown_force_timeout_secs: 30,
            openbao_enabled: false,
            openbao_address: "https://openbao.internal:8200".into(),
            openbao_auth_method: "approle".into(),
            openbao_role_id_file: None,
            openbao_secret_id_file: None,
            openbao_ca_file: None,
            openbao_refresh_interval_secs: 300,
            openbao_secret_path: "secret/data/tacacs".into(),
            openbao_location: None,
            openbao_pki_enabled: false,
            openbao_pki_mount: "pki".into(),
            openbao_pki_role: "tacacs-server".into(),
            openbao_pki_common_name: None,
            openbao_pki_ttl_hours: 720,
            openbao_pki_renewal_threshold: 70,
            api_enabled: false,
            api_listen: None,
            api_tls_cert: None,
            api_tls_key: None,
            api_client_ca: None,
            api_rbac_config: None,
            est_enabled: false,
            est_server_url: None,
            est_username: None,
            est_password: None,
            est_password_file: None,
            est_client_cert_path: None,
            est_client_key_path: None,
            est_ca_label: None,
            est_common_name: None,
            est_organization: None,
            est_cert_path: PathBuf::from("/etc/tacacs/server.crt"),
            est_key_path: PathBuf::from("/etc/tacacs/server.key"),
            est_ca_cert_path: PathBuf::from("/etc/tacacs/ca.crt"),
            est_renewal_threshold_percent: 70,
            est_renewal_check_interval_secs: 3600,
            est_bootstrap_timeout_secs: 300,
            est_initial_enrollment_required: false,
        };

        let result = credentials_map(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("disabled"));
    }

    #[test]
    fn credentials_map_both_inline_and_file_fails() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "user:pass").unwrap();

        let args = Args {
            check_policy: None,
            schema: None,
            policy: None,
            listen_tls: None,
            listen_legacy: None,
            listen_http: None,
            log_format: LogFormat::Text,
            location: None,
            tls_cert: None,
            tls_key: None,
            client_ca: None,
            tls_trust_root: Vec::new(),
            secret: None,
            secret_file: None,
            forbid_unencrypted: false,
            tls_psk: None,
            user_password: vec![("admin".into(), "secret".into())],
            user_password_file: Some(file.path().to_path_buf()),
            user_password_hash: Vec::new(),
            user_password_hash_file: None,
            allow_static_credentials: true,
            ascii_attempt_limit: 5,
            ascii_user_attempt_limit: 3,
            ascii_pass_attempt_limit: 5,
            ascii_backoff_ms: 0,
            ascii_backoff_max_ms: 5000,
            ascii_lockout_limit: 0,
            single_connect_idle_secs: 300,
            single_connect_keepalive_secs: 120,
            max_connections_per_ip: 50,
            max_sessions: 0,
            max_sessions_per_ip: 0,
            tls_allowed_client_cn: Vec::new(),
            tls_allowed_client_san: Vec::new(),
            ldaps_url: None,
            ldap_bind_dn: None,
            ldap_bind_password: None,
            ldap_bind_password_file: None,
            ldap_search_base: None,
            ldap_username_attr: "uid".into(),
            ldap_timeout_ms: 5000,
            ldap_ca_file: None,
            ldap_required_group: Vec::new(),
            ldap_group_attr: "memberOf".into(),
            legacy_nad_secret: Vec::new(),
            otlp_endpoint: None,
            otel_service_name: "tacacs-server".into(),
            shutdown_drain_timeout_secs: 30,
            shutdown_force_timeout_secs: 30,
            openbao_enabled: false,
            openbao_address: "https://openbao.internal:8200".into(),
            openbao_auth_method: "approle".into(),
            openbao_role_id_file: None,
            openbao_secret_id_file: None,
            openbao_ca_file: None,
            openbao_refresh_interval_secs: 300,
            openbao_secret_path: "secret/data/tacacs".into(),
            openbao_location: None,
            openbao_pki_enabled: false,
            openbao_pki_mount: "pki".into(),
            openbao_pki_role: "tacacs-server".into(),
            openbao_pki_common_name: None,
            openbao_pki_ttl_hours: 720,
            openbao_pki_renewal_threshold: 70,
            api_enabled: false,
            api_listen: None,
            api_tls_cert: None,
            api_tls_key: None,
            api_client_ca: None,
            api_rbac_config: None,
            est_enabled: false,
            est_server_url: None,
            est_username: None,
            est_password: None,
            est_password_file: None,
            est_client_cert_path: None,
            est_client_key_path: None,
            est_ca_label: None,
            est_common_name: None,
            est_organization: None,
            est_cert_path: PathBuf::from("/etc/tacacs/server.crt"),
            est_key_path: PathBuf::from("/etc/tacacs/server.key"),
            est_ca_cert_path: PathBuf::from("/etc/tacacs/ca.crt"),
            est_renewal_threshold_percent: 70,
            est_renewal_check_interval_secs: 3600,
            est_bootstrap_timeout_secs: 300,
            est_initial_enrollment_required: false,
        };

        let result = credentials_map(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not both"));
    }

    #[test]
    fn credentials_map_from_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "admin:filepass").unwrap();
        writeln!(file, "operator:operpass").unwrap();

        let args = Args {
            check_policy: None,
            schema: None,
            policy: None,
            listen_tls: None,
            listen_legacy: None,
            listen_http: None,
            log_format: LogFormat::Text,
            location: None,
            tls_cert: None,
            tls_key: None,
            client_ca: None,
            tls_trust_root: Vec::new(),
            secret: None,
            secret_file: None,
            forbid_unencrypted: false,
            tls_psk: None,
            user_password: Vec::new(),
            user_password_file: Some(file.path().to_path_buf()),
            user_password_hash: Vec::new(),
            user_password_hash_file: None,
            allow_static_credentials: true,
            ascii_attempt_limit: 5,
            ascii_user_attempt_limit: 3,
            ascii_pass_attempt_limit: 5,
            ascii_backoff_ms: 0,
            ascii_backoff_max_ms: 5000,
            ascii_lockout_limit: 0,
            single_connect_idle_secs: 300,
            single_connect_keepalive_secs: 120,
            max_connections_per_ip: 50,
            max_sessions: 0,
            max_sessions_per_ip: 0,
            tls_allowed_client_cn: Vec::new(),
            tls_allowed_client_san: Vec::new(),
            ldaps_url: None,
            ldap_bind_dn: None,
            ldap_bind_password: None,
            ldap_bind_password_file: None,
            ldap_search_base: None,
            ldap_username_attr: "uid".into(),
            ldap_timeout_ms: 5000,
            ldap_ca_file: None,
            ldap_required_group: Vec::new(),
            ldap_group_attr: "memberOf".into(),
            legacy_nad_secret: Vec::new(),
            otlp_endpoint: None,
            otel_service_name: "tacacs-server".into(),
            shutdown_drain_timeout_secs: 30,
            shutdown_force_timeout_secs: 30,
            openbao_enabled: false,
            openbao_address: "https://openbao.internal:8200".into(),
            openbao_auth_method: "approle".into(),
            openbao_role_id_file: None,
            openbao_secret_id_file: None,
            openbao_ca_file: None,
            openbao_refresh_interval_secs: 300,
            openbao_secret_path: "secret/data/tacacs".into(),
            openbao_location: None,
            openbao_pki_enabled: false,
            openbao_pki_mount: "pki".into(),
            openbao_pki_role: "tacacs-server".into(),
            openbao_pki_common_name: None,
            openbao_pki_ttl_hours: 720,
            openbao_pki_renewal_threshold: 70,
            api_enabled: false,
            api_listen: None,
            api_tls_cert: None,
            api_tls_key: None,
            api_client_ca: None,
            api_rbac_config: None,
            est_enabled: false,
            est_server_url: None,
            est_username: None,
            est_password: None,
            est_password_file: None,
            est_client_cert_path: None,
            est_client_key_path: None,
            est_ca_label: None,
            est_common_name: None,
            est_organization: None,
            est_cert_path: PathBuf::from("/etc/tacacs/server.crt"),
            est_key_path: PathBuf::from("/etc/tacacs/server.key"),
            est_ca_cert_path: PathBuf::from("/etc/tacacs/ca.crt"),
            est_renewal_threshold_percent: 70,
            est_renewal_check_interval_secs: 3600,
            est_bootstrap_timeout_secs: 300,
            est_initial_enrollment_required: false,
        };

        let result = credentials_map(&args);
        assert!(result.is_ok());
        let creds = result.unwrap();
        assert_eq!(creds.plain.len(), 2);
        assert_eq!(creds.plain.get("admin"), Some(&"filepass".to_string()));
        assert_eq!(creds.plain.get("operator"), Some(&"operpass".to_string()));
    }

    #[test]
    fn credentials_map_argon_inline() {
        let args = Args {
            check_policy: None,
            schema: None,
            policy: None,
            listen_tls: None,
            listen_legacy: None,
            listen_http: None,
            log_format: LogFormat::Text,
            location: None,
            tls_cert: None,
            tls_key: None,
            client_ca: None,
            tls_trust_root: Vec::new(),
            secret: None,
            secret_file: None,
            forbid_unencrypted: false,
            tls_psk: None,
            user_password: Vec::new(),
            user_password_file: None,
            user_password_hash: vec![("admin".into(), "$argon2id$v=19$m=65536...".into())],
            user_password_hash_file: None,
            allow_static_credentials: true,
            ascii_attempt_limit: 5,
            ascii_user_attempt_limit: 3,
            ascii_pass_attempt_limit: 5,
            ascii_backoff_ms: 0,
            ascii_backoff_max_ms: 5000,
            ascii_lockout_limit: 0,
            single_connect_idle_secs: 300,
            single_connect_keepalive_secs: 120,
            max_connections_per_ip: 50,
            max_sessions: 0,
            max_sessions_per_ip: 0,
            tls_allowed_client_cn: Vec::new(),
            tls_allowed_client_san: Vec::new(),
            ldaps_url: None,
            ldap_bind_dn: None,
            ldap_bind_password: None,
            ldap_bind_password_file: None,
            ldap_search_base: None,
            ldap_username_attr: "uid".into(),
            ldap_timeout_ms: 5000,
            ldap_ca_file: None,
            ldap_required_group: Vec::new(),
            ldap_group_attr: "memberOf".into(),
            legacy_nad_secret: Vec::new(),
            otlp_endpoint: None,
            otel_service_name: "tacacs-server".into(),
            shutdown_drain_timeout_secs: 30,
            shutdown_force_timeout_secs: 30,
            openbao_enabled: false,
            openbao_address: "https://openbao.internal:8200".into(),
            openbao_auth_method: "approle".into(),
            openbao_role_id_file: None,
            openbao_secret_id_file: None,
            openbao_ca_file: None,
            openbao_refresh_interval_secs: 300,
            openbao_secret_path: "secret/data/tacacs".into(),
            openbao_location: None,
            openbao_pki_enabled: false,
            openbao_pki_mount: "pki".into(),
            openbao_pki_role: "tacacs-server".into(),
            openbao_pki_common_name: None,
            openbao_pki_ttl_hours: 720,
            openbao_pki_renewal_threshold: 70,
            api_enabled: false,
            api_listen: None,
            api_tls_cert: None,
            api_tls_key: None,
            api_client_ca: None,
            api_rbac_config: None,
            est_enabled: false,
            est_server_url: None,
            est_username: None,
            est_password: None,
            est_password_file: None,
            est_client_cert_path: None,
            est_client_key_path: None,
            est_ca_label: None,
            est_common_name: None,
            est_organization: None,
            est_cert_path: PathBuf::from("/etc/tacacs/server.crt"),
            est_key_path: PathBuf::from("/etc/tacacs/server.key"),
            est_ca_cert_path: PathBuf::from("/etc/tacacs/ca.crt"),
            est_renewal_threshold_percent: 70,
            est_renewal_check_interval_secs: 3600,
            est_bootstrap_timeout_secs: 300,
            est_initial_enrollment_required: false,
        };

        let result = credentials_map(&args);
        assert!(result.is_ok());
        let creds = result.unwrap();
        assert_eq!(creds.argon.len(), 1);
        assert!(creds.argon.contains_key("admin"));
    }

    // ==================== StaticCreds Tests ====================

    #[test]
    fn static_creds_default() {
        let creds = StaticCreds::default();
        assert!(creds.plain.is_empty());
        assert!(creds.argon.is_empty());
    }

    #[test]
    fn static_creds_clone() {
        let mut creds = StaticCreds::default();
        creds.plain.insert("user".into(), "pass".into());
        creds.argon.insert("admin".into(), "$argon2id$...".into());

        let cloned = creds.clone();
        assert_eq!(cloned.plain.get("user"), Some(&"pass".to_string()));
        assert_eq!(
            cloned.argon.get("admin"),
            Some(&"$argon2id$...".to_string())
        );
    }

    // ==================== read_secret_file Tests ====================

    #[test]
    fn read_secret_file_valid() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "my-secret-value").unwrap();

        let result = read_secret_file(&file.path().to_path_buf());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "my-secret-value");
    }

    #[test]
    fn read_secret_file_trims_whitespace() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "  secret-with-spaces  \n\n").unwrap();

        let result = read_secret_file(&file.path().to_path_buf());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "secret-with-spaces");
    }

    #[test]
    fn read_secret_file_empty_fails() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "   \n\n  ").unwrap(); // Only whitespace

        let result = read_secret_file(&file.path().to_path_buf());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn read_secret_file_nonexistent() {
        let result = read_secret_file(&PathBuf::from("/nonexistent/secret/file"));
        assert!(result.is_err());
    }

    // ==================== resolve_tacacs_secret Tests ====================

    #[test]
    fn resolve_tacacs_secret_from_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "file-based-secret").unwrap();

        let args = Args {
            check_policy: None,
            schema: None,
            policy: None,
            listen_tls: None,
            listen_legacy: None,
            listen_http: None,
            log_format: LogFormat::Text,
            location: None,
            tls_cert: None,
            tls_key: None,
            client_ca: None,
            tls_trust_root: Vec::new(),
            secret: Some("cli-secret".into()), // Should be ignored
            secret_file: Some(file.path().to_path_buf()),
            forbid_unencrypted: false,
            tls_psk: None,
            user_password: Vec::new(),
            user_password_file: None,
            user_password_hash: Vec::new(),
            user_password_hash_file: None,
            allow_static_credentials: false,
            ascii_attempt_limit: 5,
            ascii_user_attempt_limit: 3,
            ascii_pass_attempt_limit: 5,
            ascii_backoff_ms: 0,
            ascii_backoff_max_ms: 5000,
            ascii_lockout_limit: 0,
            single_connect_idle_secs: 300,
            single_connect_keepalive_secs: 120,
            max_connections_per_ip: 50,
            max_sessions: 0,
            max_sessions_per_ip: 0,
            tls_allowed_client_cn: Vec::new(),
            tls_allowed_client_san: Vec::new(),
            ldaps_url: None,
            ldap_bind_dn: None,
            ldap_bind_password: None,
            ldap_bind_password_file: None,
            ldap_search_base: None,
            ldap_username_attr: "uid".into(),
            ldap_timeout_ms: 5000,
            ldap_ca_file: None,
            ldap_required_group: Vec::new(),
            ldap_group_attr: "memberOf".into(),
            legacy_nad_secret: Vec::new(),
            otlp_endpoint: None,
            otel_service_name: "tacacs-server".into(),
            shutdown_drain_timeout_secs: 30,
            shutdown_force_timeout_secs: 30,
            openbao_enabled: false,
            openbao_address: "https://openbao.internal:8200".into(),
            openbao_auth_method: "approle".into(),
            openbao_role_id_file: None,
            openbao_secret_id_file: None,
            openbao_ca_file: None,
            openbao_refresh_interval_secs: 300,
            openbao_secret_path: "secret/data/tacacs".into(),
            openbao_location: None,
            openbao_pki_enabled: false,
            openbao_pki_mount: "pki".into(),
            openbao_pki_role: "tacacs-server".into(),
            openbao_pki_common_name: None,
            openbao_pki_ttl_hours: 720,
            openbao_pki_renewal_threshold: 70,
            api_enabled: false,
            api_listen: None,
            api_tls_cert: None,
            api_tls_key: None,
            api_client_ca: None,
            api_rbac_config: None,
            est_enabled: false,
            est_server_url: None,
            est_username: None,
            est_password: None,
            est_password_file: None,
            est_client_cert_path: None,
            est_client_key_path: None,
            est_ca_label: None,
            est_common_name: None,
            est_organization: None,
            est_cert_path: PathBuf::from("/etc/tacacs/server.crt"),
            est_key_path: PathBuf::from("/etc/tacacs/server.key"),
            est_ca_cert_path: PathBuf::from("/etc/tacacs/ca.crt"),
            est_renewal_threshold_percent: 70,
            est_renewal_check_interval_secs: 3600,
            est_bootstrap_timeout_secs: 300,
            est_initial_enrollment_required: false,
        };

        let result = resolve_tacacs_secret(&args);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some("file-based-secret".to_string()));
    }

    #[test]
    fn resolve_tacacs_secret_from_cli() {
        let args = Args {
            check_policy: None,
            schema: None,
            policy: None,
            listen_tls: None,
            listen_legacy: None,
            listen_http: None,
            log_format: LogFormat::Text,
            location: None,
            tls_cert: None,
            tls_key: None,
            client_ca: None,
            tls_trust_root: Vec::new(),
            secret: Some("cli-secret".into()),
            secret_file: None,
            forbid_unencrypted: false,
            tls_psk: None,
            user_password: Vec::new(),
            user_password_file: None,
            user_password_hash: Vec::new(),
            user_password_hash_file: None,
            allow_static_credentials: false,
            ascii_attempt_limit: 5,
            ascii_user_attempt_limit: 3,
            ascii_pass_attempt_limit: 5,
            ascii_backoff_ms: 0,
            ascii_backoff_max_ms: 5000,
            ascii_lockout_limit: 0,
            single_connect_idle_secs: 300,
            single_connect_keepalive_secs: 120,
            max_connections_per_ip: 50,
            max_sessions: 0,
            max_sessions_per_ip: 0,
            tls_allowed_client_cn: Vec::new(),
            tls_allowed_client_san: Vec::new(),
            ldaps_url: None,
            ldap_bind_dn: None,
            ldap_bind_password: None,
            ldap_bind_password_file: None,
            ldap_search_base: None,
            ldap_username_attr: "uid".into(),
            ldap_timeout_ms: 5000,
            ldap_ca_file: None,
            ldap_required_group: Vec::new(),
            ldap_group_attr: "memberOf".into(),
            legacy_nad_secret: Vec::new(),
            otlp_endpoint: None,
            otel_service_name: "tacacs-server".into(),
            shutdown_drain_timeout_secs: 30,
            shutdown_force_timeout_secs: 30,
            openbao_enabled: false,
            openbao_address: "https://openbao.internal:8200".into(),
            openbao_auth_method: "approle".into(),
            openbao_role_id_file: None,
            openbao_secret_id_file: None,
            openbao_ca_file: None,
            openbao_refresh_interval_secs: 300,
            openbao_secret_path: "secret/data/tacacs".into(),
            openbao_location: None,
            openbao_pki_enabled: false,
            openbao_pki_mount: "pki".into(),
            openbao_pki_role: "tacacs-server".into(),
            openbao_pki_common_name: None,
            openbao_pki_ttl_hours: 720,
            openbao_pki_renewal_threshold: 70,
            api_enabled: false,
            api_listen: None,
            api_tls_cert: None,
            api_tls_key: None,
            api_client_ca: None,
            api_rbac_config: None,
            est_enabled: false,
            est_server_url: None,
            est_username: None,
            est_password: None,
            est_password_file: None,
            est_client_cert_path: None,
            est_client_key_path: None,
            est_ca_label: None,
            est_common_name: None,
            est_organization: None,
            est_cert_path: PathBuf::from("/etc/tacacs/server.crt"),
            est_key_path: PathBuf::from("/etc/tacacs/server.key"),
            est_ca_cert_path: PathBuf::from("/etc/tacacs/ca.crt"),
            est_renewal_threshold_percent: 70,
            est_renewal_check_interval_secs: 3600,
            est_bootstrap_timeout_secs: 300,
            est_initial_enrollment_required: false,
        };

        let result = resolve_tacacs_secret(&args);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some("cli-secret".to_string()));
    }

    #[test]
    fn resolve_tacacs_secret_none() {
        let args = Args {
            check_policy: None,
            schema: None,
            policy: None,
            listen_tls: None,
            listen_legacy: None,
            listen_http: None,
            log_format: LogFormat::Text,
            location: None,
            tls_cert: None,
            tls_key: None,
            client_ca: None,
            tls_trust_root: Vec::new(),
            secret: None,
            secret_file: None,
            forbid_unencrypted: false,
            tls_psk: None,
            user_password: Vec::new(),
            user_password_file: None,
            user_password_hash: Vec::new(),
            user_password_hash_file: None,
            allow_static_credentials: false,
            ascii_attempt_limit: 5,
            ascii_user_attempt_limit: 3,
            ascii_pass_attempt_limit: 5,
            ascii_backoff_ms: 0,
            ascii_backoff_max_ms: 5000,
            ascii_lockout_limit: 0,
            single_connect_idle_secs: 300,
            single_connect_keepalive_secs: 120,
            max_connections_per_ip: 50,
            max_sessions: 0,
            max_sessions_per_ip: 0,
            tls_allowed_client_cn: Vec::new(),
            tls_allowed_client_san: Vec::new(),
            ldaps_url: None,
            ldap_bind_dn: None,
            ldap_bind_password: None,
            ldap_bind_password_file: None,
            ldap_search_base: None,
            ldap_username_attr: "uid".into(),
            ldap_timeout_ms: 5000,
            ldap_ca_file: None,
            ldap_required_group: Vec::new(),
            ldap_group_attr: "memberOf".into(),
            legacy_nad_secret: Vec::new(),
            otlp_endpoint: None,
            otel_service_name: "tacacs-server".into(),
            shutdown_drain_timeout_secs: 30,
            shutdown_force_timeout_secs: 30,
            openbao_enabled: false,
            openbao_address: "https://openbao.internal:8200".into(),
            openbao_auth_method: "approle".into(),
            openbao_role_id_file: None,
            openbao_secret_id_file: None,
            openbao_ca_file: None,
            openbao_refresh_interval_secs: 300,
            openbao_secret_path: "secret/data/tacacs".into(),
            openbao_location: None,
            openbao_pki_enabled: false,
            openbao_pki_mount: "pki".into(),
            openbao_pki_role: "tacacs-server".into(),
            openbao_pki_common_name: None,
            openbao_pki_ttl_hours: 720,
            openbao_pki_renewal_threshold: 70,
            api_enabled: false,
            api_listen: None,
            api_tls_cert: None,
            api_tls_key: None,
            api_client_ca: None,
            api_rbac_config: None,
            est_enabled: false,
            est_server_url: None,
            est_username: None,
            est_password: None,
            est_password_file: None,
            est_client_cert_path: None,
            est_client_key_path: None,
            est_ca_label: None,
            est_common_name: None,
            est_organization: None,
            est_cert_path: PathBuf::from("/etc/tacacs/server.crt"),
            est_key_path: PathBuf::from("/etc/tacacs/server.key"),
            est_ca_cert_path: PathBuf::from("/etc/tacacs/ca.crt"),
            est_renewal_threshold_percent: 70,
            est_renewal_check_interval_secs: 3600,
            est_bootstrap_timeout_secs: 300,
            est_initial_enrollment_required: false,
        };

        let result = resolve_tacacs_secret(&args);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }

    // ==================== resolve_ldap_bind_password Tests ====================

    #[test]
    fn resolve_ldap_bind_password_from_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "ldap-file-password").unwrap();

        let args = Args {
            check_policy: None,
            schema: None,
            policy: None,
            listen_tls: None,
            listen_legacy: None,
            listen_http: None,
            log_format: LogFormat::Text,
            location: None,
            tls_cert: None,
            tls_key: None,
            client_ca: None,
            tls_trust_root: Vec::new(),
            secret: None,
            secret_file: None,
            forbid_unencrypted: false,
            tls_psk: None,
            user_password: Vec::new(),
            user_password_file: None,
            user_password_hash: Vec::new(),
            user_password_hash_file: None,
            allow_static_credentials: false,
            ascii_attempt_limit: 5,
            ascii_user_attempt_limit: 3,
            ascii_pass_attempt_limit: 5,
            ascii_backoff_ms: 0,
            ascii_backoff_max_ms: 5000,
            ascii_lockout_limit: 0,
            single_connect_idle_secs: 300,
            single_connect_keepalive_secs: 120,
            max_connections_per_ip: 50,
            max_sessions: 0,
            max_sessions_per_ip: 0,
            tls_allowed_client_cn: Vec::new(),
            tls_allowed_client_san: Vec::new(),
            ldaps_url: None,
            ldap_bind_dn: None,
            ldap_bind_password: Some("cli-ldap-pass".into()), // Should be ignored
            ldap_bind_password_file: Some(file.path().to_path_buf()),
            ldap_search_base: None,
            ldap_username_attr: "uid".into(),
            ldap_timeout_ms: 5000,
            ldap_ca_file: None,
            ldap_required_group: Vec::new(),
            ldap_group_attr: "memberOf".into(),
            legacy_nad_secret: Vec::new(),
            otlp_endpoint: None,
            otel_service_name: "tacacs-server".into(),
            shutdown_drain_timeout_secs: 30,
            shutdown_force_timeout_secs: 30,
            openbao_enabled: false,
            openbao_address: "https://openbao.internal:8200".into(),
            openbao_auth_method: "approle".into(),
            openbao_role_id_file: None,
            openbao_secret_id_file: None,
            openbao_ca_file: None,
            openbao_refresh_interval_secs: 300,
            openbao_secret_path: "secret/data/tacacs".into(),
            openbao_location: None,
            openbao_pki_enabled: false,
            openbao_pki_mount: "pki".into(),
            openbao_pki_role: "tacacs-server".into(),
            openbao_pki_common_name: None,
            openbao_pki_ttl_hours: 720,
            openbao_pki_renewal_threshold: 70,
            api_enabled: false,
            api_listen: None,
            api_tls_cert: None,
            api_tls_key: None,
            api_client_ca: None,
            api_rbac_config: None,
            est_enabled: false,
            est_server_url: None,
            est_username: None,
            est_password: None,
            est_password_file: None,
            est_client_cert_path: None,
            est_client_key_path: None,
            est_ca_label: None,
            est_common_name: None,
            est_organization: None,
            est_cert_path: PathBuf::from("/etc/tacacs/server.crt"),
            est_key_path: PathBuf::from("/etc/tacacs/server.key"),
            est_ca_cert_path: PathBuf::from("/etc/tacacs/ca.crt"),
            est_renewal_threshold_percent: 70,
            est_renewal_check_interval_secs: 3600,
            est_bootstrap_timeout_secs: 300,
            est_initial_enrollment_required: false,
        };

        let result = resolve_ldap_bind_password(&args);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some("ldap-file-password".to_string()));
    }
}
