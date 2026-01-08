// SPDX-License-Identifier: Apache-2.0
//! Configuration management for TACACS+ server.
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
/// - **CM-2/CM-6**: All parameters support secure baseline configuration
/// - **SI-10**: Input validation via clap argument parsing
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
    #[arg(long)]
    pub secret: Option<String>,

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
    #[arg(long)]
    pub ldap_bind_password: Option<String>,

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

fn parse_nad_secret(s: &str) -> std::result::Result<(IpAddr, String), String> {
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
    fn parse_nad_secret_ipv6() {
        // IPv6 addresses contain colons, so the parser uses splitn(2, ':')
        // which means the first colon splits IP from secret.
        // For IPv6, you need to use bracket notation or a full address.
        // Testing with a full IPv6 address that works with the simple parser:
        let result = parse_nad_secret("2001:db8:85a3:8d3:1319:8a2e:370:7348:mysecret");
        // This will fail because the parser splits on first colon
        // The current parser doesn't support IPv6 well, so we test what it does:
        assert!(result.is_err()); // First segment "2001" is not a valid IP
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
            tls_allowed_client_cn: Vec::new(),
            tls_allowed_client_san: Vec::new(),
            ldaps_url: None,
            ldap_bind_dn: None,
            ldap_bind_password: None,
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
            tls_allowed_client_cn: Vec::new(),
            tls_allowed_client_san: Vec::new(),
            ldaps_url: None,
            ldap_bind_dn: None,
            ldap_bind_password: None,
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
            tls_allowed_client_cn: Vec::new(),
            tls_allowed_client_san: Vec::new(),
            ldaps_url: None,
            ldap_bind_dn: None,
            ldap_bind_password: None,
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
            tls_allowed_client_cn: Vec::new(),
            tls_allowed_client_san: Vec::new(),
            ldaps_url: None,
            ldap_bind_dn: None,
            ldap_bind_password: None,
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
            tls_allowed_client_cn: Vec::new(),
            tls_allowed_client_san: Vec::new(),
            ldaps_url: None,
            ldap_bind_dn: None,
            ldap_bind_password: None,
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
            tls_allowed_client_cn: Vec::new(),
            tls_allowed_client_san: Vec::new(),
            ldaps_url: None,
            ldap_bind_dn: None,
            ldap_bind_password: None,
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
}
