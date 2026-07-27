// SPDX-License-Identifier: Apache-2.0

//! TACACS+ server main entry point and application initialization.
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
//! | AC-3 | Access Control | Implemented | 2026-01-26 | Management API TLS/mTLS |
//! | AC-10 | Access Control | Implemented | 2026-01-26 | [`main`] session registry |
//! | AC-12 | Access Control | Implemented | 2026-01-26 | [`main`] idle sweep task |
//! | CM-3 | Config Management | Implemented | 2026-01-26 | Policy reload coordination |
//! | IA-5 | Ident/Authentication | Implemented | 2026-01-26 | EST bootstrap enrollment |
//! | SC-8 | Sys/Comm Protection | Implemented | 2026-01-26 | Management API TLS |
//! | SC-17 | Sys/Comm Protection | Implemented | 2026-01-26 | EST certificate management |
//!
//! <details>
//! <summary><b>Validation Metadata (JSON)</b></summary>
//!
//! ```json
//! {
//!   "nist_framework": "NIST SP 800-53 Rev. 5",
//!   "software_version": "0.77.1",
//!   "last_validation": "2026-01-26",
//!   "control_families": ["AC", "CM", "IA", "SC"],
//!   "total_controls": 7,
//!   "file_path": "crates/tacacs-server/src/main.rs"
//! }
//! ```
//!
//! </details>
//!
//! ## Control Details
//!
//! ### AC-3: Access Enforcement
//! - **Implementation:** Management API requires TLS with mutual TLS (mTLS) for authentication
//! - **Evidence:** TLS acceptor configuration, client certificate validation
//! - **Reference:** [AC-3](../../../docs/NIST-CONTROLS-MAPPING.md#ac-3-access-enforcement)
//!
//! ### AC-10: Concurrent Session Control
//! - **Implementation:** Session registry tracks active connections with configurable limits
//! - **Evidence:** Per-IP and total session counting, connection rejection when limits exceeded
//! - **Reference:** [AC-10](../../../docs/NIST-CONTROLS-MAPPING.md#ac-10-concurrent-session-control)
//!
//! ### AC-12: Session Termination
//! - **Implementation:** Background idle sweep task terminates inactive sessions
//! - **Evidence:** Configurable idle timeout, periodic session cleanup
//! - **Reference:** [AC-12](../../../docs/NIST-CONTROLS-MAPPING.md#ac-11-session-lock--ac-12-session-termination)
//!
//! ### CM-3: Configuration Change Control
//! - **Implementation:** Policy reload coordination via SIGHUP signal and management API
//! - **Evidence:** Unified policy change watcher, atomic policy updates
//! - **Reference:** [CM-3](../../../docs/NIST-CONTROLS-MAPPING.md#cm-3-configuration-change-control)
//!
//! ### IA-5: Authenticator Management
//! - **Implementation:** EST (Enrollment over Secure Transport) bootstrap for zero-touch certificate enrollment
//! - **Evidence:** Automatic certificate provisioning, secure credential establishment
//! - **Reference:** [IA-5](../../../docs/NIST-CONTROLS-MAPPING.md#ia-5-authenticator-management)
//!
//! ### SC-8: Transmission Confidentiality and Integrity
//! - **Implementation:** TLS 1.2+ for all management API connections
//! - **Evidence:** TLS acceptor with certificate validation, encrypted channels
//! - **Reference:** [SC-8](../../../docs/NIST-CONTROLS-MAPPING.md#sc-8-transmission-confidentiality-and-integrity)
//!
//! ### SC-17: Public Key Infrastructure Certificates
//! - **Implementation:** EST integration for automated certificate lifecycle management
//! - **Evidence:** Certificate enrollment, renewal, and rotation via RFC 7030
//! - **Reference:** [SC-17](../../../docs/NIST-CONTROLS-MAPPING.md#sc-17-public-key-infrastructure-certificates)

use crate::ascii::AsciiConfig;
use crate::auth::LdapConfig;
use crate::config::{
    Args, LogFormat, StaticCreds, build_est_config, credentials_map, read_secret_file,
    resolve_icam_client_secret, resolve_legacy_nad_secrets,
};
use crate::http::{ServerState, serve_http};
use crate::icam::{IcamConfig, icam_build_client};
use crate::metrics::metrics;
use crate::server::{
    AuthContext, CertificateReloadRequest, ConnLimiter, ConnectionConfig, PolicyReloadRequest,
    TlsIdentityConfig, init_audit_hmac, normalize_ip, serve_legacy, serve_tls, tls_acceptor,
    validate_policy, watch_certificate_changes, watch_policy_changes,
};
use crate::session_registry::{SessionLimits, SessionRegistry, run_idle_sweep_task};
use crate::telemetry::{TelemetryConfig, init_telemetry, shutdown_telemetry};
use anyhow::{Context, Result, bail};
use clap::Parser;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{RwLock, mpsc};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};
use tracing_subscriber::fmt::time::UtcTime;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use usg_tacacs_config::{
    NadAuthentication, RuleEffect as DeclarativeRuleEffect, ServerConfiguration,
};
use usg_tacacs_policy::PolicyEngine;
use usg_tacacs_proto::MIN_SECRET_LEN;
use usg_tacacs_secrets::SecretsProvider;

type LegacyNadSecrets = Arc<std::collections::HashMap<std::net::IpAddr, Arc<Vec<u8>>>>;
type JitLegacyNads =
    Arc<std::collections::HashMap<std::net::IpAddr, crate::jit_lease::NadIdentity>>;

// ============================================================================
// Application State Container
// ============================================================================

/// Shared application state passed between initialization phases.
struct AppState {
    shared_policy: Arc<RwLock<PolicyEngine>>,
    shared_secret: Option<Arc<Vec<u8>>>,
    credentials: Arc<StaticCreds>,
    ldap_config: Option<Arc<LdapConfig>>,
    icam_config: Option<Arc<IcamConfig>>,
    device_flow_config: Option<Arc<crate::icam_device::DeviceFlowConfig>>,
    username_limiter: Arc<crate::username_limiter::UsernameRateLimiter>,
    ip_limiter: Arc<crate::ip_limiter::IpRateLimiter>,
    /// HMAC-SHA256 key for audit event signing (`None` = disabled).
    audit_hmac_key: Option<Arc<Vec<u8>>>,
    jit_lease_store: Option<Arc<crate::jit_lease_store::JitLeaseStore>>,
    nad_store: Option<Arc<crate::nad_store::NadStore>>,
    runtime_nads: Option<Arc<crate::nad_reconciler::RuntimeNadRegistry>>,
    jit_managed_nads: Arc<std::collections::HashSet<String>>,
    jit_legacy_nads: JitLegacyNads,
    legacy_nad_secrets: LegacyNadSecrets,
    conn_limiter: ConnLimiter,
    session_registry: Arc<SessionRegistry>,
    est_provider: Option<Arc<usg_tacacs_secrets::EstProvider>>,
    est_config: Option<usg_tacacs_secrets::EstConfig>,
    policy_path: PathBuf,
    declarative_config: Option<Arc<ServerConfiguration>>,
}

// ============================================================================
// Initialization Helper Functions
// ============================================================================

/// Initialize tracing with the configured log format and optional OpenTelemetry.
fn init_tracing(args: &Args) -> Result<bool> {
    let otel_enabled = args.otlp_endpoint.is_some();

    match (&args.log_format, &args.otlp_endpoint) {
        (LogFormat::Text, None) => {
            tracing_subscriber::fmt()
                .with_timer(UtcTime::rfc_3339())
                .finish()
                .init();
        }
        (LogFormat::Json, None) => {
            tracing_subscriber::fmt()
                .with_timer(UtcTime::rfc_3339())
                .json()
                .flatten_event(true)
                .with_current_span(true)
                .finish()
                .init();
        }
        (LogFormat::Text, Some(endpoint)) => {
            let cfg = TelemetryConfig::new(
                endpoint.clone(),
                args.otel_service_name.clone(),
                args.location.clone(),
            );
            let otel_layer = init_telemetry(&cfg)?;
            tracing_subscriber::registry()
                .with(otel_layer)
                .with(tracing_subscriber::fmt::layer().with_timer(UtcTime::rfc_3339()))
                .init();
            info!(otlp_endpoint = %endpoint, "OpenTelemetry tracing enabled");
        }
        (LogFormat::Json, Some(endpoint)) => {
            let cfg = TelemetryConfig::new(
                endpoint.clone(),
                args.otel_service_name.clone(),
                args.location.clone(),
            );
            let otel_layer = init_telemetry(&cfg)?;
            tracing_subscriber::registry()
                .with(otel_layer)
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_timer(UtcTime::rfc_3339())
                        .json()
                        .flatten_event(true)
                        .with_current_span(true),
                )
                .init();
            info!(otlp_endpoint = %endpoint, "OpenTelemetry tracing enabled");
        }
    }
    Ok(otel_enabled)
}

/// Handle --check-policy CLI mode. Returns Ok(true) if validation was performed.
fn handle_check_policy_mode(args: &Args) -> Result<bool> {
    if let Some(config_path) = args.check_config.as_ref() {
        let config = ServerConfiguration::from_path(config_path)?;
        config.validate(false)?;
        println!("configuration validated: {}", config_path.display());
        return Ok(true);
    }
    if let Some(policy_path) = args.check_policy.as_ref() {
        let schema = args
            .schema
            .as_ref()
            .context("--schema is required with --check-policy")?;
        validate_policy(policy_path, Some(schema))?;
        println!("policy validated");
        return Ok(true);
    }
    Ok(false)
}

fn apply_declarative_config(args: &mut Args, config: &ServerConfiguration) -> Result<()> {
    config.validate(true)?;
    args.listen_legacy = config.spec.listeners.legacy;
    args.listen_http = Some(config.spec.listeners.health);
    if let Some(tls) = &config.spec.listeners.tls {
        args.listen_tls = Some(tls.address);
        args.tls_cert = Some(tls.certificate_file.clone());
        args.tls_key = Some(tls.private_key_file.clone());
        args.client_ca = Some(tls.client_ca_file.clone());
    }
    args.api_enabled = config.spec.management.is_some();
    if let Some(management) = &config.spec.management {
        args.api_listen = Some(management.listener.address);
        args.api_tls_cert = Some(management.listener.certificate_file.clone());
        args.api_tls_key = Some(management.listener.private_key_file.clone());
        args.api_client_ca = Some(management.listener.client_ca_file.clone());
    }
    args.audit_hmac_key_file = Some(config.spec.audit.hmac_key_file.clone());
    args.legacy_nad_secret.clear();
    args.legacy_nad_secrets_file = None;
    args.tls_allowed_client_cn.clear();
    for nad in &config.spec.nads {
        match &nad.authentication {
            NadAuthentication::Legacy { secret_file } => {
                let secret = read_secret_file(secret_file)
                    .with_context(|| format!("reading secret for declarative NAD {}", nad.name))?;
                args.legacy_nad_secret.push((nad.source_address, secret));
            }
            NadAuthentication::Tls {
                certificate_identities,
            } => args
                .tls_allowed_client_cn
                .extend(certificate_identities.iter().cloned()),
        }
    }
    Ok(())
}

fn declarative_policy(config: &ServerConfiguration) -> Result<PolicyEngine> {
    let rules: Vec<serde_json::Value> = config
        .spec
        .authorization
        .rules
        .iter()
        .map(|rule| {
            let effect = match rule.effect {
                DeclarativeRuleEffect::Allow => "allow",
                DeclarativeRuleEffect::Deny => "deny",
            };
            serde_json::json!({
                "id": rule.id,
                "priority": rule.priority,
                "effect": effect,
                "pattern": rule.command.as_deref().unwrap_or(".*"),
                "users": rule.users,
                "groups": rule.groups,
                "nad_groups": rule.nad_groups,
                "schedule": null
            })
        })
        .collect();
    let document = serde_json::from_value(serde_json::json!({
        "default_allow": config.spec.authorization.default_allow,
        "rules": rules
    }))
    .context("converting declarative authorization policy")?;
    PolicyEngine::from_document(document)
}

/// Validate secrets and build LDAP configuration.
fn validate_secrets_and_build_ldap(
    args: &Args,
    legacy_nad_secrets: &[(std::net::IpAddr, String)],
) -> Result<Option<Arc<LdapConfig>>> {
    for (ip, sec) in legacy_nad_secrets {
        if sec.len() < MIN_SECRET_LEN {
            bail!(
                "legacy NAD secret for {} must be at least {} bytes",
                ip,
                MIN_SECRET_LEN
            );
        }
    }
    if let (Some(secret), Some(psk)) = (args.secret.as_ref(), args.tls_psk.as_ref())
        && secret == psk
    {
        bail!("TACACS+ shared secret must not match TLS PSK");
    }

    if let Some(url) = args.ldaps_url.clone() {
        let bind_dn = args
            .ldap_bind_dn
            .clone()
            .context("--ldap-bind-dn is required with --ldaps-url")?;
        let bind_password = args
            .ldap_bind_password
            .clone()
            .context("--ldap-bind-password is required with --ldaps-url")?;
        let search_base = args
            .ldap_search_base
            .clone()
            .context("--ldap-search-base is required with --ldaps-url")?;
        if args.ldap_ca_file.is_some() {
            warn!(
                "--ldap-ca-file is specified but custom CA is not supported in this build; LDAP connections will fail"
            );
        }
        Ok(Some(Arc::new(LdapConfig {
            url,
            bind_dn,
            bind_password,
            search_base,
            username_attr: args.ldap_username_attr.clone(),
            timeout: Duration::from_millis(args.ldap_timeout_ms),
            ca_file: args.ldap_ca_file.clone(),
            required_group: args.ldap_required_group.clone(),
            group_attr: args.ldap_group_attr.clone(),
        })))
    } else {
        Ok(None)
    }
}

/// Setup session registry with limits and idle sweep task.
fn setup_session_registry(args: &Args) -> Arc<SessionRegistry> {
    let limits = SessionLimits {
        max_total_sessions: args.max_sessions,
        max_sessions_per_ip: args.max_sessions_per_ip,
    };
    let registry = Arc::new(SessionRegistry::with_limits(limits));
    if args.max_sessions > 0 || args.max_sessions_per_ip > 0 {
        info!(
            max_sessions = args.max_sessions,
            max_sessions_per_ip = args.max_sessions_per_ip,
            "session limits configured"
        );
    }
    if args.single_connect_idle_secs > 0 {
        let sweep_registry = registry.clone();
        let idle_timeout = Duration::from_secs(args.single_connect_idle_secs);
        let sweep_interval = Duration::from_secs(args.single_connect_idle_secs.max(4) / 4);
        tokio::spawn(async move {
            run_idle_sweep_task(sweep_registry, idle_timeout, sweep_interval).await;
        });
    }
    registry
}

/// NIST IA-5/SC-17: Setup EST provider for zero-touch certificate provisioning.
async fn setup_est_provider(
    args: &Args,
) -> Result<(
    Option<Arc<usg_tacacs_secrets::EstProvider>>,
    Option<usg_tacacs_secrets::EstConfig>,
)> {
    let est_config_opt = build_est_config(args).map_err(anyhow::Error::msg)?;

    if let Some(est_config) = est_config_opt {
        info!(server_url = %est_config.server_url, common_name = %est_config.common_name, "EST zero-touch provisioning enabled");
        let mut provider = usg_tacacs_secrets::EstProvider::new(est_config.clone())
            .await
            .context("failed to initialize EST provider")?;

        if !est_config.cert_path.exists() || !est_config.key_path.exists() {
            perform_est_bootstrap(&mut provider, &est_config).await?;
        } else {
            info!(cert_path = ?est_config.cert_path, "EST certificates found, loading existing");
        }

        provider
            .start_renewal_loop()
            .context("failed to start EST renewal loop")?;
        info!("EST certificate renewal loop started");
        Ok((Some(Arc::new(provider)), Some(est_config)))
    } else {
        Ok((None, None))
    }
}

/// Perform EST bootstrap enrollment with timeout handling.
async fn perform_est_bootstrap(
    provider: &mut usg_tacacs_secrets::EstProvider,
    est_config: &usg_tacacs_secrets::EstConfig,
) -> Result<()> {
    info!("EST certificates not found, performing bootstrap enrollment");
    let bootstrap_timeout = Duration::from_secs(est_config.bootstrap_timeout_secs);
    let enroll_result =
        tokio::time::timeout(bootstrap_timeout, provider.bootstrap_enrollment()).await;

    match enroll_result {
        Ok(Ok(bundle)) => {
            info!(serial = %bundle.serial_number, expires_at = bundle.expires_at, "EST bootstrap enrollment successful");
            Ok(())
        }
        Ok(Err(e)) => {
            error!(error = %e, "EST bootstrap enrollment failed");
            if est_config.initial_enrollment_required {
                bail!("EST enrollment required but failed: {}", e);
            }
            warn!("EST enrollment failed, continuing in degraded mode");
            Ok(())
        }
        Err(_) => {
            error!(
                timeout_secs = est_config.bootstrap_timeout_secs,
                "EST bootstrap enrollment timed out"
            );
            if est_config.initial_enrollment_required {
                bail!(
                    "EST enrollment required but timed out after {} seconds",
                    est_config.bootstrap_timeout_secs
                );
            }
            warn!("EST enrollment timed out, continuing in degraded mode");
            Ok(())
        }
    }
}

// ============================================================================
// Listener Setup Functions
// ============================================================================

/// Build connection configuration from arguments.
fn build_connection_config(args: &Args, conn_limiter: ConnLimiter) -> ConnectionConfig {
    ConnectionConfig {
        single_connect_idle_secs: args.single_connect_idle_secs,
        single_connect_keepalive_secs: args.single_connect_keepalive_secs,
        packet_read_timeout_secs: args.packet_read_timeout_secs,
        conn_limiter,
        ascii: AsciiConfig {
            attempt_limit: args.ascii_attempt_limit,
            user_attempt_limit: args.ascii_user_attempt_limit,
            pass_attempt_limit: args.ascii_pass_attempt_limit,
            backoff_ms: args.ascii_backoff_ms,
            backoff_max_ms: args.ascii_backoff_max_ms,
            lockout_limit: args.ascii_lockout_limit,
        },
    }
}

/// Setup TLS listener if configured.
#[allow(clippy::too_many_arguments)]
async fn setup_tls_listener(
    args: &Args,
    state: &AppState,
    handles: &mut Vec<JoinHandle<()>>,
) -> Result<()> {
    let addr = match args.listen_tls {
        Some(addr) => addr,
        None => return Ok(()),
    };

    log_tls_warnings(addr, &state.shared_secret);

    let (cert, key) = resolve_tls_certificates(args, &state.est_config)?;
    let ca = args
        .client_ca
        .as_ref()
        .context("--client-ca is required when --listen-tls is set")?;
    let acceptor = Arc::new(RwLock::new(tls_acceptor(
        cert,
        key,
        ca,
        &args.tls_trust_root,
    )?));

    let (cert_reload_tx, cert_reload_rx) = mpsc::channel::<CertificateReloadRequest>(10);
    let cert_acceptor = acceptor.clone();
    handles.push(tokio::spawn(async move {
        watch_certificate_changes(cert_reload_rx, cert_acceptor).await;
    }));

    setup_est_cert_reload(args, state, ca, cert_reload_tx, handles)?;

    let (auth_ctx, conn_cfg, tls_identity, tls_registry) = build_tls_contexts(args, state);

    handles.push(tokio::spawn(async move {
        if let Err(err) = serve_tls(
            addr,
            acceptor,
            auth_ctx,
            conn_cfg,
            tls_identity,
            tls_registry,
        )
        .await
        {
            error!(error = %err, "TLS listener stopped");
        }
    }));
    Ok(())
}

/// Log TLS-related warnings about port and encryption.
fn log_tls_warnings(addr: std::net::SocketAddr, shared_secret: &Option<Arc<Vec<u8>>>) {
    const RFC9887_TLS_PORT: u16 = 300;
    if addr.port() != RFC9887_TLS_PORT {
        warn!(
            "TLS listener on port {} instead of RFC 9887 standard port {} (tacacss)",
            addr.port(),
            RFC9887_TLS_PORT
        );
    }
    info!(
        "TLS mode: MD5 obfuscation applied for defense-in-depth (RFC 9887 permits TLS-only encryption)"
    );
    if shared_secret.as_ref().map(|s| s.len()).unwrap_or(0) < MIN_SECRET_LEN {
        warn!("TLS mode: shared secret missing/short; UNENCRYPTED packets will be accepted");
    }
}

/// Resolve TLS certificate paths from EST or manual configuration.
fn resolve_tls_certificates<'a>(
    args: &'a Args,
    est_config: &'a Option<usg_tacacs_secrets::EstConfig>,
) -> Result<(&'a PathBuf, &'a PathBuf)> {
    if let Some(est_cfg) = est_config {
        info!(cert_path = ?est_cfg.cert_path, key_path = ?est_cfg.key_path, "using EST-provisioned certificates for TLS");
        Ok((&est_cfg.cert_path, &est_cfg.key_path))
    } else {
        let cert_ref = args
            .tls_cert
            .as_ref()
            .context("--tls-cert is required when --listen-tls is set (or use --est-enabled)")?;
        let key_ref = args
            .tls_key
            .as_ref()
            .context("--tls-key is required when --listen-tls is set (or use --est-enabled)")?;
        Ok((cert_ref, key_ref))
    }
}

/// Build TLS authentication and connection contexts.
fn build_tls_contexts(
    args: &Args,
    state: &AppState,
) -> (
    AuthContext,
    ConnectionConfig,
    TlsIdentityConfig,
    Arc<SessionRegistry>,
) {
    let auth_ctx = AuthContext {
        policy: state.shared_policy.clone(),
        secret: state.shared_secret.clone(),
        credentials: state.credentials.clone(),
        ldap: state.ldap_config.clone(),
        icam: state.icam_config.clone(),
        device_flow: state.device_flow_config.clone(),
        username_limiter: state.username_limiter.clone(),
        ip_limiter: state.ip_limiter.clone(),
        audit_hmac_key: state.audit_hmac_key.clone(),
        jit_lease_store: state.jit_lease_store.clone(),
        jit_managed_nads: state.jit_managed_nads.clone(),
        runtime_nads: state.runtime_nads.clone(),
        jit_nad_identity: None,
    };
    let conn_cfg = build_connection_config(args, state.conn_limiter.clone());
    let mut allowed_san = args.tls_allowed_client_san.clone();
    if let Some(registry) = &state.runtime_nads {
        allowed_san.extend(registry.snapshot().tls_identities.keys().cloned());
    }
    let tls_identity = TlsIdentityConfig {
        allowed_cn: args.tls_allowed_client_cn.clone(),
        allowed_san,
        runtime_nads: state.runtime_nads.clone(),
    };
    let tls_registry = state.session_registry.clone();
    (auth_ctx, conn_cfg, tls_identity, tls_registry)
}

/// Setup EST certificate reload watcher if EST is enabled.
fn setup_est_cert_reload(
    args: &Args,
    state: &AppState,
    ca: &std::path::Path,
    reload_tx: mpsc::Sender<CertificateReloadRequest>,
    handles: &mut Vec<JoinHandle<()>>,
) -> Result<()> {
    if let (Some(est_prov), Some(est_cfg)) = (&state.est_provider, &state.est_config) {
        let est_cert_path = est_cfg.cert_path.clone();
        let est_key_path = est_cfg.key_path.clone();
        let est_ca_path = ca.to_path_buf();
        let est_trust_roots = args.tls_trust_root.clone();
        let mut change_rx = (**est_prov).subscribe();

        handles.push(tokio::spawn(async move {
            while let Ok(change) = change_rx.recv().await {
                if matches!(
                    change,
                    usg_tacacs_secrets::SecretChange::TlsCertificates { .. }
                ) {
                    info!("EST certificate renewed, triggering reload");
                    let request = CertificateReloadRequest::FromFiles {
                        cert_path: est_cert_path.clone(),
                        key_path: est_key_path.clone(),
                        client_ca_path: est_ca_path.clone(),
                        extra_trust_roots: est_trust_roots.clone(),
                    };
                    if let Err(err) = reload_tx.send(request).await {
                        warn!(error = %err, "failed to send certificate reload request");
                    }
                }
            }
        }));
    }
    Ok(())
}

/// Setup legacy TACACS+ listener if configured.
fn setup_legacy_listener(
    args: &Args,
    state: &AppState,
    handles: &mut Vec<JoinHandle<()>>,
) -> Result<()> {
    let addr = match args.listen_legacy {
        Some(addr) => addr,
        None => return Ok(()),
    };

    let (nad_secrets, jit_legacy_nads) = legacy_runtime_maps(state);
    let default_ok = state
        .shared_secret
        .as_deref()
        .map(|s| s.len() >= MIN_SECRET_LEN)
        .unwrap_or(false);
    let any_nad = !nad_secrets.is_empty();
    if !default_ok && !any_nad {
        bail!(
            "legacy TACACS+ requires a shared secret of at least {} bytes or per-NAD secrets",
            MIN_SECRET_LEN
        );
    }

    let auth_ctx = AuthContext {
        policy: state.shared_policy.clone(),
        secret: state.shared_secret.clone(),
        credentials: state.credentials.clone(),
        ldap: state.ldap_config.clone(),
        icam: state.icam_config.clone(),
        device_flow: state.device_flow_config.clone(),
        username_limiter: state.username_limiter.clone(),
        ip_limiter: state.ip_limiter.clone(),
        audit_hmac_key: state.audit_hmac_key.clone(),
        jit_lease_store: state.jit_lease_store.clone(),
        jit_managed_nads: state.jit_managed_nads.clone(),
        runtime_nads: state.runtime_nads.clone(),
        jit_nad_identity: None,
    };
    let conn_cfg = build_connection_config(args, state.conn_limiter.clone());
    let legacy_registry = state.session_registry.clone();
    let runtime_nads = state.runtime_nads.clone();

    handles.push(tokio::spawn(async move {
        if let Err(err) = serve_legacy(
            addr,
            auth_ctx,
            conn_cfg,
            nad_secrets,
            jit_legacy_nads,
            runtime_nads,
            legacy_registry,
        )
        .await
        {
            error!(error = %err, "legacy listener stopped");
        }
    }));
    Ok(())
}

fn legacy_runtime_maps(state: &AppState) -> (LegacyNadSecrets, JitLegacyNads) {
    match &state.runtime_nads {
        Some(registry) => {
            let snapshot = registry.snapshot();
            (
                snapshot.legacy_secrets.clone(),
                snapshot.legacy_identities.clone(),
            )
        }
        None => (
            state.legacy_nad_secrets.clone(),
            state.jit_legacy_nads.clone(),
        ),
    }
}

/// Setup HTTP health check server if configured.
fn setup_http_server(args: &Args, server_state: &ServerState, handles: &mut Vec<JoinHandle<()>>) {
    if let Some(addr) = args.listen_http {
        let state = server_state.clone();
        handles.push(tokio::spawn(async move {
            if let Err(err) = serve_http(addr, state).await {
                error!(error = %err, "HTTP server stopped");
            }
        }));
    }
}

/// Setup Management API server if enabled.
fn setup_management_api(
    args: &Args,
    state: &AppState,
    reload_tx: mpsc::Sender<PolicyReloadRequest>,
    handles: &mut Vec<JoinHandle<()>>,
) -> Result<()> {
    if !args.api_enabled {
        return Ok(());
    }

    let api_addr = args
        .api_listen
        .context("--api-listen is required when --api-enabled is set")?;
    let rbac_config = load_rbac_config(args, state.declarative_config.as_deref())?;
    let api_tls_acceptor = build_api_tls_acceptor(args)?;
    if state.jit_lease_store.is_some() && api_tls_acceptor.is_none() {
        bail!("JIT lease management requires TLS 1.3 mutual authentication");
    }

    let runtime_config = crate::api::RuntimeConfig {
        listen_tls: args.listen_tls,
        listen_legacy: args.listen_legacy,
        tls_enabled: args.listen_tls.is_some(),
        ldap_enabled: state.ldap_config.is_some(),
        policy_source: state.policy_path.display().to_string(),
        declarative_config: state.declarative_config.is_some(),
        source_config: state.declarative_config.clone(),
    };

    let api_policy = state.shared_policy.clone();
    let api_policy_path = state.policy_path.display().to_string();
    let api_schema_path = args.schema.clone();
    let api_registry = state.session_registry.clone();
    let jit_lease_store = state.jit_lease_store.clone();
    let nad_store = state.nad_store.clone();
    let runtime_nads = state.runtime_nads.clone();
    setup_management_est_reload(args, state, api_tls_acceptor.as_ref(), handles)?;

    handles.push(tokio::spawn(async move {
        if let Err(err) = crate::api::serve_api(
            api_addr,
            api_tls_acceptor,
            rbac_config,
            api_policy,
            api_policy_path,
            api_schema_path,
            reload_tx,
            api_registry,
            runtime_config,
            jit_lease_store,
            nad_store,
            runtime_nads,
        )
        .await
        {
            error!(error = %err, "Management API server stopped");
        }
    }));
    Ok(())
}

/// Load RBAC configuration from file or use defaults.
fn load_rbac_config(
    args: &Args,
    declarative: Option<&ServerConfiguration>,
) -> Result<crate::api::RbacConfig> {
    let rbac = if let Some(config) = declarative {
        let management = config
            .spec
            .management
            .as_ref()
            .context("management role requires management configuration")?;
        let roles = management
            .rbac
            .roles
            .iter()
            .map(|(name, role)| (name.clone(), role.permissions.clone()))
            .collect();
        let users = management
            .rbac
            .subjects
            .iter()
            .map(|subject| (subject.certificate_identity.clone(), subject.role.clone()))
            .collect();
        crate::api::RbacConfig { roles, users }
    } else if let Some(rbac_path) = args.api_rbac_config.as_ref() {
        let rbac_json = std::fs::read_to_string(rbac_path)
            .with_context(|| format!("failed to read RBAC config from {}", rbac_path.display()))?;
        serde_json::from_str(&rbac_json)
            .with_context(|| format!("failed to parse RBAC config from {}", rbac_path.display()))?
    } else {
        info!("using default RBAC configuration (admin, operator, viewer roles)");
        crate::api::RbacConfig::default()
    };
    rbac.validate()
        .map_err(|error| anyhow::anyhow!("invalid management RBAC configuration: {error}"))?;
    Ok(rbac)
}

/// Build TLS acceptor for Management API.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | SC-8 | Transmission Confidentiality | Refuses plaintext API unless --api-allow-plaintext is set |
fn build_api_tls_acceptor(args: &Args) -> Result<Option<Arc<RwLock<tokio_rustls::TlsAcceptor>>>> {
    if let (Some(cert), Some(key), Some(client_ca)) = (
        args.api_tls_cert.as_ref(),
        args.api_tls_key.as_ref(),
        args.api_client_ca.as_ref(),
    ) {
        let tls_config = tls::build_tls_config(cert, key, client_ca, &[])
            .context("building API TLS configuration")?;
        Ok(Some(Arc::new(RwLock::new(
            tokio_rustls::TlsAcceptor::from(Arc::new(tls_config)),
        ))))
    } else if args.api_allow_plaintext {
        // NIST SC-8: Explicit opt-in required for plaintext mode
        warn!(
            "Management API TLS is not configured and --api-allow-plaintext is set. \
             Running in PLAINTEXT mode. NOT RECOMMENDED FOR PRODUCTION."
        );
        Ok(None)
    } else {
        bail!(
            "Management API TLS is not configured. Provide --api-tls-cert, --api-tls-key, \
             and --api-client-ca, or pass --api-allow-plaintext for non-production use."
        );
    }
}

fn setup_management_est_reload(
    args: &Args,
    state: &AppState,
    acceptor: Option<&Arc<RwLock<tokio_rustls::TlsAcceptor>>>,
    handles: &mut Vec<JoinHandle<()>>,
) -> Result<()> {
    let (Some(provider), Some(acceptor)) = (&state.est_provider, acceptor) else {
        return Ok(());
    };
    let cert = args
        .api_tls_cert
        .clone()
        .context("management EST reload requires API certificate path")?;
    let key = args
        .api_tls_key
        .clone()
        .context("management EST reload requires API key path")?;
    let client_ca = args
        .api_client_ca
        .clone()
        .context("management EST reload requires API client CA path")?;
    let mut changes = (**provider).subscribe();
    let acceptor = acceptor.clone();
    handles.push(tokio::spawn(async move {
        while let Ok(change) = changes.recv().await {
            if !matches!(
                change,
                usg_tacacs_secrets::SecretChange::TlsCertificates { .. }
            ) {
                continue;
            }
            match tls::build_tls_config(&cert, &key, &client_ca, &[]) {
                Ok(config) => {
                    *acceptor.write().await = tokio_rustls::TlsAcceptor::from(Arc::new(config));
                    info!("management API certificate reloaded after EST renewal");
                }
                Err(error) => {
                    error!(error = %error, "refusing invalid renewed management certificate");
                }
            }
        }
    }));
    Ok(())
}

/// Setup policy watcher and graceful shutdown handler.
fn setup_policy_watcher_and_shutdown(
    args: &Args,
    state: &AppState,
    server_state: &ServerState,
    reload_rx: mpsc::Receiver<PolicyReloadRequest>,
    handles: &mut Vec<JoinHandle<()>>,
) {
    let policy = state.shared_policy.clone();
    let policy_path = state.policy_path.clone();
    if state.declarative_config.is_some() {
        handles.push(tokio::spawn(async move {
            watch_declarative_policy(policy_path, policy, reload_rx).await;
        }));
    } else {
        let schema_path = args.schema.clone();
        handles.push(tokio::spawn(async move {
            watch_policy_changes(policy_path, schema_path, policy, reload_rx).await;
        }));
    }

    let shutdown_state = server_state.clone();
    let drain_timeout = args.shutdown_drain_timeout_secs;
    let force_timeout = args.shutdown_force_timeout_secs;
    tokio::spawn(async move {
        handle_graceful_shutdown(shutdown_state, drain_timeout, force_timeout).await;
    });
}

async fn watch_declarative_policy(
    config_path: PathBuf,
    policy: Arc<RwLock<PolicyEngine>>,
    mut reload_rx: mpsc::Receiver<PolicyReloadRequest>,
) {
    let Ok(mut sighup) = signal(SignalKind::hangup()) else {
        warn!("failed to install SIGHUP handler for declarative configuration");
        while let Some(request) = reload_rx.recv().await {
            handle_declarative_reload(&config_path, &policy, request).await;
        }
        return;
    };
    loop {
        tokio::select! {
            signal = sighup.recv() => {
                if signal.is_none() {
                    return;
                }
                let request = PolicyReloadRequest::FromDisk {
                    path: config_path.clone(),
                    schema: None,
                    completion: None,
                };
                handle_declarative_reload(&config_path, &policy, request).await;
            }
            request = reload_rx.recv() => {
                let Some(request) = request else {
                    return;
                };
                handle_declarative_reload(&config_path, &policy, request).await;
            }
        }
    }
}

async fn handle_declarative_reload(
    config_path: &Path,
    policy: &Arc<RwLock<PolicyEngine>>,
    request: PolicyReloadRequest,
) {
    let completion = match request {
        PolicyReloadRequest::FromDisk { completion, .. } => completion,
        PolicyReloadRequest::FromJson { completion, .. } => {
            warn!("policy JSON upload rejected while authoritative YAML configuration is active");
            if let Some(sender) = completion {
                let _ = sender.send(Err(
                    "policy JSON upload is disabled by declarative configuration".to_string(),
                ));
            }
            return;
        }
    };
    let result = ServerConfiguration::from_path(config_path).and_then(|config| {
        config.validate(true)?;
        declarative_policy(&config)
    });
    match result {
        Ok(engine) => {
            *policy.write().await = engine;
            info!(
                config = %config_path.display(),
                "authorization policy reloaded from declarative configuration"
            );
            if let Some(sender) = completion {
                let _ = sender.send(Ok(()));
            }
        }
        Err(error) => {
            error!(
                config = %config_path.display(),
                error = %error,
                "declarative policy reload rejected; retaining previous policy"
            );
            if let Some(sender) = completion {
                let _ = sender.send(Err(error.to_string()));
            }
        }
    }
}

/// Handle SIGTERM for graceful shutdown.
async fn handle_graceful_shutdown(
    shutdown_state: ServerState,
    drain_timeout: u64,
    force_timeout: u64,
) {
    match signal(SignalKind::terminate()) {
        Ok(mut sigterm) => {
            sigterm.recv().await;
            info!("received SIGTERM, starting graceful shutdown");
            shutdown_state.set_ready(false);
            info!(
                drain_timeout_secs = drain_timeout,
                "draining connections, /ready now returns 503"
            );
            tokio::time::sleep(Duration::from_secs(drain_timeout)).await;
            info!(
                force_timeout_secs = force_timeout,
                "drain timeout reached, waiting for force timeout"
            );
            shutdown_state.set_alive(false);
            tokio::time::sleep(Duration::from_secs(force_timeout)).await;
            info!("graceful shutdown complete, exiting");
            std::process::exit(0);
        }
        Err(err) => error!(error = %err, "failed to install SIGTERM handler"),
    }
}

/// Build ICAM config from CLI args, returning None if not configured.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | IA-2 | Identification and Authentication | ICAM delegation configuration |
/// | SC-8 | Transmission Confidentiality | HTTPS-only reqwest client built once |
fn build_icam_config(args: &Args) -> Result<Option<Arc<IcamConfig>>> {
    let Some(endpoint) = args.icam_token_endpoint.as_ref() else {
        return Ok(None);
    };
    let client_id = args
        .icam_client_id
        .as_ref()
        .context("--icam-client-id is required when --icam-token-endpoint is set")?
        .clone();
    let client_secret = resolve_icam_client_secret(args)
        .map_err(anyhow::Error::msg)?
        .context("--icam-client-secret or --icam-client-secret-file is required when --icam-token-endpoint is set")?;
    let timeout = std::time::Duration::from_millis(args.icam_timeout_ms);
    let ca_file = args.icam_ca_file.clone();
    let ca_pem: Option<Vec<u8>> = if let Some(ref path) = ca_file {
        Some(std::fs::read(path).with_context(|| format!("failed to read ICAM CA file {path:?}"))?)
    } else {
        None
    };
    let https_only = endpoint.starts_with("https://");
    let http_client = icam_build_client(timeout, ca_pem.as_deref(), https_only)
        .context("failed to build ICAM HTTP client")?;
    let cfg = IcamConfig {
        token_endpoint: endpoint.clone(),
        client_id,
        client_secret,
        groups_claim: args.icam_groups_claim.clone(),
        timeout,
        ca_file,
        http_client,
    };
    info!(endpoint = %endpoint, "ICAM/OIDC authentication enabled");
    Ok(Some(Arc::new(cfg)))
}

/// Build device authorization grant configuration from CLI arguments.
///
/// Returns None when `--icam-device-flow` is disabled or ICAM is unconfigured.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | IA-2 | Identification and Authentication | RFC 8628 device flow configuration |
/// | SC-8 | Transmission Confidentiality | HTTPS-only client enforced |
fn build_device_flow_config(
    args: &Args,
    icam_cfg: Option<&IcamConfig>,
) -> Result<Option<Arc<crate::icam_device::DeviceFlowConfig>>> {
    if !args.icam_device_flow {
        return Ok(None);
    }
    let icam = icam_cfg.context(
        "--icam-device-flow requires --icam-token-endpoint, --icam-client-id, and --icam-client-secret",
    )?;
    let device_auth_endpoint = match args.icam_device_auth_endpoint.as_ref() {
        Some(ep) => ep.clone(),
        None => {
            // Derive from token endpoint: replace trailing /token with /auth/device.
            let base = icam.token_endpoint.trim_end_matches("/token");
            format!("{base}/auth/device")
        }
    };
    let cfg = crate::icam_device::DeviceFlowConfig {
        device_auth_endpoint: device_auth_endpoint.clone(),
        token_endpoint: icam.token_endpoint.clone(),
        client_id: icam.client_id.clone(),
        client_secret: icam.client_secret.clone(),
        groups_claim: icam.groups_claim.clone(),
        max_polls: args.icam_device_auth_max_polls,
        ca_file: icam.ca_file.clone(),
        http_client: icam.http_client.clone(),
    };
    info!(
        device_auth_endpoint = %device_auth_endpoint,
        max_polls = cfg.max_polls,
        "RFC 8628 device authorization flow enabled"
    );
    Ok(Some(Arc::new(cfg)))
}

/// Resolve and decode the hex audit HMAC key from file or CLI/env.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AU-9 | Protection of Audit Information | Loads key for log integrity signing |
/// | SC-28 | Protection at Rest | Key stored in file with restrictive permissions |
fn resolve_audit_hmac_key(args: &Args) -> std::result::Result<Option<Arc<Vec<u8>>>, String> {
    let raw = if let Some(ref path) = args.audit_hmac_key_file {
        Some(
            std::fs::read_to_string(path)
                .map_err(|e| format!("failed to read audit HMAC key file {path:?}: {e}"))?
                .trim()
                .to_string(),
        )
    } else {
        args.audit_hmac_key.clone()
    };
    let Some(hex_key) = raw else {
        return Ok(None);
    };
    let bytes = hex::decode(hex_key.trim())
        .map_err(|e| format!("audit HMAC key must be hex-encoded: {e}"))?;
    if bytes.len() < 32 {
        return Err(format!(
            "audit HMAC key must be at least 32 bytes ({} provided)",
            bytes.len()
        ));
    }
    info!(
        key_bytes = bytes.len(),
        "audit log HMAC signing enabled (AU-9)"
    );
    Ok(Some(Arc::new(bytes)))
}

/// Resolve the group cache password, preferring a file over the flag/env value.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | IA-5 | Authenticator Management | File-based secret avoids process-listing exposure |
fn resolve_group_cache_password(args: &Args) -> Result<Option<String>> {
    if let Some(path) = &args.group_cache_password_file {
        let pw = std::fs::read_to_string(path)
            .with_context(|| format!("reading group cache password file {path:?}"))?;
        return Ok(Some(pw.trim().to_string()));
    }
    Ok(args.group_cache_password.clone())
}

/// Initialize the shared login→authz group cache when `--group-cache-url` is set.
///
/// A no-op when the cache is unconfigured. Failure to connect is fatal at
/// A no-op when the cache is unconfigured. Initialization failure is logged but
/// NOT fatal: the TACACS+ server gates network access, so a cache outage during
/// a pod restart must never prevent startup. The server proceeds with the cache
/// disabled (group resolution degrades to LDAP/empty); a pod started while the
/// cache was unreachable picks it up on its next restart.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-3 | Access Enforcement | Enables cross-session group resolution for authz |
/// | SC-8 | Transmission Confidentiality | `rediss://` URLs use TLS transport |
/// | SI-13 | Predictable Failure Prevention | Cache outage cannot block server startup |
async fn setup_group_cache(args: &Args) -> Result<()> {
    let Some(url) = args.group_cache_url.as_ref() else {
        return Ok(());
    };
    let password = resolve_group_cache_password(args)?;
    if let Err(e) = crate::group_cache::init_group_cache(
        url,
        password.as_deref(),
        args.group_cache_ttl_secs,
        &args.group_cache_key_prefix,
    )
    .await
    {
        warn!(error = %e, "shared group cache unavailable; continuing without it");
        return Ok(());
    }
    info!(
        ttl_secs = args.group_cache_ttl_secs,
        "shared login→authz group cache enabled"
    );
    Ok(())
}

/// Build application state from parsed arguments.
async fn build_app_state(
    args: &Args,
    declarative_config: Option<Arc<ServerConfiguration>>,
) -> Result<AppState> {
    let policy_path = resolve_policy_path(args)?;
    let legacy_nad_secret_entries = resolve_legacy_nad_secrets(args).map_err(anyhow::Error::msg)?;
    let ldap_config = validate_secrets_and_build_ldap(args, &legacy_nad_secret_entries)?;
    let icam_config = build_icam_config(args)?;
    let device_flow_config = build_device_flow_config(args, icam_config.as_deref())?;
    let audit_hmac_key = resolve_audit_hmac_key(args).map_err(anyhow::Error::msg)?;
    setup_group_cache(args).await?;
    let jit_lease_store = setup_jit_lease_store(args, declarative_config.as_deref()).await?;
    let jit_managed_nads =
        resolve_jit_managed_nads(jit_lease_store.is_some(), declarative_config.as_deref())?;
    let (legacy_nad_secrets, jit_legacy_nads) = build_jit_legacy_config(
        &legacy_nad_secret_entries,
        jit_lease_store.is_some(),
        jit_managed_nads.as_ref(),
        declarative_config.as_deref(),
    )?;
    if jit_lease_store.is_some() && audit_hmac_key.is_none() {
        bail!("JIT lease management requires AUDIT_HMAC_KEY_FILE for signed audit records");
    }
    let (username_limiter, ip_limiter) = setup_request_limiters(args);
    let (est_provider, est_config) = setup_est_provider(args).await?;
    let nad_store = setup_nad_store(&jit_lease_store, &audit_hmac_key).await?;
    let runtime_nads = setup_runtime_nads(nad_store.clone(), declarative_config.as_deref()).await?;

    let policy_engine = build_initial_policy(args, &policy_path, declarative_config.as_deref())?;
    Ok(AppState {
        shared_policy: Arc::new(RwLock::new(policy_engine)),
        shared_secret: args
            .secret
            .as_ref()
            .map(|s| Arc::new(s.clone().into_bytes())),
        credentials: Arc::new(credentials_map(args).map_err(anyhow::Error::msg)?),
        ldap_config,
        icam_config,
        device_flow_config,
        username_limiter,
        ip_limiter,
        audit_hmac_key,
        jit_lease_store,
        nad_store,
        runtime_nads,
        jit_managed_nads,
        jit_legacy_nads,
        legacy_nad_secrets,
        conn_limiter: ConnLimiter::new(args.max_connections_per_ip),
        session_registry: setup_session_registry(args),
        est_provider,
        est_config,
        policy_path,
        declarative_config,
    })
}

async fn setup_runtime_nads(
    store: Option<Arc<crate::nad_store::NadStore>>,
    declarative: Option<&ServerConfiguration>,
) -> Result<Option<Arc<crate::nad_reconciler::RuntimeNadRegistry>>> {
    let Some(store) = store else {
        return Ok(None);
    };
    let yaml_nads = declarative
        .map(|config| config.spec.nads.clone())
        .unwrap_or_default();
    let registry = crate::nad_reconciler::RuntimeNadRegistry::initialize(
        store,
        yaml_nads,
        PathBuf::from("/run/secrets/nads"),
    )
    .await
    .map_err(|error| anyhow::anyhow!("loading API-owned NADs: {error}"))?;
    let snapshot = registry.snapshot();
    let active = snapshot
        .statuses
        .values()
        .filter(|status| status.state == crate::nad_reconciler::ReconciliationState::Active)
        .count();
    info!(
        api_nads = snapshot.statuses.len(),
        active, "initial NAD reconciliation complete"
    );
    Ok(Some(Arc::new(registry)))
}

fn setup_nad_reconciliation_watcher(state: &AppState, handles: &mut Vec<JoinHandle<()>>) {
    let Some(registry) = state.runtime_nads.clone() else {
        return;
    };
    handles.push(tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;
        loop {
            interval.tick().await;
            match registry.refresh().await {
                Ok(snapshot) => info!(
                    reconciled_at = %snapshot.reconciled_at,
                    active_legacy = snapshot.legacy_identities.len(),
                    active_tls = snapshot.tls_identities.len(),
                    "periodic NAD reconciliation published"
                ),
                Err(error) => warn!(
                    error = %error,
                    "periodic NAD reconciliation failed; retaining last valid snapshot"
                ),
            }
        }
    }));
}

fn setup_request_limiters(
    args: &Args,
) -> (
    Arc<crate::username_limiter::UsernameRateLimiter>,
    Arc<crate::ip_limiter::IpRateLimiter>,
) {
    let username = crate::username_limiter::UsernameRateLimiter::new(
        args.username_lockout_window_secs,
        args.username_lockout_limit,
        args.username_lockout_secs,
    );
    let ip = crate::ip_limiter::IpRateLimiter::new(
        args.ip_lockout_window_secs,
        args.ip_lockout_limit,
        args.ip_lockout_secs,
    );
    (username, ip)
}

async fn setup_nad_store(
    jit_store: &Option<Arc<crate::jit_lease_store::JitLeaseStore>>,
    audit_key: &Option<Arc<Vec<u8>>>,
) -> Result<Option<Arc<crate::nad_store::NadStore>>> {
    let (Some(store), Some(key)) = (jit_store, audit_key) else {
        return Ok(None);
    };
    let store = crate::nad_store::NadStore::new(store.pool(), key.clone())
        .map_err(|error| anyhow::anyhow!("initializing NAD store: {error}"))?;
    let cutoff = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
    let recovered = store
        .fail_abandoned_operations(cutoff)
        .await
        .map_err(|error| anyhow::anyhow!("recovering abandoned management operations: {error}"))?;
    if recovered > 0 {
        warn!(
            recovered,
            "marked abandoned management operations failed during startup"
        );
    }
    Ok(Some(Arc::new(store)))
}

fn resolve_policy_path(args: &Args) -> Result<PathBuf> {
    if let Some(path) = args.config.as_ref() {
        return Ok(path.clone());
    }
    args.policy
        .as_ref()
        .context("a --policy path or --config is required to start the server")
        .cloned()
}

fn build_initial_policy(
    args: &Args,
    policy_path: &Path,
    declarative: Option<&ServerConfiguration>,
) -> Result<PolicyEngine> {
    match declarative {
        Some(config) => declarative_policy(config),
        None => PolicyEngine::from_path(policy_path, args.schema.as_ref()),
    }
}

fn build_jit_legacy_config(
    legacy_nad_secret_entries: &[(std::net::IpAddr, String)],
    enabled: bool,
    managed_nads: &std::collections::HashSet<String>,
    declarative: Option<&ServerConfiguration>,
) -> Result<(LegacyNadSecrets, JitLegacyNads)> {
    let legacy_nad_secrets: LegacyNadSecrets = Arc::new(
        legacy_nad_secret_entries
            .iter()
            .map(|(ip, secret)| (normalize_ip(*ip), Arc::new(secret.clone().into_bytes())))
            .collect(),
    );
    let jit_legacy_nads = resolve_jit_legacy_nads(
        enabled,
        managed_nads,
        legacy_nad_secrets.as_ref(),
        declarative,
    )?;
    Ok((legacy_nad_secrets, jit_legacy_nads))
}

fn resolve_jit_managed_nads(
    enabled: bool,
    declarative: Option<&ServerConfiguration>,
) -> Result<Arc<std::collections::HashSet<String>>> {
    if !enabled {
        return Ok(Arc::new(std::collections::HashSet::new()));
    }
    let raw = if let Some(config) = declarative {
        config
            .spec
            .nads
            .iter()
            .map(|nad| nad.name.as_str())
            .collect::<Vec<_>>()
            .join(",")
    } else {
        std::env::var("JIT_MANAGED_NADS").context("JIT_MANAGED_NADS is required")?
    };
    let mut identities = std::collections::HashSet::new();
    for value in raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let identity =
            crate::jit_lease::NadIdentity::parse(value).map_err(|error| anyhow::anyhow!(error))?;
        identities.insert(identity.as_str().to_owned());
    }
    if identities.is_empty() {
        bail!("JIT_MANAGED_NADS must contain at least one canonical NAD identity");
    }
    Ok(Arc::new(identities))
}

fn resolve_jit_legacy_nads(
    enabled: bool,
    managed_nads: &std::collections::HashSet<String>,
    legacy_nad_secrets: &std::collections::HashMap<std::net::IpAddr, Arc<Vec<u8>>>,
    declarative: Option<&ServerConfiguration>,
) -> Result<JitLegacyNads> {
    let raw = declarative.map(|config| {
        config
            .spec
            .nads
            .iter()
            .filter(|nad| matches!(nad.authentication, NadAuthentication::Legacy { .. }))
            .map(|nad| format!("{}={}", nad.source_address, nad.name))
            .collect::<Vec<_>>()
            .join(",")
    });
    let raw = raw.or_else(|| std::env::var("JIT_LEGACY_NADS").ok());
    let Some(raw) = raw else {
        return Ok(Arc::new(std::collections::HashMap::new()));
    };
    if !enabled {
        bail!("JIT_LEGACY_NADS requires the JIT lease store");
    }
    parse_jit_legacy_nads(&raw, managed_nads, legacy_nad_secrets).map(Arc::new)
}

fn parse_jit_legacy_nads(
    raw: &str,
    managed_nads: &std::collections::HashSet<String>,
    legacy_nad_secrets: &std::collections::HashMap<std::net::IpAddr, Arc<Vec<u8>>>,
) -> Result<std::collections::HashMap<std::net::IpAddr, crate::jit_lease::NadIdentity>> {
    let mut mappings = std::collections::HashMap::new();
    for entry in raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let (ip_value, identity_value) = entry
            .split_once('=')
            .context("JIT_LEGACY_NADS entries must use IP=NAD_IDENTITY")?;
        let ip = normalize_ip(
            ip_value
                .trim()
                .parse()
                .context("JIT_LEGACY_NADS contains an invalid IP address")?,
        );
        let identity = crate::jit_lease::NadIdentity::parse(identity_value.trim())
            .map_err(|error| anyhow::anyhow!(error))?;
        if !managed_nads.contains(identity.as_str()) {
            bail!("JIT legacy NAD identity is not listed in JIT_MANAGED_NADS");
        }
        if !legacy_nad_secrets.contains_key(&ip) {
            bail!("JIT legacy NAD requires a unique per-NAD TACACS secret");
        }
        if mappings.insert(ip, identity).is_some() {
            bail!("JIT_LEGACY_NADS contains a duplicate normalized IP address");
        }
    }
    if raw.trim().is_empty() {
        bail!("JIT_LEGACY_NADS must not be empty when set");
    }
    let entries = mappings.iter().collect::<Vec<_>>();
    for (index, (ip, identity)) in entries.iter().enumerate() {
        for (other_ip, other_identity) in entries.iter().skip(index + 1) {
            if identity != other_identity
                && legacy_nad_secrets.get(ip).map(Arc::as_ref)
                    == legacy_nad_secrets.get(other_ip).map(Arc::as_ref)
            {
                bail!("JIT legacy NAD identities must not share TACACS secrets");
            }
        }
    }
    Ok(mappings)
}

/// Configure the authoritative JIT store from file-backed secrets.
///
/// The feature is disabled unless `JIT_LEASE_STORE_URL` is set. Production
/// activation is deliberately strict: the API, mTLS material, PostgreSQL password,
/// and verifier key must all be present or startup fails.
async fn setup_jit_lease_store(
    args: &Args,
    declarative: Option<&ServerConfiguration>,
) -> Result<Option<Arc<crate::jit_lease_store::JitLeaseStore>>> {
    let Some((url, password_path, ca_path, verifier_path)) = resolve_jit_store_paths(declarative)?
    else {
        return Ok(None);
    };
    if !args.api_enabled
        || args.api_tls_cert.is_none()
        || args.api_tls_key.is_none()
        || args.api_client_ca.is_none()
    {
        bail!("JIT lease store requires the mTLS Management API to be fully configured");
    }
    aws_lc_rs::try_fips_mode()
        .map_err(|error| anyhow::anyhow!("AWS-LC FIPS self-test failed: {error}"))?;
    let password = zeroize::Zeroizing::new(
        read_secret_file(&password_path).context("reading JIT lease store password")?,
    );
    let key_hex = zeroize::Zeroizing::new(
        read_secret_file(&verifier_path).context("reading JIT lease verifier key")?,
    );
    let key_bytes =
        hex::decode(key_hex.as_bytes()).context("JIT lease verifier key must be hex")?;
    let verifier_key = Arc::new(
        crate::jit_lease::VerifierKey::new(zeroize::Zeroizing::new(key_bytes))
            .map_err(|error| anyhow::anyhow!(error))?,
    );
    let store = crate::jit_lease_store::JitLeaseStore::connect(
        &url,
        Some(password.as_str()),
        &ca_path,
        verifier_key,
    )
    .await
    .map_err(|error| anyhow::anyhow!("initializing JIT lease store: {error}"))?;
    info!("authoritative JIT lease store enabled");
    Ok(Some(Arc::new(store)))
}

type JitStorePaths = (String, PathBuf, PathBuf, PathBuf);

fn resolve_jit_store_paths(
    declarative: Option<&ServerConfiguration>,
) -> Result<Option<JitStorePaths>> {
    if let Some(jit) = declarative.and_then(|config| config.spec.jit.as_ref()) {
        return Ok(Some((
            jit.store_url.clone(),
            jit.store_password_file.clone(),
            jit.store_ca_file.clone(),
            jit.verifier_key_file.clone(),
        )));
    }
    let Ok(url) = std::env::var("JIT_LEASE_STORE_URL") else {
        return Ok(None);
    };
    Ok(Some((
        url,
        required_env_path("JIT_LEASE_STORE_PASSWORD_FILE")?,
        required_env_path("JIT_LEASE_STORE_CA_FILE")?,
        required_env_path("JIT_LEASE_VERIFIER_KEY_FILE")?,
    )))
}

fn required_env_path(name: &'static str) -> Result<PathBuf> {
    std::env::var(name)
        .with_context(|| format!("{name} is required"))
        .map(PathBuf::from)
}

/// Run all server tasks and await completion.
async fn run_server(args: &Args, state: &AppState, otel_enabled: bool) -> Result<()> {
    // Initialize the audit HMAC key once, before any listener accepts a
    // connection, so the very first audit event (conn_open) is already signed
    // (AU-9). Initializing per-connection raced the OnceLock against the first
    // emitted events, leaving early conn_open records unsigned.
    init_audit_hmac(state.audit_hmac_key.as_ref());
    let mut handles = Vec::new();
    setup_tls_listener(args, state, &mut handles).await?;
    setup_legacy_listener(args, state, &mut handles)?;

    let server_state = ServerState::new().with_registry(state.session_registry.clone());
    setup_http_server(args, &server_state, &mut handles);

    let (reload_tx, reload_rx) = mpsc::channel::<PolicyReloadRequest>(10);
    setup_management_api(args, state, reload_tx, &mut handles)?;
    setup_nad_reconciliation_watcher(state, &mut handles);

    if handles.is_empty() {
        bail!("no listeners configured for the selected server role");
    }

    {
        metrics()
            .policy_rules_count
            .set(state.shared_policy.read().await.rule_count() as f64);
    }
    server_state.set_ready(true);
    info!("server ready");

    setup_policy_watcher_and_shutdown(args, state, &server_state, reload_rx, &mut handles);

    for handle in handles {
        let _ = handle.await;
    }
    if otel_enabled {
        shutdown_telemetry();
    }
    Ok(())
}

// ============================================================================
// Main Entry Point (NASA Power of 10 Rule #4 compliant: ≤60 lines)
// ============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    // rustls 0.23 cannot auto-select a CryptoProvider when both the aws-lc-rs
    // and ring backends are present in the dependency tree (ring is pulled via
    // rcgen in usg-est-client and via reqwest's hyper-rustls). Install aws-lc-rs
    // as the process-level provider before any TLS use; Err means it is already
    // installed, which is fine.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let mut args = Args::parse();
    let declarative_config = if let Some(config_path) = args.config.clone() {
        let config = Arc::new(ServerConfiguration::from_path(&config_path)?);
        apply_declarative_config(&mut args, &config)?;
        Some(config)
    } else {
        None
    };
    let otel_enabled = init_tracing(&args)?;

    if handle_check_policy_mode(&args)? {
        return Ok(());
    }

    let state = build_app_state(&args, declarative_config).await?;
    run_server(&args, &state, otel_enabled).await
}

mod api;
mod ascii;
mod auth;
mod config;
mod group_cache;
mod http;
mod icam;
mod icam_device;
mod ip_limiter;
mod jit_lease;
mod jit_lease_store;
mod metrics;
mod nad_reconciler;
mod nad_store;
mod policy;
mod server;
mod session;
mod session_registry;
mod telemetry;
mod tls;
mod username_limiter;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_flow_without_icam_returns_error() {
        let args = config::Args::try_parse_from(["usg-tacacs", "--icam-device-flow"]).unwrap();
        assert!(args.icam_device_flow);
        assert!(args.icam_token_endpoint.is_none());
        let result = build_device_flow_config(&args, None);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("--icam-device-flow requires"),
            "error should mention --icam-device-flow, got: {msg}"
        );
    }

    #[test]
    fn device_flow_disabled_without_icam_returns_none() {
        let args = config::Args::try_parse_from(["usg-tacacs"]).unwrap();
        assert!(!args.icam_device_flow);
        let result = build_device_flow_config(&args, None);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn legacy_jit_mapping_requires_managed_identity_and_per_nad_secret() {
        let ip: std::net::IpAddr = "192.0.2.10".parse().unwrap();
        let managed = std::collections::HashSet::from(["router-a.example.mil".to_owned()]);
        let secrets = std::collections::HashMap::from([(ip, Arc::new(vec![7_u8; 32]))]);

        let mappings =
            parse_jit_legacy_nads("192.0.2.10=router-a.example.mil", &managed, &secrets).unwrap();
        assert_eq!(mappings[&ip].as_str(), "router-a.example.mil");
        assert!(
            parse_jit_legacy_nads("192.0.2.10=router-b.example.mil", &managed, &secrets).is_err()
        );
        assert!(
            parse_jit_legacy_nads("192.0.2.11=router-a.example.mil", &managed, &secrets).is_err()
        );
    }

    #[test]
    fn legacy_jit_mapping_rejects_duplicate_normalized_ip() {
        let ip: std::net::IpAddr = "192.0.2.10".parse().unwrap();
        let managed = std::collections::HashSet::from(["router-a.example.mil".to_owned()]);
        let secrets = std::collections::HashMap::from([(ip, Arc::new(vec![7_u8; 32]))]);
        let raw = "192.0.2.10=router-a.example.mil,::ffff:192.0.2.10=router-a.example.mil";

        assert!(parse_jit_legacy_nads(raw, &managed, &secrets).is_err());
    }

    #[test]
    fn legacy_jit_mapping_rejects_secret_reuse_between_identities() {
        let first_ip: std::net::IpAddr = "192.0.2.10".parse().unwrap();
        let second_ip: std::net::IpAddr = "192.0.2.11".parse().unwrap();
        let managed = std::collections::HashSet::from([
            "router-a.example.mil".to_owned(),
            "router-b.example.mil".to_owned(),
        ]);
        let shared = vec![7_u8; 32];
        let secrets = std::collections::HashMap::from([
            (first_ip, Arc::new(shared.clone())),
            (second_ip, Arc::new(shared)),
        ]);
        let raw = "192.0.2.10=router-a.example.mil,192.0.2.11=router-b.example.mil";

        assert!(parse_jit_legacy_nads(raw, &managed, &secrets).is_err());
    }
}
