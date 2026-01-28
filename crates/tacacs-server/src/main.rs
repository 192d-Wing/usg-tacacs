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
use crate::config::{Args, LogFormat, StaticCreds, build_est_config, credentials_map};
use crate::http::{ServerState, serve_http};
use crate::metrics::metrics;
use crate::server::{
    AuthContext, CertificateReloadRequest, ConnLimiter, ConnectionConfig, PolicyReloadRequest,
    TlsIdentityConfig, serve_legacy, serve_tls, tls_acceptor, validate_policy,
    watch_certificate_changes, watch_policy_changes,
};
use crate::session_registry::{SessionLimits, SessionRegistry, run_idle_sweep_task};
use crate::telemetry::{TelemetryConfig, init_telemetry, shutdown_telemetry};
use anyhow::{Context, Result, bail};
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{RwLock, mpsc};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};
use tracing_subscriber::fmt::time::UtcTime;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use usg_tacacs_policy::PolicyEngine;
use usg_tacacs_proto::MIN_SECRET_LEN;
use usg_tacacs_secrets::SecretsProvider;

// ============================================================================
// Application State Container
// ============================================================================

/// Shared application state passed between initialization phases.
struct AppState {
    shared_policy: Arc<RwLock<PolicyEngine>>,
    shared_secret: Option<Arc<Vec<u8>>>,
    credentials: Arc<StaticCreds>,
    ldap_config: Option<Arc<LdapConfig>>,
    legacy_nad_secrets: Arc<std::collections::HashMap<std::net::IpAddr, Arc<Vec<u8>>>>,
    conn_limiter: ConnLimiter,
    session_registry: Arc<SessionRegistry>,
    est_provider: Option<Arc<usg_tacacs_secrets::EstProvider>>,
    est_config: Option<usg_tacacs_secrets::EstConfig>,
    policy_path: PathBuf,
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

/// Validate secrets and build LDAP configuration.
fn validate_secrets_and_build_ldap(args: &Args) -> Result<Option<Arc<LdapConfig>>> {
    for (ip, sec) in &args.legacy_nad_secret {
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
    };
    let conn_cfg = build_connection_config(args, state.conn_limiter.clone());
    let tls_identity = TlsIdentityConfig {
        allowed_cn: args.tls_allowed_client_cn.clone(),
        allowed_san: args.tls_allowed_client_san.clone(),
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

    let default_ok = state
        .shared_secret
        .as_deref()
        .map(|s| s.len() >= MIN_SECRET_LEN)
        .unwrap_or(false);
    let any_nad = !state.legacy_nad_secrets.is_empty();
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
    };
    let conn_cfg = build_connection_config(args, state.conn_limiter.clone());
    let nad_secrets = state.legacy_nad_secrets.clone();
    let legacy_registry = state.session_registry.clone();

    handles.push(tokio::spawn(async move {
        if let Err(err) = serve_legacy(addr, auth_ctx, conn_cfg, nad_secrets, legacy_registry).await
        {
            error!(error = %err, "legacy listener stopped");
        }
    }));
    Ok(())
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
    let rbac_config = load_rbac_config(args)?;
    let api_tls_acceptor = build_api_tls_acceptor(args)?;

    let runtime_config = crate::api::RuntimeConfig {
        listen_tls: args.listen_tls,
        listen_legacy: args.listen_legacy,
        tls_enabled: args.listen_tls.is_some(),
        ldap_enabled: state.ldap_config.is_some(),
        policy_source: state.policy_path.display().to_string(),
    };

    let api_policy = state.shared_policy.clone();
    let api_policy_path = state.policy_path.display().to_string();
    let api_schema_path = args.schema.clone();
    let api_registry = state.session_registry.clone();

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
        )
        .await
        {
            error!(error = %err, "Management API server stopped");
        }
    }));
    Ok(())
}

/// Load RBAC configuration from file or use defaults.
fn load_rbac_config(args: &Args) -> Result<crate::api::RbacConfig> {
    if let Some(rbac_path) = args.api_rbac_config.as_ref() {
        let rbac_json = std::fs::read_to_string(rbac_path)
            .with_context(|| format!("failed to read RBAC config from {}", rbac_path.display()))?;
        serde_json::from_str(&rbac_json)
            .with_context(|| format!("failed to parse RBAC config from {}", rbac_path.display()))
    } else {
        info!("using default RBAC configuration (admin, operator, viewer roles)");
        Ok(crate::api::RbacConfig::default())
    }
}

/// Build TLS acceptor for Management API.
fn build_api_tls_acceptor(args: &Args) -> Result<Option<tokio_rustls::TlsAcceptor>> {
    if let (Some(cert), Some(key), Some(client_ca)) = (
        args.api_tls_cert.as_ref(),
        args.api_tls_key.as_ref(),
        args.api_client_ca.as_ref(),
    ) {
        let tls_config = tls::build_tls_config(cert, key, client_ca, &[])
            .context("building API TLS configuration")?;
        Ok(Some(tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(
            tls_config,
        ))))
    } else {
        warn!(
            "Management API TLS is not configured. Running in PLAINTEXT mode. For production use, configure --api-tls-cert, --api-tls-key, and --api-client-ca."
        );
        Ok(None)
    }
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
    let schema_path = args.schema.clone();
    let policy_path = state.policy_path.clone();
    handles.push(tokio::spawn(async move {
        watch_policy_changes(policy_path, schema_path, policy, reload_rx).await;
    }));

    let shutdown_state = server_state.clone();
    let drain_timeout = args.shutdown_drain_timeout_secs;
    let force_timeout = args.shutdown_force_timeout_secs;
    tokio::spawn(async move {
        handle_graceful_shutdown(shutdown_state, drain_timeout, force_timeout).await;
    });
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

/// Build application state from parsed arguments.
async fn build_app_state(args: &Args) -> Result<AppState> {
    let policy_path = args
        .policy
        .as_ref()
        .context("a --policy path is required to start the server")?
        .clone();
    let ldap_config = validate_secrets_and_build_ldap(args)?;
    let (est_provider, est_config) = setup_est_provider(args).await?;

    Ok(AppState {
        shared_policy: Arc::new(RwLock::new(PolicyEngine::from_path(
            &policy_path,
            args.schema.as_ref(),
        )?)),
        shared_secret: args
            .secret
            .as_ref()
            .map(|s| Arc::new(s.clone().into_bytes())),
        credentials: Arc::new(credentials_map(args).map_err(anyhow::Error::msg)?),
        ldap_config,
        legacy_nad_secrets: Arc::new(
            args.legacy_nad_secret
                .iter()
                .map(|(ip, sec)| (*ip, Arc::new(sec.clone().into_bytes())))
                .collect(),
        ),
        conn_limiter: ConnLimiter::new(args.max_connections_per_ip),
        session_registry: setup_session_registry(args),
        est_provider,
        est_config,
        policy_path,
    })
}

/// Run all server tasks and await completion.
async fn run_server(args: &Args, state: &AppState, otel_enabled: bool) -> Result<()> {
    let mut handles = Vec::new();
    setup_tls_listener(args, state, &mut handles).await?;
    setup_legacy_listener(args, state, &mut handles)?;

    if handles.is_empty() {
        bail!("no listeners configured; set --listen-tls and/or --listen-legacy");
    }

    let server_state = ServerState::new();
    setup_http_server(args, &server_state, &mut handles);

    let (reload_tx, reload_rx) = mpsc::channel::<PolicyReloadRequest>(10);
    setup_management_api(args, state, reload_tx, &mut handles)?;

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
    let args = Args::parse();
    let otel_enabled = init_tracing(&args)?;

    if handle_check_policy_mode(&args)? {
        return Ok(());
    }

    let state = build_app_state(&args).await?;
    run_server(&args, &state, otel_enabled).await
}

mod api;
mod ascii;
mod auth;
mod config;
mod http;
mod metrics;
mod policy;
mod server;
mod session;
mod session_registry;
mod telemetry;
mod tls;
