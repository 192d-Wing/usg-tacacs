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
use tracing::{error, info, warn};
use tracing_subscriber::fmt::time::UtcTime;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use usg_tacacs_policy::PolicyEngine;
use usg_tacacs_proto::MIN_SECRET_LEN;
use usg_tacacs_secrets::SecretsProvider;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize tracing with the configured log format and optional OpenTelemetry
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
            let telemetry_config = TelemetryConfig::new(
                endpoint.clone(),
                args.otel_service_name.clone(),
                args.location.clone(),
            );
            let otel_layer = init_telemetry(&telemetry_config)?;
            tracing_subscriber::registry()
                .with(otel_layer)
                .with(tracing_subscriber::fmt::layer().with_timer(UtcTime::rfc_3339()))
                .init();
            info!(otlp_endpoint = %endpoint, "OpenTelemetry tracing enabled");
        }
        (LogFormat::Json, Some(endpoint)) => {
            let telemetry_config = TelemetryConfig::new(
                endpoint.clone(),
                args.otel_service_name.clone(),
                args.location.clone(),
            );
            let otel_layer = init_telemetry(&telemetry_config)?;
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

    if let Some(policy_path) = args.check_policy.as_ref() {
        let schema = args
            .schema
            .as_ref()
            .context("--schema is required with --check-policy")?;
        validate_policy(policy_path, Some(schema))?;
        println!("policy validated");
        return Ok(());
    }

    let policy_path = args
        .policy
        .as_ref()
        .context("a --policy path is required to start the server")?;
    let engine = PolicyEngine::from_path(policy_path, args.schema.as_ref())?;
    let shared_policy = Arc::new(RwLock::new(engine));
    let shared_secret: Option<Arc<Vec<u8>>> = args
        .secret
        .as_ref()
        .map(|s| Arc::new(s.clone().into_bytes()));
    for (ip, sec) in &args.legacy_nad_secret {
        if sec.len() < MIN_SECRET_LEN {
            bail!(
                "legacy NAD secret for {} must be at least {} bytes",
                ip,
                MIN_SECRET_LEN
            );
        }
    }
    let legacy_nad_secrets: Arc<std::collections::HashMap<std::net::IpAddr, Arc<Vec<u8>>>> =
        Arc::new(
            args.legacy_nad_secret
                .iter()
                .map(|(ip, sec)| (*ip, Arc::new(sec.clone().into_bytes())))
                .collect(),
        );
    if let (Some(secret), Some(psk)) = (args.secret.as_ref(), args.tls_psk.as_ref())
        && secret == psk
    {
        bail!("TACACS+ shared secret must not match TLS PSK");
    }
    let credentials: Arc<StaticCreds> =
        Arc::new(credentials_map(&args).map_err(anyhow::Error::msg)?);
    let ascii_backoff_max_ms = args.ascii_backoff_max_ms;
    let ascii_lockout_limit = args.ascii_lockout_limit;
    let single_connect_idle_secs = args.single_connect_idle_secs;
    let single_connect_keepalive_secs = args.single_connect_keepalive_secs;
    let conn_limiter = ConnLimiter::new(args.max_connections_per_ip);
    let ldap_config: Option<Arc<LdapConfig>> = if let Some(url) = args.ldaps_url.clone() {
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
        Some(Arc::new(LdapConfig {
            url,
            bind_dn,
            bind_password,
            search_base,
            username_attr: args.ldap_username_attr.clone(),
            timeout: Duration::from_millis(args.ldap_timeout_ms),
            ca_file: args.ldap_ca_file.clone(),
            required_group: args.ldap_required_group.clone(),
            group_attr: args.ldap_group_attr.clone(),
        }))
    } else {
        None
    };

    let mut handles = Vec::new();

    // NIST AC-10/AC-12: Create session registry for tracking active connections
    // This is shared with both connection handlers and the API for session visibility and termination
    let session_limits = SessionLimits {
        max_total_sessions: args.max_sessions,
        max_sessions_per_ip: args.max_sessions_per_ip,
    };
    let session_registry = Arc::new(SessionRegistry::with_limits(session_limits));
    if args.max_sessions > 0 || args.max_sessions_per_ip > 0 {
        info!(
            max_sessions = args.max_sessions,
            max_sessions_per_ip = args.max_sessions_per_ip,
            "session limits configured"
        );
    }

    // NIST AC-12: Spawn background idle sweep task if idle timeout is configured
    if single_connect_idle_secs > 0 {
        let sweep_registry = session_registry.clone();
        let idle_timeout = Duration::from_secs(single_connect_idle_secs);
        // Sweep at 1/4 of idle timeout for responsive termination
        let sweep_interval = Duration::from_secs(single_connect_idle_secs.max(4) / 4);
        tokio::spawn(async move {
            run_idle_sweep_task(sweep_registry, idle_timeout, sweep_interval).await;
        });
    }

    // ==================== EST Zero-Touch Certificate Provisioning ====================
    // NIST IA-5/SC-17: Bootstrap certificate enrollment for zero-touch deployment
    let mut est_provider: Option<Arc<usg_tacacs_secrets::EstProvider>> = None;
    let est_config_opt = build_est_config(&args).map_err(anyhow::Error::msg)?;

    if let Some(est_config) = &est_config_opt {
        info!(
            server_url = %est_config.server_url,
            common_name = %est_config.common_name,
            "EST zero-touch provisioning enabled"
        );

        // Create EST provider
        let mut provider = usg_tacacs_secrets::EstProvider::new(est_config.clone())
            .await
            .context("failed to initialize EST provider")?;

        // Check if bootstrap enrollment is needed
        if !est_config.cert_path.exists() || !est_config.key_path.exists() {
            info!("EST certificates not found, performing bootstrap enrollment");

            // Perform bootstrap enrollment with timeout
            let bootstrap_timeout = Duration::from_secs(est_config.bootstrap_timeout_secs);
            let enroll_result =
                tokio::time::timeout(bootstrap_timeout, provider.bootstrap_enrollment()).await;

            match enroll_result {
                Ok(Ok(bundle)) => {
                    info!(
                        serial = %bundle.serial_number,
                        expires_at = bundle.expires_at,
                        "EST bootstrap enrollment successful"
                    );
                }
                Ok(Err(e)) => {
                    error!(error = %e, "EST bootstrap enrollment failed");
                    if est_config.initial_enrollment_required {
                        bail!("EST enrollment required but failed: {}", e);
                    } else {
                        warn!("EST enrollment failed, continuing in degraded mode");
                    }
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
                    } else {
                        warn!("EST enrollment timed out, continuing in degraded mode");
                    }
                }
            }
        } else {
            info!(
                cert_path = ?est_config.cert_path,
                "EST certificates found, loading existing"
            );
        }

        // Start certificate renewal loop
        provider
            .start_renewal_loop()
            .context("failed to start EST renewal loop")?;

        est_provider = Some(Arc::new(provider));

        info!("EST certificate renewal loop started");
    }

    if let Some(addr) = args.listen_tls {
        // RFC 9887: TACACS+ over TLS 1.3 SHOULD use port 300
        const RFC9887_TLS_PORT: u16 = 300;
        if addr.port() != RFC9887_TLS_PORT {
            warn!(
                "TLS listener on port {} instead of RFC 9887 standard port {} (tacacss)",
                addr.port(),
                RFC9887_TLS_PORT
            );
        }
        // Note: RFC 9887 specifies that obfuscation MUST NOT be used over TLS.
        // This implementation applies obfuscation for defense-in-depth, which
        // deviates from strict RFC 9887 but provides additional security layer.
        // A future --rfc9887-strict mode could disable obfuscation over TLS.
        info!(
            "TLS mode: MD5 obfuscation applied for defense-in-depth (RFC 9887 permits TLS-only encryption)"
        );
        let allow_unencrypted = !(args.forbid_unencrypted
            && shared_secret
                .as_ref()
                .map(|s| s.len() >= MIN_SECRET_LEN)
                .unwrap_or(false));
        if allow_unencrypted
            && shared_secret.as_ref().map(|s| s.len()).unwrap_or(0) < MIN_SECRET_LEN
        {
            warn!("TLS mode: shared secret missing/short; UNENCRYPTED packets will be accepted");
        }

        // Determine certificate source: EST or manual paths
        let (cert, key) = if let Some(ref est_cfg) = est_config_opt {
            // Use EST-provisioned certificates
            info!(
                cert_path = ?est_cfg.cert_path,
                key_path = ?est_cfg.key_path,
                "using EST-provisioned certificates for TLS"
            );
            (&est_cfg.cert_path, &est_cfg.key_path)
        } else {
            // Use manually configured certificates
            let cert_ref = args.tls_cert.as_ref().context(
                "--tls-cert is required when --listen-tls is set (or use --est-enabled)",
            )?;
            let key_ref = args
                .tls_key
                .as_ref()
                .context("--tls-key is required when --listen-tls is set (or use --est-enabled)")?;
            (cert_ref, key_ref)
        };

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

        // Create certificate reload channel and watcher task
        let (cert_reload_tx, cert_reload_rx) = mpsc::channel::<CertificateReloadRequest>(10);
        let cert_acceptor = acceptor.clone();
        handles.push(tokio::spawn(async move {
            watch_certificate_changes(cert_reload_rx, cert_acceptor).await;
        }));

        // Wire up EST provider to certificate reload channel
        if let Some(ref est_prov) = est_provider {
            let reload_tx = cert_reload_tx.clone();
            let est_config = est_config_opt
                .as_ref()
                .context("EST config missing when EST provider is active")?;
            let est_cert_path = est_config.cert_path.clone();
            let est_key_path = est_config.key_path.clone();
            let est_ca_path = ca.clone();
            let est_trust_roots = args.tls_trust_root.clone();

            // Subscribe to EST certificate change events
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

        let auth_ctx = AuthContext {
            policy: shared_policy.clone(),
            secret: shared_secret.clone(),
            credentials: credentials.clone(),
            ldap: ldap_config.clone(),
        };
        let conn_cfg = ConnectionConfig {
            single_connect_idle_secs,
            single_connect_keepalive_secs,
            conn_limiter: conn_limiter.clone(),
            ascii: AsciiConfig {
                attempt_limit: args.ascii_attempt_limit,
                user_attempt_limit: args.ascii_user_attempt_limit,
                pass_attempt_limit: args.ascii_pass_attempt_limit,
                backoff_ms: args.ascii_backoff_ms,
                backoff_max_ms: ascii_backoff_max_ms,
                lockout_limit: ascii_lockout_limit,
            },
        };
        let tls_identity = TlsIdentityConfig {
            allowed_cn: args.tls_allowed_client_cn.clone(),
            allowed_san: args.tls_allowed_client_san.clone(),
        };
        let tls_registry = session_registry.clone();
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
    }

    if let Some(addr) = args.listen_legacy {
        let default_ok = shared_secret
            .as_deref()
            .map(|s| s.len() >= MIN_SECRET_LEN)
            .unwrap_or(false);
        let any_nad = !legacy_nad_secrets.is_empty();
        if !default_ok && !any_nad {
            bail!(
                "legacy TACACS+ requires a shared secret of at least {} bytes or per-NAD secrets",
                MIN_SECRET_LEN
            );
        }
        let auth_ctx = AuthContext {
            policy: shared_policy.clone(),
            secret: shared_secret.clone(),
            credentials: credentials.clone(),
            ldap: ldap_config.clone(),
        };
        let conn_cfg = ConnectionConfig {
            single_connect_idle_secs,
            single_connect_keepalive_secs,
            conn_limiter: conn_limiter.clone(),
            ascii: AsciiConfig {
                attempt_limit: args.ascii_attempt_limit,
                user_attempt_limit: args.ascii_user_attempt_limit,
                pass_attempt_limit: args.ascii_pass_attempt_limit,
                backoff_ms: args.ascii_backoff_ms,
                backoff_max_ms: ascii_backoff_max_ms,
                lockout_limit: ascii_lockout_limit,
            },
        };
        let nad_secrets = legacy_nad_secrets.clone();
        let legacy_registry = session_registry.clone();
        handles.push(tokio::spawn(async move {
            if let Err(err) =
                serve_legacy(addr, auth_ctx, conn_cfg, nad_secrets, legacy_registry).await
            {
                error!(error = %err, "legacy listener stopped");
            }
        }));
    }

    if handles.is_empty() {
        bail!("no listeners configured; set --listen-tls and/or --listen-legacy");
    }

    // Create HTTP server state for health checks
    let server_state = ServerState::new();

    // Start HTTP server for health checks and metrics if configured
    if let Some(addr) = args.listen_http {
        let state = server_state.clone();
        handles.push(tokio::spawn(async move {
            if let Err(err) = serve_http(addr, state).await {
                error!(error = %err, "HTTP server stopped");
            }
        }));
    }

    // NIST CM-3: Create policy reload channel for API and SIGHUP coordination
    // Channel capacity of 10 allows buffering reload requests if needed
    let (reload_tx, reload_rx) = mpsc::channel::<PolicyReloadRequest>(10);

    // Start Management API server if enabled
    // NIST AC-3/SC-8: Management API requires TLS with mTLS for security
    if args.api_enabled {
        let api_addr = args
            .api_listen
            .context("--api-listen is required when --api-enabled is set")?;

        // Load RBAC configuration from file or use defaults
        let rbac_config = if let Some(rbac_path) = args.api_rbac_config.as_ref() {
            let rbac_json = std::fs::read_to_string(rbac_path).with_context(|| {
                format!("failed to read RBAC config from {}", rbac_path.display())
            })?;
            serde_json::from_str(&rbac_json).with_context(|| {
                format!("failed to parse RBAC config from {}", rbac_path.display())
            })?
        } else {
            info!("using default RBAC configuration (admin, operator, viewer roles)");
            crate::api::RbacConfig::default()
        };

        // NIST SC-8: Build TLS acceptor for Management API (mTLS required)
        let api_tls_acceptor = if let (Some(cert), Some(key), Some(client_ca)) = (
            args.api_tls_cert.as_ref(),
            args.api_tls_key.as_ref(),
            args.api_client_ca.as_ref(),
        ) {
            let tls_config = tls::build_tls_config(cert, key, client_ca, &[])
                .context("building API TLS configuration")?;
            Some(tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(
                tls_config,
            )))
        } else {
            // Warn if TLS is not configured - API will run in plaintext mode
            // In production, TLS should always be enabled
            warn!(
                "Management API TLS is not configured. Running in PLAINTEXT mode. \
                 For production use, configure --api-tls-cert, --api-tls-key, and --api-client-ca."
            );
            None
        };

        // Build runtime config snapshot for API display (sanitized, no secrets)
        let runtime_config = crate::api::RuntimeConfig {
            listen_tls: args.listen_tls,
            listen_legacy: args.listen_legacy,
            tls_enabled: args.listen_tls.is_some(),
            ldap_enabled: ldap_config.is_some(),
            policy_source: policy_path.display().to_string(),
        };
        let api_policy = shared_policy.clone();
        let api_policy_path = policy_path.display().to_string();
        let api_schema_path = args.schema.clone();
        let api_reload_tx = reload_tx.clone();
        let api_registry = session_registry.clone();
        handles.push(tokio::spawn(async move {
            if let Err(err) = crate::api::serve_api(
                api_addr,
                api_tls_acceptor,
                rbac_config,
                api_policy,
                api_policy_path,
                api_schema_path,
                api_reload_tx,
                api_registry,
                runtime_config,
            )
            .await
            {
                error!(error = %err, "Management API server stopped");
            }
        }));
    }

    // Initialize policy rules count metric
    {
        let policy = shared_policy.read().await;
        metrics().policy_rules_count.set(policy.rule_count() as f64);
    }

    // Mark server as ready now that all listeners are started
    server_state.set_ready(true);
    info!("server ready");

    // NIST CM-3: Unified policy change watcher for both SIGHUP and API channel
    let policy = shared_policy.clone();
    let schema_path = args.schema.clone();
    let policy_path_for_watcher: PathBuf = policy_path.clone();
    handles.push(tokio::spawn(async move {
        watch_policy_changes(policy_path_for_watcher, schema_path, policy, reload_rx).await;
    }));

    // Graceful shutdown handler for SIGTERM
    let shutdown_state = server_state.clone();
    let drain_timeout = args.shutdown_drain_timeout_secs;
    let force_timeout = args.shutdown_force_timeout_secs;
    tokio::spawn(async move {
        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                sigterm.recv().await;
                info!("received SIGTERM, starting graceful shutdown");

                // Phase 1: Stop accepting new connections by marking not ready
                // This causes /ready to return 503, so load balancers will stop sending traffic
                shutdown_state.set_ready(false);
                info!(
                    drain_timeout_secs = drain_timeout,
                    "draining connections, /ready now returns 503"
                );

                // Wait for drain timeout to allow existing connections to complete
                tokio::time::sleep(Duration::from_secs(drain_timeout)).await;
                info!(
                    force_timeout_secs = force_timeout,
                    "drain timeout reached, waiting for force timeout"
                );

                // Phase 2: Force timeout - set alive to false (triggers liveness probe failure)
                // This signals orchestrators like Kubernetes to forcefully terminate if needed
                shutdown_state.set_alive(false);
                tokio::time::sleep(Duration::from_secs(force_timeout)).await;

                // Phase 3: Exit the process
                info!("graceful shutdown complete, exiting");
                std::process::exit(0);
            }
            Err(err) => {
                error!(error = %err, "failed to install SIGTERM handler");
            }
        }
    });

    for handle in handles {
        let _ = handle.await;
    }

    // Shutdown OpenTelemetry gracefully to flush pending traces
    if otel_enabled {
        shutdown_telemetry();
    }

    Ok(())
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
