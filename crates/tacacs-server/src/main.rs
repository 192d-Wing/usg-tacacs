use crate::ascii::AsciiConfig;
use crate::auth::LdapConfig;
use crate::config::{Args, LogFormat, StaticCreds, credentials_map};
use crate::http::{ServerState, serve_http};
use crate::metrics::metrics;
use crate::server::{
    AuthContext, ConnLimiter, ConnectionConfig, TlsIdentityConfig, serve_legacy, serve_tls,
    tls_acceptor, validate_policy, watch_sighup,
};
use crate::telemetry::{TelemetryConfig, init_telemetry, shutdown_telemetry};
use anyhow::{Context, Result, bail};
use clap::Parser;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use tracing_subscriber::fmt::time::UtcTime;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use usg_tacacs_policy::PolicyEngine;
use usg_tacacs_proto::MIN_SECRET_LEN;

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
        let cert = args
            .tls_cert
            .as_ref()
            .context("--tls-cert is required when --listen-tls is set")?;
        let key = args
            .tls_key
            .as_ref()
            .context("--tls-key is required when --listen-tls is set")?;
        let ca = args
            .client_ca
            .as_ref()
            .context("--client-ca is required when --listen-tls is set")?;
        let acceptor = tls_acceptor(cert, key, ca, &args.tls_trust_root)?;
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
        handles.push(tokio::spawn(async move {
            if let Err(err) = serve_tls(addr, acceptor, auth_ctx, conn_cfg, tls_identity).await {
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
        handles.push(tokio::spawn(async move {
            if let Err(err) = serve_legacy(addr, auth_ctx, conn_cfg, nad_secrets).await {
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

        handles.push(tokio::spawn(async move {
            if let Err(err) = crate::api::serve_api(api_addr, api_tls_acceptor, rbac_config).await {
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

    let policy = shared_policy.clone();
    let schema_path = args.schema.clone();
    let policy_path = policy_path.clone();
    handles.push(tokio::spawn(async move {
        watch_sighup(policy_path, schema_path, policy).await;
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
mod telemetry;
mod tls;
