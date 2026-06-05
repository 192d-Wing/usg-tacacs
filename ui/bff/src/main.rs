// SPDX-License-Identifier: Apache-2.0
//! Backend-for-frontend for the usg-tacacs operator UI.
//!
//! Aggregates Loki (audit logs + per-NAD flows), Prometheus (server metrics +
//! container CPU/memory), and computed alerts into a small JSON API, and serves
//! the Cloudscape SPA. Authentication is enforced upstream by oauth2-proxy
//! (Keycloak OIDC); the identity is read from forwarded headers.

mod clients;
mod handlers;

use axum::{routing::get, Router};
use std::net::SocketAddr;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;

#[derive(Clone)]
pub struct AppState {
    pub http: reqwest::Client,
    pub loki_url: String,
    pub prom_url: String,
    pub namespace: String,
    pub audit_target: String,
    /// Active authentication source: "icam", "ldap", or "local".
    pub auth_source: Option<String>,
    /// ICAM OIDC token endpoint URL (when auth_source = "icam").
    pub icam_endpoint: Option<String>,
    /// Internal (HTTP) base URL for the ICAM provider — used for reachability
    /// checks from the BFF, which has no TLS client. Optional; omit to skip probing.
    pub icam_internal_base: Option<String>,
    /// ICAM OIDC client ID (when auth_source = "icam").
    pub icam_client_id: Option<String>,
    /// JWT claim used for group membership (default: "groups").
    pub icam_groups_claim: Option<String>,
    /// Whether the RFC 8628 device authorization flow is enabled on the server.
    pub icam_device_flow: bool,
    /// LDAP server URL (when auth_source = "ldap").
    pub ldap_url: Option<String>,
    /// Internal HTTP base URL of the TACACS+ server health/metrics port.
    /// e.g. `http://tacacs-metrics.tacacs.svc:8080`
    /// Used to proxy the `/sessions` snapshot for the live session dashboard.
    pub tacacs_http_url: Option<String>,
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tacacs_ui_bff=debug".into()),
        )
        .init();

    let opt_env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let state = AppState {
        http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .build()?,
        loki_url: env_or("LOKI_URL", "http://loki.monitoring.svc:3100"),
        prom_url: env_or("PROM_URL", "http://prometheus.monitoring.svc:9090"),
        namespace: env_or("TACACS_NAMESPACE", "tacacs"),
        audit_target: env_or("AUDIT_TARGET", "tacacs_audit"),
        auth_source: opt_env("AUTH_SOURCE"),
        icam_endpoint: opt_env("ICAM_ENDPOINT"),
        icam_internal_base: opt_env("ICAM_INTERNAL_BASE"),
        icam_client_id: opt_env("ICAM_CLIENT_ID"),
        icam_groups_claim: opt_env("ICAM_GROUPS_CLAIM"),
        icam_device_flow: std::env::var("ICAM_DEVICE_FLOW")
            .map(|v| matches!(v.to_lowercase().as_str(), "true" | "1" | "yes"))
            .unwrap_or(false),
        ldap_url: opt_env("LDAP_URL"),
        tacacs_http_url: opt_env("TACACS_HTTP_URL"),
    };
    let listen: SocketAddr = env_or("BFF_LISTEN", "0.0.0.0:8088").parse()?;
    let static_dir = env_or("UI_STATIC_DIR", "/app/web");

    // SPA: serve files, fall back to index.html for client-side routes.
    let index = format!("{static_dir}/index.html");
    let spa = ServeDir::new(&static_dir).not_found_service(ServeFile::new(index));

    let api = Router::new()
        .route("/me", get(handlers::me))
        .route("/config", get(handlers::config))
        .route("/audit", get(handlers::audit))
        .route("/flows", get(handlers::flows))
        .route("/metrics", get(handlers::metrics))
        .route("/resources", get(handlers::resources))
        .route("/alerts", get(handlers::alerts))
        .route("/policy/dry-run", axum::routing::post(handlers::policy_dry_run))
        .route("/sessions", get(handlers::sessions))
        .with_state(state.clone());

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .nest("/api", api)
        .fallback_service(spa)
        .layer(TraceLayer::new_for_http());

    tracing::info!(%listen, loki = %state.loki_url, prom = %state.prom_url, "tacacs-ui-bff listening");
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}

async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
}
