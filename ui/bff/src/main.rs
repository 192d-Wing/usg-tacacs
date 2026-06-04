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

    let state = AppState {
        http: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .build()?,
        loki_url: env_or("LOKI_URL", "http://loki.monitoring.svc:3100"),
        prom_url: env_or("PROM_URL", "http://prometheus.monitoring.svc:9090"),
        namespace: env_or("TACACS_NAMESPACE", "tacacs"),
        audit_target: env_or("AUDIT_TARGET", "tacacs_audit"),
    };
    let listen: SocketAddr = env_or("BFF_LISTEN", "0.0.0.0:8088").parse()?;
    let static_dir = env_or("UI_STATIC_DIR", "/app/web");

    // SPA: serve files, fall back to index.html for client-side routes.
    let index = format!("{static_dir}/index.html");
    let spa = ServeDir::new(&static_dir).not_found_service(ServeFile::new(index));

    let api = Router::new()
        .route("/me", get(handlers::me))
        .route("/audit", get(handlers::audit))
        .route("/flows", get(handlers::flows))
        .route("/metrics", get(handlers::metrics))
        .route("/resources", get(handlers::resources))
        .route("/alerts", get(handlers::alerts))
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
