// SPDX-License-Identifier: Apache-2.0
mod api;
mod bundle;
mod db;
mod schema;
mod tls;
mod tls_allowlist;

use crate::api::router;
use crate::db::PgStore;
use crate::schema::SchemaSet;

use anyhow::Context;
use std::{net::SocketAddr, sync::Arc};
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<PgStore>,
    pub schemas: Arc<SchemaSet>,
    pub expected_repo_allowlist: Arc<Vec<String>>, // optional
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install the aws-lc-rs rustls CryptoProvider before any TLS use (rustls
    // 0.23 cannot auto-select when both aws-lc-rs and ring are in the tree).
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_timer(tracing_subscriber::fmt::time::UtcTime::rfc_3339())
        .init();

    let listen = std::env::var("LISTEN").context("LISTEN required (host:port)")?;
    let addr: SocketAddr = listen.parse().context("LISTEN must be host:port")?;

    let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL required")?;

    let config_schema_path = std::env::var("CONFIG_SCHEMA_PATH")
        .unwrap_or_else(|_| "schemas/config.schema.json".to_string());
    let policy_schema_path = std::env::var("POLICY_SCHEMA_PATH")
        .unwrap_or_else(|_| "schemas/policy.schema.json".to_string());

    let allowlist = std::env::var("REPO_ALLOWLIST").unwrap_or_default();
    let expected_repo_allowlist: Vec<String> = allowlist
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string())
        .collect();

    let store = PgStore::connect(&database_url).await?;
    store.migrate().await?;

    let schemas = SchemaSet::load_from_files(&config_schema_path, &policy_schema_path).await?;

    let state = AppState {
        store: Arc::new(store),
        schemas: Arc::new(schemas),
        expected_repo_allowlist: Arc::new(expected_repo_allowlist),
    };

    let app = router(state).layer(TraceLayer::new_for_http());

    let rustls_config = tls::make_rustls_config_from_env().await?;

    tracing::info!("listening on https://{addr} (mTLS required)");
    axum_server::bind_rustls(addr, rustls_config)
        .serve(app.into_make_service())
        .await
        .context("axum-server serve failed")?;

    Ok(())
}
