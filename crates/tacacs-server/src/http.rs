// SPDX-License-Identifier: Apache-2.0
//! HTTP server for health checks and Prometheus metrics.

use crate::metrics::metrics;
use crate::session_registry::SessionRegistry;
use axum::{
    Router,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::TcpListener;
use tracing::{error, info};

/// Server readiness state shared between HTTP server and main application.
#[derive(Clone)]
pub struct ServerState {
    /// Whether the server is ready to accept TACACS+ connections.
    ready: Arc<AtomicBool>,
    /// Whether the server is alive (not deadlocked).
    alive: Arc<AtomicBool>,
    /// Active session registry for the `/sessions` snapshot endpoint.
    pub registry: Option<Arc<SessionRegistry>>,
}

impl ServerState {
    pub fn new() -> Self {
        Self {
            ready: Arc::new(AtomicBool::new(false)),
            alive: Arc::new(AtomicBool::new(true)),
            registry: None,
        }
    }

    /// Attach the session registry so `/sessions` can serve live snapshots.
    pub fn with_registry(mut self, registry: Arc<SessionRegistry>) -> Self {
        self.registry = Some(registry);
        self
    }

    /// Set the ready state.
    pub fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::SeqCst);
    }

    /// Check if server is ready.
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }

    /// Set the alive state (used during graceful shutdown).
    #[allow(dead_code)]
    pub fn set_alive(&self, alive: bool) {
        self.alive.store(alive, Ordering::SeqCst);
    }

    /// Check if server is alive.
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }
}

impl Default for ServerState {
    fn default() -> Self {
        Self::new()
    }
}

/// Health check response.
#[derive(serde::Serialize)]
struct HealthResponse {
    status: &'static str,
}

/// Liveness probe - returns 200 if the process is alive.
async fn health_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        axum::Json(HealthResponse { status: "healthy" }),
    )
}

/// Readiness probe - returns 200 if ready to accept connections, 503 otherwise.
/// During graceful shutdown (draining), returns 503 with status "draining".
async fn ready_handler(axum::extract::State(state): axum::extract::State<ServerState>) -> Response {
    if state.is_ready() {
        (
            StatusCode::OK,
            axum::Json(HealthResponse { status: "ready" }),
        )
            .into_response()
    } else if state.is_alive() {
        // Server is alive but not ready - draining connections during graceful shutdown
        (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(HealthResponse { status: "draining" }),
        )
            .into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(HealthResponse {
                status: "not_ready",
            }),
        )
            .into_response()
    }
}

/// Liveness probe - returns 200 if not deadlocked, 503 otherwise.
async fn live_handler(axum::extract::State(state): axum::extract::State<ServerState>) -> Response {
    if state.is_alive() {
        (
            StatusCode::OK,
            axum::Json(HealthResponse { status: "alive" }),
        )
            .into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(HealthResponse { status: "dead" }),
        )
            .into_response()
    }
}

/// Prometheus metrics endpoint.
async fn metrics_handler() -> impl IntoResponse {
    let body = metrics().encode();
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

/// GET /sessions — live snapshot of active TACACS+ sessions.
///
/// Returns all sessions currently tracked by the session registry.
/// This endpoint is on the unauthenticated health port (internal-only);
/// the BFF proxies it as `/api/sessions` for the operator UI.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-10 | Concurrent Session Control | Exposes live session count for monitoring |
/// | SI-4 | System Monitoring | Supports real-time operator visibility |
async fn sessions_handler(axum::extract::State(state): axum::extract::State<ServerState>) -> Response {
    let Some(ref registry) = state.registry else {
        return (StatusCode::SERVICE_UNAVAILABLE, "session registry unavailable").into_response();
    };
    let sessions = registry.list_sessions().await;
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let json: Vec<serde_json::Value> = sessions.iter().map(|s| {
        let connected = s.connected_at
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let last_active = s.last_activity
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        serde_json::json!({
            "id":           s.connection_id,
            "peer":         s.peer_addr.to_string(),
            "user":         s.username,
            "session_id":   s.session_id,
            "connected_at": connected,
            "last_active":  last_active,
            "idle_secs":    now_secs.saturating_sub(last_active),
            "requests":     s.request_count,
        })
    }).collect();
    (StatusCode::OK, axum::Json(serde_json::json!({
        "count": json.len(),
        "sessions": json,
    }))).into_response()
}

/// Build the HTTP router with all endpoints.
fn build_router(state: ServerState) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/ready", get(ready_handler))
        .route("/live", get(live_handler))
        .route("/metrics", get(metrics_handler))
        .route("/sessions", get(sessions_handler))
        .with_state(state)
}

/// Start the HTTP server for health checks and metrics.
pub async fn serve_http(addr: SocketAddr, state: ServerState) -> anyhow::Result<()> {
    let app = build_router(state);

    let listener = TcpListener::bind(addr).await?;
    info!(addr = %addr, "HTTP server listening for health checks and metrics");

    if let Err(e) = axum::serve(listener, app).await {
        error!(error = %e, "HTTP server error");
        return Err(e.into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_health_endpoint() {
        let state = ServerState::new();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_ready_endpoint_not_ready() {
        let state = ServerState::new();
        // Default is not ready
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_ready_endpoint_ready() {
        let state = ServerState::new();
        state.set_ready(true);
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_live_endpoint() {
        let state = ServerState::new();
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/live").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_metrics_endpoint() {
        let state = ServerState::new();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_server_state() {
        let state = ServerState::new();

        assert!(!state.is_ready());
        assert!(state.is_alive());

        state.set_ready(true);
        assert!(state.is_ready());

        state.set_alive(false);
        assert!(!state.is_alive());
    }

    // ==================== ServerState Default Tests ====================

    #[test]
    fn test_server_state_default() {
        let state = ServerState::default();
        // Default should be same as new()
        assert!(!state.is_ready());
        assert!(state.is_alive());
    }

    // ==================== Live Handler Dead State Tests ====================

    #[tokio::test]
    async fn test_live_endpoint_not_alive() {
        let state = ServerState::new();
        state.set_alive(false);
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/live").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    // ==================== Clone Tests ====================

    #[test]
    fn test_server_state_clone_shares_state() {
        let state1 = ServerState::new();
        let state2 = state1.clone();

        // Changes in one clone should be visible in the other (they share the same Arc)
        state1.set_ready(true);
        assert!(state2.is_ready());

        state2.set_alive(false);
        assert!(!state1.is_alive());
    }

    // ==================== Response Body Tests ====================

    #[tokio::test]
    async fn test_health_response_body() {
        let state = ServerState::new();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

        assert!(body_str.contains("healthy"));
    }

    #[tokio::test]
    async fn test_ready_response_body_ready() {
        let state = ServerState::new();
        state.set_ready(true);
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

        assert!(body_str.contains("ready"));
    }

    #[tokio::test]
    async fn test_ready_response_body_not_ready() {
        let state = ServerState::new();
        // Set alive to false to get "not_ready" instead of "draining"
        state.set_alive(false);
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

        assert!(body_str.contains("not_ready"));
    }

    #[tokio::test]
    async fn test_ready_response_body_draining() {
        let state = ServerState::new();
        // Simulate graceful shutdown: not ready but still alive
        state.set_ready(false);
        state.set_alive(true);
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

        assert!(body_str.contains("draining"));
    }

    #[tokio::test]
    async fn test_live_response_body_alive() {
        let state = ServerState::new();
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/live").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

        assert!(body_str.contains("alive"));
    }

    #[tokio::test]
    async fn test_live_response_body_dead() {
        let state = ServerState::new();
        state.set_alive(false);
        let app = build_router(state);

        let response = app
            .oneshot(Request::builder().uri("/live").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

        assert!(body_str.contains("dead"));
    }

    #[tokio::test]
    async fn test_metrics_content_type() {
        let state = ServerState::new();
        let app = build_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let content_type = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(content_type.contains("text/plain"));
    }
}
