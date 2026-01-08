// SPDX-License-Identifier: Apache-2.0
//! HTTP handlers for the Management API endpoints.
//!
//! # NIST SP 800-53 Security Controls
//!
//! This module implements the following NIST security controls:
//!
//! - **AC-3 (Access Enforcement)**: All endpoints enforce RBAC permissions
//!   via middleware before allowing access to resources.
//!
//! - **AU-2/AU-12 (Audit Events/Generation)**: All API requests are logged
//!   with user identity, endpoint, and authorization result.

use super::models::*;
use super::rbac::{RbacConfig, require_permission};
use crate::metrics::metrics;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    middleware,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use std::sync::Arc;
use std::time::SystemTime;
use tracing::info;

/// Shared state for API handlers.
#[derive(Clone)]
pub struct ApiState {
    pub rbac: RbacConfig,
    pub start_time: SystemTime,
}

/// Build the API router with all endpoints.
///
/// # NIST Controls
/// - **AC-3 (Access Enforcement)**: Each endpoint is protected by RBAC middleware
///   that enforces the required permission before allowing access.
///
/// # Security Note
/// All endpoints require authentication. User identity is extracted from:
/// - TLS client certificate CN (when API TLS is enabled)
/// - `X-User-CN` header (for testing/development only)
///
/// Anonymous users are denied access to all endpoints.
pub fn build_api_router(rbac: RbacConfig) -> Router {
    let state = Arc::new(ApiState {
        rbac: rbac.clone(),
        start_time: SystemTime::now(),
    });

    // NIST AC-3: Build individual routers with appropriate RBAC middleware
    // Each endpoint gets its own permission requirement

    // GET /api/v1/status - requires read:status
    let status_router = Router::new()
        .route("/api/v1/status", get(get_status))
        .route_layer(middleware::from_fn(require_permission(&rbac, "read:status")));

    // GET /api/v1/sessions - requires read:sessions
    let sessions_read_router = Router::new()
        .route("/api/v1/sessions", get(get_sessions))
        .route_layer(middleware::from_fn(require_permission(&rbac, "read:sessions")));

    // DELETE /api/v1/sessions/:id - requires write:sessions
    let sessions_write_router = Router::new()
        .route("/api/v1/sessions/{id}", delete(delete_session))
        .route_layer(middleware::from_fn(require_permission(&rbac, "write:sessions")));

    // GET /api/v1/policy - requires read:policy
    let policy_read_router = Router::new()
        .route("/api/v1/policy", get(get_policy))
        .route_layer(middleware::from_fn(require_permission(&rbac, "read:policy")));

    // POST /api/v1/policy/reload - requires write:policy
    let policy_write_router = Router::new()
        .route("/api/v1/policy/reload", post(reload_policy))
        .route_layer(middleware::from_fn(require_permission(&rbac, "write:policy")));

    // GET /api/v1/config - requires read:config
    let config_router = Router::new()
        .route("/api/v1/config", get(get_config))
        .route_layer(middleware::from_fn(require_permission(&rbac, "read:config")));

    // GET /api/v1/metrics - requires read:metrics
    let metrics_router = Router::new()
        .route("/api/v1/metrics", get(get_metrics))
        .route_layer(middleware::from_fn(require_permission(&rbac, "read:metrics")));

    // Merge all routers and attach shared state
    Router::new()
        .merge(status_router)
        .merge(sessions_read_router)
        .merge(sessions_write_router)
        .merge(policy_read_router)
        .merge(policy_write_router)
        .merge(config_router)
        .merge(metrics_router)
        .with_state(state)
}

/// GET /api/v1/status - Server health and statistics.
///
/// Requires permission: `read:status`
async fn get_status(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let uptime = state.start_time.elapsed().unwrap_or_default().as_secs();

    // Collect metrics from Prometheus registry
    // Note: For now, we return placeholder values
    // TODO: Implement proper metric aggregation from CounterVec
    let metrics = metrics();
    let active_conns = metrics.connections_active.get() as u64;

    let response = StatusResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: uptime,
        stats: ServerStats {
            total_connections: 0, // TODO: aggregate from connections_total CounterVec
            active_connections: active_conns,
            total_authn_requests: 0, // TODO: aggregate from authn_requests_total CounterVec
            total_authz_requests: 0, // TODO: aggregate from authz_requests_total CounterVec
            total_acct_requests: 0,  // TODO: aggregate from acct_requests_total CounterVec
            authn_success_rate: 0.0, // TODO: calculate from CounterVec labels
            authz_success_rate: 0.0, // TODO: calculate from CounterVec labels
        },
    };

    Json(response)
}

/// GET /api/v1/sessions - List active sessions.
///
/// Requires permission: `read:sessions`
async fn get_sessions() -> impl IntoResponse {
    // TODO: Implement actual session tracking
    // For now, return empty list
    let response = SessionsResponse {
        sessions: vec![],
        total: 0,
    };

    Json(response)
}

/// DELETE /api/v1/sessions/:id - Terminate a session.
///
/// Requires permission: `write:sessions`
async fn delete_session(Path(session_id): Path<u32>) -> impl IntoResponse {
    info!(session_id = session_id, "API request to terminate session");

    // TODO: Implement actual session termination
    // For now, return success
    let response = SuccessResponse {
        success: true,
        message: format!("Session {} termination requested", session_id),
    };

    Json(response)
}

/// GET /api/v1/policy - Get current policy information.
///
/// Requires permission: `read:policy`
async fn get_policy() -> impl IntoResponse {
    // TODO: Get actual policy information from PolicyEngine
    let response = PolicyResponse {
        rule_count: 0,
        last_loaded: "unknown".to_string(),
        source: "unknown".to_string(),
    };

    Json(response)
}

/// POST /api/v1/policy/reload - Trigger policy hot reload.
///
/// Requires permission: `write:policy`
///
/// Note: This endpoint logs the reload request. The actual reload is triggered
/// by sending SIGHUP to the server process externally (e.g., `kill -HUP <pid>`).
/// In a future update, this will trigger the reload directly via an internal channel.
async fn reload_policy() -> impl IntoResponse {
    info!("API request to reload policy - operator should send SIGHUP to process");

    // TODO: Implement internal channel-based policy reload
    // For now, operators must send SIGHUP externally after calling this endpoint
    let response = SuccessResponse {
        success: true,
        message: "Policy reload request logged. Send SIGHUP to process to trigger reload.".to_string(),
    };

    Json(response)
}

/// GET /api/v1/config - Get running configuration (sanitized).
///
/// Requires permission: `read:config`
async fn get_config() -> impl IntoResponse {
    // TODO: Get actual configuration
    let response = ConfigResponse {
        listen_addrs: vec![],
        tls_enabled: false,
        ldap_enabled: false,
        policy_source: "unknown".to_string(),
        metrics_enabled: true,
        api_enabled: true,
    };

    Json(response)
}

/// GET /api/v1/metrics - Get Prometheus metrics.
///
/// Requires permission: `read:metrics`
async fn get_metrics() -> impl IntoResponse {
    let body = metrics().encode();
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        .body(body)
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    /// Create an RBAC config with an admin user for testing.
    fn make_test_rbac() -> RbacConfig {
        let mut rbac = RbacConfig::default();
        rbac.users
            .insert("CN=admin.test".to_string(), "admin".to_string());
        rbac.users
            .insert("CN=viewer.test".to_string(), "viewer".to_string());
        rbac
    }

    // ==================== Authentication Tests ====================

    #[tokio::test]
    async fn test_unauthenticated_request_denied() {
        let rbac = make_test_rbac();
        let app = build_api_router(rbac);

        // Request without X-User-CN header should be denied
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_unknown_user_denied() {
        let rbac = make_test_rbac();
        let app = build_api_router(rbac);

        // Request with unknown user should be denied
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/status")
                    .header("X-User-CN", "CN=unknown.user")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_authenticated_admin_allowed() {
        let rbac = make_test_rbac();
        let app = build_api_router(rbac);

        // Admin user should have access
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/status")
                    .header("X-User-CN", "CN=admin.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_viewer_cannot_write() {
        let rbac = make_test_rbac();
        let app = build_api_router(rbac);

        // Viewer should not have write access
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/policy/reload")
                    .header("X-User-CN", "CN=viewer.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_viewer_can_read_allowed_endpoints() {
        let rbac = make_test_rbac();
        let app = build_api_router(rbac);

        // Viewer should have access to read:status
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/status")
                    .header("X-User-CN", "CN=viewer.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_viewer_cannot_read_policy() {
        let rbac = make_test_rbac();
        let app = build_api_router(rbac);

        // Viewer role only has read:status and read:metrics, not read:policy
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/policy")
                    .header("X-User-CN", "CN=viewer.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    // ==================== Endpoint Functionality Tests ====================

    #[tokio::test]
    async fn test_get_status_with_auth() {
        let rbac = make_test_rbac();
        let app = build_api_router(rbac);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/status")
                    .header("X-User-CN", "CN=admin.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_sessions_with_auth() {
        let rbac = make_test_rbac();
        let app = build_api_router(rbac);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/sessions")
                    .header("X-User-CN", "CN=admin.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_get_metrics_with_auth() {
        let rbac = make_test_rbac();
        let app = build_api_router(rbac);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/metrics")
                    .header("X-User-CN", "CN=admin.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(content_type.contains("text/plain"));
    }

    #[tokio::test]
    async fn test_get_config_with_auth() {
        let rbac = make_test_rbac();
        let app = build_api_router(rbac);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/config")
                    .header("X-User-CN", "CN=admin.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_reload_policy_with_auth() {
        let rbac = make_test_rbac();
        let app = build_api_router(rbac);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/policy/reload")
                    .header("X-User-CN", "CN=admin.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
