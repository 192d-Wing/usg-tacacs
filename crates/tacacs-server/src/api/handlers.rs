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
use crate::server::PolicyReloadRequest;
use crate::session_registry::SessionRegistry;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    middleware,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::{RwLock, mpsc};
use tracing::{info, warn};
use usg_tacacs_policy::PolicyEngine;

/// Runtime configuration snapshot for API display.
///
/// Contains sanitized configuration data (no secrets) for the config endpoint.
#[derive(Clone)]
pub struct RuntimeConfig {
    /// TLS listener address (if configured)
    pub listen_tls: Option<SocketAddr>,
    /// Legacy listener address (if configured)
    pub listen_legacy: Option<SocketAddr>,
    /// Whether TLS is enabled
    pub tls_enabled: bool,
    /// Whether LDAP authentication is enabled
    pub ldap_enabled: bool,
    /// Policy file path
    pub policy_source: String,
}

/// Shared state for API handlers.
#[derive(Clone)]
pub struct ApiState {
    /// RBAC configuration for permission checks
    #[allow(dead_code)]
    pub rbac: RbacConfig,
    /// Server start time for uptime calculation
    pub start_time: SystemTime,
    /// Shared policy engine for policy info
    pub policy: Arc<RwLock<PolicyEngine>>,
    /// Policy file path for last-loaded info
    pub policy_path: String,
    /// Schema path for policy validation (if configured)
    pub schema_path: Option<PathBuf>,
    /// Channel sender for policy reload requests
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | CM-3 | Configuration Change Control | Enables API-triggered policy updates |
    pub reload_tx: mpsc::Sender<PolicyReloadRequest>,
    /// Session registry for tracking active connections
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | AC-10 | Concurrent Session Control | Session visibility |
    /// | AC-12 | Session Termination | Session termination support |
    pub registry: Arc<SessionRegistry>,
    /// Runtime configuration snapshot
    pub config: RuntimeConfig,
}

/// Build the API router with all endpoints.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-3 | Access Enforcement | Each endpoint protected by RBAC middleware |
/// | AC-10/AC-12 | Session Control | Session listing and termination via API |
/// | CM-3 | Configuration Change Control | Policy reload channel for controlled updates |
///
/// # Security Note
/// All endpoints require authentication. User identity is extracted from:
/// - TLS client certificate CN (when API TLS is enabled)
/// - `X-User-CN` header (for testing/development only)
///
/// Anonymous users are denied access to all endpoints.
pub fn build_api_router(
    rbac: RbacConfig,
    policy: Arc<RwLock<PolicyEngine>>,
    policy_path: String,
    schema_path: Option<PathBuf>,
    reload_tx: mpsc::Sender<PolicyReloadRequest>,
    registry: Arc<SessionRegistry>,
    config: RuntimeConfig,
) -> Router {
    let state = Arc::new(ApiState {
        rbac: rbac.clone(),
        start_time: SystemTime::now(),
        policy,
        policy_path,
        schema_path,
        reload_tx,
        registry,
        config,
    });

    // NIST AC-3: Build individual routers with appropriate RBAC middleware
    // Each endpoint gets its own permission requirement

    // GET /api/v1/status - requires read:status
    let status_router = Router::new()
        .route("/api/v1/status", get(get_status))
        .route_layer(middleware::from_fn(require_permission(
            &rbac,
            "read:status",
        )));

    // GET /api/v1/sessions - requires read:sessions
    let sessions_read_router = Router::new()
        .route("/api/v1/sessions", get(get_sessions))
        .route_layer(middleware::from_fn(require_permission(
            &rbac,
            "read:sessions",
        )));

    // DELETE /api/v1/sessions/:id - requires write:sessions
    let sessions_write_router = Router::new()
        .route("/api/v1/sessions/{id}", delete(delete_session))
        .route_layer(middleware::from_fn(require_permission(
            &rbac,
            "write:sessions",
        )));

    // GET /api/v1/policy - requires read:policy
    let policy_read_router = Router::new()
        .route("/api/v1/policy", get(get_policy))
        .route_layer(middleware::from_fn(require_permission(
            &rbac,
            "read:policy",
        )));

    // POST /api/v1/policy/reload - requires write:policy
    // POST /api/v1/policy - requires write:policy
    let policy_write_router = Router::new()
        .route("/api/v1/policy/reload", post(reload_policy))
        .route("/api/v1/policy", post(upload_policy))
        .route_layer(middleware::from_fn(require_permission(
            &rbac,
            "write:policy",
        )));

    // GET /api/v1/config - requires read:config
    let config_router = Router::new()
        .route("/api/v1/config", get(get_config))
        .route_layer(middleware::from_fn(require_permission(
            &rbac,
            "read:config",
        )));

    // GET /api/v1/metrics - requires read:metrics
    let metrics_router = Router::new()
        .route("/api/v1/metrics", get(get_metrics))
        .route_layer(middleware::from_fn(require_permission(
            &rbac,
            "read:metrics",
        )));

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

    // Collect aggregated metrics from Prometheus registry
    let m = metrics();
    let active_conns = m.connections_active.get() as u64;
    let total_conns = m.total_connections();
    let total_authn = m.total_authn_requests();
    let authn_success = m.authn_success_count();
    let total_authz = m.total_authz_requests();
    let authz_success = m.authz_success_count();
    let total_acct = m.total_acct_requests();

    // Calculate success rates (avoid division by zero)
    let authn_success_rate = if total_authn > 0 {
        (authn_success as f64 / total_authn as f64) * 100.0
    } else {
        0.0
    };
    let authz_success_rate = if total_authz > 0 {
        (authz_success as f64 / total_authz as f64) * 100.0
    } else {
        0.0
    };

    let response = StatusResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: uptime,
        stats: ServerStats {
            total_connections: total_conns,
            active_connections: active_conns,
            total_authn_requests: total_authn,
            total_authz_requests: total_authz,
            total_acct_requests: total_acct,
            authn_success_rate,
            authz_success_rate,
        },
    };

    Json(response)
}

/// GET /api/v1/sessions - List active sessions.
///
/// Requires permission: `read:sessions`
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-10 | Concurrent Session Control | Provides visibility into active sessions |
/// | SI-4 | System Monitoring | Enables session enumeration for monitoring |
async fn get_sessions(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let records = state.registry.list_sessions().await;
    let total = records.len();

    let sessions: Vec<SessionInfo> = records
        .iter()
        .map(|r| SessionInfo {
            id: r.connection_id as u32, // Use connection_id as the session identifier
            peer_addr: r.peer_addr.to_string(),
            username: r.username.clone(),
            start_time: r
                .connected_at
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            idle_seconds: r.idle_duration().as_secs(),
            request_count: r.request_count,
        })
        .collect();

    let response = SessionsResponse { sessions, total };

    Json(response)
}

/// DELETE /api/v1/sessions/:id - Terminate a session.
///
/// Requires permission: `write:sessions`
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-12 | Session Termination | Administrative session termination |
/// | AU-12 | Audit Generation | Logs termination request |
async fn delete_session(
    State(state): State<Arc<ApiState>>,
    Path(session_id): Path<u64>,
) -> impl IntoResponse {
    info!(session_id = session_id, "API request to terminate session");

    // NIST AC-12: Terminate session by connection ID
    let success = state.registry.terminate_session(session_id).await;

    if success {
        let response = SuccessResponse {
            success: true,
            message: format!("Session {} termination requested", session_id),
        };
        (StatusCode::OK, Json(response))
    } else {
        let response = SuccessResponse {
            success: false,
            message: format!("Session {} not found", session_id),
        };
        (StatusCode::NOT_FOUND, Json(response))
    }
}

/// GET /api/v1/policy - Get current policy information.
///
/// Requires permission: `read:policy`
async fn get_policy(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let policy = state.policy.read().await;
    let rule_count = policy.rule_count();

    // Calculate time since server start as a proxy for last policy load
    // A proper implementation would track the actual reload timestamp
    let uptime = state.start_time.elapsed().unwrap_or_default().as_secs();
    let last_loaded = format!("{}s since server start", uptime);

    let response = PolicyResponse {
        rule_count,
        last_loaded,
        source: state.policy_path.clone(),
    };

    Json(response)
}

/// POST /api/v1/policy/reload - Trigger policy hot reload.
///
/// Requires permission: `write:policy`
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-3 | Access Enforcement | Requires `write:policy` permission |
/// | AU-12 | Audit Generation | Logs reload request initiation |
/// | CM-3 | Configuration Change Control | API-triggered policy reload with audit logging |
async fn reload_policy(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    info!("API request to reload policy");

    // NIST CM-3: Send reload request through internal channel
    let request = PolicyReloadRequest::FromDisk {
        path: PathBuf::from(&state.policy_path),
        schema: state.schema_path.clone(),
    };

    match state.reload_tx.send(request).await {
        Ok(_) => {
            info!("Policy reload request queued successfully");
            let response = SuccessResponse {
                success: true,
                message: "Policy reload triggered".to_string(),
            };
            (StatusCode::OK, Json(response))
        }
        Err(e) => {
            warn!(error = %e, "Failed to queue policy reload request");
            let response = SuccessResponse {
                success: false,
                message: "Failed to queue policy reload - channel closed".to_string(),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(response))
        }
    }
}

/// POST /api/v1/policy - Upload new policy from JSON.
///
/// Requires permission: `write:policy`
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-3 | Access Enforcement | Requires `write:policy` permission |
/// | AU-12 | Audit Generation | Logs upload request and validation result |
/// | CM-3 | Configuration Change Control | API-based policy upload with validation |
async fn upload_policy(
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<PolicyUploadRequest>,
) -> impl IntoResponse {
    info!(validate = payload.validate, "API request to upload policy");

    // Parse the policy JSON to validate it's well-formed
    let policy_doc: Result<usg_tacacs_policy::PolicyDocument, _> =
        serde_json::from_str(&payload.policy);

    let policy_doc = match policy_doc {
        Ok(doc) => doc,
        Err(e) => {
            warn!(error = %e, "Invalid policy JSON in upload request");
            let response = PolicyUploadResponse {
                success: false,
                message: format!("Invalid policy JSON: {}", e),
                rule_count: None,
            };
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    };

    // If validation is requested, validate against schema
    if payload.validate {
        if let Some(schema_path) = &state.schema_path {
            match usg_tacacs_policy::validate_policy_document(&policy_doc, schema_path) {
                Ok(_) => {
                    info!("Policy validated successfully against schema");
                }
                Err(e) => {
                    warn!(error = %e, "Policy validation failed");
                    let response = PolicyUploadResponse {
                        success: false,
                        message: format!("Policy validation failed: {}", e),
                        rule_count: None,
                    };
                    return (StatusCode::BAD_REQUEST, Json(response));
                }
            }
        } else {
            warn!("Validation requested but no schema configured");
            let response = PolicyUploadResponse {
                success: false,
                message: "Validation requested but no schema configured".to_string(),
                rule_count: None,
            };
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    }

    let rule_count = policy_doc.rules.len();

    // NIST CM-3: Send upload request through internal channel
    let request = PolicyReloadRequest::FromJson {
        content: payload.policy,
        schema: state.schema_path.clone(),
    };

    match state.reload_tx.send(request).await {
        Ok(_) => {
            info!(rules = rule_count, "Policy upload queued successfully");
            let response = PolicyUploadResponse {
                success: true,
                message: "Policy upload triggered".to_string(),
                rule_count: Some(rule_count),
            };
            (StatusCode::OK, Json(response))
        }
        Err(e) => {
            warn!(error = %e, "Failed to queue policy upload");
            let response = PolicyUploadResponse {
                success: false,
                message: "Failed to queue policy upload - channel closed".to_string(),
                rule_count: None,
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(response))
        }
    }
}

/// GET /api/v1/config - Get running configuration (sanitized).
///
/// Requires permission: `read:config`
async fn get_config(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let mut listen_addrs = Vec::new();
    if let Some(addr) = state.config.listen_tls {
        listen_addrs.push(format!("tls://{}", addr));
    }
    if let Some(addr) = state.config.listen_legacy {
        listen_addrs.push(format!("tcp://{}", addr));
    }

    let response = ConfigResponse {
        listen_addrs,
        tls_enabled: state.config.tls_enabled,
        ldap_enabled: state.config.ldap_enabled,
        policy_source: state.config.policy_source.clone(),
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

    /// Create a test policy engine.
    fn make_test_policy() -> Arc<RwLock<PolicyEngine>> {
        let doc = usg_tacacs_policy::PolicyDocument {
            default_allow: false,
            rules: vec![],
            shell_start: std::collections::HashMap::new(),
            ascii_prompts: None,
            ascii_user_prompts: std::collections::HashMap::new(),
            ascii_password_prompts: std::collections::HashMap::new(),
            ascii_port_prompts: std::collections::HashMap::new(),
            ascii_remaddr_prompts: std::collections::HashMap::new(),
            allow_raw_server_msg: true,
            raw_server_msg_allow_prefixes: vec![],
            raw_server_msg_deny_prefixes: vec![],
            raw_server_msg_user_overrides: std::collections::HashMap::new(),
            ascii_messages: None,
        };
        Arc::new(RwLock::new(PolicyEngine::from_document(doc).unwrap()))
    }

    /// Create test runtime config.
    fn make_test_config() -> RuntimeConfig {
        RuntimeConfig {
            listen_tls: None,
            listen_legacy: None,
            tls_enabled: false,
            ldap_enabled: false,
            policy_source: "test-policy.json".to_string(),
        }
    }

    /// Build a test router with all required state.
    /// Returns the router, the reload receiver, and the session registry.
    fn make_test_router_with_channel(
        rbac: RbacConfig,
    ) -> (
        Router,
        mpsc::Receiver<PolicyReloadRequest>,
        Arc<SessionRegistry>,
    ) {
        let (reload_tx, reload_rx) = mpsc::channel::<PolicyReloadRequest>(1);
        let registry = Arc::new(SessionRegistry::new());
        let router = build_api_router(
            rbac,
            make_test_policy(),
            "test-policy.json".to_string(),
            None,
            reload_tx,
            registry.clone(),
            make_test_config(),
        );
        (router, reload_rx, registry)
    }

    /// Build a test router with all required state (convenience wrapper).
    fn make_test_router(rbac: RbacConfig) -> Router {
        let (router, _rx, _registry) = make_test_router_with_channel(rbac);
        router
    }

    // ==================== Authentication Tests ====================

    #[tokio::test]
    async fn test_unauthenticated_request_denied() {
        let rbac = make_test_rbac();
        let app = make_test_router(rbac);

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
        let app = make_test_router(rbac);

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
        let app = make_test_router(rbac);

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
        let app = make_test_router(rbac);

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
        let app = make_test_router(rbac);

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
        let app = make_test_router(rbac);

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
        let app = make_test_router(rbac);

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
        let app = make_test_router(rbac);

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
        let app = make_test_router(rbac);

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
        let app = make_test_router(rbac);

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
        // Use the channel variant to keep the receiver alive during the test
        let (app, mut reload_rx, _registry) = make_test_router_with_channel(rbac);

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

        // Verify the reload request was sent to the channel
        let reload_request = reload_rx.try_recv().expect("should receive reload request");
        match reload_request {
            PolicyReloadRequest::FromDisk { path, schema } => {
                assert_eq!(path.to_string_lossy(), "test-policy.json");
                assert!(schema.is_none());
            }
            PolicyReloadRequest::FromJson { .. } => {
                panic!("Expected FromDisk, got FromJson");
            }
        }
    }

    // ==================== Session Registry Integration Tests ====================

    #[tokio::test]
    async fn test_sessions_api_shows_registered_sessions() {
        use http_body_util::BodyExt;
        use std::net::{IpAddr, Ipv4Addr};

        let rbac = make_test_rbac();
        let (app, _rx, registry) = make_test_router_with_channel(rbac);

        // Register a test session
        let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 54321);
        let conn_id = registry.register_connection(peer_addr).await;

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

        // Parse response body
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let sessions_response: SessionsResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(sessions_response.total, 1);
        assert_eq!(sessions_response.sessions.len(), 1);
        assert_eq!(sessions_response.sessions[0].id, conn_id as u32);
        assert_eq!(
            sessions_response.sessions[0].peer_addr,
            "192.168.1.100:54321"
        );
        assert!(sessions_response.sessions[0].username.is_none());

        // Cleanup
        registry.unregister_connection(conn_id).await;
    }

    #[tokio::test]
    async fn test_sessions_api_shows_authenticated_user() {
        use http_body_util::BodyExt;
        use std::net::{IpAddr, Ipv4Addr};

        let rbac = make_test_rbac();
        let (app, _rx, registry) = make_test_router_with_channel(rbac);

        // Register and authenticate a session
        let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50)), 12345);
        let conn_id = registry.register_connection(peer_addr).await;
        registry
            .update_authentication(conn_id, "network_admin".to_string(), 42)
            .await;

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

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let sessions_response: SessionsResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(sessions_response.total, 1);
        assert_eq!(
            sessions_response.sessions[0].username,
            Some("network_admin".to_string())
        );

        // Cleanup
        registry.unregister_connection(conn_id).await;
    }

    #[tokio::test]
    async fn test_sessions_api_empty_when_no_sessions() {
        use http_body_util::BodyExt;

        let rbac = make_test_rbac();
        let (app, _rx, _registry) = make_test_router_with_channel(rbac);

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

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let sessions_response: SessionsResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(sessions_response.total, 0);
        assert!(sessions_response.sessions.is_empty());
    }

    #[tokio::test]
    async fn test_delete_session_terminates_existing() {
        use http_body_util::BodyExt;
        use std::net::{IpAddr, Ipv4Addr};

        let rbac = make_test_rbac();
        let (app, _rx, registry) = make_test_router_with_channel(rbac);

        // Register a session to terminate
        let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), 9999);
        let conn_id = registry.register_connection(peer_addr).await;

        // Verify session is not yet marked for termination
        assert!(!registry.is_termination_requested(conn_id).await);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(&format!("/api/v1/sessions/{}", conn_id))
                    .header("X-User-CN", "CN=admin.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let success_response: SuccessResponse = serde_json::from_slice(&body).unwrap();

        assert!(success_response.success);
        assert!(success_response.message.contains("termination requested"));

        // Verify session is now marked for termination
        assert!(registry.is_termination_requested(conn_id).await);

        // Cleanup
        registry.unregister_connection(conn_id).await;
    }

    #[tokio::test]
    async fn test_delete_session_nonexistent_returns_not_found() {
        use http_body_util::BodyExt;

        let rbac = make_test_rbac();
        let (app, _rx, _registry) = make_test_router_with_channel(rbac);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/v1/sessions/999999")
                    .header("X-User-CN", "CN=admin.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let success_response: SuccessResponse = serde_json::from_slice(&body).unwrap();

        assert!(!success_response.success);
        assert!(success_response.message.contains("not found"));
    }

    #[tokio::test]
    async fn test_sessions_api_multiple_sessions() {
        use http_body_util::BodyExt;
        use std::net::{IpAddr, Ipv4Addr};

        let rbac = make_test_rbac();
        let (app, _rx, registry) = make_test_router_with_channel(rbac);

        // Register multiple sessions
        let peer1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1)), 1001);
        let peer2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 2)), 1002);
        let peer3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 3)), 1003);

        let conn1 = registry.register_connection(peer1).await;
        let conn2 = registry.register_connection(peer2).await;
        let conn3 = registry.register_connection(peer3).await;

        // Authenticate some sessions
        registry
            .update_authentication(conn1, "user1".to_string(), 100)
            .await;
        registry
            .update_authentication(conn3, "user3".to_string(), 300)
            .await;

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

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let sessions_response: SessionsResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(sessions_response.total, 3);
        assert_eq!(sessions_response.sessions.len(), 3);

        // Verify session details
        let conn_ids: Vec<u32> = sessions_response.sessions.iter().map(|s| s.id).collect();
        assert!(conn_ids.contains(&(conn1 as u32)));
        assert!(conn_ids.contains(&(conn2 as u32)));
        assert!(conn_ids.contains(&(conn3 as u32)));

        // Cleanup
        registry.unregister_connection(conn1).await;
        registry.unregister_connection(conn2).await;
        registry.unregister_connection(conn3).await;
    }

    #[tokio::test]
    async fn test_sessions_disappear_after_unregister() {
        use http_body_util::BodyExt;
        use std::net::{IpAddr, Ipv4Addr};

        let rbac = make_test_rbac();
        let (reload_tx, _reload_rx) = mpsc::channel::<PolicyReloadRequest>(1);
        let registry = Arc::new(SessionRegistry::new());
        let router = build_api_router(
            rbac,
            make_test_policy(),
            "test-policy.json".to_string(),
            None,
            reload_tx,
            registry.clone(),
            make_test_config(),
        );

        // Register a session
        let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 5000);
        let conn_id = registry.register_connection(peer_addr).await;

        // Verify it appears
        {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/sessions")
                        .header("X-User-CN", "CN=admin.test")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            let body = response.into_body().collect().await.unwrap().to_bytes();
            let sessions_response: SessionsResponse = serde_json::from_slice(&body).unwrap();
            assert_eq!(sessions_response.total, 1);
        }

        // Unregister the session
        registry.unregister_connection(conn_id).await;

        // Verify it's gone
        {
            let response = router
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/sessions")
                        .header("X-User-CN", "CN=admin.test")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            let body = response.into_body().collect().await.unwrap().to_bytes();
            let sessions_response: SessionsResponse = serde_json::from_slice(&body).unwrap();
            assert_eq!(sessions_response.total, 0);
        }
    }

    #[tokio::test]
    async fn test_session_request_count_tracked() {
        use http_body_util::BodyExt;
        use std::net::{IpAddr, Ipv4Addr};

        let rbac = make_test_rbac();
        let (app, _rx, registry) = make_test_router_with_channel(rbac);

        // Register a session and record some activity
        let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);
        let conn_id = registry.register_connection(peer_addr).await;

        // Record 5 requests
        for _ in 0..5 {
            registry.record_activity(conn_id).await;
        }

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

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let sessions_response: SessionsResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(sessions_response.sessions[0].request_count, 5);

        // Cleanup
        registry.unregister_connection(conn_id).await;
    }

    #[tokio::test]
    async fn test_viewer_cannot_delete_sessions() {
        use std::net::{IpAddr, Ipv4Addr};

        let rbac = make_test_rbac();
        let (app, _rx, registry) = make_test_router_with_channel(rbac);

        // Register a session
        let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1234);
        let conn_id = registry.register_connection(peer_addr).await;

        // Viewer should not be able to delete sessions (requires write:sessions)
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(&format!("/api/v1/sessions/{}", conn_id))
                    .header("X-User-CN", "CN=viewer.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // Session should NOT be marked for termination
        assert!(!registry.is_termination_requested(conn_id).await);

        // Cleanup
        registry.unregister_connection(conn_id).await;
    }
}
