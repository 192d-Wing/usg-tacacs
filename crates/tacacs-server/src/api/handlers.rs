// SPDX-License-Identifier: Apache-2.0
//! HTTP handlers for the Management API endpoints.
//!
//! # NIST SP 800-53 Rev. 5 Security Controls
//!
//! **Control Implementation Matrix**
//!
//! This module implements controls documented in
//! [../../../../docs/NIST-CONTROLS-MAPPING.md](../../../../docs/NIST-CONTROLS-MAPPING.md).
//!
//! | Control | Family | Status | Validated | Primary Functions |
//! |---------|--------|--------|-----------|-------------------|
//! | AC-10 | Access Control | Implemented | 2026-01-31 | See functions below |
//! | AC-12 | Access Control | Implemented | 2026-01-31 | See functions below |
//! | AC-3 | Access Control | Implemented | 2026-01-31 | See functions below |
//! | AU-12 | Audit and Accountability | Implemented | 2026-01-31 | See functions below |
//! | AU-2 | Audit and Accountability | Implemented | 2026-01-31 | See functions below |
//! | CM-3 | Configuration Management | Implemented | 2026-01-31 | See functions below |
//! | SI-4 | System and Information Integrity | Implemented | 2026-01-31 | See functions below |
//!
//! <details>
//! <summary><b>Validation Metadata (JSON)</b></summary>
//!
//! ```json
//! {
//!   "nist_framework": "NIST SP 800-53 Rev. 5",
//!   "software_version": "0.77.1",
//!   "last_validation": "2026-01-31",
//!   "control_families": [
//!     "AC",
//!     "AU",
//!     "CM",
//!     "SI"
//!   ],
//!   "total_controls": 7,
//!   "file_path": "crates/tacacs-server/src/api/handlers.rs"
//! }
//! ```
//!
//! </details>
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

use super::middleware::request_context;
use super::models::*;
use super::rbac::TlsClientIdentity;
use super::rbac::{RbacConfig, require_permission};
use crate::jit_lease::{CanonicalEid, LeaseTtl, NadIdentity};
use crate::jit_lease_store::{
    CreateLeaseInput, CreateLeaseOutcome, JitLeaseStore, LeaseMetadata, StoreError,
};
use crate::metrics::metrics;
use crate::nad_reconciler::RuntimeNadRegistry;
use crate::nad_store::{
    CreateNadInput, CreateNadOutcome, NadAuthentication, NadStore, NadStoreError, UpdateNadInput,
};
use crate::server::PolicyReloadRequest;
use crate::session_registry::SessionRegistry;
use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Extension, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post},
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::{RwLock, mpsc};
use tracing::{info, warn};
use usg_tacacs_policy::PolicyEngine;
use utoipa_swagger_ui::{Config as SwaggerConfig, SwaggerUi};
use uuid::Uuid;

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
    /// True when policy is owned by the typed YAML server configuration.
    pub declarative_config: bool,
    /// Parsed authoritative YAML, retained for redacted management reads.
    pub source_config: Option<Arc<usg_tacacs_config::ServerConfiguration>>,
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
    /// Authoritative JIT lease store; absent when the feature is disabled.
    pub jit_lease_store: Option<Arc<JitLeaseStore>>,
    /// Transactional repository for API-owned NAD resources.
    pub nad_store: Option<Arc<NadStore>>,
    /// Atomically published runtime NAD registry.
    pub runtime_nads: Option<Arc<RuntimeNadRegistry>>,
    /// Observable asynchronous management operations.
    pub operations: Arc<RwLock<HashMap<Uuid, OperationResponse>>>,
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
// NASA-RULE4-EXEMPT: route registration requires one .merge()+.route_layer() block per permission
#[allow(clippy::too_many_arguments)]
pub fn build_api_router(
    rbac: RbacConfig,
    policy: Arc<RwLock<PolicyEngine>>,
    policy_path: String,
    schema_path: Option<PathBuf>,
    reload_tx: mpsc::Sender<PolicyReloadRequest>,
    registry: Arc<SessionRegistry>,
    config: RuntimeConfig,
    jit_lease_store: Option<Arc<JitLeaseStore>>,
    nad_store: Option<Arc<NadStore>>,
    runtime_nads: Option<Arc<RuntimeNadRegistry>>,
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
        jit_lease_store,
        nad_store,
        runtime_nads,
        operations: Arc::new(RwLock::new(HashMap::new())),
    });

    Router::new()
        .merge(
            Router::new()
                .route("/api/mgmt/v1/audit/nads", get(list_nad_audit))
                .route("/api/mgmt/v1/audit/nads/verify", get(verify_nad_audit))
                .route_layer(middleware::from_fn(require_permission(&rbac, "read:audit"))),
        )
        .merge(
            Router::new()
                .route("/api/mgmt/v1/nads", get(list_nads))
                .route("/api/mgmt/v1/nads/inventory", get(list_nad_inventory))
                .route(
                    "/api/mgmt/v1/nads/reconciliation",
                    get(get_nad_reconciliation),
                )
                .route("/api/mgmt/v1/nads/{id}", get(get_nad))
                .route_layer(middleware::from_fn(require_permission(&rbac, "read:nads"))),
        )
        .merge(
            Router::new()
                .route("/api/mgmt/v1/nads", post(create_nad))
                .route(
                    "/api/mgmt/v1/nads/{id}",
                    patch(update_nad).delete(delete_nad),
                )
                .route_layer(DefaultBodyLimit::max(16 * 1024))
                .route_layer(middleware::from_fn(require_permission(&rbac, "write:nads"))),
        )
        .merge(
            Router::new()
                .route("/api/mgmt/v1/status", get(get_status))
                .route_layer(middleware::from_fn(require_permission(
                    &rbac,
                    "read:status",
                ))),
        )
        .merge(
            Router::new()
                .route("/api/mgmt/v1/sessions", get(get_sessions))
                .route_layer(middleware::from_fn(require_permission(
                    &rbac,
                    "read:sessions",
                ))),
        )
        .merge(
            Router::new()
                .route("/api/mgmt/v1/sessions/{id}", delete(delete_session))
                .route_layer(middleware::from_fn(require_permission(
                    &rbac,
                    "write:sessions",
                ))),
        )
        .merge(
            Router::new()
                .route("/api/mgmt/v1/policy", get(get_policy))
                .route_layer(middleware::from_fn(require_permission(
                    &rbac,
                    "read:policy",
                ))),
        )
        .merge(
            Router::new()
                .route("/api/mgmt/v1/policy/reload", post(reload_policy))
                .route("/api/mgmt/v1/policy", post(upload_policy))
                .route_layer(middleware::from_fn(require_permission(
                    &rbac,
                    "write:policy",
                ))),
        )
        .merge(
            Router::new()
                .route("/api/mgmt/v1/operations/{id}", get(get_operation))
                .route_layer(middleware::from_fn(require_permission(
                    &rbac,
                    "read:operations",
                ))),
        )
        .merge(
            Router::new()
                .route("/api/mgmt/v1/config", get(get_config))
                .route("/api/mgmt/v1/config/effective", get(get_effective_config))
                .route("/api/mgmt/v1/config/schema", get(get_config_schema))
                .route("/api/mgmt/v1/config/validate", post(validate_config))
                .route_layer(DefaultBodyLimit::max(256 * 1024))
                .route_layer(middleware::from_fn(require_permission(
                    &rbac,
                    "read:config",
                ))),
        )
        .merge(
            Router::new()
                .route("/api/mgmt/v1/metrics", get(get_metrics))
                .route_layer(middleware::from_fn(require_permission(
                    &rbac,
                    "read:metrics",
                ))),
        )
        .merge(
            Router::new()
                .route("/api/jit/v1/leases", post(create_jit_lease))
                .route("/api/jit/v1/leases/{lease_id}", delete(revoke_jit_lease))
                // Compatibility aliases for JITPW clients using the original contract.
                .route("/api/v1/jit-leases", post(create_jit_lease))
                .route("/api/v1/jit-leases/{lease_id}", delete(revoke_jit_lease))
                .route_layer(DefaultBodyLimit::max(16 * 1024))
                .route_layer(middleware::from_fn(require_permission(
                    &rbac,
                    "write:jit-leases",
                ))),
        )
        .merge(
            Router::new()
                .route("/api/jit/v1/leases/{lease_id}", get(get_jit_lease))
                .route("/api/v1/jit-leases/{lease_id}", get(get_jit_lease))
                .route_layer(middleware::from_fn(require_permission(
                    &rbac,
                    "read:jit-leases",
                ))),
        )
        .merge(
            Router::new()
                .merge(
                    SwaggerUi::new("/api/docs/mgmt")
                        .config(SwaggerConfig::new(["/api/docs/mgmt/openapi.yaml"])),
                )
                .route("/api/docs/mgmt/openapi.yaml", get(get_mgmt_openapi))
                .route_layer(middleware::from_fn(require_permission(
                    &rbac,
                    "read:config",
                ))),
        )
        .merge(
            Router::new()
                .merge(
                    SwaggerUi::new("/api/docs/jit")
                        .config(SwaggerConfig::new(["/api/docs/jit/openapi.yaml"])),
                )
                .route("/api/docs/jit/openapi.yaml", get(get_jit_openapi))
                .route_layer(middleware::from_fn(require_permission(
                    &rbac,
                    "read:jit-leases",
                ))),
        )
        .with_state(state)
        .layer(middleware::from_fn(request_context))
}

/// Return the version-controlled management OpenAPI 3.1.1 contract.
async fn get_mgmt_openapi() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/yaml; charset=utf-8")],
        include_str!("../../../../docs/api/mgmt/openapi.yaml"),
    )
}

/// Return the version-controlled JIT lease OpenAPI 3.1.1 contract.
async fn get_jit_openapi() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/yaml; charset=utf-8")],
        include_str!("../../../../docs/api/jit-lease.openapi.yaml"),
    )
}

async fn list_nads(
    State(state): State<Arc<ApiState>>,
    Query(query): Query<NadListQuery>,
    headers: HeaderMap,
) -> Response {
    let correlation_id = mutation_correlation(&headers);
    let Some((limit, offset)) = nad_list_page(&query) else {
        return problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_pagination",
            correlation_id,
        );
    };
    let Some(store) = state.nad_store.as_ref() else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "nad_store_unavailable",
            correlation_id,
        );
    };
    match store
        .list_page(query.name_prefix.as_deref(), limit, offset)
        .await
    {
        Ok(page) => {
            let snapshot = state.runtime_nads.as_ref().map(|value| value.snapshot());
            let items = page
                .items
                .into_iter()
                .map(|record| NadResponse {
                    reconciliation: snapshot
                        .as_ref()
                        .and_then(|value| value.statuses.get(&record.nad_id).cloned()),
                    record,
                })
                .collect();
            let next_offset = page.has_more.then_some(offset + limit);
            (StatusCode::OK, Json(NadListResponse { items, next_offset })).into_response()
        }
        Err(error) => nad_problem(error, correlation_id),
    }
}

async fn list_nad_audit(
    State(state): State<Arc<ApiState>>,
    Query(query): Query<NadAuditQuery>,
    headers: HeaderMap,
) -> Response {
    let correlation_id = mutation_correlation(&headers);
    let Some((limit, offset)) = nad_audit_page(&query) else {
        return problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_audit_query",
            correlation_id,
        );
    };
    let Some(store) = state.nad_store.as_ref() else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "nad_store_unavailable",
            correlation_id,
        );
    };
    match store
        .list_audit(
            query.nad_id,
            query.correlation_id,
            query.action.as_deref(),
            limit,
            offset,
        )
        .await
    {
        Ok(page) => Json(NadAuditResponse {
            items: page.items,
            next_offset: page.has_more.then_some(offset + limit),
        })
        .into_response(),
        Err(error) => nad_problem(error, correlation_id),
    }
}

async fn verify_nad_audit(
    State(state): State<Arc<ApiState>>,
    Query(query): Query<NadAuditVerificationQuery>,
    headers: HeaderMap,
) -> Response {
    let correlation_id = mutation_correlation(&headers);
    let Some((limit, offset)) = nad_audit_verification_page(&query) else {
        return problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_audit_query",
            correlation_id,
        );
    };
    let Some(store) = state.nad_store.as_ref() else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "nad_store_unavailable",
            correlation_id,
        );
    };
    match store.verify_audit_page(limit, offset).await {
        Ok(report) => Json(report).into_response(),
        Err(error) => nad_problem(error, correlation_id),
    }
}

fn nad_audit_verification_page(query: &NadAuditVerificationQuery) -> Option<(usize, usize)> {
    let limit = query.limit.unwrap_or(1_000);
    let offset = query.offset.unwrap_or(0);
    (limit > 0 && limit <= 5_000 && offset <= 1_000_000).then_some((limit, offset))
}

fn nad_audit_page(query: &NadAuditQuery) -> Option<(usize, usize)> {
    let limit = query.limit.unwrap_or(100);
    let offset = query.offset.unwrap_or(0);
    let valid_action = query
        .action
        .as_deref()
        .is_none_or(|value| matches!(value, "create" | "update" | "delete"));
    (valid_action && limit > 0 && limit <= 200 && offset <= 1_000_000).then_some((limit, offset))
}

fn nad_list_page(query: &NadListQuery) -> Option<(usize, usize)> {
    let limit = query.limit.unwrap_or(100);
    let offset = query.offset.unwrap_or(0);
    let valid_prefix = query.name_prefix.as_deref().is_none_or(valid_nad_prefix);
    (valid_prefix && limit > 0 && limit <= 200 && offset <= 1_000_000).then_some((limit, offset))
}

fn valid_nad_prefix(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value == value.to_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".-".contains(&byte))
}

async fn list_nad_inventory(State(state): State<Arc<ApiState>>, headers: HeaderMap) -> Response {
    let correlation_id = mutation_correlation(&headers);
    let Some(store) = state.nad_store.as_ref() else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "nad_store_unavailable",
            correlation_id,
        );
    };
    let api_records = match store.list().await {
        Ok(records) => records,
        Err(error) => return nad_problem(error, correlation_id),
    };
    let snapshot = state.runtime_nads.as_ref().map(|value| value.snapshot());
    let mut items = yaml_inventory(&state.config);
    items.extend(api_records.into_iter().map(|record| {
        let reconciliation = snapshot
            .as_ref()
            .and_then(|value| value.statuses.get(&record.nad_id).cloned());
        NadInventoryItem {
            nad_id: Some(record.nad_id),
            name: record.name,
            description: record.description,
            source_address: record.source_address,
            authentication: record.authentication,
            ownership: "api",
            mutable: true,
            resource_version: Some(record.resource_version),
            reconciliation,
        }
    }));
    items.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.ownership.cmp(right.ownership))
            .then_with(|| left.source_address.cmp(&right.source_address))
    });
    (StatusCode::OK, Json(NadInventoryResponse { items })).into_response()
}

fn yaml_inventory(config: &RuntimeConfig) -> Vec<NadInventoryItem> {
    let Some(source) = &config.source_config else {
        return Vec::new();
    };
    source
        .spec
        .nads
        .iter()
        .map(|nad| NadInventoryItem {
            nad_id: None,
            name: nad.name.clone(),
            description: nad.description.clone(),
            source_address: nad.source_address,
            authentication: yaml_authentication(&nad.authentication),
            ownership: "yaml",
            mutable: false,
            resource_version: None,
            reconciliation: None,
        })
        .collect()
}

fn yaml_authentication(value: &usg_tacacs_config::NadAuthentication) -> NadAuthentication {
    match value {
        usg_tacacs_config::NadAuthentication::Legacy { secret_file } => NadAuthentication::Legacy {
            secret_ref: secret_file.display().to_string(),
        },
        usg_tacacs_config::NadAuthentication::Tls {
            certificate_identities,
        } => NadAuthentication::Tls {
            certificate_identities: certificate_identities.clone(),
        },
    }
}

async fn get_nad_reconciliation(
    State(state): State<Arc<ApiState>>,
    Query(query): Query<NadReconciliationQuery>,
    headers: HeaderMap,
) -> Response {
    let correlation_id = mutation_correlation(&headers);
    let Some(registry) = state.runtime_nads.as_ref() else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "nad_reconciliation_unavailable",
            correlation_id,
        );
    };
    let Some((limit, offset)) = reconciliation_page(&query) else {
        return problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_pagination",
            correlation_id,
        );
    };
    let snapshot = registry.snapshot();
    let mut all = snapshot.statuses.values().cloned().collect::<Vec<_>>();
    all.sort_by_key(|status| status.nad_id);
    let counts = reconciliation_counts(&all);
    if let Some(state) = query.state {
        all.retain(|status| status.state == state);
    }
    let total = all.len();
    let items = all.into_iter().skip(offset).take(limit).collect();
    let next_offset = (offset.saturating_add(limit) < total).then_some(offset + limit);
    Json(NadReconciliationResponse {
        reconciled_at: snapshot.reconciled_at,
        total,
        active: counts[0],
        conflict: counts[1],
        secret_unavailable: counts[2],
        items,
        next_offset,
    })
    .into_response()
}

fn reconciliation_page(query: &NadReconciliationQuery) -> Option<(usize, usize)> {
    let limit = query.limit.unwrap_or(100);
    let offset = query.offset.unwrap_or(0);
    (limit > 0 && limit <= 200 && offset <= 1_000_000).then_some((limit, offset))
}

fn reconciliation_counts(
    statuses: &[crate::nad_reconciler::NadReconciliationStatus],
) -> [usize; 3] {
    let mut counts = [0; 3];
    for status in statuses {
        match status.state {
            crate::nad_reconciler::ReconciliationState::Active => counts[0] += 1,
            crate::nad_reconciler::ReconciliationState::Conflict => counts[1] += 1,
            crate::nad_reconciler::ReconciliationState::SecretUnavailable => counts[2] += 1,
        }
    }
    counts
}

async fn get_nad(
    State(state): State<Arc<ApiState>>,
    Path(nad_id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    let correlation_id = mutation_correlation(&headers);
    let Some(store) = state.nad_store.as_ref() else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "nad_store_unavailable",
            correlation_id,
        );
    };
    match store.get(nad_id).await {
        Ok(record) => nad_response(StatusCode::OK, record, state.runtime_nads.as_deref()),
        Err(error) => nad_problem(error, correlation_id),
    }
}

async fn create_nad(
    State(state): State<Arc<ApiState>>,
    Extension(identity): Extension<TlsClientIdentity>,
    headers: HeaderMap,
    Json(request): Json<CreateNadRequest>,
) -> Response {
    let Some(correlation_id) = uuid_header(&headers, "x-correlation-id") else {
        return invalid_header_problem();
    };
    let Some(idempotency_key) = required_header(&headers, "idempotency-key", validate_idempotency)
    else {
        return invalid_header_problem();
    };
    let Some(store) = state.nad_store.as_ref() else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "nad_store_unavailable",
            correlation_id.to_string(),
        );
    };
    let input = CreateNadInput {
        name: request.name,
        description: request.description,
        source_address: request.source_address,
        authentication: request.authentication,
        actor: identity.cn,
        correlation_id,
        idempotency_key,
    };
    match store.create(input).await {
        Ok(CreateNadOutcome::Created(record)) => {
            refresh_runtime(&state, correlation_id).await;
            nad_response(StatusCode::CREATED, record, state.runtime_nads.as_deref())
        }
        Ok(CreateNadOutcome::Replay(record)) => {
            refresh_runtime(&state, correlation_id).await;
            nad_response(StatusCode::OK, record, state.runtime_nads.as_deref())
        }
        Err(error) => nad_problem(error, correlation_id.to_string()),
    }
}

async fn update_nad(
    State(state): State<Arc<ApiState>>,
    Extension(identity): Extension<TlsClientIdentity>,
    Path(nad_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<UpdateNadRequest>,
) -> Response {
    let Some(correlation_id) = uuid_header(&headers, "x-correlation-id") else {
        return invalid_header_problem();
    };
    let Some(expected_version) = resource_version(&headers) else {
        return invalid_header_problem();
    };
    let Some(store) = state.nad_store.as_ref() else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "nad_store_unavailable",
            correlation_id.to_string(),
        );
    };
    let input = UpdateNadInput {
        nad_id,
        description: request.description,
        source_address: request.source_address,
        authentication: request.authentication,
        expected_version,
        actor: identity.cn,
        correlation_id,
    };
    match store.update(input).await {
        Ok(record) => {
            refresh_runtime(&state, correlation_id).await;
            nad_response(StatusCode::OK, record, state.runtime_nads.as_deref())
        }
        Err(error) => nad_problem(error, correlation_id.to_string()),
    }
}

async fn delete_nad(
    State(state): State<Arc<ApiState>>,
    Extension(identity): Extension<TlsClientIdentity>,
    Path(nad_id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    let Some(correlation_id) = uuid_header(&headers, "x-correlation-id") else {
        return invalid_header_problem();
    };
    let Some(expected_version) = resource_version(&headers) else {
        return invalid_header_problem();
    };
    let Some(store) = state.nad_store.as_ref() else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "nad_store_unavailable",
            correlation_id.to_string(),
        );
    };
    match store
        .delete(nad_id, expected_version, &identity.cn, correlation_id)
        .await
    {
        Ok(_) => {
            refresh_runtime(&state, correlation_id).await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(error) => nad_problem(error, correlation_id.to_string()),
    }
}

async fn refresh_runtime(state: &ApiState, correlation_id: Uuid) {
    let Some(registry) = &state.runtime_nads else {
        return;
    };
    match registry.refresh().await {
        Ok(snapshot) => info!(
            correlation_id = %correlation_id,
            active_legacy = snapshot.legacy_identities.len(),
            active_tls = snapshot.tls_identities.len(),
            "published reconciled NAD snapshot"
        ),
        Err(error) => warn!(
            correlation_id = %correlation_id,
            error = %error,
            "NAD reconciliation failed; retaining last valid snapshot"
        ),
    }
}

fn uuid_header(headers: &HeaderMap, name: &'static str) -> Option<Uuid> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Uuid::parse_str(value).ok())
}

fn resource_version(headers: &HeaderMap) -> Option<i64> {
    let value = headers.get(header::IF_MATCH)?.to_str().ok()?;
    let value = value.strip_prefix('"')?.strip_suffix('"')?;
    value
        .strip_prefix("rv-")?
        .parse()
        .ok()
        .filter(|value| *value > 0)
}

fn mutation_correlation(headers: &HeaderMap) -> String {
    uuid_header(headers, "x-correlation-id")
        .unwrap_or_else(Uuid::new_v4)
        .to_string()
}

fn nad_response(
    status: StatusCode,
    record: crate::nad_store::NadRecord,
    registry: Option<&RuntimeNadRegistry>,
) -> Response {
    let version = record.resource_version;
    let nad_id = record.nad_id;
    let reconciliation = registry
        .map(RuntimeNadRegistry::snapshot)
        .and_then(|snapshot| snapshot.statuses.get(&nad_id).cloned());
    let mut response = (
        status,
        Json(NadResponse {
            record,
            reconciliation,
        }),
    )
        .into_response();
    if let Ok(value) = HeaderValue::from_str(&format!("\"rv-{version}\"")) {
        response.headers_mut().insert(header::ETAG, value);
    }
    if status == StatusCode::CREATED
        && let Ok(value) = HeaderValue::from_str(&format!("/api/mgmt/v1/nads/{nad_id}"))
    {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
}

fn nad_problem(error: NadStoreError, correlation_id: String) -> Response {
    match error {
        NadStoreError::Unavailable | NadStoreError::CorruptRecord => problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "nad_store_unavailable",
            correlation_id,
        ),
        NadStoreError::Conflict => problem(StatusCode::CONFLICT, "nad_conflict", correlation_id),
        NadStoreError::NotFound => problem(StatusCode::NOT_FOUND, "nad_not_found", correlation_id),
        NadStoreError::InvalidInput(code) => {
            problem(StatusCode::UNPROCESSABLE_ENTITY, code, correlation_id)
        }
    }
}

async fn create_jit_lease(
    State(state): State<Arc<ApiState>>,
    Extension(identity): Extension<TlsClientIdentity>,
    headers: HeaderMap,
    Json(request): Json<CreateJitLeaseRequest>,
) -> Response {
    let correlation_id = match required_header(&headers, "x-correlation-id", validate_correlation) {
        Some(value) => value,
        None => return invalid_header_problem(),
    };
    let idempotency_key = match required_header(&headers, "idempotency-key", validate_idempotency) {
        Some(value) => value,
        None => return invalid_header_problem(),
    };
    let Some(store) = state.jit_lease_store.as_ref() else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            correlation_id,
        );
    };
    let input = match create_input(request, idempotency_key) {
        Ok(input) => input,
        Err(error) => return store_problem(error, correlation_id),
    };
    let (audit_eid, audit_nad) = create_audit_target(&input);
    match store.create(input).await {
        Ok(outcome) => {
            let (status, metadata) = match outcome {
                CreateLeaseOutcome::Created(value) => (StatusCode::CREATED, value),
                CreateLeaseOutcome::Replay(value) => (StatusCode::OK, value),
            };
            crate::server::audit_event(
                "jit_lease_create",
                "management-api",
                &identity.cn,
                0,
                "success",
                "authorized",
                &format!(
                    "correlation_id={correlation_id},eid={audit_eid},nad={audit_nad},lease_id={}",
                    metadata.lease_id
                ),
            );
            lease_response(status, metadata)
        }
        Err(error) => {
            crate::server::audit_event(
                "jit_lease_create",
                "management-api",
                &identity.cn,
                0,
                "denied",
                error.to_string().as_str(),
                &format!("correlation_id={correlation_id},eid={audit_eid},nad={audit_nad}"),
            );
            store_problem(error, correlation_id)
        }
    }
}

fn create_audit_target(input: &CreateLeaseInput) -> (String, String) {
    (
        input.eid.as_str().to_owned(),
        input.nad_identity.as_str().to_owned(),
    )
}

async fn get_jit_lease(
    State(state): State<Arc<ApiState>>,
    Extension(identity): Extension<TlsClientIdentity>,
    Path(lease_id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    let correlation_id = match required_header(&headers, "x-correlation-id", validate_correlation) {
        Some(value) => value,
        None => return invalid_header_problem(),
    };
    let Some(store) = state.jit_lease_store.as_ref() else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            correlation_id,
        );
    };
    match store.get(lease_id).await {
        Ok(Some(metadata)) => {
            audit_lease_api(
                "jit_lease_read",
                &identity.cn,
                "success",
                "authorized",
                &correlation_id,
                lease_id,
            );
            lease_response(StatusCode::OK, metadata)
        }
        Ok(None) => {
            audit_lease_api(
                "jit_lease_read",
                &identity.cn,
                "denied",
                "lease_not_found",
                &correlation_id,
                lease_id,
            );
            problem(StatusCode::NOT_FOUND, "lease_not_found", correlation_id)
        }
        Err(error) => {
            audit_lease_api(
                "jit_lease_read",
                &identity.cn,
                "error",
                error.to_string().as_str(),
                &correlation_id,
                lease_id,
            );
            store_problem(error, correlation_id)
        }
    }
}

async fn revoke_jit_lease(
    State(state): State<Arc<ApiState>>,
    Extension(identity): Extension<TlsClientIdentity>,
    Path(lease_id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    let correlation_id = match required_header(&headers, "x-correlation-id", validate_correlation) {
        Some(value) => value,
        None => return invalid_header_problem(),
    };
    let Some(store) = state.jit_lease_store.as_ref() else {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            correlation_id,
        );
    };
    match store.revoke(lease_id).await {
        Ok(()) | Err(StoreError::NotFound) => {
            crate::server::audit_event(
                "jit_lease_revoke",
                "management-api",
                &identity.cn,
                0,
                "success",
                "revoked",
                &format!("correlation_id={correlation_id},lease_id={lease_id}"),
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Err(error) => {
            audit_lease_api(
                "jit_lease_revoke",
                &identity.cn,
                "error",
                error.to_string().as_str(),
                &correlation_id,
                lease_id,
            );
            store_problem(error, correlation_id)
        }
    }
}

fn audit_lease_api(
    event: &str,
    actor: &str,
    status: &str,
    reason: &str,
    correlation_id: &str,
    lease_id: Uuid,
) {
    crate::server::audit_event(
        event,
        "management-api",
        actor,
        0,
        status,
        reason,
        &format!("correlation_id={correlation_id},lease_id={lease_id}"),
    );
}

fn create_input(
    request: CreateJitLeaseRequest,
    idempotency_key: String,
) -> Result<CreateLeaseInput, StoreError> {
    if !(24..=128).contains(&request.password.len()) {
        return Err(StoreError::InvalidInput("invalid_password_length"));
    }
    Ok(CreateLeaseInput {
        eid: CanonicalEid::parse(&request.eid)?,
        icam_subject: request.icam_subject,
        nad_identity: NadIdentity::parse(&request.nad_identity)?,
        authorization_groups: request.authorization_groups,
        ttl: LeaseTtl::new(request.ttl_seconds)?,
        idempotency_key,
        password: request.password,
    })
}

fn required_header(
    headers: &HeaderMap,
    name: &'static str,
    validator: fn(&str) -> bool,
) -> Option<String> {
    let value = headers.get(name).and_then(|value| value.to_str().ok());
    value.filter(|value| validator(value)).map(str::to_owned)
}

fn invalid_header_problem() -> Response {
    problem(
        StatusCode::BAD_REQUEST,
        "invalid_header",
        "invalid-correlation".to_owned(),
    )
}

fn validate_correlation(value: &str) -> bool {
    (16..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn validate_idempotency(value: &str) -> bool {
    (16..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn lease_response(status: StatusCode, metadata: LeaseMetadata) -> Response {
    let lease_id = metadata.lease_id;
    let response = JitLeaseResponse {
        lease_id: lease_id.to_string(),
        eid: metadata.eid.as_str().to_owned(),
        icam_subject: metadata.icam_subject,
        nad_identity: metadata.nad_identity.as_str().to_owned(),
        authorization_groups: metadata.authorization_groups,
        issued_at: format_timestamp(metadata.issued_at),
        expires_at: format_timestamp(metadata.expires_at),
        status: "active".to_owned(),
    };
    let mut result = (status, Json(response)).into_response();
    if status == StatusCode::CREATED {
        let value = format!("/api/v1/jit-leases/{lease_id}");
        if let Ok(value) = HeaderValue::from_str(&value) {
            result.headers_mut().insert(header::LOCATION, value);
        }
    }
    result
}

fn format_timestamp(value: u64) -> String {
    i64::try_from(value)
        .ok()
        .and_then(|value| time::OffsetDateTime::from_unix_timestamp(value).ok())
        .and_then(|value| {
            value
                .format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_owned())
}

fn store_problem(error: StoreError, correlation_id: String) -> Response {
    match error {
        StoreError::Unavailable => problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            correlation_id,
        ),
        StoreError::Conflict => problem(
            StatusCode::CONFLICT,
            "active_lease_conflict",
            correlation_id,
        ),
        StoreError::NotFound => problem(StatusCode::NOT_FOUND, "lease_not_found", correlation_id),
        StoreError::CorruptRecord => problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            correlation_id,
        ),
        StoreError::InvalidInput(code) => {
            problem(StatusCode::UNPROCESSABLE_ENTITY, code, correlation_id)
        }
    }
}

fn problem(status: StatusCode, code: &'static str, correlation_id: String) -> Response {
    let body = ProblemResponse {
        problem_type: "about:blank",
        title: status.canonical_reason().unwrap_or("Request failed"),
        status: status.as_u16(),
        code,
        correlation_id,
    };
    let mut response = (status, Json(body)).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    if status == StatusCode::SERVICE_UNAVAILABLE {
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
    }
    response
}

/// GET /api/v1/status - Server health and statistics.
///
/// Requires permission: `read:status`
async fn get_status(State(state): State<Arc<ApiState>>) -> impl IntoResponse {
    let uptime = SystemTime::now()
        .duration_since(state.start_time)
        .unwrap_or_default()
        .as_secs();

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
            id: r.connection_id, // Use connection_id as the session identifier (u64)
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
    headers: HeaderMap,
) -> Response {
    info!(session_id = session_id, "API request to terminate session");

    // NIST AC-12: Terminate session by connection ID
    let success = state.registry.terminate_session(session_id).await;

    if success {
        StatusCode::NO_CONTENT.into_response()
    } else {
        problem(
            StatusCode::NOT_FOUND,
            "session_not_found",
            mutation_correlation(&headers),
        )
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
    let uptime = SystemTime::now()
        .duration_since(state.start_time)
        .unwrap_or_default()
        .as_secs();
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
async fn reload_policy(State(state): State<Arc<ApiState>>, headers: HeaderMap) -> Response {
    info!("API request to reload policy");

    // NIST CM-3: Send reload request through internal channel
    let operation_id = Uuid::now_v7();
    let operation = OperationResponse {
        operation_id: operation_id.to_string(),
        kind: "authorizationPolicyReload",
        status: "running",
        submitted_at: current_timestamp(),
        completed_at: None,
        error: None,
    };
    if !register_operation(&state.operations, operation_id, operation.clone()).await {
        return problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "operation_capacity_exceeded",
            mutation_correlation(&headers),
        );
    }
    let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();
    let request = PolicyReloadRequest::FromDisk {
        path: PathBuf::from(&state.policy_path),
        schema: state.schema_path.clone(),
        completion: Some(completion_tx),
    };

    match state.reload_tx.send(request).await {
        Ok(_) => {
            info!("Policy reload request queued successfully");
            let operations = Arc::clone(&state.operations);
            tokio::spawn(async move {
                let result = completion_rx
                    .await
                    .unwrap_or_else(|_| Err("policy reload worker stopped".to_string()));
                if let Some(operation) = operations.write().await.get_mut(&operation_id) {
                    operation.completed_at = Some(current_timestamp());
                    match result {
                        Ok(()) => operation.status = "succeeded",
                        Err(error) => {
                            operation.status = "failed";
                            operation.error = Some(error);
                        }
                    }
                }
            });
            (StatusCode::ACCEPTED, Json(operation)).into_response()
        }
        Err(e) => {
            warn!(error = %e, "Failed to queue policy reload request");
            state.operations.write().await.remove(&operation_id);
            problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "policy_reload_unavailable",
                mutation_correlation(&headers),
            )
        }
    }
}

async fn register_operation(
    operations: &RwLock<HashMap<Uuid, OperationResponse>>,
    id: Uuid,
    operation: OperationResponse,
) -> bool {
    const MAX_OPERATIONS: usize = 1024;
    let mut records = operations.write().await;
    if records.len() >= MAX_OPERATIONS {
        let completed = records
            .iter()
            .filter(|(_, value)| value.completed_at.is_some())
            .min_by_key(|(_, value)| &value.submitted_at)
            .map(|(id, _)| *id);
        let Some(completed) = completed else {
            return false;
        };
        records.remove(&completed);
    }
    records.insert(id, operation);
    true
}

async fn get_operation(
    State(state): State<Arc<ApiState>>,
    Path(operation_id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    match state.operations.read().await.get(&operation_id).cloned() {
        Some(operation) => Json(operation).into_response(),
        None => problem(
            StatusCode::NOT_FOUND,
            "operation_not_found",
            mutation_correlation(&headers),
        ),
    }
}

fn current_timestamp() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .expect("UTC timestamp is RFC 3339 representable")
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
///
/// Validate policy document against schema if validation is requested.
///
/// # NIST SP 800-53 Controls
/// - CM-3: Configuration validation before acceptance
fn validate_policy_if_requested(
    policy_doc: &usg_tacacs_policy::PolicyDocument,
    should_validate: bool,
    schema_path: &Option<PathBuf>,
) -> Result<(), (StatusCode, Json<PolicyUploadResponse>)> {
    if !should_validate {
        return Ok(());
    }

    if let Some(schema) = schema_path {
        match usg_tacacs_policy::validate_policy_document(policy_doc, schema) {
            Ok(_) => {
                info!("Policy validated successfully against schema");
                Ok(())
            }
            Err(e) => {
                warn!(error = %e, "Policy validation failed");
                let response = PolicyUploadResponse {
                    success: false,
                    message: format!("Policy validation failed: {}", e),
                    rule_count: None,
                };
                Err((StatusCode::BAD_REQUEST, Json(response)))
            }
        }
    } else {
        warn!("Validation requested but no schema configured");
        let response = PolicyUploadResponse {
            success: false,
            message: "Validation requested but no schema configured".to_string(),
            rule_count: None,
        };
        Err((StatusCode::BAD_REQUEST, Json(response)))
    }
}

/// Queue policy upload request and build response.
///
/// # NIST SP 800-53 Controls
/// - CM-3: Configuration change control via channel
async fn queue_policy_upload(
    reload_tx: &mpsc::Sender<PolicyReloadRequest>,
    policy_json: String,
    schema_path: Option<PathBuf>,
    rule_count: usize,
) -> (StatusCode, Json<PolicyUploadResponse>) {
    let request = PolicyReloadRequest::FromJson {
        content: policy_json,
        schema: schema_path,
        completion: None,
    };

    match reload_tx.send(request).await {
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

async fn upload_policy(
    State(state): State<Arc<ApiState>>,
    Json(payload): Json<PolicyUploadRequest>,
) -> impl IntoResponse {
    info!(validate = payload.validate, "API request to upload policy");
    if state.config.declarative_config {
        let response = PolicyUploadResponse {
            success: false,
            message: "Policy upload is disabled while authoritative YAML configuration is active"
                .to_string(),
            rule_count: None,
        };
        return (StatusCode::CONFLICT, Json(response));
    }

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

    if let Err(response) =
        validate_policy_if_requested(&policy_doc, payload.validate, &state.schema_path)
    {
        return response;
    }

    let rule_count = policy_doc.rules.len();

    queue_policy_upload(
        &state.reload_tx,
        payload.policy,
        state.schema_path.clone(),
        rule_count,
    )
    .await
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

async fn validate_config(body: String) -> Response {
    let parsed = yaml_serde::from_str::<usg_tacacs_config::ServerConfiguration>(&body);
    let config = match parsed {
        Ok(value) => value,
        Err(error) => {
            return (
                StatusCode::OK,
                Json(ConfigValidationResponse {
                    valid: false,
                    configuration_hash: None,
                    diagnostics: vec![ConfigDiagnostic {
                        severity: "error",
                        code: "configuration_parse_failed",
                        path: None,
                        message: error.to_string(),
                    }],
                }),
            )
                .into_response();
        }
    };
    if let Err(error) = config.validate(false) {
        return (
            StatusCode::OK,
            Json(ConfigValidationResponse {
                valid: false,
                configuration_hash: Some(configuration_hash(&config)),
                diagnostics: vec![ConfigDiagnostic {
                    severity: "error",
                    code: "configuration_validation_failed",
                    path: diagnostic_path(&error.to_string()),
                    message: error.to_string(),
                }],
            }),
        )
            .into_response();
    }
    (
        StatusCode::OK,
        Json(ConfigValidationResponse {
            valid: true,
            configuration_hash: Some(configuration_hash(&config)),
            diagnostics: Vec::new(),
        }),
    )
        .into_response()
}

async fn get_config_schema() -> Json<schemars::Schema> {
    Json(schemars::schema_for!(
        usg_tacacs_config::ServerConfiguration
    ))
}

async fn get_effective_config(State(state): State<Arc<ApiState>>, headers: HeaderMap) -> Response {
    let Some(config) = state.config.source_config.as_ref() else {
        return problem(
            StatusCode::NOT_FOUND,
            "declarative_config_unavailable",
            mutation_correlation(&headers),
        );
    };
    match serde_json::to_value(config.as_ref()) {
        Ok(value) => Json(EffectiveConfigResponse {
            ownership: "yaml",
            mutable: false,
            configuration_hash: configuration_hash(config),
            config: value,
        })
        .into_response(),
        Err(error) => {
            tracing::error!(error = %error, "failed to serialize effective configuration");
            problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "configuration_serialization_failed",
                mutation_correlation(&headers),
            )
        }
    }
}

fn configuration_hash(config: &usg_tacacs_config::ServerConfiguration) -> String {
    let encoded = serde_json::to_vec(config).expect("typed configuration is serializable");
    format!("sha256:{}", hex::encode(Sha256::digest(encoded)))
}

fn diagnostic_path(message: &str) -> Option<String> {
    let field = message.split_whitespace().next()?;
    field.starts_with("spec.").then(|| {
        format!(
            "/{}",
            field
                .trim_end_matches(':')
                .split('.')
                .collect::<Vec<_>>()
                .join("/")
        )
    })
}

/// GET /api/v1/metrics - Get Prometheus metrics.
///
/// Requires permission: `read:metrics`
async fn get_metrics() -> Result<Response<Body>, (StatusCode, &'static str)> {
    let body_text = metrics().encode();
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        .body(Body::from(body_text))
        .map_err(|e| {
            tracing::error!(error = %e, "failed to build metrics response");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to build metrics response",
            )
        })
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
            shell_start_groups: std::collections::HashMap::new(),
            author_service_attributes: std::collections::HashMap::new(),
            device_flow_exclude_users: Vec::new(),
            nad_groups: std::collections::HashMap::new(),
            enable_groups: std::collections::HashMap::new(),
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
        let source_config =
            yaml_serde::from_str(include_str!("../../../../docs/config/server.example.yaml"))
                .expect("example declarative configuration must parse");
        RuntimeConfig {
            listen_tls: None,
            listen_legacy: None,
            tls_enabled: false,
            ldap_enabled: false,
            policy_source: "test-policy.json".to_string(),
            declarative_config: false,
            source_config: Some(Arc::new(source_config)),
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
            None,
            None,
            None,
        );
        (router, reload_rx, registry)
    }

    /// Build a test router with all required state (convenience wrapper).
    fn make_test_router(rbac: RbacConfig) -> Router {
        let (router, _rx, _registry) = make_test_router_with_channel(rbac);
        router
    }

    #[test]
    fn nad_if_match_requires_a_strong_resource_version_etag() {
        let mut headers = HeaderMap::new();
        headers.insert(header::IF_MATCH, HeaderValue::from_static("\"rv-42\""));
        assert_eq!(resource_version(&headers), Some(42));
        headers.insert(header::IF_MATCH, HeaderValue::from_static("W/\"rv-42\""));
        assert_eq!(resource_version(&headers), None);
        headers.insert(header::IF_MATCH, HeaderValue::from_static("\"rv-0\""));
        assert_eq!(resource_version(&headers), None);
    }

    #[test]
    fn nad_mutation_correlation_must_be_a_uuid() {
        let mut headers = HeaderMap::new();
        let expected = Uuid::new_v4();
        headers.insert(
            "x-correlation-id",
            HeaderValue::from_str(&expected.to_string()).unwrap(),
        );
        assert_eq!(uuid_header(&headers, "x-correlation-id"), Some(expected));
        headers.insert("x-correlation-id", HeaderValue::from_static("not-a-uuid"));
        assert_eq!(uuid_header(&headers, "x-correlation-id"), None);
    }

    #[test]
    fn yaml_inventory_is_read_only_and_contains_only_secret_references() {
        let items = yaml_inventory(&make_test_config());
        assert_eq!(items.len(), 2);
        assert!(items.iter().all(|item| {
            item.ownership == "yaml"
                && !item.mutable
                && item.nad_id.is_none()
                && item.resource_version.is_none()
        }));
        let legacy = items
            .iter()
            .find(|item| item.name == "oopl-an-001")
            .expect("example legacy NAD must be present");
        assert_eq!(
            legacy.authentication,
            NadAuthentication::Legacy {
                secret_ref: "/run/secrets/nads/oopl-an-001".to_owned(),
            }
        );
    }

    #[test]
    fn reconciliation_queries_are_bounded_and_count_all_states() {
        assert_eq!(
            reconciliation_page(&NadReconciliationQuery {
                state: None,
                limit: None,
                offset: None,
            }),
            Some((100, 0))
        );
        assert_eq!(
            reconciliation_page(&NadReconciliationQuery {
                state: None,
                limit: Some(201),
                offset: None,
            }),
            None
        );
        let statuses = [
            reconciliation_status(crate::nad_reconciler::ReconciliationState::Active),
            reconciliation_status(crate::nad_reconciler::ReconciliationState::Conflict),
            reconciliation_status(crate::nad_reconciler::ReconciliationState::SecretUnavailable),
        ];
        assert_eq!(reconciliation_counts(&statuses), [1, 1, 1]);
    }

    #[test]
    fn nad_collection_queries_are_bounded_and_prefixes_are_canonical() {
        assert_eq!(
            nad_list_page(&NadListQuery {
                name_prefix: Some("oopl-an-".to_owned()),
                limit: None,
                offset: None,
            }),
            Some((100, 0))
        );
        assert_eq!(
            nad_list_page(&NadListQuery {
                name_prefix: Some("OOPL".to_owned()),
                limit: Some(10),
                offset: None,
            }),
            None
        );
        assert_eq!(
            nad_list_page(&NadListQuery {
                name_prefix: None,
                limit: Some(201),
                offset: None,
            }),
            None
        );
    }

    #[test]
    fn audit_queries_are_bounded_and_actions_are_allowlisted() {
        assert_eq!(
            nad_audit_page(&NadAuditQuery {
                nad_id: None,
                correlation_id: None,
                action: Some("delete".to_owned()),
                limit: None,
                offset: None,
            }),
            Some((100, 0))
        );
        assert_eq!(
            nad_audit_page(&NadAuditQuery {
                nad_id: None,
                correlation_id: None,
                action: Some("truncate".to_owned()),
                limit: Some(10),
                offset: None,
            }),
            None
        );
        assert_eq!(
            nad_audit_verification_page(&NadAuditVerificationQuery {
                limit: None,
                offset: None,
            }),
            Some((1_000, 0))
        );
        assert_eq!(
            nad_audit_verification_page(&NadAuditVerificationQuery {
                limit: Some(5_001),
                offset: None,
            }),
            None
        );
    }

    fn reconciliation_status(
        state: crate::nad_reconciler::ReconciliationState,
    ) -> crate::nad_reconciler::NadReconciliationStatus {
        crate::nad_reconciler::NadReconciliationStatus {
            nad_id: Uuid::new_v4(),
            resource_version: 1,
            state,
            reason: None,
        }
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
                    .uri("/api/mgmt/v1/status")
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
                    .uri("/api/mgmt/v1/status")
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
                    .uri("/api/mgmt/v1/status")
                    .header("X-User-CN", "CN=admin.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn jit_openapi_requires_read_permission() {
        let app = make_test_router(make_test_rbac());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/docs/jit/openapi.yaml")
                    .header("X-User-CN", "CN=viewer.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn mgmt_openapi_requires_config_read_permission() {
        let app = make_test_router(make_test_rbac());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/docs/mgmt/openapi.yaml")
                    .header("X-User-CN", "CN=viewer.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn mgmt_openapi_serves_oas_3_1_1_contract() {
        use http_body_util::BodyExt;

        let app = make_test_router(make_test_rbac());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/docs/mgmt/openapi.yaml")
                    .header("X-User-CN", "CN=admin.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(body.starts_with(b"openapi: 3.1.1"));
        assert!(
            !body
                .windows(b"jit-leases".len())
                .any(|w| w == b"jit-leases")
        );
    }

    #[test]
    fn mgmt_openapi_is_parseable_and_internal_references_resolve() {
        let document: serde_json::Value =
            yaml_serde::from_str(include_str!("../../../../docs/api/mgmt/openapi.yaml"))
                .expect("management OpenAPI document must be valid YAML");
        assert_eq!(document["openapi"], "3.1.1");
        assert!(
            document["paths"]
                .as_object()
                .is_some_and(|paths| !paths.is_empty())
        );

        fn verify_references(root: &serde_json::Value, value: &serde_json::Value) {
            match value {
                serde_json::Value::Object(object) => {
                    if let Some(reference) = object.get("$ref").and_then(|value| value.as_str()) {
                        let pointer = reference
                            .strip_prefix('#')
                            .expect("only internal OpenAPI references are allowed");
                        assert!(
                            root.pointer(pointer).is_some(),
                            "unresolved OpenAPI reference: {reference}"
                        );
                    }
                    for child in object.values() {
                        verify_references(root, child);
                    }
                }
                serde_json::Value::Array(array) => {
                    for child in array {
                        verify_references(root, child);
                    }
                }
                _ => {}
            }
        }

        verify_references(&document, &document);
    }

    #[tokio::test]
    async fn config_validation_uses_typed_declarative_model() {
        use http_body_util::BodyExt;

        let app = make_test_router(make_test_rbac());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/mgmt/v1/config/validate")
                    .header("X-User-CN", "CN=admin.test")
                    .header(header::CONTENT_TYPE, "application/yaml")
                    .body(Body::from(include_str!(
                        "../../../../docs/config/server.example.yaml"
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["valid"], true);
        assert!(
            body["configurationHash"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
    }

    #[tokio::test]
    async fn config_schema_and_effective_views_are_available() {
        use http_body_util::BodyExt;

        for path in [
            "/api/mgmt/v1/config/schema",
            "/api/mgmt/v1/config/effective",
        ] {
            let response = make_test_router(make_test_rbac())
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header("X-User-CN", "CN=admin.test")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body: serde_json::Value =
                serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                    .unwrap();
            assert!(body.is_object());
        }
    }

    #[tokio::test]
    async fn jit_openapi_serves_versioned_contract() {
        use http_body_util::BodyExt;

        let app = make_test_router(make_test_rbac());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/docs/jit/openapi.yaml")
                    .header("X-User-CN", "CN=admin.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/yaml; charset=utf-8"
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(body.starts_with(b"openapi: 3.1.1"));
    }

    #[tokio::test]
    async fn jit_swagger_ui_is_available_to_authorized_admin() {
        let app = make_test_router(make_test_rbac());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/docs/jit/")
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
                    .uri("/api/mgmt/v1/policy/reload")
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
                    .uri("/api/mgmt/v1/status")
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
                    .uri("/api/mgmt/v1/policy")
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
                    .uri("/api/mgmt/v1/status")
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
                    .uri("/api/mgmt/v1/sessions")
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
                    .uri("/api/mgmt/v1/metrics")
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
                    .uri("/api/mgmt/v1/config")
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
        use http_body_util::BodyExt;

        let rbac = make_test_rbac();
        // Use the channel variant to keep the receiver alive during the test
        let (app, mut reload_rx, _registry) = make_test_router_with_channel(rbac);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/mgmt/v1/policy/reload")
                    .header("X-User-CN", "CN=admin.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        let operation_id = body["operationId"].as_str().unwrap();

        // Verify the reload request was sent to the channel
        let reload_request = reload_rx.try_recv().expect("should receive reload request");
        match reload_request {
            PolicyReloadRequest::FromDisk {
                path,
                schema,
                completion,
            } => {
                assert_eq!(path.to_string_lossy(), "test-policy.json");
                assert!(schema.is_none());
                completion.unwrap().send(Ok(())).unwrap();
            }
            PolicyReloadRequest::FromJson { .. } => {
                panic!("Expected FromDisk, got FromJson");
            }
        }
        tokio::task::yield_now().await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/mgmt/v1/operations/{operation_id}"))
                    .header("X-User-CN", "CN=admin.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body: serde_json::Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["status"], "succeeded");
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
        let conn_id = registry.try_register_connection(peer_addr).await.unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/mgmt/v1/sessions")
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
        assert_eq!(sessions_response.sessions[0].id, conn_id);
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
        let conn_id = registry.try_register_connection(peer_addr).await.unwrap();
        registry
            .update_authentication(conn_id, "network_admin".to_string(), 42)
            .await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/mgmt/v1/sessions")
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
                    .uri("/api/mgmt/v1/sessions")
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
        use std::net::{IpAddr, Ipv4Addr};

        let rbac = make_test_rbac();
        let (app, _rx, registry) = make_test_router_with_channel(rbac);

        // Register a session to terminate
        let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), 9999);
        let conn_id = registry.try_register_connection(peer_addr).await.unwrap();

        // Verify session is not yet marked for termination
        assert!(!registry.is_termination_requested(conn_id).await);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/mgmt/v1/sessions/{}", conn_id))
                    .header("X-User-CN", "CN=admin.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);

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
                    .uri("/api/mgmt/v1/sessions/999999")
                    .header("X-User-CN", "CN=admin.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let problem: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(problem["code"], "session_not_found");
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

        let conn1 = registry.try_register_connection(peer1).await.unwrap();
        let conn2 = registry.try_register_connection(peer2).await.unwrap();
        let conn3 = registry.try_register_connection(peer3).await.unwrap();

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
                    .uri("/api/mgmt/v1/sessions")
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
        let conn_ids: Vec<u64> = sessions_response.sessions.iter().map(|s| s.id).collect();
        assert!(conn_ids.contains(&conn1));
        assert!(conn_ids.contains(&conn2));
        assert!(conn_ids.contains(&conn3));

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
            None,
            None,
            None,
        );

        // Register a session
        let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 5000);
        let conn_id = registry.try_register_connection(peer_addr).await.unwrap();

        // Verify it appears
        {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/mgmt/v1/sessions")
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
                        .uri("/api/mgmt/v1/sessions")
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
        let conn_id = registry.try_register_connection(peer_addr).await.unwrap();

        // Record 5 requests
        for _ in 0..5 {
            registry.record_activity(conn_id).await;
        }

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/mgmt/v1/sessions")
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
        let conn_id = registry.try_register_connection(peer_addr).await.unwrap();

        // Viewer should not be able to delete sessions (requires write:sessions)
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/api/mgmt/v1/sessions/{}", conn_id))
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
