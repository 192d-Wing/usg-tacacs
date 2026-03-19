// SPDX-License-Identifier: Apache-2.0
use crate::{AppState, bundle};
use axum::{
    Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
};
use bytes::Bytes;
use sha2::{Digest, Sha256};
use tracing::warn;

fn header_required(
    headers: &HeaderMap,
    name: &'static str,
) -> Result<String, (StatusCode, String)> {
    headers
        .get(name)
        .ok_or((StatusCode::BAD_REQUEST, format!("missing header {name}")))?
        .to_str()
        .map(|s| s.to_string())
        .map_err(|_| (StatusCode::BAD_REQUEST, format!("invalid header {name}")))
}

fn header_optional(headers: &HeaderMap, name: &'static str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/ingest", post(ingest))
        .route(
            "/api/v1/promote/:repo_id/:location_code/:commit_sha",
            post(promote),
        )
        .with_state(state)
}

/// Verify bundle SHA256 checksum if provided in headers.
fn verify_bundle_checksum(headers: &HeaderMap, body: &Bytes) -> Result<(), (StatusCode, String)> {
    if let Some(expected) = header_optional(headers, "X-Bundle-SHA256") {
        let mut hasher = Sha256::new();
        hasher.update(body);
        let got = hex::encode(hasher.finalize());
        if !got.eq_ignore_ascii_case(expected.trim()) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("bundle sha256 mismatch (got {got})"),
            ));
        }
    }
    Ok(())
}

/// Store and validate all policies from parsed bundle.
async fn store_policies(
    state: &AppState,
    repo_id: &str,
    commit_sha: &str,
    policies: &std::collections::HashMap<String, serde_json::Value>,
) -> Result<(), (StatusCode, String)> {
    for (loc, pol) in policies.iter() {
        if let Err(e) = state.schemas.validate_policy(pol) {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("policy invalid for {loc}: {e}"),
            ));
        }
        if let Err(e) = state
            .store
            .upsert_policy(repo_id, commit_sha, loc, pol)
            .await
        {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("db upsert policy failed for {loc}: {e}"),
            ));
        }
    }
    Ok(())
}

/// Store and validate all configs from parsed bundle.
async fn store_configs(
    state: &AppState,
    repo_id: &str,
    commit_sha: &str,
    configs: &std::collections::HashMap<String, serde_json::Value>,
) -> Result<(), (StatusCode, String)> {
    for (loc, cfg) in configs.iter() {
        if let Err(e) = state.schemas.validate_config(cfg) {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("config invalid for {loc}: {e}"),
            ));
        }
        if let Err(e) = state
            .store
            .upsert_config(repo_id, commit_sha, loc, cfg)
            .await
        {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("db upsert config failed for {loc}: {e}"),
            ));
        }
    }
    Ok(())
}

pub async fn ingest(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let repo_id = match header_required(&headers, "X-Repo-Id") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let commit_sha = match header_required(&headers, "X-Commit-SHA") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let r#ref = header_optional(&headers, "X-Ref").unwrap_or_else(|| "unknown".to_string());

    if !state.expected_repo_allowlist.is_empty()
        && !state.expected_repo_allowlist.iter().any(|r| r == &repo_id)
    {
        return (StatusCode::FORBIDDEN, "repo not allowed".to_string());
    }

    if let Err(e) = verify_bundle_checksum(&headers, &body) {
        return e;
    }

    let parsed = match bundle::parse_tar_gz(&body) {
        Ok(b) => b,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("bundle parse failed: {e}")),
    };

    if let Err(e) = state.store.record_run(&repo_id, &commit_sha, &r#ref).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}"));
    }

    if let Err(e) = store_policies(&state, &repo_id, &commit_sha, &parsed.policies).await {
        return e;
    }

    if let Err(e) = store_configs(&state, &repo_id, &commit_sha, &parsed.configs).await {
        return e;
    }

    (StatusCode::OK, "staged".to_string())
}

pub async fn promote(
    State(state): State<AppState>,
    Path((repo_id, location_code, commit_sha)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !state.expected_repo_allowlist.is_empty()
        && !state.expected_repo_allowlist.iter().any(|r| r == &repo_id)
    {
        return (StatusCode::FORBIDDEN, "repo not allowed".to_string());
    }

    // SECURITY WARNING: X-Activated-By header is spoofable. In production,
    // derive audit attribution from the mTLS client certificate CN instead.
    let activated_by =
        header_optional(&headers, "X-Activated-By").unwrap_or_else(|| "mtls-client".to_string());
    warn!(
        "X-Activated-By header used for audit attribution; in production, derive from mTLS client certificate"
    );

    if let Err(e) = state
        .store
        .promote(&repo_id, &location_code, &commit_sha, &activated_by)
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("promote failed: {e}"),
        );
    }

    (StatusCode::OK, "active".to_string())
}
