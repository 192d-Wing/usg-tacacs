// SPDX-License-Identifier: Apache-2.0
//! Role-Based Access Control for the Management API.
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
//! | AC-2 | Access Control | Implemented | 2026-01-31 | See functions below |
//! | AC-3 | Access Control | Implemented | 2026-01-31 | See functions below |
//! | AC-6 | Access Control | Implemented | 2026-01-31 | See functions below |
//! | AU-12 | Audit and Accountability | Implemented | 2026-01-31 | See functions below |
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
//!     "AU"
//!   ],
//!   "total_controls": 4,
//!   "file_path": "crates/tacacs-server/src/api/rbac.rs"
//! }
//! ```
//!
//! </details>
//!
//! # NIST SP 800-53 Security Controls
//!
//! This module implements the following NIST security controls:
//!
//! - **AC-2 (Account Management)**: Maps users (identified by TLS certificate
//!   CN/SAN) to roles for access management.
//!
//! - **AC-3 (Access Enforcement)**: Enforces role-based permissions for
//!   Management API endpoints.
//!
//! - **AC-6 (Least Privilege)**: Supports granular permissions (read:*, write:*,
//!   read:status, etc.) enabling minimum necessary access.
//!
//! - **AU-12 (Audit Generation)**: Permission denials are logged via tracing.

use axum::{
    Json,
    body::Body,
    extract::Request,
    http::{HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::warn;
use uuid::Uuid;

#[derive(Serialize)]
struct AuthorizationProblem {
    #[serde(rename = "type")]
    problem_type: &'static str,
    title: &'static str,
    status: u16,
    code: &'static str,
    correlation_id: String,
}

/// Identity extracted from TLS client certificate CN.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | IA-3 | Device Identification | Identity derived from mTLS client certificate, not spoofable headers |
/// | AC-3 | Access Enforcement | Used by RBAC middleware to enforce permissions |
#[derive(Debug, Clone)]
pub struct TlsClientIdentity {
    /// The single typed certificate identity selected by RBAC.
    pub certificate_identity: String,
}

/// Typed identity candidates extracted from a validated peer certificate.
#[derive(Debug, Clone)]
pub struct TlsPeerIdentity {
    pub candidates: Vec<String>,
}

/// RBAC configuration.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-2 | Account Management | User-to-role mapping |
/// | AC-6 | Least Privilege | Granular permission definitions |
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbacConfig {
    /// Role definitions: role_name -> list of permissions (NIST AC-6)
    pub roles: HashMap<String, Vec<String>>,
    /// User to role mapping: CN or identifier -> role_name (NIST AC-2)
    pub users: HashMap<String, String>,
}

impl Default for RbacConfig {
    fn default() -> Self {
        let mut roles = HashMap::new();
        roles.insert(
            "admin".to_string(),
            vec!["read:*".to_string(), "write:*".to_string()],
        );
        roles.insert(
            "operator".to_string(),
            vec!["read:*".to_string(), "write:sessions".to_string()],
        );
        roles.insert(
            "viewer".to_string(),
            vec!["read:status".to_string(), "read:metrics".to_string()],
        );

        Self {
            roles,
            users: HashMap::new(),
        }
    }
}

impl RbacConfig {
    pub fn validate(&self) -> Result<(), &'static str> {
        for (identity, role) in &self.users {
            if !valid_typed_identity(identity) {
                return Err("invalid_certificate_identity");
            }
            if !self.roles.contains_key(role) {
                return Err("undefined_rbac_role");
            }
        }
        for permissions in self.roles.values() {
            if permissions.is_empty() || !permissions.iter().all(|value| valid_permission(value)) {
                return Err("invalid_rbac_permission");
            }
        }
        Ok(())
    }

    /// Check if a user has a specific permission.
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | AC-3 | Access Enforcement | Enforces permission checks |
    /// | AU-12 | Audit Generation | Logs permission denials |
    pub fn has_permission(&self, user: &str, permission: &str) -> bool {
        // NIST AC-2: Get user's role from mapping
        let role = match self.users.get(user) {
            Some(r) => r,
            None => {
                // NIST AU-12: Log unauthorized access attempt
                warn!(user = %user, "user not found in RBAC config");
                return false;
            }
        };

        // Get role's permissions
        let permissions = match self.roles.get(role) {
            Some(perms) => perms,
            None => {
                warn!(role = %role, "role not found in RBAC config");
                return false;
            }
        };

        // Check for exact match or wildcard
        for perm in permissions {
            if perm == permission {
                return true;
            }

            // Handle wildcards (e.g., "read:*" matches "read:status")
            if perm.ends_with(":*") {
                let prefix = &perm[..perm.len() - 1]; // "read:"
                if permission.starts_with(prefix) {
                    return true;
                }
            }
        }

        false
    }
}

fn valid_typed_identity(value: &str) -> bool {
    if let Some(identity) = value.strip_prefix("dns:") {
        return !identity.is_empty()
            && identity.len() <= 253
            && identity == identity.to_ascii_lowercase()
            && identity.as_bytes()[0].is_ascii_alphanumeric()
            && !identity.contains("..")
            && identity.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".-".contains(&byte)
            });
    }
    if let Some(identity) = value.strip_prefix("email:") {
        return identity == identity.to_ascii_lowercase()
            && identity.contains('@')
            && valid_identity_text(identity, 512);
    }
    if let Some(identity) = value.strip_prefix("uri:") {
        return identity.contains(':') && valid_identity_text(identity, 1024);
    }
    value
        .strip_prefix("cn:")
        .is_some_and(|identity| valid_identity_text(identity, 512))
}

fn valid_identity_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
}

fn valid_permission(value: &str) -> bool {
    let Some((verb, resource)) = value.split_once(':') else {
        return false;
    };
    matches!(verb, "read" | "write")
        && !resource.is_empty()
        && resource.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_*".contains(&byte)
        })
        && (!resource.contains('*') || resource == "*")
}

/// Middleware for RBAC permission checking.
#[derive(Clone)]
pub struct RbacMiddleware {
    config: RbacConfig,
    required_permission: String,
}

impl RbacMiddleware {
    pub fn new(config: RbacConfig, required_permission: impl Into<String>) -> Self {
        Self {
            config,
            required_permission: required_permission.into(),
        }
    }

    /// Middleware handler.
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | IA-3 | Device Identification | Extracts identity from TLS client certificate extension |
    /// | AC-3 | Access Enforcement | Denies requests without valid certificate identity |
    pub async fn check_permission(&self, mut req: Request<Body>, next: Next) -> Response {
        // NIST IA-3: Extract user identity from TLS client certificate extension.
        // The TlsClientIdentity is inserted by the TLS connection handler after
        // validating the client certificate -- it cannot be spoofed via headers.
        let user = self.extract_user_identity(&req);

        if !self.config.has_permission(&user, &self.required_permission) {
            warn!(
                user = %user,
                permission = %self.required_permission,
                "access denied: insufficient permissions"
            );
            let correlation_id = req
                .headers()
                .get("x-correlation-id")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| Uuid::parse_str(value).ok())
                .unwrap_or_else(Uuid::now_v7);
            let body = AuthorizationProblem {
                problem_type: "about:blank",
                title: "Forbidden",
                status: StatusCode::FORBIDDEN.as_u16(),
                code: "permission_denied",
                correlation_id: correlation_id.to_string(),
            };
            let mut response = (StatusCode::FORBIDDEN, Json(body)).into_response();
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/problem+json"),
            );
            return response;
        }

        req.extensions_mut().insert(TlsClientIdentity {
            certificate_identity: user,
        });
        next.run(req).await
    }

    /// Extract user identity from request extensions (production) or header (test only).
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | IA-3 | Device Identification | Production path uses TLS certificate extension only |
    fn extract_user_identity(&self, req: &Request<Body>) -> String {
        if let Some(peer) = req.extensions().get::<TlsPeerIdentity>() {
            let mut matches = peer
                .candidates
                .iter()
                .filter(|candidate| self.config.users.contains_key(*candidate));
            let Some(identity) = matches.next() else {
                return "anonymous".to_string();
            };
            if matches.next().is_some() {
                warn!("client certificate matches multiple RBAC identities");
                return "ambiguous".to_string();
            }
            return identity.clone();
        }

        // Test-only fallback: allow X-User-CN header for integration tests
        #[cfg(test)]
        {
            if let Some(val) = req.headers().get("X-User-CN")
                && let Ok(s) = val.to_str()
            {
                return s.to_string();
            }
        }

        "anonymous".to_string()
    }
}

/// Helper to create RBAC middleware for a specific permission.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-3 | Access Enforcement | Creates middleware that enforces permission checks |
///
/// # Arguments
/// * `config` - RBAC configuration (cloned for 'static lifetime)
/// * `permission` - Required permission string (e.g., "read:status")
#[allow(clippy::type_complexity)]
pub fn require_permission(
    config: &RbacConfig,
    permission: &'static str,
) -> impl Fn(
    Request<Body>,
    Next,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>
+ Clone
+ Send
+ Sync
+ 'static {
    let middleware = RbacMiddleware::new(config.clone(), permission);
    move |req: Request<Body>, next: Next| {
        let middleware = middleware.clone();
        Box::pin(async move { middleware.check_permission(req, next).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rbac_admin_has_all_permissions() {
        let mut config = RbacConfig::default();
        config
            .users
            .insert("CN=admin.tacacs.internal".to_string(), "admin".to_string());

        assert!(config.has_permission("CN=admin.tacacs.internal", "read:status"));
        assert!(config.has_permission("CN=admin.tacacs.internal", "write:sessions"));
        assert!(config.has_permission("CN=admin.tacacs.internal", "read:policy"));
    }

    #[test]
    fn test_rbac_operator_limited_write() {
        let mut config = RbacConfig::default();
        config.users.insert(
            "CN=operator.tacacs.internal".to_string(),
            "operator".to_string(),
        );

        assert!(config.has_permission("CN=operator.tacacs.internal", "read:status"));
        assert!(config.has_permission("CN=operator.tacacs.internal", "write:sessions"));
        assert!(!config.has_permission("CN=operator.tacacs.internal", "write:policy"));
    }

    #[test]
    fn test_rbac_viewer_read_only() {
        let mut config = RbacConfig::default();
        config.users.insert(
            "CN=viewer.tacacs.internal".to_string(),
            "viewer".to_string(),
        );

        assert!(config.has_permission("CN=viewer.tacacs.internal", "read:status"));
        assert!(config.has_permission("CN=viewer.tacacs.internal", "read:metrics"));
        assert!(!config.has_permission("CN=viewer.tacacs.internal", "read:policy"));
        assert!(!config.has_permission("CN=viewer.tacacs.internal", "write:sessions"));
    }

    #[test]
    fn test_rbac_unknown_user_denied() {
        let config = RbacConfig::default();
        assert!(!config.has_permission("CN=unknown.tacacs.internal", "read:status"));
    }

    #[test]
    fn peer_identity_selection_fails_closed_on_multiple_rbac_matches() {
        let mut config = RbacConfig::default();
        config
            .users
            .insert("cn:admin.example.mil".to_owned(), "admin".to_owned());
        config
            .users
            .insert("dns:admin.example.mil".to_owned(), "admin".to_owned());
        let middleware = RbacMiddleware::new(config, "read:status");
        let mut request = Request::new(Body::empty());
        request.extensions_mut().insert(TlsPeerIdentity {
            candidates: vec![
                "cn:admin.example.mil".to_owned(),
                "dns:admin.example.mil".to_owned(),
            ],
        });
        assert_eq!(middleware.extract_user_identity(&request), "ambiguous");
    }

    #[test]
    fn production_rbac_config_requires_typed_identities() {
        let mut config = RbacConfig::default();
        config
            .users
            .insert("admin.example.mil".to_owned(), "admin".to_owned());
        assert_eq!(config.validate(), Err("invalid_certificate_identity"));
    }
}
