// SPDX-License-Identifier: Apache-2.0
//! Role-Based Access Control for the Management API.
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
    body::Body,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::warn;

/// RBAC configuration.
///
/// # NIST Controls
/// - **AC-2 (Account Management)**: User-to-role mapping
/// - **AC-6 (Least Privilege)**: Granular permission definitions
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
    /// Check if a user has a specific permission.
    ///
    /// # NIST Controls
    /// - **AC-3 (Access Enforcement)**: Enforces permission checks
    /// - **AU-12 (Audit Generation)**: Logs permission denials
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
    pub async fn check_permission(
        &self,
        req: Request<Body>,
        next: Next,
    ) -> Result<Response, StatusCode> {
        // Extract user from TLS client certificate CN
        // For now, we'll use a header for testing (X-User-CN)
        // In production, this should come from the TLS client certificate
        let user = req
            .headers()
            .get("X-User-CN")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("anonymous");

        if !self.config.has_permission(user, &self.required_permission) {
            warn!(
                user = %user,
                permission = %self.required_permission,
                "access denied: insufficient permissions"
            );
            return Err(StatusCode::FORBIDDEN);
        }

        Ok(next.run(req).await)
    }
}

/// Helper to create RBAC middleware for a specific permission.
pub fn require_permission(
    config: &RbacConfig,
    permission: impl Into<String>,
) -> impl Fn(
    Request<Body>,
    Next,
)
    -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, StatusCode>> + Send>>
+ Clone {
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
}
