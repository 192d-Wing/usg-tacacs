// SPDX-License-Identifier: Apache-2.0
//! Data models for the Management API.
//!
//! # NIST SP 800-53 Rev. 5 Security Controls
//!
//! **Control Implementation Matrix**
//!
//! This module implements controls documented in
//! [NIST-CONTROLS-MAPPING.md](../../../../docs/NIST-CONTROLS-MAPPING.md).
//!
//! | Control | Family | Status | Validated | Primary Functions |
//! |---------|--------|--------|-----------|-------------------|
//! | AC-10 | Access Control | Implemented | 2026-01-26 | [`SessionInfo`] |
//! | AU-3 | Audit/Accountability | Implemented | 2026-01-26 | [`SessionInfo`], [`AuditEvent`] |
//! | AU-12 | Audit/Accountability | Implemented | 2026-01-26 | [`AuditEvent`] |
//! | CM-3 | Config Management | Implemented | 2026-01-26 | [`PolicyReloadResponse`] |
//!
//! <details>
//! <summary><b>Validation Metadata (JSON)</b></summary>
//!
//! ```json
//! {
//!   "nist_framework": "NIST SP 800-53 Rev. 5",
//!   "software_version": "0.77.1",
//!   "last_validation": "2026-01-26",
//!   "control_families": ["AC", "AU", "CM"],
//!   "total_controls": 4,
//!   "file_path": "crates/tacacs-server/src/api/models.rs"
//! }
//! ```
//!
//! </details>
//!
//! ## Control Details
//!
//! ### AC-10: Concurrent Session Control
//! - **Implementation:** Session data structures provide visibility into active connections
//! - **Evidence:** SessionInfo tracks connection metadata, enables session monitoring
//! - **Reference:** [AC-10](../../../../docs/NIST-CONTROLS-MAPPING.md#ac-10-concurrent-session-control)
//!
//! ### AU-3: Content of Audit Records
//! - **Implementation:** Structured audit event data with comprehensive session context
//! - **Evidence:** Timestamp, peer address, username, event type, reason, detail fields
//! - **Reference:** [AU-3](../../../../docs/NIST-CONTROLS-MAPPING.md#au-3-content-of-audit-records)
//!
//! ### AU-12: Audit Generation
//! - **Implementation:** API models for audit event query and retrieval
//! - **Evidence:** AuditEvent struct with all required audit fields
//! - **Reference:** [AU-12](../../../../docs/NIST-CONTROLS-MAPPING.md#au-12-audit-generation)
//!
//! ### CM-3: Configuration Change Control
//! - **Implementation:** Policy reload response models track configuration changes
//! - **Evidence:** PolicyReloadResponse with status and metadata
//! - **Reference:** [CM-3](../../../../docs/NIST-CONTROLS-MAPPING.md#cm-3-configuration-change-control)

use serde::{Deserialize, Serialize};

/// Server status response.
#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub stats: ServerStats,
}

/// Server statistics.
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerStats {
    pub total_connections: u64,
    pub active_connections: u64,
    pub total_authn_requests: u64,
    pub total_authz_requests: u64,
    pub total_acct_requests: u64,
    pub authn_success_rate: f64,
    pub authz_success_rate: f64,
}

/// Active session information.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AU-3 | Content of Audit Records | Contains session metadata for audit |
/// | AC-10 | Concurrent Session Control | Provides session visibility |
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionInfo {
    /// Unique connection/session identifier (u64 to prevent overflow after 4B connections)
    pub id: u64,
    /// Remote peer address (IP:port)
    pub peer_addr: String,
    /// Authenticated username (if authentication completed)
    pub username: Option<String>,
    /// Unix timestamp when session started
    pub start_time: u64,
    /// Seconds since last activity
    pub idle_seconds: u64,
    /// Total requests processed on this session
    pub request_count: u64,
}

/// List of active sessions.
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionsResponse {
    pub sessions: Vec<SessionInfo>,
    pub total: usize,
}

/// Policy information response.
#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyResponse {
    pub rule_count: usize,
    pub last_loaded: String,
    pub source: String,
}

/// Configuration response (sanitized).
#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigResponse {
    pub listen_addrs: Vec<String>,
    pub tls_enabled: bool,
    pub ldap_enabled: bool,
    pub policy_source: String,
    pub metrics_enabled: bool,
    pub api_enabled: bool,
}

/// Generic success response.
#[derive(Debug, Serialize, Deserialize)]
pub struct SuccessResponse {
    pub success: bool,
    pub message: String,
}

/// Generic error response.
#[allow(dead_code)] // Will be used for error handling in future phases
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: String,
}

/// Metrics export format.
#[allow(dead_code)] // Will be used for metrics format selection in future phases
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricsFormat {
    Prometheus,
    Json,
}

/// Policy upload request.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | CM-3 | Configuration Change Control | API-based policy updates with validation |
/// | AU-12 | Audit Generation | Policy upload attempts are logged |
#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyUploadRequest {
    /// The policy JSON content as a string
    pub policy: String,
    /// Optional: validate against schema before applying
    #[serde(default)]
    pub validate: bool,
}

/// Policy upload response.
#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyUploadResponse {
    pub success: bool,
    pub message: String,
    /// Number of rules in the uploaded policy
    pub rule_count: Option<usize>,
}

/// A user record returned by the management API.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-2 | Account Management | Exposes user enabled/disabled state |
#[derive(Debug, Serialize, Deserialize)]
pub struct UserRecord {
    pub id: i64,
    pub username: String,
    pub enabled: bool,
    pub created_at: String,
}

/// Response for the list-users endpoint.
#[derive(Debug, Serialize, Deserialize)]
pub struct UsersResponse {
    pub users: Vec<UserRecord>,
    pub total: usize,
}

/// A single SSH public key record.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | IA-5(2) | PKI-Based Authentication | Public key metadata for management |
#[derive(Debug, Serialize, Deserialize)]
pub struct SshKeyRecord {
    pub id: i64,
    pub key_type: String,
    pub key_data: String,
    pub comment: String,
    pub created_at: String,
}

/// Response for listing a user's SSH keys.
#[derive(Debug, Serialize, Deserialize)]
pub struct SshKeysResponse {
    pub username: String,
    pub keys: Vec<SshKeyRecord>,
    pub total: usize,
}

/// Request body for adding an SSH key.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | IA-5(2) | PKI-Based Authentication | Registers a new public key for a user |
#[derive(Debug, Serialize, Deserialize)]
pub struct AddSshKeyRequest {
    /// SSH key type, e.g. `ssh-ed25519`.
    pub key_type: String,
    /// Base64-encoded key material (the second field in authorized_keys format).
    pub key_data: String,
    /// Optional free-text comment (third field in authorized_keys format).
    #[serde(default)]
    pub comment: String,
}

/// Response for a successful SSH key addition.
#[derive(Debug, Serialize, Deserialize)]
pub struct AddSshKeyResponse {
    pub success: bool,
    pub message: String,
    pub key_id: Option<i64>,
}
