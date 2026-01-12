// SPDX-License-Identifier: Apache-2.0
//! Data models for the Management API.

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
    /// Unique connection/session identifier
    pub id: u32,
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
