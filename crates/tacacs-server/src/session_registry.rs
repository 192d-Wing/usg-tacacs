// SPDX-License-Identifier: Apache-2.0
//! Session registry for tracking active TACACS+ connections.
//!
//! # NIST SP 800-53 Rev. 5 Security Controls
//!
//! **Control Implementation Matrix**
//!
//! This module implements controls documented in
//! [../../../docs/NIST-CONTROLS-MAPPING.md](../../../docs/NIST-CONTROLS-MAPPING.md).
//!
//! | Control | Family | Status | Validated | Primary Functions |
//! |---------|--------|--------|-----------|-------------------|
//! | AC-10 | Access Control | Implemented | 2026-01-31 | See functions below |
//! | AC-11 | Access Control | Implemented | 2026-01-31 | See functions below |
//! | AC-12 | Access Control | Implemented | 2026-01-31 | See functions below |
//! | AU-2 | Audit and Accountability | Implemented | 2026-01-31 | See functions below |
//! | AU-3 | Audit and Accountability | Implemented | 2026-01-31 | See functions below |
//! | SC-23 | System and Communications Protection | Implemented | 2026-01-31 | See functions below |
//! | SC-7 | System and Communications Protection | Implemented | 2026-01-31 | See functions below |
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
//!     "SC",
//!     "SI"
//!   ],
//!   "total_controls": 8,
//!   "file_path": "crates/tacacs-server/src/session_registry.rs"
//! }
//! ```
//!
//! </details>
//!
//! This module provides centralized, thread-safe session tracking for the TACACS+
//! server. It enables the Management API to list active connections, enforce
//! session limits, and support administrative session termination.
//!
//! # Overview
//!
//! The [`SessionRegistry`] maintains a registry of all active client connections,
//! storing metadata such as connection timestamps, authentication state, and
//! activity counts. This information supports:
//!
//! - **Session enumeration**: List all active sessions via the Management API
//! - **Session limits**: Enforce maximum concurrent sessions (total and per-IP)
//! - **Idle timeout**: Automatically terminate sessions exceeding idle thresholds
//! - **Administrative termination**: Force-close sessions by ID or session ID
//! - **Metrics integration**: Track active session counts for monitoring
//!
//! # Usage
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use tacacs_server::session_registry::{SessionRegistry, SessionLimits};
//!
//! // Create registry with limits
//! let limits = SessionLimits {
//!     max_total_sessions: 1000,
//!     max_sessions_per_ip: 10,
//! };
//! let registry = Arc::new(SessionRegistry::with_limits(limits));
//!
//! // Register a new connection (with limit checking)
//! let peer_addr = "192.168.1.100:12345".parse().unwrap();
//! let conn_id = registry.try_register_connection(peer_addr).await?;
//!
//! // Update after authentication
//! registry.update_authentication(conn_id, "admin".to_string(), 42).await;
//!
//! // Record activity on the connection
//! registry.record_activity(conn_id).await;
//!
//! // List all sessions
//! let sessions = registry.list_sessions().await;
//!
//! // Cleanup on disconnect
//! registry.unregister_connection(conn_id).await;
//! ```
//!
//! # Idle Session Sweeping
//!
//! Use [`run_idle_sweep_task`] to automatically terminate idle sessions:
//!
//! ```rust,ignore
//! use std::time::Duration;
//!
//! // Start background task to sweep idle sessions every 30 seconds
//! tokio::spawn(run_idle_sweep_task(
//!     registry.clone(),
//!     Duration::from_secs(300),  // 5 minute idle timeout
//!     Duration::from_secs(30),   // sweep every 30 seconds
//! ));
//! ```
//!
//! # NIST SP 800-53 Security Controls
//!
//! This module implements the following NIST security controls:
//!
//! | Control | Name | Implementation |
//! |---------|------|----------------|
//! | AC-10 | Concurrent Session Control | Session limits and visibility |
//! | AC-11/AC-12 | Session Lock/Termination | Administrative and idle termination |
//! | AU-2/AU-3 | Audit Events | Timestamps and activity counts |
//! | SC-7 | Boundary Protection | Per-IP limits prevent exhaustion attacks |
//! | SC-23 | Session Authenticity | Session ID tracking and validation |
//! | SI-4 | System Monitoring | Real-time session enumeration |

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::metrics::metrics;

/// Error returned when session limits are exceeded.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-10 | Concurrent Session Control | Documents limit violations |
#[derive(Debug, Clone)]
pub enum SessionLimitExceeded {
    /// Total session limit across all IPs was exceeded
    TotalLimit { current: usize, max: usize },
    /// Per-IP session limit was exceeded
    PerIpLimit {
        ip: std::net::IpAddr,
        current: usize,
        max: usize,
    },
}

impl std::fmt::Display for SessionLimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TotalLimit { current, max } => {
                write!(f, "total session limit exceeded ({}/{})", current, max)
            }
            Self::PerIpLimit { ip, current, max } => {
                write!(
                    f,
                    "per-IP session limit exceeded for {} ({}/{})",
                    ip, current, max
                )
            }
        }
    }
}

impl std::error::Error for SessionLimitExceeded {}

/// Global connection ID counter for unique session identification.
static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

/// Information about an active session for API display.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AU-3 | Content of Audit Records | Contains session metadata for audit |
#[derive(Debug, Clone)]
pub struct SessionRecord {
    /// Unique connection ID assigned when connection was established
    pub connection_id: u64,
    /// TACACS+ session ID (if authentication completed)
    pub session_id: Option<u32>,
    /// Remote peer address
    pub peer_addr: SocketAddr,
    /// Authenticated username (if authentication completed)
    pub username: Option<String>,
    /// When the connection was established
    pub connected_at: SystemTime,
    /// When the last activity occurred
    pub last_activity: SystemTime,
    /// Total number of requests processed on this connection
    pub request_count: u64,
    /// Whether this session has been marked for termination
    pub termination_requested: bool,
}

impl SessionRecord {
    /// Create a new session record for a connection.
    fn new(connection_id: u64, peer_addr: SocketAddr) -> Self {
        let now = SystemTime::now();
        Self {
            connection_id,
            session_id: None,
            peer_addr,
            username: None,
            connected_at: now,
            last_activity: now,
            request_count: 0,
            termination_requested: false,
        }
    }

    /// Calculate session duration.
    pub fn duration(&self) -> Duration {
        SystemTime::now()
            .duration_since(self.connected_at)
            .unwrap_or_default()
    }

    /// Calculate time since last activity.
    pub fn idle_duration(&self) -> Duration {
        SystemTime::now()
            .duration_since(self.last_activity)
            .unwrap_or_default()
    }
}

/// Configuration for session limits.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-10 | Concurrent Session Control | Configures session limits |
#[derive(Debug, Clone, Default)]
pub struct SessionLimits {
    /// Maximum total sessions across all IPs (0 = unlimited)
    pub max_total_sessions: usize,
    /// Maximum sessions per IP address (0 = unlimited)
    pub max_sessions_per_ip: usize,
}

/// Thread-safe registry for tracking active sessions.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-10 | Concurrent Session Control | Tracks all active connections |
/// | SI-4 | System Monitoring | Enables session visibility for monitoring |
#[derive(Debug)]
pub struct SessionRegistry {
    /// Map from connection ID to session record
    sessions: RwLock<HashMap<u64, SessionRecord>>,
    /// Session limits configuration
    limits: SessionLimits,
}

impl SessionRegistry {
    /// Create a new empty session registry with no limits.
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            limits: SessionLimits::default(),
        }
    }

    /// Create a new session registry with configured limits.
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | AC-10 | Concurrent Session Control | Configures session limits |
    pub fn with_limits(limits: SessionLimits) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            limits,
        }
    }

    /// Try to register a new connection, checking limits first.
    ///
    /// Returns `Ok(connection_id)` if successful, or `Err` if limits exceeded.
    ///
    /// This method performs the limit check and registration atomically under
    /// a single write lock to prevent race conditions where concurrent requests
    /// could exceed configured limits.
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | AC-10 | Concurrent Session Control | Enforces session limits and tracks new connection |
    /// | AU-2 | Audit Events | Connection establishment is recorded |
    pub async fn try_register_connection(
        &self,
        peer_addr: SocketAddr,
    ) -> Result<u64, SessionLimitExceeded> {
        let mut sessions = self.sessions.write().await;

        // Check total limit
        if self.limits.max_total_sessions > 0 && sessions.len() >= self.limits.max_total_sessions {
            return Err(SessionLimitExceeded::TotalLimit {
                current: sessions.len(),
                max: self.limits.max_total_sessions,
            });
        }

        // Check per-IP limit
        if self.limits.max_sessions_per_ip > 0 {
            let ip = peer_addr.ip();
            let count = sessions.values().filter(|r| r.peer_addr.ip() == ip).count();
            if count >= self.limits.max_sessions_per_ip {
                return Err(SessionLimitExceeded::PerIpLimit {
                    ip,
                    current: count,
                    max: self.limits.max_sessions_per_ip,
                });
            }
        }

        // Register the connection while still holding the lock
        let connection_id = NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
        let record = SessionRecord::new(connection_id, peer_addr);
        sessions.insert(connection_id, record);

        // Update metrics
        metrics().sessions_active.inc();

        debug!(
            connection_id = connection_id,
            peer = %peer_addr,
            "session registered"
        );

        Ok(connection_id)
    }

    /// Register a new connection and return its unique ID.
    ///
    /// Note: This method does not check limits. Use `try_register_connection`
    /// for limit-checked registration.
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | AC-10 | Concurrent Session Control | Tracks new connection for session control |
    /// | AU-2 | Audit Events | Connection establishment is recorded |
    ///
    /// # Security Warning
    ///
    /// **DEPRECATED**: This method bypasses session limits and should not be used.
    /// Use `try_register_connection` instead to enforce concurrent session limits.
    ///
    /// This method is kept for backwards compatibility but will be removed in a future version.
    #[deprecated(
        since = "0.77.0",
        note = "Use try_register_connection() to enforce session limits"
    )]
    #[allow(dead_code)]
    pub async fn register_connection(&self, peer_addr: SocketAddr) -> u64 {
        let connection_id = NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
        let record = SessionRecord::new(connection_id, peer_addr);

        let mut sessions = self.sessions.write().await;
        sessions.insert(connection_id, record);

        // Update metrics
        metrics().sessions_active.inc();

        debug!(
            connection_id = connection_id,
            peer = %peer_addr,
            "session registered"
        );

        connection_id
    }

    /// Update session with authentication information.
    ///
    /// Called after successful authentication to record the username and
    /// session ID for tracking and audit purposes.
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | AU-3 | Content of Audit Records | Records authentication result |
    /// | SC-23 | Session Authenticity | Associates session ID with connection |
    pub async fn update_authentication(
        &self,
        connection_id: u64,
        username: String,
        session_id: u32,
    ) {
        let mut sessions = self.sessions.write().await;
        if let Some(record) = sessions.get_mut(&connection_id) {
            record.username = Some(username.clone());
            record.session_id = Some(session_id);
            record.last_activity = SystemTime::now();

            debug!(
                connection_id = connection_id,
                username = %username,
                session_id = session_id,
                "session authenticated"
            );
        }
    }

    /// Record activity on a connection.
    ///
    /// Updates the last activity timestamp and increments the request counter.
    /// Used for idle timeout enforcement and audit trails.
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | AC-12 | Session Termination | Tracks activity for idle timeout |
    /// | AU-3 | Content of Audit Records | Records request count |
    pub async fn record_activity(&self, connection_id: u64) {
        let mut sessions = self.sessions.write().await;
        if let Some(record) = sessions.get_mut(&connection_id) {
            record.last_activity = SystemTime::now();
            record.request_count += 1;
        }
    }

    /// Unregister a connection when it closes.
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | AU-2 | Audit Events | Connection termination is recorded |
    pub async fn unregister_connection(&self, connection_id: u64) {
        let mut sessions = self.sessions.write().await;
        if let Some(record) = sessions.remove(&connection_id) {
            // Update metrics
            metrics().sessions_active.dec();

            debug!(
                connection_id = connection_id,
                peer = %record.peer_addr,
                duration_secs = record.duration().as_secs(),
                requests = record.request_count,
                "session unregistered"
            );
        }
    }

    /// List all active sessions.
    ///
    /// Returns a snapshot of all currently registered sessions.
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | AC-10 | Concurrent Session Control | Visibility into active sessions |
    /// | SI-4 | System Monitoring | Session enumeration for monitoring |
    pub async fn list_sessions(&self) -> Vec<SessionRecord> {
        let sessions = self.sessions.read().await;
        sessions.values().cloned().collect()
    }

    /// Get the count of active sessions.
    #[allow(dead_code)]
    pub async fn session_count(&self) -> usize {
        let sessions = self.sessions.read().await;
        sessions.len()
    }

    /// Request termination of a session by connection ID.
    ///
    /// Marks the session for termination. The actual connection close is
    /// handled by the connection handler when it next checks this flag.
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | AC-12 | Session Termination | Administrative session termination |
    ///
    /// Returns `true` if the session was found and marked, `false` otherwise.
    pub async fn terminate_session(&self, connection_id: u64) -> bool {
        let mut sessions = self.sessions.write().await;
        if let Some(record) = sessions.get_mut(&connection_id) {
            record.termination_requested = true;
            debug!(
                connection_id = connection_id,
                peer = %record.peer_addr,
                "session termination requested"
            );
            true
        } else {
            false
        }
    }

    /// Request termination of a session by TACACS+ session ID.
    ///
    /// Searches for a session with the given TACACS+ session ID and marks it
    /// for termination.
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | AC-12 | Session Termination | Administrative session termination |
    ///
    /// Returns `true` if a matching session was found and marked, `false` otherwise.
    #[allow(dead_code)]
    pub async fn terminate_by_session_id(&self, session_id: u32) -> bool {
        let mut sessions = self.sessions.write().await;
        for record in sessions.values_mut() {
            if record.session_id == Some(session_id) {
                record.termination_requested = true;
                debug!(
                    connection_id = record.connection_id,
                    session_id = session_id,
                    "session termination requested by session_id"
                );
                return true;
            }
        }
        false
    }

    /// Check if a connection has been marked for termination.
    ///
    /// Called by connection handlers to check if they should close.
    pub async fn is_termination_requested(&self, connection_id: u64) -> bool {
        let sessions = self.sessions.read().await;
        sessions
            .get(&connection_id)
            .map(|r| r.termination_requested)
            .unwrap_or(false)
    }

    /// Mark sessions exceeding idle timeout for termination.
    ///
    /// Scans all sessions and marks those that have been idle longer than
    /// `idle_timeout` for termination. Returns the number of sessions marked.
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | AC-12 | Session Termination | Automatic idle timeout enforcement |
    /// | AU-2 | Audit Events | Logs idle timeout events |
    pub async fn sweep_idle_sessions(&self, idle_timeout: Duration) -> usize {
        let mut sessions = self.sessions.write().await;
        let mut terminated: usize = 0;

        for record in sessions.values_mut() {
            if !record.termination_requested && record.idle_duration() > idle_timeout {
                record.termination_requested = true;
                terminated = terminated.saturating_add(1);
                debug!(
                    connection_id = record.connection_id,
                    peer = %record.peer_addr,
                    idle_secs = record.idle_duration().as_secs(),
                    "session marked for idle timeout termination"
                );
            }
        }

        if terminated > 0 {
            debug!(count = terminated, "idle session sweep completed");
        }

        terminated
    }

    /// Count sessions from a specific IP address.
    ///
    /// Used for enforcing per-IP session limits.
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | AC-10 | Concurrent Session Control | Per-IP session counting |
    #[allow(dead_code)]
    pub async fn count_sessions_from_ip(&self, ip: std::net::IpAddr) -> usize {
        let sessions = self.sessions.read().await;
        sessions.values().filter(|r| r.peer_addr.ip() == ip).count()
    }
}

/// Run a background task that periodically sweeps idle sessions.
///
/// This task runs indefinitely, checking for idle sessions at the specified
/// interval and marking those exceeding `idle_timeout` for termination.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-12 | Session Termination | Automatic idle timeout enforcement |
/// | SI-4 | System Monitoring | Continuous session health monitoring |
///
/// # Arguments
/// * `registry` - The session registry to sweep
/// * `idle_timeout` - Sessions idle longer than this will be terminated
/// * `sweep_interval` - How often to run the sweep (typically idle_timeout / 2 or /4)
pub async fn run_idle_sweep_task(
    registry: Arc<SessionRegistry>,
    idle_timeout: Duration,
    sweep_interval: Duration,
) {
    info!(
        idle_timeout_secs = idle_timeout.as_secs(),
        sweep_interval_secs = sweep_interval.as_secs(),
        "starting idle session sweep task"
    );

    loop {
        tokio::time::sleep(sweep_interval).await;
        let terminated = registry.sweep_idle_sessions(idle_timeout).await;
        if terminated > 0 {
            info!(
                terminated = terminated,
                "idle session sweep terminated sessions"
            );
        }
    }
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    #[tokio::test]
    async fn test_register_and_unregister() {
        let registry = SessionRegistry::new();
        let addr = test_addr(12345);

        let conn_id = registry.try_register_connection(addr).await.unwrap();
        assert!(conn_id > 0);
        assert_eq!(registry.session_count().await, 1);

        registry.unregister_connection(conn_id).await;
        assert_eq!(registry.session_count().await, 0);
    }

    #[tokio::test]
    async fn test_update_authentication() {
        let registry = SessionRegistry::new();
        let addr = test_addr(12346);

        let conn_id = registry.try_register_connection(addr).await.unwrap();
        registry
            .update_authentication(conn_id, "testuser".to_string(), 42)
            .await;

        let sessions = registry.list_sessions().await;
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].username.as_deref(), Some("testuser"));
        assert_eq!(sessions[0].session_id, Some(42));
    }

    #[tokio::test]
    async fn test_record_activity() {
        let registry = SessionRegistry::new();
        let addr = test_addr(12347);

        let conn_id = registry.try_register_connection(addr).await.unwrap();
        assert_eq!(registry.list_sessions().await[0].request_count, 0);

        registry.record_activity(conn_id).await;
        registry.record_activity(conn_id).await;
        registry.record_activity(conn_id).await;

        assert_eq!(registry.list_sessions().await[0].request_count, 3);
    }

    #[tokio::test]
    async fn test_terminate_session() {
        let registry = SessionRegistry::new();
        let addr = test_addr(12348);

        let conn_id = registry.try_register_connection(addr).await.unwrap();
        assert!(!registry.is_termination_requested(conn_id).await);

        let result = registry.terminate_session(conn_id).await;
        assert!(result);
        assert!(registry.is_termination_requested(conn_id).await);
    }

    #[tokio::test]
    async fn test_terminate_by_session_id() {
        let registry = SessionRegistry::new();
        let addr = test_addr(12349);

        let conn_id = registry.try_register_connection(addr).await.unwrap();
        registry
            .update_authentication(conn_id, "user".to_string(), 999)
            .await;

        let result = registry.terminate_by_session_id(999).await;
        assert!(result);
        assert!(registry.is_termination_requested(conn_id).await);
    }

    #[tokio::test]
    async fn test_terminate_nonexistent() {
        let registry = SessionRegistry::new();

        let result = registry.terminate_session(99999).await;
        assert!(!result);

        let result = registry.terminate_by_session_id(99999).await;
        assert!(!result);
    }

    #[tokio::test]
    async fn test_multiple_sessions() {
        let registry = SessionRegistry::new();

        let conn1 = registry
            .try_register_connection(test_addr(10001))
            .await
            .unwrap();
        let conn2 = registry
            .try_register_connection(test_addr(10002))
            .await
            .unwrap();
        let conn3 = registry
            .try_register_connection(test_addr(10003))
            .await
            .unwrap();

        assert_eq!(registry.session_count().await, 3);

        registry.unregister_connection(conn2).await;
        assert_eq!(registry.session_count().await, 2);

        let sessions = registry.list_sessions().await;
        let conn_ids: Vec<u64> = sessions.iter().map(|s| s.connection_id).collect();
        assert!(conn_ids.contains(&conn1));
        assert!(!conn_ids.contains(&conn2));
        assert!(conn_ids.contains(&conn3));
    }

    #[tokio::test]
    async fn test_session_record_duration() {
        let registry = SessionRegistry::new();
        let addr = test_addr(12350);

        let conn_id = registry.try_register_connection(addr).await.unwrap();

        // Small delay to ensure duration > 0
        tokio::time::sleep(Duration::from_millis(10)).await;

        let sessions = registry.list_sessions().await;
        assert!(sessions[0].duration().as_millis() >= 10);

        registry.unregister_connection(conn_id).await;
    }

    #[tokio::test]
    async fn test_sweep_idle_sessions() {
        let registry = SessionRegistry::new();
        let addr = test_addr(12351);

        let conn_id = registry.try_register_connection(addr).await.unwrap();

        // Immediate sweep with short timeout shouldn't terminate (just registered)
        let terminated = registry.sweep_idle_sessions(Duration::from_secs(1)).await;
        assert_eq!(terminated, 0);
        assert!(!registry.is_termination_requested(conn_id).await);

        // Wait for session to become idle
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Sweep with very short timeout should mark for termination
        let terminated = registry
            .sweep_idle_sessions(Duration::from_millis(10))
            .await;
        assert_eq!(terminated, 1);
        assert!(registry.is_termination_requested(conn_id).await);

        // Subsequent sweep should not re-terminate
        let terminated = registry
            .sweep_idle_sessions(Duration::from_millis(10))
            .await;
        assert_eq!(terminated, 0);

        registry.unregister_connection(conn_id).await;
    }

    #[tokio::test]
    async fn test_sweep_idle_preserves_active_sessions() {
        let registry = SessionRegistry::new();

        let idle_conn = registry
            .try_register_connection(test_addr(12352))
            .await
            .unwrap();
        let active_conn = registry
            .try_register_connection(test_addr(12353))
            .await
            .unwrap();

        // Wait for both to become "idle"
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Refresh activity on one connection
        registry.record_activity(active_conn).await;

        // Sweep should only terminate the idle one
        let terminated = registry
            .sweep_idle_sessions(Duration::from_millis(10))
            .await;
        assert_eq!(terminated, 1);
        assert!(registry.is_termination_requested(idle_conn).await);
        assert!(!registry.is_termination_requested(active_conn).await);

        registry.unregister_connection(idle_conn).await;
        registry.unregister_connection(active_conn).await;
    }

    #[tokio::test]
    async fn test_count_sessions_from_ip() {
        let registry = SessionRegistry::new();

        // Register 3 sessions from same IP (different ports)
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let _conn1 = registry
            .try_register_connection(SocketAddr::new(ip, 10001))
            .await
            .unwrap();
        let _conn2 = registry
            .try_register_connection(SocketAddr::new(ip, 10002))
            .await
            .unwrap();
        let _conn3 = registry
            .try_register_connection(SocketAddr::new(ip, 10003))
            .await
            .unwrap();

        // Register 1 session from different IP
        let other_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));
        let _conn4 = registry
            .try_register_connection(SocketAddr::new(other_ip, 10004))
            .await
            .unwrap();

        assert_eq!(registry.count_sessions_from_ip(ip).await, 3);
        assert_eq!(registry.count_sessions_from_ip(other_ip).await, 1);
        assert_eq!(
            registry
                .count_sessions_from_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
                .await,
            0
        );
    }

    #[tokio::test]
    async fn test_session_limits_total() {
        let limits = SessionLimits {
            max_total_sessions: 2,
            max_sessions_per_ip: 0,
        };
        let registry = SessionRegistry::with_limits(limits);

        // First two should succeed
        let result1 = registry.try_register_connection(test_addr(10001)).await;
        assert!(result1.is_ok());

        let result2 = registry.try_register_connection(test_addr(10002)).await;
        assert!(result2.is_ok());

        // Third should fail
        let result3 = registry.try_register_connection(test_addr(10003)).await;
        assert!(result3.is_err());
        assert!(matches!(
            result3.unwrap_err(),
            SessionLimitExceeded::TotalLimit { current: 2, max: 2 }
        ));

        // After unregistering one, should succeed again
        registry.unregister_connection(result1.unwrap()).await;
        let result4 = registry.try_register_connection(test_addr(10004)).await;
        assert!(result4.is_ok());
    }

    #[tokio::test]
    async fn test_session_limits_per_ip() {
        let limits = SessionLimits {
            max_total_sessions: 0,
            max_sessions_per_ip: 2,
        };
        let registry = SessionRegistry::with_limits(limits);

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

        // First two from same IP should succeed
        let result1 = registry
            .try_register_connection(SocketAddr::new(ip, 10001))
            .await;
        assert!(result1.is_ok());

        let result2 = registry
            .try_register_connection(SocketAddr::new(ip, 10002))
            .await;
        assert!(result2.is_ok());

        // Third from same IP should fail
        let result3 = registry
            .try_register_connection(SocketAddr::new(ip, 10003))
            .await;
        assert!(result3.is_err());
        assert!(matches!(
            result3.unwrap_err(),
            SessionLimitExceeded::PerIpLimit {
                current: 2,
                max: 2,
                ..
            }
        ));

        // Different IP should still succeed
        let other_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));
        let result4 = registry
            .try_register_connection(SocketAddr::new(other_ip, 10001))
            .await;
        assert!(result4.is_ok());
    }

    #[tokio::test]
    async fn test_session_limits_combined() {
        let limits = SessionLimits {
            max_total_sessions: 3,
            max_sessions_per_ip: 2,
        };
        let registry = SessionRegistry::with_limits(limits);

        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));

        // Two from IP1
        assert!(
            registry
                .try_register_connection(SocketAddr::new(ip1, 10001))
                .await
                .is_ok()
        );
        assert!(
            registry
                .try_register_connection(SocketAddr::new(ip1, 10002))
                .await
                .is_ok()
        );

        // Third from IP1 fails (per-IP limit)
        let result = registry
            .try_register_connection(SocketAddr::new(ip1, 10003))
            .await;
        assert!(matches!(
            result.unwrap_err(),
            SessionLimitExceeded::PerIpLimit { .. }
        ));

        // One from IP2 succeeds (total now 3)
        assert!(
            registry
                .try_register_connection(SocketAddr::new(ip2, 10001))
                .await
                .is_ok()
        );

        // Second from IP2 fails (total limit)
        let result = registry
            .try_register_connection(SocketAddr::new(ip2, 10002))
            .await;
        assert!(matches!(
            result.unwrap_err(),
            SessionLimitExceeded::TotalLimit { .. }
        ));
    }

    #[tokio::test]
    async fn test_session_limits_disabled() {
        // With zero limits, no restrictions apply
        let limits = SessionLimits {
            max_total_sessions: 0,
            max_sessions_per_ip: 0,
        };
        let registry = SessionRegistry::with_limits(limits);

        // Should be able to register many sessions
        for i in 0..100 {
            let result = registry.try_register_connection(test_addr(10000 + i)).await;
            assert!(result.is_ok());
        }
        assert_eq!(registry.session_count().await, 100);
    }
}
