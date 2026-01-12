// SPDX-License-Identifier: Apache-2.0
//! Session registry for tracking active TACACS+ connections.
//!
//! Provides centralized session tracking for the Management API to list
//! active connections and support session termination requests.
//!
//! # NIST SP 800-53 Security Controls
//!
//! This module implements the following NIST security controls:
//!
//! - **AC-10 (Concurrent Session Control)**: Provides visibility into all
//!   active sessions for monitoring concurrent connections.
//!
//! - **AC-11/AC-12 (Session Lock/Termination)**: Supports session termination
//!   via the Management API for administrative session control.
//!
//! - **AU-2/AU-3 (Audit Events)**: Session records include timestamps and
//!   activity counts for audit trail purposes.
//!
//! - **SC-23 (Session Authenticity)**: Tracks session IDs for session
//!   identification and validation.
//!
//! - **SI-4 (System Monitoring)**: Enables real-time session monitoring
//!   through the Management API.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tracing::debug;

use crate::metrics::metrics;

/// Global connection ID counter for unique session identification.
static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

/// Information about an active session for API display.
///
/// # NIST Controls
/// - **AU-3 (Content of Audit Records)**: Contains session metadata for audit
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
        self.connected_at.elapsed().unwrap_or_default()
    }

    /// Calculate time since last activity.
    pub fn idle_duration(&self) -> Duration {
        self.last_activity.elapsed().unwrap_or_default()
    }
}

/// Thread-safe registry for tracking active sessions.
///
/// # NIST Controls
/// - **AC-10 (Concurrent Session Control)**: Tracks all active connections
/// - **SI-4 (System Monitoring)**: Enables session visibility for monitoring
#[derive(Debug)]
pub struct SessionRegistry {
    /// Map from connection ID to session record
    sessions: RwLock<HashMap<u64, SessionRecord>>,
}

impl SessionRegistry {
    /// Create a new empty session registry.
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Register a new connection and return its unique ID.
    ///
    /// # NIST Controls
    /// - **AC-10**: Tracks new connection for session control
    /// - **AU-2 (Audit Events)**: Connection establishment is recorded
    pub async fn register_connection(&self, peer_addr: SocketAddr) -> u64 {
        let connection_id = NEXT_CONNECTION_ID.fetch_add(1, Ordering::SeqCst);
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
    /// - **AU-3 (Content of Audit Records)**: Records authentication result
    /// - **SC-23 (Session Authenticity)**: Associates session ID with connection
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
    /// - **AC-12 (Session Termination)**: Tracks activity for idle timeout
    /// - **AU-3 (Content of Audit Records)**: Records request count
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
    /// - **AU-2 (Audit Events)**: Connection termination is recorded
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
    /// - **AC-10 (Concurrent Session Control)**: Visibility into active sessions
    /// - **SI-4 (System Monitoring)**: Session enumeration for monitoring
    pub async fn list_sessions(&self) -> Vec<SessionRecord> {
        let sessions = self.sessions.read().await;
        sessions.values().cloned().collect()
    }

    /// Get the count of active sessions.
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
    /// - **AC-12 (Session Termination)**: Administrative session termination
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
    /// - **AC-12 (Session Termination)**: Administrative session termination
    ///
    /// Returns `true` if a matching session was found and marked, `false` otherwise.
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

        let conn_id = registry.register_connection(addr).await;
        assert!(conn_id > 0);
        assert_eq!(registry.session_count().await, 1);

        registry.unregister_connection(conn_id).await;
        assert_eq!(registry.session_count().await, 0);
    }

    #[tokio::test]
    async fn test_update_authentication() {
        let registry = SessionRegistry::new();
        let addr = test_addr(12346);

        let conn_id = registry.register_connection(addr).await;
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

        let conn_id = registry.register_connection(addr).await;
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

        let conn_id = registry.register_connection(addr).await;
        assert!(!registry.is_termination_requested(conn_id).await);

        let result = registry.terminate_session(conn_id).await;
        assert!(result);
        assert!(registry.is_termination_requested(conn_id).await);
    }

    #[tokio::test]
    async fn test_terminate_by_session_id() {
        let registry = SessionRegistry::new();
        let addr = test_addr(12349);

        let conn_id = registry.register_connection(addr).await;
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

        let conn1 = registry.register_connection(test_addr(10001)).await;
        let conn2 = registry.register_connection(test_addr(10002)).await;
        let conn3 = registry.register_connection(test_addr(10003)).await;

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

        let conn_id = registry.register_connection(addr).await;

        // Small delay to ensure duration > 0
        tokio::time::sleep(Duration::from_millis(10)).await;

        let sessions = registry.list_sessions().await;
        assert!(sessions[0].duration().as_millis() >= 10);

        registry.unregister_connection(conn_id).await;
    }
}
