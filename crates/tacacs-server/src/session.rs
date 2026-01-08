// SPDX-License-Identifier: Apache-2.0
//! Session state management for TACACS+ connections.
//!
//! # NIST SP 800-53 Security Controls
//!
//! This module implements the following NIST security controls:
//!
//! - **SC-23 (Session Authenticity)**: Tracks session state including session ID,
//!   user identity, and connection status per RFC 8907.
//!
//! - **AU-2/AU-3 (Audit Events/Content)**: Task ID tracking enables correlation
//!   of accounting records (start/stop/watchdog) for audit trails.
//!
//! - **SI-7 (Software/Information Integrity)**: Enforces RFC 8907 task_id reuse
//!   violations to detect protocol anomalies.

use std::collections::HashSet;

#[derive(Debug, Default)]
pub struct SingleConnectState {
    pub user: Option<String>,
    pub active: bool,
    pub locked: bool,
    pub session: Option<u32>,
}

impl SingleConnectState {
    pub fn reset(&mut self) {
        self.user = None;
        self.active = false;
        self.locked = false;
        self.session = None;
    }

    pub fn activate(&mut self, user: String, session: u32) {
        self.user = Some(user);
        self.active = true;
        self.locked = true;
        self.session = Some(session);
    }
}

/// Tracks active accounting task_ids per connection to enforce RFC 8907:
/// "Clients MUST NOT reuse a task_id in a start record until it has sent
/// a stop record for that task_id."
///
/// # NIST Controls
/// - **AU-2/AU-3 (Audit Events)**: Enables correlation of start/stop/watchdog
///   accounting records for complete audit trails
/// - **SI-7 (Information Integrity)**: Detects protocol violations that may
///   indicate misconfiguration or attack attempts
#[derive(Debug, Default)]
pub struct TaskIdTracker {
    /// Set of task_ids that have received a START but not yet a STOP.
    active: HashSet<u32>,
}

impl TaskIdTracker {
    /// Record a START accounting event. Returns an error message if the
    /// task_id is already active (reuse violation per RFC 8907).
    pub fn start(&mut self, task_id: u32) -> Result<(), &'static str> {
        if self.active.contains(&task_id) {
            return Err(
                "task_id reuse: start record received for already-active task_id (RFC 8907 violation)",
            );
        }
        self.active.insert(task_id);
        Ok(())
    }

    /// Record a STOP accounting event. Returns an error message if no
    /// matching START was previously received.
    pub fn stop(&mut self, task_id: u32) -> Result<(), &'static str> {
        if !self.active.remove(&task_id) {
            // RFC 8907 says start and stop must match, but we issue a warning
            // rather than error since some NADs may send orphan stops.
            return Err("task_id mismatch: stop record for unknown task_id");
        }
        Ok(())
    }

    /// Record a WATCHDOG accounting event. The task_id must be active.
    pub fn watchdog(&mut self, task_id: u32) -> Result<(), &'static str> {
        if !self.active.contains(&task_id) {
            return Err("task_id mismatch: watchdog record for unknown task_id");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== SingleConnectState Tests ====================

    #[test]
    fn single_connect_state_default() {
        let state = SingleConnectState::default();
        assert!(state.user.is_none());
        assert!(!state.active);
        assert!(!state.locked);
        assert!(state.session.is_none());
    }

    #[test]
    fn single_connect_state_activate() {
        let mut state = SingleConnectState::default();
        state.activate("alice".to_string(), 12345);

        assert_eq!(state.user, Some("alice".to_string()));
        assert!(state.active);
        assert!(state.locked);
        assert_eq!(state.session, Some(12345));
    }

    #[test]
    fn single_connect_state_reset() {
        let mut state = SingleConnectState::default();
        state.activate("bob".to_string(), 99999);
        state.reset();

        assert!(state.user.is_none());
        assert!(!state.active);
        assert!(!state.locked);
        assert!(state.session.is_none());
    }

    // ==================== TaskIdTracker Tests ====================

    #[test]
    fn task_id_tracker_start_stop_sequence() {
        let mut tracker = TaskIdTracker::default();

        // Start a task
        assert!(tracker.start(100).is_ok());

        // Stop the task
        assert!(tracker.stop(100).is_ok());

        // Can reuse the same task_id after stop
        assert!(tracker.start(100).is_ok());
    }

    #[test]
    fn task_id_tracker_rejects_duplicate_start() {
        let mut tracker = TaskIdTracker::default();

        assert!(tracker.start(200).is_ok());

        // Starting same task_id again should fail (RFC 8907 violation)
        let result = tracker.start(200);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("RFC 8907"));
    }

    #[test]
    fn task_id_tracker_stop_unknown_task() {
        let mut tracker = TaskIdTracker::default();

        // Stopping a task that was never started
        let result = tracker.stop(300);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown task_id"));
    }

    #[test]
    fn task_id_tracker_watchdog_active_task() {
        let mut tracker = TaskIdTracker::default();

        tracker.start(400).unwrap();

        // Watchdog should succeed for active task
        assert!(tracker.watchdog(400).is_ok());

        // Multiple watchdogs are fine
        assert!(tracker.watchdog(400).is_ok());
    }

    #[test]
    fn task_id_tracker_watchdog_unknown_task() {
        let mut tracker = TaskIdTracker::default();

        // Watchdog for unknown task should fail
        let result = tracker.watchdog(500);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown task_id"));
    }

    #[test]
    fn task_id_tracker_watchdog_after_stop_fails() {
        let mut tracker = TaskIdTracker::default();

        tracker.start(600).unwrap();
        tracker.stop(600).unwrap();

        // Watchdog after stop should fail
        let result = tracker.watchdog(600);
        assert!(result.is_err());
    }

    #[test]
    fn task_id_tracker_multiple_concurrent_tasks() {
        let mut tracker = TaskIdTracker::default();

        // Start multiple tasks
        assert!(tracker.start(1).is_ok());
        assert!(tracker.start(2).is_ok());
        assert!(tracker.start(3).is_ok());

        // Watchdog all of them
        assert!(tracker.watchdog(1).is_ok());
        assert!(tracker.watchdog(2).is_ok());
        assert!(tracker.watchdog(3).is_ok());

        // Stop in different order
        assert!(tracker.stop(2).is_ok());
        assert!(tracker.stop(1).is_ok());
        assert!(tracker.stop(3).is_ok());

        // All should be stoppable only once
        assert!(tracker.stop(1).is_err());
    }

    #[test]
    fn task_id_tracker_double_stop_fails() {
        let mut tracker = TaskIdTracker::default();

        tracker.start(700).unwrap();
        assert!(tracker.stop(700).is_ok());

        // Second stop should fail
        assert!(tracker.stop(700).is_err());
    }
}
