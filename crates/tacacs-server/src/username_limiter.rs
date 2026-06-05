// SPDX-License-Identifier: Apache-2.0
//! Per-username authentication rate limiter.
//!
//! Complements the per-source-IP `ConnLimiter` by tracking failure counts
//! per username across all source addresses.  This closes username-spray
//! attacks where the attacker rotates source IPs to evade IP-based limits.
//!
//! State is in-process (per-pod); it resets on pod restart.  For cross-pod
//! coordination a shared store (Redis / OpenBao) would be required, but
//! in-process protection stops the common single-source spray pattern and
//! provides defence-in-depth alongside the session-level lockouts.
//!
//! # NIST SP 800-53 Rev. 5 Security Controls
//!
//! | Control | Family | Status | Validated | Primary Functions |
//! |---------|--------|--------|-----------|-------------------|
//! | AC-7 | Access Control | Implemented | 2026-06-05 | [`UsernameRateLimiter`] |
//! | AU-2 | Audit and Accountability | Implemented | 2026-06-05 | [`UsernameRateLimiter::record_failure`] |
//! | SI-3 | System and Information Integrity | Implemented | 2026-06-05 | [`UsernameRateLimiter::is_locked`] |

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::Mutex;
use tracing::warn;

/// Maximum tracked usernames (bounds HashMap growth; CLAUDE.md rule 2).
const MAX_TRACKED_USERS: usize = 65536;

/// Per-username tracking state.
struct UserState {
    /// Number of consecutive failures in the current window.
    failures: u32,
    /// Start of the current counting window.
    window_start: SystemTime,
    /// Absolute time at which the lockout expires (`None` = not locked).
    locked_until: Option<SystemTime>,
}

/// Shared per-username rate limiter.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-7 | Unsuccessful Logon Attempts | Tracks failure counts per username across source IPs |
pub struct UsernameRateLimiter {
    /// Sliding window duration for failure counting.
    window: Duration,
    /// Maximum failures within a window before lockout.
    limit: u32,
    /// How long to lock out a username after the limit is exceeded.
    lockout: Duration,
    state: Mutex<HashMap<String, UserState>>,
}

impl UsernameRateLimiter {
    /// Create a new limiter.
    ///
    /// `limit = 0` disables locking; `lockout = 0` defaults to `window`.
    pub fn new(window_secs: u64, limit: u32, lockout_secs: u64) -> Arc<Self> {
        assert!(window_secs > 0, "window must be positive");
        let lockout = if lockout_secs == 0 {
            Duration::from_secs(window_secs)
        } else {
            Duration::from_secs(lockout_secs)
        };
        Arc::new(Self {
            window: Duration::from_secs(window_secs),
            limit,
            lockout,
            state: Mutex::new(HashMap::new()),
        })
    }

    /// Return `true` if the username is currently locked out.
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | AC-7 | Unsuccessful Logon Attempts | Enforces cross-IP username lockout |
    pub async fn is_locked(&self, username: &str) -> bool {
        assert!(!username.is_empty(), "username must not be empty");
        if self.limit == 0 {
            return false;
        }
        let guard = self.state.lock().await;
        let Some(entry) = guard.get(&username.to_lowercase()) else {
            return false;
        };
        if let Some(until) = entry.locked_until {
            return SystemTime::now() < until;
        }
        false
    }

    /// Record an authentication failure.  Locks the username when the failure
    /// count exceeds the configured limit within the window.
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | AC-7 | Unsuccessful Logon Attempts | Increments per-username failure counter |
    /// | AU-2 | Audit Events | Logs lockout events via tracing |
    pub async fn record_failure(&self, username: &str) {
        assert!(!username.is_empty(), "username must not be empty");
        if self.limit == 0 {
            return;
        }
        let key = username.to_lowercase();
        let now = SystemTime::now();
        let mut guard = self.state.lock().await;
        // Prune stale entries before inserting to bound map growth (rule 2).
        if guard.len() >= MAX_TRACKED_USERS {
            guard.retain(|_, v| {
                v.locked_until.map(|u| now < u).unwrap_or(false)
                    || now < v.window_start + self.window
            });
        }
        let entry = guard.entry(key).or_insert_with(|| UserState {
            failures: 0,
            window_start: now,
            locked_until: None,
        });
        // Reset window if expired.
        if now >= entry.window_start + self.window {
            entry.failures = 0;
            entry.window_start = now;
            entry.locked_until = None;
        }
        entry.failures = entry.failures.saturating_add(1);
        if entry.failures >= self.limit {
            let until = now + self.lockout;
            entry.locked_until = Some(until);
            warn!(
                username = %username,
                failures = entry.failures,
                limit = self.limit,
                lockout_secs = self.lockout.as_secs(),
                "per-username lockout triggered (AC-7)"
            );
        }
    }

    /// Record a successful authentication and reset the failure counter.
    pub async fn record_success(&self, username: &str) {
        assert!(!username.is_empty(), "username must not be empty");
        if self.limit == 0 {
            return;
        }
        let key = username.to_lowercase();
        let mut guard = self.state.lock().await;
        guard.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn not_locked_with_zero_failures() {
        let lim = UsernameRateLimiter::new(60, 3, 300);
        assert!(!lim.is_locked("alice").await);
    }

    #[tokio::test]
    async fn locked_after_limit_exceeded() {
        let lim = UsernameRateLimiter::new(60, 3, 300);
        lim.record_failure("alice").await;
        lim.record_failure("alice").await;
        assert!(!lim.is_locked("alice").await);
        lim.record_failure("alice").await;
        assert!(lim.is_locked("alice").await);
    }

    #[tokio::test]
    async fn success_clears_lockout() {
        let lim = UsernameRateLimiter::new(60, 2, 300);
        lim.record_failure("bob").await;
        lim.record_failure("bob").await;
        assert!(lim.is_locked("bob").await);
        lim.record_success("bob").await;
        assert!(!lim.is_locked("bob").await);
    }

    #[tokio::test]
    async fn disabled_when_limit_zero() {
        let lim = UsernameRateLimiter::new(60, 0, 300);
        for _ in 0..100 {
            lim.record_failure("carol").await;
        }
        assert!(!lim.is_locked("carol").await);
    }

    #[tokio::test]
    async fn case_insensitive() {
        let lim = UsernameRateLimiter::new(60, 2, 300);
        lim.record_failure("ALICE").await;
        lim.record_failure("alice").await;
        assert!(lim.is_locked("Alice").await);
    }

    #[tokio::test]
    async fn different_users_are_independent() {
        let lim = UsernameRateLimiter::new(60, 2, 300);
        lim.record_failure("alice").await;
        lim.record_failure("alice").await;
        assert!(lim.is_locked("alice").await);
        assert!(!lim.is_locked("bob").await);
    }
}
