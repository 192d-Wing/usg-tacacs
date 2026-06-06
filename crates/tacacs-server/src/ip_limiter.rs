// SPDX-License-Identifier: Apache-2.0
//! Per-source-IP authentication rate limiter.
//!
//! Complements the per-username [`crate::username_limiter`] and the
//! per-IP concurrency `ConnLimiter`: this tracks *failed authentication*
//! attempts per source address across all usernames, so a password-spray that
//! rotates usernames from one source is throttled (the username limiter does
//! not catch it because each username has its own counter).
//!
//! # Operational caveat (read before enabling)
//!
//! On a TACACS+ server the source IP is usually a **NAD** (switch/router) that
//! aggregates *many* end users behind one address. A limit set too low can lock
//! out an entire NAD — every user behind it — during a burst of legitimate
//! failures. For that reason this limiter is **disabled by default**
//! (`--ip-lockout-limit 0`); enable it with a limit comfortably above the
//! busiest NAD's expected failed-auth volume in the window, and prefer per-NAD
//! secrets + network restriction as the primary control.
//!
//! State is in-process (per-pod); it resets on pod restart. A shared store
//! (Redis) would be required for replica-global coordination.
//!
//! # NIST SP 800-53 Rev. 5 Security Controls
//!
//! | Control | Family | Status | Validated | Primary Functions |
//! |---------|--------|--------|-----------|-------------------|
//! | AC-7 | Access Control | Implemented | 2026-06-06 | [`IpRateLimiter`] |
//! | SC-5 | System and Communications Protection | Implemented | 2026-06-06 | [`IpRateLimiter::record_failure`] |
//! | AU-2 | Audit and Accountability | Implemented | 2026-06-06 | [`IpRateLimiter::record_failure`] |

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::Mutex;
use tracing::warn;

/// Maximum tracked source addresses (bounds map growth; CLAUDE.md rule 2).
const MAX_TRACKED_IPS: usize = 65536;

/// Per-source-IP tracking state.
struct IpState {
    /// Consecutive failures in the current window.
    failures: u32,
    /// Start of the current counting window.
    window_start: SystemTime,
    /// Absolute time the lockout expires (`None` = not locked).
    locked_until: Option<SystemTime>,
}

/// Shared per-source-IP authentication rate limiter.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-7 | Unsuccessful Logon Attempts | Tracks failed auth per source IP across usernames |
/// | SC-5 | Denial of Service Protection | Caps spray volume from a single source |
pub struct IpRateLimiter {
    window: Duration,
    limit: u32,
    lockout: Duration,
    state: Mutex<HashMap<IpAddr, IpState>>,
}

impl IpRateLimiter {
    /// Create a new limiter. `limit = 0` disables it entirely; `lockout = 0`
    /// defaults the lockout duration to the window length.
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

    /// Return `true` if the source IP is currently locked out.
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | AC-7 | Unsuccessful Logon Attempts | Enforces per-source lockout |
    pub async fn is_locked(&self, ip: IpAddr) -> bool {
        if self.limit == 0 {
            return false;
        }
        let guard = self.state.lock().await;
        let Some(entry) = guard.get(&ip) else {
            return false;
        };
        match entry.locked_until {
            Some(until) => SystemTime::now() < until,
            None => false,
        }
    }

    /// Record an authentication failure for `ip`, locking it when the failure
    /// count reaches the configured limit within the window.
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | AC-7 | Unsuccessful Logon Attempts | Increments per-source failure counter |
    /// | SC-5 | Denial of Service Protection | Bounds spray volume per source |
    /// | AU-2 | Audit Events | Logs lockout events via tracing |
    pub async fn record_failure(&self, ip: IpAddr) {
        if self.limit == 0 {
            return;
        }
        let now = SystemTime::now();
        let mut guard = self.state.lock().await;
        // Prune stale entries before inserting to bound map growth (rule 2).
        if guard.len() >= MAX_TRACKED_IPS {
            guard.retain(|_, v| {
                v.locked_until.map(|u| now < u).unwrap_or(false)
                    || now < v.window_start + self.window
            });
        }
        let entry = guard.entry(ip).or_insert_with(|| IpState {
            failures: 0,
            window_start: now,
            locked_until: None,
        });
        // Reset the window if it has expired.
        if now >= entry.window_start + self.window {
            entry.failures = 0;
            entry.window_start = now;
            entry.locked_until = None;
        }
        entry.failures = entry.failures.saturating_add(1);
        if entry.failures >= self.limit {
            entry.locked_until = Some(now + self.lockout);
            warn!(
                source_ip = %ip,
                failures = entry.failures,
                limit = self.limit,
                lockout_secs = self.lockout.as_secs(),
                "per-source-IP lockout triggered (AC-7/SC-5)"
            );
        }
    }

    /// Record a successful authentication and clear the source's counter.
    pub async fn record_success(&self, ip: IpAddr) {
        if self.limit == 0 {
            return;
        }
        let mut guard = self.state.lock().await;
        guard.remove(&ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("valid ip")
    }

    #[tokio::test]
    async fn not_locked_initially() {
        let lim = IpRateLimiter::new(60, 3, 300);
        assert!(!lim.is_locked(ip("10.0.0.1")).await);
    }

    #[tokio::test]
    async fn locks_after_limit() {
        let lim = IpRateLimiter::new(60, 3, 300);
        lim.record_failure(ip("10.0.0.1")).await;
        lim.record_failure(ip("10.0.0.1")).await;
        assert!(!lim.is_locked(ip("10.0.0.1")).await);
        lim.record_failure(ip("10.0.0.1")).await;
        assert!(lim.is_locked(ip("10.0.0.1")).await);
    }

    #[tokio::test]
    async fn spray_across_usernames_same_ip_is_caught() {
        // The whole point: distinct usernames, one source IP -> still throttled.
        let lim = IpRateLimiter::new(60, 5, 300);
        for _ in 0..5 {
            lim.record_failure(ip("10.0.100.7")).await;
        }
        assert!(lim.is_locked(ip("10.0.100.7")).await);
    }

    #[tokio::test]
    async fn distinct_ips_are_independent() {
        let lim = IpRateLimiter::new(60, 2, 300);
        lim.record_failure(ip("10.0.0.1")).await;
        lim.record_failure(ip("10.0.0.1")).await;
        assert!(lim.is_locked(ip("10.0.0.1")).await);
        assert!(!lim.is_locked(ip("10.0.0.2")).await);
    }

    #[tokio::test]
    async fn success_clears_counter() {
        let lim = IpRateLimiter::new(60, 2, 300);
        lim.record_failure(ip("10.0.0.1")).await;
        lim.record_failure(ip("10.0.0.1")).await;
        assert!(lim.is_locked(ip("10.0.0.1")).await);
        lim.record_success(ip("10.0.0.1")).await;
        assert!(!lim.is_locked(ip("10.0.0.1")).await);
    }

    #[tokio::test]
    async fn disabled_when_limit_zero() {
        let lim = IpRateLimiter::new(60, 0, 300);
        for _ in 0..100 {
            lim.record_failure(ip("10.0.0.1")).await;
        }
        assert!(!lim.is_locked(ip("10.0.0.1")).await);
    }
}
