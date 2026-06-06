// SPDX-License-Identifier: Apache-2.0
//! Shared login→authz group cache backed by Valkey (Redis wire protocol).
//!
//! ICAM/OIDC group memberships are present only in the JWT at authentication
//! time, bound to the authentication connection's [`SingleConnectState`]. A
//! command-authorization request is an independent TACACS+ transaction that may
//! arrive on a separate connection — and on a different server replica — with no
//! JWT and therefore no groups. Group-based policy rules then fail to match for
//! standalone command authorization.
//!
//! This module bridges that gap. On a successful ICAM authentication the user's
//! groups are written to a shared Valkey cache keyed by username with a bounded
//! TTL; at authorization time the groups are read back, so group-based policy
//! applies to standalone command authorization across all replicas. The cache
//! is best-effort: every Valkey error is logged and swallowed so a cache outage
//! never blocks authentication or authorization (it degrades to the prior
//! "no groups resolved" behavior).
//!
//! # NIST SP 800-53 Rev. 5 Security Controls
//!
//! | Control | Family | Status | Primary Functions |
//! |---------|--------|--------|-------------------|
//! | AC-2 | Account Management | Implemented | [`GroupCache::put`] |
//! | AC-3 | Access Enforcement | Implemented | [`GroupCache::get`] |
//! | SC-5 | Denial of Service Protection | Implemented | [`MAX_CACHED_GROUPS`] |
//! | SI-10 | Information Input Validation | Implemented | [`GroupCache::get`] |
//! | AU-12 | Audit Generation | Implemented | cache errors logged via tracing |

use redis::AsyncCommands;
use redis::aio::ConnectionManager;
use std::sync::OnceLock;

/// Upper bound on cached groups per user (loop/DoS guard, NASA rule 2 / SC-5).
const MAX_CACHED_GROUPS: usize = 256;

/// Process-global cache handle, initialized once at startup when configured.
static GROUP_CACHE: OnceLock<GroupCache> = OnceLock::new();

/// A shared group cache backed by a Valkey/Redis connection manager.
///
/// `ConnectionManager` is cheaply cloneable and transparently reconnects, so a
/// single handle is shared across all connection-handling tasks.
#[derive(Clone)]
pub struct GroupCache {
    conn: ConnectionManager,
    ttl_secs: u64,
    key_prefix: String,
}

/// Build the namespaced cache key for a username.
///
/// Kept free-standing (no `self`) so it can be unit-tested without a live Valkey.
fn build_key(prefix: &str, username: &str) -> String {
    assert!(!prefix.is_empty(), "key prefix must not be empty");
    assert!(!username.is_empty(), "username must not be empty");
    format!("{prefix}:groups:{username}")
}

/// Serialize groups to a bounded JSON array string for storage.
///
/// Returns `None` when there is nothing useful to store or serialization fails.
fn encode_groups(groups: &[String]) -> Option<String> {
    if groups.is_empty() {
        return None;
    }
    let bounded: Vec<&String> = groups.iter().take(MAX_CACHED_GROUPS).collect();
    match serde_json::to_string(&bounded) {
        Ok(payload) => Some(payload),
        Err(e) => {
            tracing::warn!(error = %e, "group cache: failed to serialize groups");
            None
        }
    }
}

/// Parse a stored JSON array back into a bounded group list.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | SI-10 | Information Input Validation | Rejects malformed JSON; bounds list length |
fn decode_groups(payload: &str) -> Option<Vec<String>> {
    let groups: Vec<String> = serde_json::from_str(payload)
        .map_err(|e| tracing::warn!(error = %e, "group cache: malformed cached payload"))
        .ok()?;
    if groups.is_empty() {
        return None;
    }
    Some(groups.into_iter().take(MAX_CACHED_GROUPS).collect())
}

impl GroupCache {
    /// Write a user's groups to the cache with the configured TTL (best-effort).
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | AC-2 | Account Management | Persists group memberships for cross-session authz |
    /// | AU-12 | Audit Generation | Cache write failures logged, never propagated |
    pub async fn put(&self, username: &str, groups: &[String]) {
        assert!(self.ttl_secs > 0, "cache TTL must be positive");
        if username.is_empty() {
            return;
        }
        let Some(payload) = encode_groups(groups) else {
            return;
        };
        let key = build_key(&self.key_prefix, username);
        let mut conn = self.conn.clone();
        let result: redis::RedisResult<()> = conn.set_ex(&key, payload, self.ttl_secs).await;
        if let Err(e) = result {
            tracing::warn!(error = %e, user = username, "group cache: write failed");
        } else {
            tracing::debug!(
                user = username,
                groups = groups.len(),
                "group cache: stored"
            );
        }
    }

    /// Read a user's cached groups, or `None` on miss/error (best-effort).
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | AC-3 | Access Enforcement | Supplies groups for standalone authz decisions |
    /// | SI-10 | Information Input Validation | Validates and bounds the decoded payload |
    pub async fn get(&self, username: &str) -> Option<Vec<String>> {
        if username.is_empty() {
            return None;
        }
        let key = build_key(&self.key_prefix, username);
        let mut conn = self.conn.clone();
        let payload: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| tracing::warn!(error = %e, user = username, "group cache: read failed"))
            .ok()?;
        let groups = decode_groups(&payload?)?;
        tracing::debug!(user = username, groups = groups.len(), "group cache: hit");
        Some(groups)
    }
}

/// Initialize the global group cache from a Valkey URL (called once at startup).
///
/// `password`, when present, overrides any password embedded in the URL so the
/// secret can be supplied via a mounted file rather than the connection string.
/// Returns an error if the URL is invalid or the initial connection fails.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | SC-8 | Transmission Confidentiality | Honors `rediss://` for TLS transport |
/// | IA-5 | Authenticator Management | Password injected out-of-band, never logged |
pub async fn init_group_cache(
    url: &str,
    password: Option<&str>,
    ttl_secs: u64,
    key_prefix: &str,
) -> anyhow::Result<()> {
    assert!(!url.is_empty(), "group cache URL must not be empty");
    assert!(ttl_secs > 0, "group cache TTL must be positive");
    use redis::IntoConnectionInfo;
    let mut info = url
        .into_connection_info()
        .map_err(|e| anyhow::anyhow!("invalid group cache URL: {e}"))?;
    if let Some(pw) = password {
        info.redis.password = Some(pw.to_string());
    }
    let client =
        redis::Client::open(info).map_err(|e| anyhow::anyhow!("group cache client: {e}"))?;
    let conn = ConnectionManager::new(client)
        .await
        .map_err(|e| anyhow::anyhow!("group cache connect: {e}"))?;
    let cache = GroupCache {
        conn,
        ttl_secs,
        key_prefix: key_prefix.to_string(),
    };
    GROUP_CACHE
        .set(cache)
        .map_err(|_| anyhow::anyhow!("group cache already initialized"))?;
    Ok(())
}

/// Return the global group cache handle, or `None` when caching is disabled.
pub fn group_cache() -> Option<&'static GroupCache> {
    GROUP_CACHE.get()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_key_is_namespaced() {
        let key = build_key("tacacs", "operator");
        assert_eq!(key, "tacacs:groups:operator");
        assert!(key.starts_with("tacacs:groups:"));
    }

    #[test]
    fn encode_then_decode_roundtrips() {
        let groups = vec!["netops".to_string(), "admins".to_string()];
        let payload = encode_groups(&groups).expect("encode must succeed");
        let decoded = decode_groups(&payload).expect("decode must succeed");
        assert_eq!(decoded, groups);
    }

    #[test]
    fn encode_empty_returns_none() {
        let groups: Vec<String> = Vec::new();
        assert!(encode_groups(&groups).is_none());
    }

    #[test]
    fn encode_bounds_group_count() {
        let big: Vec<String> = (0..300).map(|i| format!("g{i}")).collect();
        let payload = encode_groups(&big).expect("encode must succeed");
        let decoded = decode_groups(&payload).expect("decode must succeed");
        assert_eq!(decoded.len(), MAX_CACHED_GROUPS);
    }

    #[test]
    fn decode_malformed_returns_none() {
        assert!(decode_groups("not json").is_none());
        assert!(decode_groups("[]").is_none());
    }
}
