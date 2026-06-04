// SPDX-License-Identifier: Apache-2.0
//! User store backed by PostgreSQL for SSH public key management.
//!
//! # NIST SP 800-53 Rev. 5 Security Controls
//!
//! **Control Implementation Matrix**
//!
//! | Control | Family | Status | Primary Functions |
//! |---------|--------|--------|-------------------|
//! | AC-2    | Access Control | Implemented | [`UserStore::list_users`], [`UserStore::ensure_user_exists`] |
//! | IA-5    | Identification and Auth | Implemented | [`UserStore::add_ssh_key`], [`UserStore::delete_ssh_key`] |
//! | IA-5(2) | PKI-Based Auth | Implemented | [`UserStore::lookup_keys_for_authz`], [`UserStore::validate_key_type`] |
//! | AU-3    | Audit/Accountability | Implemented | `created_at` timestamps on all key records |

use anyhow::{Context, Result, ensure};
use sqlx::PgPool;
use tracing::info;

/// Stored record for a user.
#[derive(Debug, Clone)]
pub struct UserRow {
    pub id: i64,
    pub username: String,
    pub enabled: bool,
    pub created_at: time::OffsetDateTime,
}

/// Stored record for a single SSH public key.
#[derive(Debug, Clone)]
pub struct SshKeyRow {
    pub id: i64,
    pub key_type: String,
    pub key_data: String,
    pub comment: String,
    pub created_at: time::OffsetDateTime,
}

/// Shared database handle for SSH public key lookups.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | IA-5(2) | PKI-Based Authentication | Central key store for SSH authorized-key distribution |
/// | AC-2    | Account Management | User enable/disable via `users.enabled` column |
#[derive(Debug, Clone)]
pub struct UserStore {
    pool: PgPool,
}

impl UserStore {
    /// Connect to the database and apply schema migrations.
    ///
    /// # NIST Controls
    /// - **IA-5(2)**: Establishes PKI key storage infrastructure at init time
    pub async fn connect(db_url: &str) -> Result<Self> {
        assert!(!db_url.is_empty(), "db_url must not be empty");
        let pool = PgPool::connect(db_url)
            .await
            .context("connecting to user database")?;
        let store = Self { pool };
        store.create_users_table().await?;
        store.create_ssh_keys_table().await?;
        info!("user store connected and schema applied");
        Ok(store)
    }

    /// Create the users table if it does not exist.
    ///
    /// # NIST Controls
    /// - **AC-2**: Account management table with enabled/disabled status
    async fn create_users_table(&self) -> Result<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS users (
                id         BIGSERIAL   PRIMARY KEY,
                username   TEXT        NOT NULL UNIQUE,
                enabled    BOOLEAN     NOT NULL DEFAULT TRUE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )",
        )
        .execute(&self.pool)
        .await
        .context("creating users table")?;
        Ok(())
    }

    /// Create the user_ssh_keys table if it does not exist.
    ///
    /// # NIST Controls
    /// - **IA-5(2)**: PKI authenticator storage with cascade-delete on user removal
    async fn create_ssh_keys_table(&self) -> Result<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS user_ssh_keys (
                id         BIGSERIAL   PRIMARY KEY,
                user_id    BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                key_type   TEXT        NOT NULL,
                key_data   TEXT        NOT NULL,
                comment    TEXT        NOT NULL DEFAULT '',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE(user_id, key_data)
            )",
        )
        .execute(&self.pool)
        .await
        .context("creating user_ssh_keys table")?;
        Ok(())
    }

    /// Return all SSH public keys for a user formatted as TACACS+ authz attributes.
    ///
    /// Each element has the form `ssh-key=<type> <data> [comment]` and is ready
    /// to be inserted into an authorization response's args list.  Only keys for
    /// enabled users are returned.
    ///
    /// # NIST Controls
    /// - **IA-5(2)**: Provides public key material for PKI-based authentication
    /// - **AC-3**: Only enabled users' keys are returned (enforced by SQL join)
    pub async fn lookup_keys_for_authz(&self, username: &str) -> Vec<String> {
        assert!(!username.is_empty(), "username must not be empty");
        let rows: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT k.key_type, k.key_data, k.comment
             FROM user_ssh_keys k
             JOIN users u ON u.id = k.user_id
             WHERE u.username = $1 AND u.enabled = TRUE
             ORDER BY k.created_at",
        )
        .bind(username)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        rows.iter()
            .map(|(kt, kd, cm)| {
                if cm.is_empty() {
                    format!("ssh-key={kt} {kd}")
                } else {
                    format!("ssh-key={kt} {kd} {cm}")
                }
            })
            .collect()
    }

    /// List all users with their enabled status.
    ///
    /// # NIST Controls
    /// - **AC-2**: Account enumeration for management
    pub async fn list_users(&self) -> Result<Vec<UserRow>> {
        let rows: Vec<(i64, String, bool, time::OffsetDateTime)> = sqlx::query_as(
            "SELECT id, username, enabled, created_at FROM users ORDER BY username",
        )
        .fetch_all(&self.pool)
        .await
        .context("listing users")?;

        Ok(rows
            .into_iter()
            .map(|(id, username, enabled, created_at)| UserRow {
                id,
                username,
                enabled,
                created_at,
            })
            .collect())
    }

    /// Retrieve all SSH keys stored for a specific user.
    ///
    /// # NIST Controls
    /// - **IA-5(2)**: Public key retrieval for management operations
    pub async fn get_user_keys(&self, username: &str) -> Result<Vec<SshKeyRow>> {
        assert!(!username.is_empty(), "username must not be empty");
        let rows: Vec<(i64, String, String, String, time::OffsetDateTime)> = sqlx::query_as(
            "SELECT k.id, k.key_type, k.key_data, k.comment, k.created_at
             FROM user_ssh_keys k
             JOIN users u ON u.id = k.user_id
             WHERE u.username = $1
             ORDER BY k.created_at",
        )
        .bind(username)
        .fetch_all(&self.pool)
        .await
        .context("fetching user SSH keys")?;

        Ok(rows
            .into_iter()
            .map(|(id, key_type, key_data, comment, created_at)| SshKeyRow {
                id,
                key_type,
                key_data,
                comment,
                created_at,
            })
            .collect())
    }

    /// Insert user if not already present; return the user's id.
    ///
    /// # NIST Controls
    /// - **AC-2**: Account creation with audit timestamp
    async fn ensure_user_exists(&self, username: &str) -> Result<i64> {
        assert!(!username.is_empty(), "username must not be empty");
        let row: (i64,) = sqlx::query_as(
            "INSERT INTO users (username) VALUES ($1)
             ON CONFLICT (username) DO UPDATE SET username = EXCLUDED.username
             RETURNING id",
        )
        .bind(username)
        .fetch_one(&self.pool)
        .await
        .context("upserting user")?;
        Ok(row.0)
    }

    /// Validate that the supplied key type is in the allowed set.
    ///
    /// Rejects `ssh-dss` (DSA) and other weak algorithm identifiers.
    ///
    /// # NIST Controls
    /// - **IA-5(2)**: Restricts key types to known-safe algorithms
    fn validate_key_type(key_type: &str) -> Result<()> {
        let allowed = [
            "ssh-ed25519",
            "ssh-rsa",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
            "sk-ssh-ed25519",
            "sk-ecdsa-sha2-nistp256",
        ];
        ensure!(
            allowed.iter().any(|a| key_type.eq_ignore_ascii_case(a)),
            "unsupported SSH key type '{}'",
            key_type
        );
        Ok(())
    }

    /// Add an SSH public key for a user, creating the user record if needed.
    ///
    /// Returns the key id (existing id if the key was already present).
    ///
    /// # NIST Controls
    /// - **IA-5(2)**: Public key registration with algorithm validation
    /// - **AU-3**: `created_at` provides audit trail for key additions
    pub async fn add_ssh_key(
        &self,
        username: &str,
        key_type: &str,
        key_data: &str,
        comment: &str,
    ) -> Result<i64> {
        assert!(!username.is_empty(), "username must not be empty");
        assert!(!key_type.is_empty(), "key_type must not be empty");
        assert!(!key_data.is_empty(), "key_data must not be empty");
        Self::validate_key_type(key_type)?;
        let user_id = self.ensure_user_exists(username).await?;
        let inserted: Option<(i64,)> = sqlx::query_as(
            "INSERT INTO user_ssh_keys (user_id, key_type, key_data, comment)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (user_id, key_data) DO NOTHING
             RETURNING id",
        )
        .bind(user_id)
        .bind(key_type)
        .bind(key_data)
        .bind(comment)
        .fetch_optional(&self.pool)
        .await
        .context("inserting SSH key")?;
        if let Some((id,)) = inserted {
            return Ok(id);
        }
        // Key already existed; fetch its id.
        let existing: (i64,) = sqlx::query_as(
            "SELECT id FROM user_ssh_keys WHERE user_id = $1 AND key_data = $2",
        )
        .bind(user_id)
        .bind(key_data)
        .fetch_one(&self.pool)
        .await
        .context("fetching existing key id")?;
        Ok(existing.0)
    }

    /// Delete a specific SSH key for a user by key id.
    ///
    /// Returns `true` if a row was deleted, `false` if not found.
    ///
    /// # NIST Controls
    /// - **IA-5(2)**: Key revocation — supports rapid removal of compromised keys
    pub async fn delete_ssh_key(&self, username: &str, key_id: i64) -> Result<bool> {
        assert!(!username.is_empty(), "username must not be empty");
        assert!(key_id > 0, "key_id must be positive");
        let result = sqlx::query(
            "DELETE FROM user_ssh_keys k
             USING users u
             WHERE k.user_id = u.id AND u.username = $1 AND k.id = $2",
        )
        .bind(username)
        .bind(key_id)
        .execute(&self.pool)
        .await
        .context("deleting SSH key")?;
        Ok(result.rows_affected() > 0)
    }
}
