// SPDX-License-Identifier: Apache-2.0
//! Transactional PostgreSQL repository for API-owned NAD resources.

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NadStoreError {
    Unavailable,
    Conflict,
    NotFound,
    InvalidInput(&'static str),
    CorruptRecord,
}

impl fmt::Display for NadStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("nad_store_unavailable"),
            Self::Conflict => formatter.write_str("nad_conflict"),
            Self::NotFound => formatter.write_str("nad_not_found"),
            Self::InvalidInput(code) => formatter.write_str(code),
            Self::CorruptRecord => formatter.write_str("corrupt_nad_record"),
        }
    }
}

impl std::error::Error for NadStoreError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NadRecord {
    pub nad_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub source_address: IpAddr,
    pub authentication: NadAuthentication,
    pub ownership: String,
    pub resource_version: i64,
    pub created_at: OffsetDateTime,
    pub created_by: String,
    pub updated_at: OffsetDateTime,
    pub updated_by: String,
    pub deleted_at: Option<OffsetDateTime>,
    pub deleted_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "camelCase")]
pub enum NadAuthentication {
    Legacy { secret_ref: String },
    Tls { certificate_identities: Vec<String> },
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateNadInput {
    pub name: String,
    pub description: Option<String>,
    pub source_address: IpAddr,
    pub authentication: NadAuthentication,
    pub actor: String,
    pub correlation_id: Uuid,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct UpdateNadInput {
    pub nad_id: Uuid,
    pub description: Option<String>,
    pub source_address: IpAddr,
    pub authentication: NadAuthentication,
    pub expected_version: i64,
    pub actor: String,
    pub correlation_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateNadOutcome {
    Created(NadRecord),
    Replay(NadRecord),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NadPage {
    pub items: Vec<NadRecord>,
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NadAuditEvent {
    pub hash_version: i16,
    pub event_id: Uuid,
    pub occurred_at: OffsetDateTime,
    pub correlation_id: Uuid,
    pub actor: String,
    pub action: String,
    pub nad_id: Uuid,
    pub resource_version: i64,
    pub before_state: Option<serde_json::Value>,
    pub after_state: serde_json::Value,
    pub previous_event_hash: Option<String>,
    pub event_hash: String,
    pub hmac_signature: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NadAuditPage {
    pub items: Vec<NadAuditEvent>,
    pub has_more: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NadAuditVerification {
    pub valid: bool,
    pub checked_events: usize,
    pub offset: usize,
    pub complete: bool,
    pub first_event_id: Option<Uuid>,
    pub last_event_id: Option<Uuid>,
    pub last_event_hash: Option<String>,
    pub failure_event_id: Option<Uuid>,
    pub failure_code: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredOperation {
    pub operation_id: Uuid,
    pub kind: String,
    pub status: String,
    pub submitted_at: OffsetDateTime,
    pub completed_at: Option<OffsetDateTime>,
    pub error: Option<String>,
}

#[derive(Clone)]
pub struct NadStore {
    pool: PgPool,
    audit_key: Arc<Vec<u8>>,
}

impl NadStore {
    pub fn new(pool: PgPool, audit_key: Arc<Vec<u8>>) -> Result<Self, NadStoreError> {
        if audit_key.len() < 32 {
            return Err(NadStoreError::InvalidInput("audit_key_too_short"));
        }
        Ok(Self { pool, audit_key })
    }

    pub async fn list(&self) -> Result<Vec<NadRecord>, NadStoreError> {
        let rows = sqlx::query(NAD_SELECT_ACTIVE)
            .fetch_all(&self.pool)
            .await
            .map_err(map_database_error)?;
        rows.iter().map(decode_nad).collect()
    }

    pub async fn list_page(
        &self,
        name_prefix: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<NadPage, NadStoreError> {
        let fetch_limit = i64::try_from(limit.saturating_add(1))
            .map_err(|_| NadStoreError::InvalidInput("invalid_pagination"))?;
        let offset =
            i64::try_from(offset).map_err(|_| NadStoreError::InvalidInput("invalid_pagination"))?;
        let rows = sqlx::query(NAD_SELECT_ACTIVE_PAGE)
            .bind(name_prefix)
            .bind(fetch_limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
            .map_err(map_database_error)?;
        let has_more = rows.len() > limit;
        let items = rows
            .iter()
            .take(limit)
            .map(decode_nad)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(NadPage { items, has_more })
    }

    pub async fn get(&self, nad_id: Uuid) -> Result<NadRecord, NadStoreError> {
        let row = sqlx::query(NAD_SELECT_ONE)
            .bind(nad_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_database_error)?
            .ok_or(NadStoreError::NotFound)?;
        decode_nad(&row)
    }

    pub async fn list_audit(
        &self,
        nad_id: Option<Uuid>,
        correlation_id: Option<Uuid>,
        action: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<NadAuditPage, NadStoreError> {
        let fetch_limit = i64::try_from(limit.saturating_add(1))
            .map_err(|_| NadStoreError::InvalidInput("invalid_pagination"))?;
        let offset =
            i64::try_from(offset).map_err(|_| NadStoreError::InvalidInput("invalid_pagination"))?;
        let rows = sqlx::query(NAD_AUDIT_SELECT_PAGE)
            .bind(nad_id)
            .bind(correlation_id)
            .bind(action)
            .bind(fetch_limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
            .map_err(map_database_error)?;
        let has_more = rows.len() > limit;
        let items = rows
            .iter()
            .take(limit)
            .map(decode_audit_event)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(NadAuditPage { items, has_more })
    }

    pub async fn verify_audit_page(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<NadAuditVerification, NadStoreError> {
        let page = self.list_audit(None, None, None, limit, offset).await?;
        let previous_hash = self.audit_page_anchor(offset).await?;
        Ok(verify_audit_events(
            &page.items,
            previous_hash.as_deref(),
            &self.audit_key,
            offset,
            !page.has_more,
        ))
    }

    async fn audit_page_anchor(&self, offset: usize) -> Result<Option<Vec<u8>>, NadStoreError> {
        if offset == 0 {
            return Ok(None);
        }
        let page = self
            .list_audit(None, None, None, 1, offset.saturating_sub(1))
            .await?;
        let Some(event) = page.items.first() else {
            return Err(NadStoreError::InvalidInput("audit_offset_out_of_range"));
        };
        hex::decode(&event.event_hash)
            .map(Some)
            .map_err(|_| NadStoreError::CorruptRecord)
    }

    pub async fn create_operation(&self, operation: &StoredOperation) -> Result<(), NadStoreError> {
        let mut tx = self.pool.begin().await.map_err(map_database_error)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('management_operations'))")
            .execute(&mut *tx)
            .await
            .map_err(map_database_error)?;
        sqlx::query(
            "DELETE FROM tacacs_management.operations
              WHERE completed_at < clock_timestamp() - interval '24 hours'",
        )
        .execute(&mut *tx)
        .await
        .map_err(map_database_error)?;
        let running: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM tacacs_management.operations WHERE status = 'running'",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(map_database_error)?;
        if running >= 1_024 {
            return Err(NadStoreError::InvalidInput("operation_capacity_exceeded"));
        }
        insert_operation(&mut tx, operation).await?;
        tx.commit().await.map_err(map_database_error)
    }

    pub async fn complete_operation(
        &self,
        operation_id: Uuid,
        status: &str,
        error: Option<&str>,
    ) -> Result<(), NadStoreError> {
        let result = sqlx::query(
            "UPDATE tacacs_management.operations
                SET status = $2, completed_at = clock_timestamp(), error = $3
              WHERE operation_id = $1 AND status = 'running'",
        )
        .bind(operation_id)
        .bind(status)
        .bind(error)
        .execute(&self.pool)
        .await
        .map_err(map_database_error)?;
        if result.rows_affected() == 1 {
            Ok(())
        } else {
            Err(NadStoreError::NotFound)
        }
    }

    pub async fn fail_abandoned_operations(
        &self,
        submitted_before: OffsetDateTime,
    ) -> Result<u64, NadStoreError> {
        let result = sqlx::query(
            "UPDATE tacacs_management.operations
                SET status = 'failed',
                    completed_at = clock_timestamp(),
                    error = 'operation owner stopped before completion'
              WHERE status = 'running' AND submitted_at < $1",
        )
        .bind(submitted_before)
        .execute(&self.pool)
        .await
        .map_err(map_database_error)?;
        Ok(result.rows_affected())
    }

    pub async fn get_operation(
        &self,
        operation_id: Uuid,
    ) -> Result<StoredOperation, NadStoreError> {
        let row = sqlx::query(
            "SELECT operation_id, kind, status, submitted_at, completed_at, error
               FROM tacacs_management.operations
              WHERE operation_id = $1",
        )
        .bind(operation_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_database_error)?
        .ok_or(NadStoreError::NotFound)?;
        Ok(StoredOperation {
            operation_id: row.get("operation_id"),
            kind: row.get("kind"),
            status: row.get("status"),
            submitted_at: row.get("submitted_at"),
            completed_at: row.get("completed_at"),
            error: row.get("error"),
        })
    }

    pub async fn create(&self, input: CreateNadInput) -> Result<CreateNadOutcome, NadStoreError> {
        validate_create(&input)?;
        let token = keyed_token(&self.audit_key, input.idempotency_key.as_bytes())?;
        let fingerprint = request_fingerprint(&input)?;
        let mut tx = self.pool.begin().await.map_err(map_database_error)?;
        if let Some(outcome) = replay_create(&mut tx, &token, &fingerprint).await? {
            tx.commit().await.map_err(map_database_error)?;
            return Ok(outcome);
        }
        let record = insert_nad(&mut tx, &input).await?;
        append_audit(
            &mut tx,
            &record,
            None,
            "create",
            input.correlation_id,
            &self.audit_key,
        )
        .await?;
        insert_idempotency(&mut tx, &token, &fingerprint, record.nad_id).await?;
        tx.commit().await.map_err(map_database_error)?;
        Ok(CreateNadOutcome::Created(record))
    }

    pub async fn update(&self, input: UpdateNadInput) -> Result<NadRecord, NadStoreError> {
        validate_update(&input)?;
        let mut tx = self.pool.begin().await.map_err(map_database_error)?;
        let before = get_for_update(&mut tx, input.nad_id).await?;
        if before.resource_version != input.expected_version {
            return Err(NadStoreError::Conflict);
        }
        let after = update_nad(&mut tx, &input).await?;
        append_audit(
            &mut tx,
            &after,
            Some(&before),
            "update",
            input.correlation_id,
            &self.audit_key,
        )
        .await?;
        tx.commit().await.map_err(map_database_error)?;
        Ok(after)
    }

    pub async fn delete(
        &self,
        nad_id: Uuid,
        expected_version: i64,
        actor: &str,
        correlation_id: Uuid,
    ) -> Result<NadRecord, NadStoreError> {
        validate_actor(actor)?;
        let mut tx = self.pool.begin().await.map_err(map_database_error)?;
        let before = get_for_update(&mut tx, nad_id).await?;
        if before.resource_version != expected_version {
            return Err(NadStoreError::Conflict);
        }
        let after = soft_delete(&mut tx, nad_id, actor).await?;
        append_audit(
            &mut tx,
            &after,
            Some(&before),
            "delete",
            correlation_id,
            &self.audit_key,
        )
        .await?;
        tx.commit().await.map_err(map_database_error)?;
        Ok(after)
    }
}

const NAD_SELECT_ACTIVE: &str = "
    SELECT nad_id, name, description, host(source_address) AS source_address,
           authentication_mode, secret_ref, certificate_identities, ownership,
           resource_version, created_at, created_by, updated_at, updated_by,
           deleted_at, deleted_by
      FROM tacacs_management.nads
     WHERE deleted_at IS NULL
     ORDER BY name, nad_id";
const NAD_SELECT_ONE: &str = "
    SELECT nad_id, name, description, host(source_address) AS source_address,
           authentication_mode, secret_ref, certificate_identities, ownership,
           resource_version, created_at, created_by, updated_at, updated_by,
           deleted_at, deleted_by
     FROM tacacs_management.nads
     WHERE nad_id = $1 AND deleted_at IS NULL";
const NAD_SELECT_ACTIVE_PAGE: &str = "
    SELECT nad_id, name, description, host(source_address) AS source_address,
           authentication_mode, secret_ref, certificate_identities, ownership,
           resource_version, created_at, created_by, updated_at, updated_by,
           deleted_at, deleted_by
      FROM tacacs_management.nads
     WHERE deleted_at IS NULL
       AND ($1::text IS NULL OR name LIKE $1 || '%')
     ORDER BY name, nad_id
     LIMIT $2 OFFSET $3";
const NAD_AUDIT_SELECT_PAGE: &str = "
    SELECT hash_version, event_id, occurred_at, correlation_id, actor, action, nad_id,
           resource_version, before_state, after_state, previous_event_hash,
           event_hash, hmac_signature
      FROM tacacs_management.nad_audit_events
     WHERE ($1::uuid IS NULL OR nad_id = $1)
       AND ($2::uuid IS NULL OR correlation_id = $2)
       AND ($3::text IS NULL OR action = $3)
     ORDER BY occurred_at, event_id
     LIMIT $4 OFFSET $5";

fn validate_create(input: &CreateNadInput) -> Result<(), NadStoreError> {
    validate_name(&input.name)?;
    validate_description(input.description.as_deref())?;
    validate_authentication(&input.authentication)?;
    validate_actor(&input.actor)?;
    if !(16..=128).contains(&input.idempotency_key.len()) {
        return Err(NadStoreError::InvalidInput("invalid_idempotency_key"));
    }
    Ok(())
}

fn validate_update(input: &UpdateNadInput) -> Result<(), NadStoreError> {
    validate_description(input.description.as_deref())?;
    validate_authentication(&input.authentication)?;
    validate_actor(&input.actor)?;
    if input.expected_version < 1 {
        return Err(NadStoreError::InvalidInput("invalid_resource_version"));
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<(), NadStoreError> {
    if name.is_empty() || name.len() > 253 || name != name.to_ascii_lowercase() {
        return Err(NadStoreError::InvalidInput("invalid_nad_name"));
    }
    if !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name.bytes().all(|value| {
            value.is_ascii_lowercase() || value.is_ascii_digit() || b".-".contains(&value)
        })
    {
        return Err(NadStoreError::InvalidInput("invalid_nad_name"));
    }
    Ok(())
}

fn validate_description(description: Option<&str>) -> Result<(), NadStoreError> {
    if description.is_some_and(|value| value.len() > 1024) {
        return Err(NadStoreError::InvalidInput("description_too_long"));
    }
    Ok(())
}

fn validate_actor(actor: &str) -> Result<(), NadStoreError> {
    if actor.is_empty() || actor.len() > 512 {
        return Err(NadStoreError::InvalidInput("invalid_actor"));
    }
    Ok(())
}

fn validate_authentication(authentication: &NadAuthentication) -> Result<(), NadStoreError> {
    match authentication {
        NadAuthentication::Legacy { secret_ref } => {
            if secret_ref.is_empty() || secret_ref.len() > 1024 {
                return Err(NadStoreError::InvalidInput("invalid_secret_ref"));
            }
        }
        NadAuthentication::Tls {
            certificate_identities,
        } => {
            if certificate_identities.is_empty()
                || certificate_identities.len() > 32
                || certificate_identities
                    .iter()
                    .any(|identity| identity.is_empty() || identity.len() > 512)
            {
                return Err(NadStoreError::InvalidInput(
                    "invalid_certificate_identities",
                ));
            }
        }
    }
    Ok(())
}

fn keyed_token(key: &[u8], value: &[u8]) -> Result<String, NadStoreError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| NadStoreError::Unavailable)?;
    mac.update(value);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn request_fingerprint(input: &CreateNadInput) -> Result<String, NadStoreError> {
    let encoded = serde_json::to_vec(&(
        &input.name,
        &input.description,
        input.source_address,
        &input.authentication,
        &input.actor,
    ))
    .map_err(|_| NadStoreError::InvalidInput("request"))?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

async fn replay_create(
    tx: &mut Transaction<'_, Postgres>,
    token: &str,
    fingerprint: &str,
) -> Result<Option<CreateNadOutcome>, NadStoreError> {
    let row = sqlx::query(
        "SELECT request_fingerprint, nad_id
           FROM tacacs_management.nad_idempotency
          WHERE idempotency_token = $1 AND expires_at > clock_timestamp()",
    )
    .bind(token)
    .fetch_optional(&mut **tx)
    .await
    .map_err(map_database_error)?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row.get::<String, _>("request_fingerprint") != fingerprint {
        return Err(NadStoreError::Conflict);
    }
    let record = get_for_update(tx, row.get("nad_id")).await?;
    Ok(Some(CreateNadOutcome::Replay(record)))
}

async fn insert_nad(
    tx: &mut Transaction<'_, Postgres>,
    input: &CreateNadInput,
) -> Result<NadRecord, NadStoreError> {
    let (mode, secret_ref, identities) = encode_authentication(&input.authentication)?;
    let row = sqlx::query(
        "INSERT INTO tacacs_management.nads
            (nad_id, name, description, source_address, authentication_mode,
             secret_ref, certificate_identities, created_by, updated_by)
         VALUES ($1, $2, $3, $4::inet, $5, $6, $7, $8, $8)
         RETURNING nad_id, name, description, host(source_address) AS source_address,
                   authentication_mode, secret_ref, certificate_identities, ownership,
                   resource_version, created_at, created_by, updated_at, updated_by,
                   deleted_at, deleted_by",
    )
    .bind(Uuid::new_v4())
    .bind(&input.name)
    .bind(&input.description)
    .bind(input.source_address.to_string())
    .bind(mode)
    .bind(secret_ref)
    .bind(identities)
    .bind(&input.actor)
    .fetch_one(&mut **tx)
    .await
    .map_err(map_database_error)?;
    decode_nad(&row)
}

async fn get_for_update(
    tx: &mut Transaction<'_, Postgres>,
    nad_id: Uuid,
) -> Result<NadRecord, NadStoreError> {
    let row = sqlx::query(
        "SELECT nad_id, name, description, host(source_address) AS source_address,
                authentication_mode, secret_ref, certificate_identities, ownership,
                resource_version, created_at, created_by, updated_at, updated_by,
                deleted_at, deleted_by
           FROM tacacs_management.nads
          WHERE nad_id = $1 AND deleted_at IS NULL
          FOR UPDATE",
    )
    .bind(nad_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(map_database_error)?
    .ok_or(NadStoreError::NotFound)?;
    decode_nad(&row)
}

async fn update_nad(
    tx: &mut Transaction<'_, Postgres>,
    input: &UpdateNadInput,
) -> Result<NadRecord, NadStoreError> {
    let (mode, secret_ref, identities) = encode_authentication(&input.authentication)?;
    let row = sqlx::query(
        "UPDATE tacacs_management.nads
            SET description = $2, source_address = $3::inet,
                authentication_mode = $4, secret_ref = $5,
                certificate_identities = $6, resource_version = resource_version + 1,
                updated_at = clock_timestamp(), updated_by = $7
          WHERE nad_id = $1 AND deleted_at IS NULL
          RETURNING nad_id, name, description, host(source_address) AS source_address,
                    authentication_mode, secret_ref, certificate_identities, ownership,
                    resource_version, created_at, created_by, updated_at, updated_by,
                    deleted_at, deleted_by",
    )
    .bind(input.nad_id)
    .bind(&input.description)
    .bind(input.source_address.to_string())
    .bind(mode)
    .bind(secret_ref)
    .bind(identities)
    .bind(&input.actor)
    .fetch_one(&mut **tx)
    .await
    .map_err(map_database_error)?;
    decode_nad(&row)
}

async fn soft_delete(
    tx: &mut Transaction<'_, Postgres>,
    nad_id: Uuid,
    actor: &str,
) -> Result<NadRecord, NadStoreError> {
    let row = sqlx::query(
        "UPDATE tacacs_management.nads
            SET deleted_at = clock_timestamp(), deleted_by = $2,
                resource_version = resource_version + 1,
                updated_at = clock_timestamp(), updated_by = $2
          WHERE nad_id = $1 AND deleted_at IS NULL
          RETURNING nad_id, name, description, host(source_address) AS source_address,
                    authentication_mode, secret_ref, certificate_identities, ownership,
                    resource_version, created_at, created_by, updated_at, updated_by,
                    deleted_at, deleted_by",
    )
    .bind(nad_id)
    .bind(actor)
    .fetch_one(&mut **tx)
    .await
    .map_err(map_database_error)?;
    decode_nad(&row)
}

async fn insert_idempotency(
    tx: &mut Transaction<'_, Postgres>,
    token: &str,
    fingerprint: &str,
    nad_id: Uuid,
) -> Result<(), NadStoreError> {
    sqlx::query(
        "INSERT INTO tacacs_management.nad_idempotency
            (idempotency_token, request_fingerprint, nad_id, expires_at)
         VALUES ($1, $2, $3, clock_timestamp() + interval '24 hours')",
    )
    .bind(token)
    .bind(fingerprint)
    .bind(nad_id)
    .execute(&mut **tx)
    .await
    .map_err(map_database_error)?;
    Ok(())
}

async fn insert_operation(
    tx: &mut Transaction<'_, Postgres>,
    operation: &StoredOperation,
) -> Result<(), NadStoreError> {
    sqlx::query(
        "INSERT INTO tacacs_management.operations
            (operation_id, kind, status, submitted_at, completed_at, error)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(operation.operation_id)
    .bind(&operation.kind)
    .bind(&operation.status)
    .bind(operation.submitted_at)
    .bind(operation.completed_at)
    .bind(&operation.error)
    .execute(&mut **tx)
    .await
    .map_err(map_database_error)?;
    Ok(())
}

async fn append_audit(
    tx: &mut Transaction<'_, Postgres>,
    after: &NadRecord,
    before: Option<&NadRecord>,
    action: &str,
    correlation_id: Uuid,
    key: &[u8],
) -> Result<(), NadStoreError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('nad_audit_events'))")
        .execute(&mut **tx)
        .await
        .map_err(map_database_error)?;
    let previous_hash = last_audit_hash(tx).await?;
    let before_state = serialize_optional(before)?;
    let after_state = serde_json::to_value(after).map_err(|_| NadStoreError::CorruptRecord)?;
    let mut event = NadAuditEvent {
        hash_version: 2,
        event_id: Uuid::now_v7(),
        occurred_at: audit_timestamp()?,
        correlation_id,
        actor: after.updated_by.clone(),
        action: action.to_owned(),
        nad_id: after.nad_id,
        resource_version: after.resource_version,
        before_state,
        after_state,
        previous_event_hash: previous_hash.as_deref().map(hex::encode),
        event_hash: String::new(),
        hmac_signature: String::new(),
    };
    let hash = audit_hash_v2(&event, previous_hash.as_deref())?;
    event.event_hash = hex::encode(&hash);
    event.hmac_signature = hex::encode(audit_signature(key, &hash)?);
    insert_audit_row(tx, &event).await
}

fn audit_timestamp() -> Result<OffsetDateTime, NadStoreError> {
    let nanos = OffsetDateTime::now_utc().unix_timestamp_nanos();
    OffsetDateTime::from_unix_timestamp_nanos((nanos / 1_000) * 1_000)
        .map_err(|_| NadStoreError::Unavailable)
}

async fn insert_audit_row(
    tx: &mut Transaction<'_, Postgres>,
    event: &NadAuditEvent,
) -> Result<(), NadStoreError> {
    let previous_hash = decode_stored_hash(event.previous_event_hash.as_deref())?;
    let hash = decode_stored_hash(Some(&event.event_hash))?.ok_or(NadStoreError::CorruptRecord)?;
    let signature =
        decode_stored_hash(Some(&event.hmac_signature))?.ok_or(NadStoreError::CorruptRecord)?;
    sqlx::query(
        "INSERT INTO tacacs_management.nad_audit_events
            (hash_version, event_id, occurred_at, correlation_id, actor, action,
             nad_id, resource_version, before_state, after_state,
             previous_event_hash, event_hash, hmac_signature)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
    )
    .bind(event.hash_version)
    .bind(event.event_id)
    .bind(event.occurred_at)
    .bind(event.correlation_id)
    .bind(&event.actor)
    .bind(&event.action)
    .bind(event.nad_id)
    .bind(event.resource_version)
    .bind(&event.before_state)
    .bind(&event.after_state)
    .bind(previous_hash)
    .bind(hash)
    .bind(signature)
    .execute(&mut **tx)
    .await
    .map_err(map_database_error)?;
    Ok(())
}

fn decode_stored_hash(value: Option<&str>) -> Result<Option<Vec<u8>>, NadStoreError> {
    value
        .map(|encoded| hex::decode(encoded).map_err(|_| NadStoreError::CorruptRecord))
        .transpose()
}

async fn last_audit_hash(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<Option<Vec<u8>>, NadStoreError> {
    sqlx::query_scalar(
        "SELECT event_hash
           FROM tacacs_management.nad_audit_events
          ORDER BY occurred_at DESC, event_id DESC
          LIMIT 1",
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(map_database_error)
}

fn serialize_optional(
    value: Option<&NadRecord>,
) -> Result<Option<serde_json::Value>, NadStoreError> {
    value
        .map(serde_json::to_value)
        .transpose()
        .map_err(|_| NadStoreError::CorruptRecord)
}

fn audit_hash(
    previous_hash: Option<&[u8]>,
    action: &str,
    correlation_id: Uuid,
    after: &NadRecord,
    before_state: Option<&serde_json::Value>,
    after_state: &serde_json::Value,
) -> Result<Vec<u8>, NadStoreError> {
    let mut digest = Sha256::new();
    digest.update(previous_hash.unwrap_or(&[0_u8; 32]));
    digest.update(action.as_bytes());
    digest.update(correlation_id.as_bytes());
    digest.update(after.nad_id.as_bytes());
    digest.update(after.resource_version.to_be_bytes());
    if let Some(before) = before_state {
        digest.update(serde_json::to_vec(before).map_err(|_| NadStoreError::CorruptRecord)?);
    }
    digest.update(serde_json::to_vec(after_state).map_err(|_| NadStoreError::CorruptRecord)?);
    Ok(digest.finalize().to_vec())
}

fn audit_hash_v2(
    event: &NadAuditEvent,
    previous_hash: Option<&[u8]>,
) -> Result<Vec<u8>, NadStoreError> {
    let mut digest = Sha256::new();
    digest.update(b"usg-tacacs:nad-audit:v2\0");
    digest.update(event.hash_version.to_be_bytes());
    digest.update(previous_hash.unwrap_or(&[0_u8; 32]));
    digest.update(event.event_id.as_bytes());
    digest.update(event.occurred_at.unix_timestamp_nanos().to_be_bytes());
    digest.update(event.correlation_id.as_bytes());
    hash_length_prefixed(&mut digest, event.actor.as_bytes());
    hash_length_prefixed(&mut digest, event.action.as_bytes());
    digest.update(event.nad_id.as_bytes());
    digest.update(event.resource_version.to_be_bytes());
    hash_optional_json(&mut digest, event.before_state.as_ref())?;
    let after = serde_json::to_vec(&event.after_state).map_err(|_| NadStoreError::CorruptRecord)?;
    hash_length_prefixed(&mut digest, &after);
    Ok(digest.finalize().to_vec())
}

fn hash_optional_json(
    digest: &mut Sha256,
    value: Option<&serde_json::Value>,
) -> Result<(), NadStoreError> {
    let Some(value) = value else {
        digest.update([0]);
        return Ok(());
    };
    digest.update([1]);
    let encoded = serde_json::to_vec(value).map_err(|_| NadStoreError::CorruptRecord)?;
    hash_length_prefixed(digest, &encoded);
    Ok(())
}

fn hash_length_prefixed(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn audit_signature(key: &[u8], hash: &[u8]) -> Result<Vec<u8>, NadStoreError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| NadStoreError::Unavailable)?;
    mac.update(hash);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn verify_audit_events(
    events: &[NadAuditEvent],
    anchor: Option<&[u8]>,
    key: &[u8],
    offset: usize,
    complete: bool,
) -> NadAuditVerification {
    let mut expected_previous = anchor.map(<[u8]>::to_vec);
    for (index, event) in events.iter().enumerate() {
        match verify_audit_event(event, expected_previous.as_deref(), key) {
            Ok(hash) => expected_previous = Some(hash),
            Err(code) => {
                return failed_audit_verification(events, offset, index, event.event_id, code);
            }
        }
    }
    NadAuditVerification {
        valid: true,
        checked_events: events.len(),
        offset,
        complete,
        first_event_id: events.first().map(|event| event.event_id),
        last_event_id: events.last().map(|event| event.event_id),
        last_event_hash: events.last().map(|event| event.event_hash.clone()),
        failure_event_id: None,
        failure_code: None,
    }
}

fn failed_audit_verification(
    events: &[NadAuditEvent],
    offset: usize,
    checked_events: usize,
    event_id: Uuid,
    code: &'static str,
) -> NadAuditVerification {
    NadAuditVerification {
        valid: false,
        checked_events,
        offset,
        complete: false,
        first_event_id: events.first().map(|event| event.event_id),
        last_event_id: None,
        last_event_hash: None,
        failure_event_id: Some(event_id),
        failure_code: Some(code),
    }
}

fn verify_audit_event(
    event: &NadAuditEvent,
    expected_previous: Option<&[u8]>,
    key: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let previous = decode_optional_hash(event.previous_event_hash.as_deref())?;
    if previous.as_deref() != expected_previous {
        return Err("chain_discontinuity");
    }
    let after: NadRecord =
        serde_json::from_value(event.after_state.clone()).map_err(|_| "invalid_after_state")?;
    verify_audit_metadata(event, &after)?;
    let calculated = calculate_stored_audit_hash(event, &after, previous.as_deref())?;
    let stored = hex::decode(&event.event_hash).map_err(|_| "invalid_event_hash")?;
    if calculated != stored {
        return Err("event_hash_mismatch");
    }
    verify_audit_hmac(key, &stored, &event.hmac_signature)?;
    Ok(stored)
}

fn calculate_stored_audit_hash(
    event: &NadAuditEvent,
    after: &NadRecord,
    previous: Option<&[u8]>,
) -> Result<Vec<u8>, &'static str> {
    match event.hash_version {
        1 => audit_hash(
            previous,
            &event.action,
            event.correlation_id,
            after,
            event.before_state.as_ref(),
            &event.after_state,
        ),
        2 => audit_hash_v2(event, previous),
        _ => return Err("unsupported_hash_version"),
    }
    .map_err(|_| "hash_calculation_failed")
}

fn verify_audit_metadata(event: &NadAuditEvent, after: &NadRecord) -> Result<(), &'static str> {
    if event.actor != after.updated_by {
        return Err("actor_mismatch");
    }
    if event.nad_id != after.nad_id || event.resource_version != after.resource_version {
        return Err("resource_metadata_mismatch");
    }
    match (event.action.as_str(), event.before_state.as_ref()) {
        ("create", None) | ("update" | "delete", Some(_)) => Ok(()),
        ("create" | "update" | "delete", _) => Err("invalid_state_transition"),
        _ => Err("invalid_action"),
    }
}

fn decode_optional_hash(value: Option<&str>) -> Result<Option<Vec<u8>>, &'static str> {
    value
        .map(|hash| hex::decode(hash).map_err(|_| "invalid_previous_event_hash"))
        .transpose()
}

fn verify_audit_hmac(key: &[u8], hash: &[u8], signature: &str) -> Result<(), &'static str> {
    let signature = hex::decode(signature).map_err(|_| "invalid_hmac_signature")?;
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| "invalid_hmac_key")?;
    mac.update(hash);
    mac.verify_slice(&signature)
        .map_err(|_| "hmac_signature_mismatch")
}

fn encode_authentication(
    authentication: &NadAuthentication,
) -> Result<(&'static str, Option<&str>, serde_json::Value), NadStoreError> {
    match authentication {
        NadAuthentication::Legacy { secret_ref } => {
            Ok(("legacy", Some(secret_ref.as_str()), serde_json::json!([])))
        }
        NadAuthentication::Tls {
            certificate_identities,
        } => Ok((
            "tls",
            None,
            serde_json::to_value(certificate_identities)
                .map_err(|_| NadStoreError::InvalidInput("certificate_identities"))?,
        )),
    }
}

fn decode_nad(row: &sqlx::postgres::PgRow) -> Result<NadRecord, NadStoreError> {
    let source = row.get::<String, _>("source_address");
    let source_address = source.parse().map_err(|_| NadStoreError::CorruptRecord)?;
    let mode = row.get::<String, _>("authentication_mode");
    let secret_ref = row.try_get::<Option<String>, _>("secret_ref");
    let identities = row.try_get::<serde_json::Value, _>("certificate_identities");
    let authentication = decode_authentication(&mode, secret_ref, identities)?;
    Ok(NadRecord {
        nad_id: row.get("nad_id"),
        name: row.get("name"),
        description: row.get("description"),
        source_address,
        authentication,
        ownership: row.get("ownership"),
        resource_version: row.get("resource_version"),
        created_at: row.get("created_at"),
        created_by: row.get("created_by"),
        updated_at: row.get("updated_at"),
        updated_by: row.get("updated_by"),
        deleted_at: row.get("deleted_at"),
        deleted_by: row.get("deleted_by"),
    })
}

fn decode_audit_event(row: &sqlx::postgres::PgRow) -> Result<NadAuditEvent, NadStoreError> {
    let previous_hash = row
        .try_get::<Option<Vec<u8>>, _>("previous_event_hash")
        .map_err(|_| NadStoreError::CorruptRecord)?
        .map(hex::encode);
    let event_hash = row
        .try_get::<Vec<u8>, _>("event_hash")
        .map(hex::encode)
        .map_err(|_| NadStoreError::CorruptRecord)?;
    let hmac_signature = row
        .try_get::<Vec<u8>, _>("hmac_signature")
        .map(hex::encode)
        .map_err(|_| NadStoreError::CorruptRecord)?;
    Ok(NadAuditEvent {
        hash_version: row.get("hash_version"),
        event_id: row.get("event_id"),
        occurred_at: row.get("occurred_at"),
        correlation_id: row.get("correlation_id"),
        actor: row.get("actor"),
        action: row.get("action"),
        nad_id: row.get("nad_id"),
        resource_version: row.get("resource_version"),
        before_state: row.get("before_state"),
        after_state: row.get("after_state"),
        previous_event_hash: previous_hash,
        event_hash,
        hmac_signature,
    })
}

fn decode_authentication(
    mode: &str,
    secret_ref: Result<Option<String>, sqlx::Error>,
    identities: Result<serde_json::Value, sqlx::Error>,
) -> Result<NadAuthentication, NadStoreError> {
    match mode {
        "legacy" => Ok(NadAuthentication::Legacy {
            secret_ref: secret_ref
                .map_err(|_| NadStoreError::CorruptRecord)?
                .ok_or(NadStoreError::CorruptRecord)?,
        }),
        "tls" => Ok(NadAuthentication::Tls {
            certificate_identities: serde_json::from_value(
                identities.map_err(|_| NadStoreError::CorruptRecord)?,
            )
            .map_err(|_| NadStoreError::CorruptRecord)?,
        }),
        _ => Err(NadStoreError::CorruptRecord),
    }
}

fn map_database_error(error: sqlx::Error) -> NadStoreError {
    match &error {
        sqlx::Error::RowNotFound => NadStoreError::NotFound,
        sqlx::Error::Database(database) if database.code().as_deref() == Some("23505") => {
            NadStoreError::Conflict
        }
        _ => NadStoreError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_rejects_uppercase_names() {
        assert_eq!(
            validate_name("OOPL-AN-001"),
            Err(NadStoreError::InvalidInput("invalid_nad_name"))
        );
    }

    #[test]
    fn audit_verification_detects_metadata_and_hmac_tampering() {
        let key = vec![0x42; 32];
        let record = test_record();
        let after_state = serde_json::to_value(&record).unwrap();
        let correlation_id = Uuid::new_v4();
        let hash = audit_hash(None, "create", correlation_id, &record, None, &after_state).unwrap();
        let signature = audit_signature(&key, &hash).unwrap();
        let mut event = NadAuditEvent {
            hash_version: 1,
            event_id: Uuid::new_v4(),
            occurred_at: OffsetDateTime::UNIX_EPOCH,
            correlation_id,
            actor: record.updated_by.clone(),
            action: "create".to_owned(),
            nad_id: record.nad_id,
            resource_version: record.resource_version,
            before_state: None,
            after_state,
            previous_event_hash: None,
            event_hash: hex::encode(hash),
            hmac_signature: hex::encode(signature),
        };
        assert!(verify_audit_events(&[event.clone()], None, &key, 0, true).valid);
        event.actor = "CN=attacker.example.mil".to_owned();
        let report = verify_audit_events(&[event], None, &key, 0, true);
        assert!(!report.valid);
        assert_eq!(report.failure_code, Some("actor_mismatch"));
    }

    #[test]
    fn audit_hash_v2_authenticates_forensic_metadata() {
        let key = vec![0x42; 32];
        let record = test_record();
        let mut event = NadAuditEvent {
            hash_version: 2,
            event_id: Uuid::now_v7(),
            occurred_at: OffsetDateTime::UNIX_EPOCH,
            correlation_id: Uuid::new_v4(),
            actor: record.updated_by.clone(),
            action: "create".to_owned(),
            nad_id: record.nad_id,
            resource_version: record.resource_version,
            before_state: None,
            after_state: serde_json::to_value(&record).unwrap(),
            previous_event_hash: None,
            event_hash: String::new(),
            hmac_signature: String::new(),
        };
        let hash = audit_hash_v2(&event, None).unwrap();
        event.event_hash = hex::encode(&hash);
        event.hmac_signature = hex::encode(audit_signature(&key, &hash).unwrap());
        assert!(verify_audit_events(&[event.clone()], None, &key, 0, true).valid);
        event.occurred_at += time::Duration::SECOND;
        let report = verify_audit_events(&[event], None, &key, 0, true);
        assert!(!report.valid);
        assert_eq!(report.failure_code, Some("event_hash_mismatch"));
    }

    fn test_record() -> NadRecord {
        NadRecord {
            nad_id: Uuid::new_v4(),
            name: "oopl-an-001".to_owned(),
            description: None,
            source_address: "192.0.2.10".parse().unwrap(),
            authentication: NadAuthentication::Legacy {
                secret_ref: "/run/secrets/nads/oopl-an-001".to_owned(),
            },
            ownership: "api".to_owned(),
            resource_version: 1,
            created_at: OffsetDateTime::UNIX_EPOCH,
            created_by: "CN=tacacs-admin.example.mil".to_owned(),
            updated_at: OffsetDateTime::UNIX_EPOCH,
            updated_by: "CN=tacacs-admin.example.mil".to_owned(),
            deleted_at: None,
            deleted_by: None,
        }
    }

    fn test_store(pool: PgPool) -> NadStore {
        NadStore::new(pool, Arc::new(vec![0x42; 32])).unwrap()
    }

    fn test_create(key: &str) -> CreateNadInput {
        CreateNadInput {
            name: "oopl-an-001".to_owned(),
            description: Some("IOS-XE lab switch".to_owned()),
            source_address: "192.0.2.10".parse().unwrap(),
            authentication: NadAuthentication::Legacy {
                secret_ref: "/run/secrets/nads/oopl-an-001".to_owned(),
            },
            actor: "CN=tacacs-admin.example.mil".to_owned(),
            correlation_id: Uuid::new_v4(),
            idempotency_key: key.to_owned(),
        }
    }

    fn test_operation() -> StoredOperation {
        StoredOperation {
            operation_id: Uuid::now_v7(),
            kind: "authorizationPolicyReload".to_owned(),
            status: "running".to_owned(),
            submitted_at: audit_timestamp().unwrap(),
            completed_at: None,
            error: None,
        }
    }

    #[sqlx::test]
    async fn postgres_nad_lifecycle_is_versioned_and_audited(pool: PgPool) {
        let store = test_store(pool.clone());
        let created = match store
            .create(test_create("nad-lifecycle-0001"))
            .await
            .unwrap()
        {
            CreateNadOutcome::Created(value) => value,
            CreateNadOutcome::Replay(_) => panic!("first request must create"),
        };
        assert_eq!(created.resource_version, 1);
        assert_eq!(store.list().await.unwrap(), vec![created.clone()]);

        let updated = store
            .update(UpdateNadInput {
                nad_id: created.nad_id,
                description: Some("updated".to_owned()),
                source_address: "192.0.2.11".parse().unwrap(),
                authentication: NadAuthentication::Tls {
                    certificate_identities: vec!["oopl-an-001.example.mil".to_owned()],
                },
                expected_version: 1,
                actor: "CN=tacacs-admin.example.mil".to_owned(),
                correlation_id: Uuid::new_v4(),
            })
            .await
            .unwrap();
        assert_eq!(updated.resource_version, 2);
        assert_eq!(
            store
                .update(UpdateNadInput {
                    nad_id: created.nad_id,
                    description: None,
                    source_address: "192.0.2.12".parse().unwrap(),
                    authentication: updated.authentication.clone(),
                    expected_version: 1,
                    actor: "CN=tacacs-admin.example.mil".to_owned(),
                    correlation_id: Uuid::new_v4(),
                })
                .await,
            Err(NadStoreError::Conflict)
        );

        let deleted = store
            .delete(
                created.nad_id,
                2,
                "CN=tacacs-admin.example.mil",
                Uuid::new_v4(),
            )
            .await
            .unwrap();
        assert_eq!(deleted.resource_version, 3);
        assert!(store.list().await.unwrap().is_empty());
        assert_eq!(
            store.get(created.nad_id).await,
            Err(NadStoreError::NotFound)
        );

        let audit_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM tacacs_management.nad_audit_events")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(audit_count, 3);
        let signed_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM tacacs_management.nad_audit_events
              WHERE octet_length(event_hash) = 32
                AND octet_length(hmac_signature) = 32",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(signed_count, 3);
        let v2_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM tacacs_management.nad_audit_events
              WHERE hash_version = 2",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(v2_count, 3);
        let verification = store.verify_audit_page(10, 0).await.unwrap();
        assert!(verification.valid);
        assert_eq!(verification.checked_events, 3);
        assert!(verification.complete);
    }

    #[sqlx::test]
    async fn postgres_create_idempotency_replays_only_identical_request(pool: PgPool) {
        let store = test_store(pool);
        let input = test_create("nad-idempotency-01");
        let created = store.create(input.clone()).await.unwrap();
        let mut retry = input.clone();
        retry.correlation_id = Uuid::new_v4();
        let replay = store.create(retry).await.unwrap();
        let (CreateNadOutcome::Created(created), CreateNadOutcome::Replay(replayed)) =
            (created, replay)
        else {
            panic!("expected create followed by replay");
        };
        assert_eq!(created.nad_id, replayed.nad_id);

        let mut conflict = input;
        conflict.description = Some("different request".to_owned());
        assert_eq!(store.create(conflict).await, Err(NadStoreError::Conflict));
    }

    #[sqlx::test]
    async fn postgres_audit_events_are_append_only(pool: PgPool) {
        let store = test_store(pool.clone());
        store
            .create(test_create("nad-audit-lock-0001"))
            .await
            .unwrap();
        let update = sqlx::query(
            "UPDATE tacacs_management.nad_audit_events
                SET action = 'tampered'",
        )
        .execute(&pool)
        .await;
        assert!(update.is_err());
        let delete = sqlx::query("DELETE FROM tacacs_management.nad_audit_events")
            .execute(&pool)
            .await;
        assert!(delete.is_err());
    }

    #[sqlx::test]
    async fn postgres_management_operations_survive_replica_handoffs(pool: PgPool) {
        let first_replica = test_store(pool.clone());
        let second_replica = test_store(pool);
        let operation = test_operation();
        first_replica.create_operation(&operation).await.unwrap();
        assert_eq!(
            second_replica
                .get_operation(operation.operation_id)
                .await
                .unwrap(),
            operation
        );
        second_replica
            .complete_operation(operation.operation_id, "succeeded", None)
            .await
            .unwrap();
        let completed = first_replica
            .get_operation(operation.operation_id)
            .await
            .unwrap();
        assert_eq!(completed.status, "succeeded");
        assert!(completed.completed_at.is_some());
    }

    #[sqlx::test]
    async fn postgres_management_operations_recover_after_owner_restart(pool: PgPool) {
        let first_replica = test_store(pool.clone());
        let second_replica = test_store(pool);
        let mut operation = test_operation();
        operation.submitted_at -= time::Duration::minutes(10);
        first_replica.create_operation(&operation).await.unwrap();
        drop(first_replica);

        let cutoff = audit_timestamp().unwrap() - time::Duration::minutes(5);
        let recovered = second_replica
            .fail_abandoned_operations(cutoff)
            .await
            .unwrap();
        let operation = second_replica
            .get_operation(operation.operation_id)
            .await
            .unwrap();
        assert_eq!(recovered, 1);
        assert_eq!(operation.status, "failed");
        assert_eq!(
            operation.error.as_deref(),
            Some("operation owner stopped before completion")
        );
    }

    #[sqlx::test]
    async fn postgres_management_operations_fail_closed_without_store(pool: PgPool) {
        let store = test_store(pool);
        let operation_id = Uuid::now_v7();
        store.pool.close().await;
        assert_eq!(
            store.get_operation(operation_id).await,
            Err(NadStoreError::Unavailable)
        );
    }

    #[test]
    fn validation_rejects_plaintext_like_empty_secret_reference() {
        let auth = NadAuthentication::Legacy {
            secret_ref: String::new(),
        };
        assert_eq!(
            validate_authentication(&auth),
            Err(NadStoreError::InvalidInput("invalid_secret_ref"))
        );
    }

    #[test]
    fn keyed_tokens_do_not_expose_idempotency_keys() {
        let key = [7_u8; 32];
        let token = keyed_token(&key, b"administrator supplied idempotency key").unwrap();
        assert_eq!(token.len(), 64);
        assert!(!token.contains("administrator"));
    }
}
