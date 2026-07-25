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

    pub async fn get(&self, nad_id: Uuid) -> Result<NadRecord, NadStoreError> {
        let row = sqlx::query(NAD_SELECT_ONE)
            .bind(nad_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_database_error)?
            .ok_or(NadStoreError::NotFound)?;
        decode_nad(&row)
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
    let hash = audit_hash(
        previous_hash.as_deref(),
        action,
        correlation_id,
        after,
        before_state.as_ref(),
        &after_state,
    )?;
    let signature = audit_signature(key, &hash)?;
    insert_audit_row(
        tx,
        after,
        action,
        correlation_id,
        before_state,
        after_state,
        previous_hash,
        hash,
        signature,
    )
    .await
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

#[allow(clippy::too_many_arguments)]
async fn insert_audit_row(
    tx: &mut Transaction<'_, Postgres>,
    after: &NadRecord,
    action: &str,
    correlation_id: Uuid,
    before_state: Option<serde_json::Value>,
    after_state: serde_json::Value,
    previous_hash: Option<Vec<u8>>,
    hash: Vec<u8>,
    signature: Vec<u8>,
) -> Result<(), NadStoreError> {
    sqlx::query(
        "INSERT INTO tacacs_management.nad_audit_events
            (event_id, correlation_id, actor, action, nad_id, resource_version,
             before_state, after_state, previous_event_hash, event_hash, hmac_signature)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(Uuid::new_v4())
    .bind(correlation_id)
    .bind(&after.updated_by)
    .bind(action)
    .bind(after.nad_id)
    .bind(after.resource_version)
    .bind(before_state)
    .bind(after_state)
    .bind(previous_hash)
    .bind(hash)
    .bind(signature)
    .execute(&mut **tx)
    .await
    .map_err(map_database_error)?;
    Ok(())
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

fn audit_signature(key: &[u8], hash: &[u8]) -> Result<Vec<u8>, NadStoreError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| NadStoreError::Unavailable)?;
    mac.update(hash);
    Ok(mac.finalize().into_bytes().to_vec())
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
