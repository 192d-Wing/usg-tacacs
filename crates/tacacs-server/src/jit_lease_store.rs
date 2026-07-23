// SPDX-License-Identifier: Apache-2.0
//! Fail-closed PostgreSQL authority for JITPW credential leases.
//!
//! Unlike the best-effort group cache, every storage error is propagated to the
//! caller. Authentication and management handlers must treat errors as denial.
//!
//! # NIST SP 800-53 Rev. 5 Security Controls
//!
//! | Control | Family | Status | Validated | Primary Functions |
//! |---------|--------|--------|-----------|-------------------|
//! | AC-2 | Access Control | Implemented | 2026-07-22 | [`JitLeaseStore::create`] |
//! | AC-12 | Access Control | Implemented | 2026-07-22 | [`JitLeaseStore::revoke`] |
//! | IA-5 | Identification and Authentication | Implemented | 2026-07-22 | [`JitLeaseStore::authenticate`] |
//! | SC-8 | System and Communications Protection | Implemented | 2026-07-22 | [`JitLeaseStore::connect`] |
//! | SI-10 | System and Information Integrity | Implemented | 2026-07-22 | All public methods |

use crate::jit_lease::{
    CanonicalEid, LeaseTtl, NadIdentity, PasswordVerifier, ValidationError, VerifierKey,
};
use serde::{Deserialize, Serialize};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::fmt;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use zeroize::Zeroizing;

const MAX_GROUPS: usize = 64;
const MAX_GROUP_BYTES: usize = 128;
const MAX_SUBJECT_BYTES: usize = 256;
const MIN_IDEMPOTENCY_BYTES: usize = 16;
const MAX_IDEMPOTENCY_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    Unavailable,
    Conflict,
    NotFound,
    CorruptRecord,
    InvalidInput(&'static str),
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("lease_store_unavailable"),
            Self::Conflict => formatter.write_str("active_lease_conflict"),
            Self::NotFound => formatter.write_str("lease_not_found"),
            Self::CorruptRecord => formatter.write_str("corrupt_lease_record"),
            Self::InvalidInput(code) => formatter.write_str(code),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<ValidationError> for StoreError {
    fn from(value: ValidationError) -> Self {
        Self::InvalidInput(value.code())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LeaseStatus {
    Active,
    Revoked,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeaseMetadata {
    pub lease_id: Uuid,
    pub eid: CanonicalEid,
    pub icam_subject: String,
    pub nad_identity: NadIdentity,
    pub authorization_groups: Vec<String>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub status: LeaseStatus,
}

pub struct CreateLeaseInput {
    pub eid: CanonicalEid,
    pub icam_subject: String,
    pub nad_identity: NadIdentity,
    pub authorization_groups: Vec<String>,
    pub ttl: LeaseTtl,
    pub idempotency_key: String,
    pub password: Zeroizing<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateLeaseOutcome {
    Created(LeaseMetadata),
    Replay(LeaseMetadata),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseAuthentication {
    pub authenticated: bool,
    pub metadata: Option<LeaseMetadata>,
}

#[derive(Clone)]
pub struct JitNadAuthenticator {
    store: Arc<JitLeaseStore>,
    nad_identity: NadIdentity,
}

impl JitNadAuthenticator {
    pub fn new(store: Arc<JitLeaseStore>, nad_identity: NadIdentity) -> Self {
        Self {
            store,
            nad_identity,
        }
    }

    pub async fn authenticate(
        &self,
        username: &str,
        password: &[u8],
    ) -> Result<LeaseAuthentication, StoreError> {
        let eid = match CanonicalEid::parse(username) {
            Ok(eid) => eid,
            Err(_) => return Ok(rejected_authentication()),
        };
        self.store
            .authenticate(&eid, &self.nad_identity, password)
            .await
    }
}

#[derive(Clone)]
struct StoredLease {
    metadata: LeaseMetadata,
    verifier: Vec<u8>,
    lookup_token: String,
    idempotency_token: String,
    request_fingerprint: String,
}

#[derive(Clone)]
pub struct JitLeaseStore {
    pool: PgPool,
    verifier_key: Arc<VerifierKey>,
}

impl JitLeaseStore {
    pub async fn connect(
        url: &str,
        password: Option<&str>,
        ca_file: &Path,
        verifier_key: Arc<VerifierKey>,
    ) -> Result<Self, StoreError> {
        validate_store_config(url)?;
        let mut options = PgConnectOptions::from_str(url)
            .map_err(|_| StoreError::InvalidInput("invalid_jit_store_url"))?;
        if let Some(value) = password {
            options = options.password(value);
        }
        options = options
            .ssl_mode(PgSslMode::VerifyFull)
            .ssl_root_cert(ca_file)
            .application_name("usg-tacacs-jit")
            .options([
                ("statement_timeout", "3s"),
                ("lock_timeout", "2s"),
                ("idle_in_transaction_session_timeout", "5s"),
            ]);
        let pool = PgPoolOptions::new()
            .max_connections(16)
            .min_connections(1)
            .acquire_timeout(Duration::from_secs(3))
            .idle_timeout(Duration::from_secs(300))
            .max_lifetime(Duration::from_secs(1_800))
            .connect_with(options)
            .await
            .map_err(|_| StoreError::Unavailable)?;
        sqlx::query("SELECT lease_id FROM jitpw.jit_leases LIMIT 0")
            .execute(&pool)
            .await
            .map_err(|_| StoreError::Unavailable)?;
        Ok(Self { pool, verifier_key })
    }

    pub async fn create(&self, input: CreateLeaseInput) -> Result<CreateLeaseOutcome, StoreError> {
        validate_create_input(&input)?;
        let mut record = self.build_record(&input)?;
        record.request_fingerprint = self.request_fingerprint(&record, input.ttl)?;
        let mut transaction = self.pool.begin().await.map_err(store_unavailable)?;
        advisory_lock(&mut transaction, &record.lookup_token).await?;
        advisory_lock(&mut transaction, &record.idempotency_token).await?;

        if let Some(prior) =
            fetch_by_idempotency(&mut transaction, &record.idempotency_token).await?
        {
            if prior.request_fingerprint != record.request_fingerprint {
                return Err(StoreError::Conflict);
            }
            transaction.commit().await.map_err(store_unavailable)?;
            return Ok(CreateLeaseOutcome::Replay(current_metadata(
                prior.metadata,
            )?));
        }

        sqlx::query(
            "UPDATE jitpw.jit_leases SET status = 'expired', updated_at = clock_timestamp() \
             WHERE lookup_token = $1 AND status = 'active' AND expires_at <= clock_timestamp()",
        )
        .bind(&record.lookup_token)
        .execute(&mut *transaction)
        .await
        .map_err(store_unavailable)?;

        let active: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM jitpw.jit_leases \
             WHERE lookup_token = $1 AND status = 'active')",
        )
        .bind(&record.lookup_token)
        .fetch_one(&mut *transaction)
        .await
        .map_err(store_unavailable)?;
        if active {
            return Err(StoreError::Conflict);
        }

        insert_record(&mut transaction, &record).await?;
        transaction.commit().await.map_err(store_unavailable)?;
        Ok(CreateLeaseOutcome::Created(record.metadata))
    }

    pub async fn get(&self, lease_id: Uuid) -> Result<Option<LeaseMetadata>, StoreError> {
        fetch_by_id(&self.pool, lease_id).await.and_then(|record| {
            record
                .map(|value| current_metadata(value.metadata))
                .transpose()
        })
    }

    pub async fn revoke(&self, lease_id: Uuid) -> Result<(), StoreError> {
        let result = sqlx::query(
            "UPDATE jitpw.jit_leases SET \
             status = CASE WHEN expires_at <= clock_timestamp() THEN 'expired' ELSE 'revoked' END, \
             revoked_at = CASE WHEN expires_at <= clock_timestamp() THEN NULL ELSE COALESCE(revoked_at, clock_timestamp()) END, \
             updated_at = clock_timestamp() WHERE lease_id = $1",
        )
            .bind(lease_id)
            .execute(&self.pool)
            .await
            .map_err(store_unavailable)?;
        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    pub async fn authenticate(
        &self,
        eid: &CanonicalEid,
        nad: &NadIdentity,
        password: &[u8],
    ) -> Result<LeaseAuthentication, StoreError> {
        let lookup = self.lookup_token(eid, nad)?;
        let record = fetch_by_lookup(&self.pool, &lookup).await?;
        let Some(record) = record else {
            return Ok(rejected_authentication());
        };
        self.verify_record(record, eid, nad, password)
    }

    fn build_record(&self, input: &CreateLeaseInput) -> Result<StoredLease, StoreError> {
        let now = unix_time()?;
        let lease_id = fips_uuid()?;
        let expires_at = now
            .checked_add(input.ttl.seconds())
            .ok_or(StoreError::InvalidInput("invalid_expiry"))?;
        let verifier =
            self.verifier_key
                .sign(&input.eid, &input.nad_identity, input.password.as_slice())?;
        let lookup_token = self.lookup_token(&input.eid, &input.nad_identity)?;
        let idempotency_token = self.idempotency_token(&input.idempotency_key)?;
        Ok(StoredLease {
            metadata: LeaseMetadata {
                lease_id,
                eid: input.eid.clone(),
                icam_subject: input.icam_subject.clone(),
                nad_identity: input.nad_identity.clone(),
                authorization_groups: input.authorization_groups.clone(),
                issued_at: now,
                expires_at,
                status: LeaseStatus::Active,
            },
            verifier: verifier.to_bytes().to_vec(),
            lookup_token,
            idempotency_token,
            request_fingerprint: String::new(),
        })
    }

    fn verify_record(
        &self,
        record: StoredLease,
        eid: &CanonicalEid,
        nad: &NadIdentity,
        password: &[u8],
    ) -> Result<LeaseAuthentication, StoreError> {
        let now = unix_time()?;
        if record.metadata.status != LeaseStatus::Active || record.metadata.expires_at <= now {
            return Ok(rejected_authentication());
        }
        if &record.metadata.eid != eid || &record.metadata.nad_identity != nad {
            return Ok(rejected_authentication());
        }
        let verifier_bytes: [u8; 32] = record
            .verifier
            .as_slice()
            .try_into()
            .map_err(|_| StoreError::CorruptRecord)?;
        let verifier = PasswordVerifier::from_bytes(verifier_bytes);
        let authenticated = self.verifier_key.verify(eid, nad, password, &verifier);
        let metadata = authenticated.then_some(record.metadata);
        Ok(LeaseAuthentication {
            authenticated,
            metadata,
        })
    }

    fn lookup_token(&self, eid: &CanonicalEid, nad: &NadIdentity) -> Result<String, StoreError> {
        let input = format!("{}\0{}", eid.as_str(), nad.as_str());
        Ok(self.verifier_key.opaque_token("lookup", input.as_bytes())?)
    }

    fn idempotency_token(&self, key: &str) -> Result<String, StoreError> {
        Ok(self
            .verifier_key
            .opaque_token("idempotency", key.as_bytes())?)
    }

    fn request_fingerprint(
        &self,
        record: &StoredLease,
        ttl: LeaseTtl,
    ) -> Result<String, StoreError> {
        let stable_request = LeaseRequestFingerprint {
            eid: &record.metadata.eid,
            icam_subject: &record.metadata.icam_subject,
            nad_identity: &record.metadata.nad_identity,
            authorization_groups: &record.metadata.authorization_groups,
            ttl_seconds: ttl.seconds(),
            verifier: &record.verifier,
        };
        let serialized =
            serde_json::to_vec(&stable_request).map_err(|_| StoreError::CorruptRecord)?;
        Ok(self.verifier_key.opaque_token("request", &serialized)?)
    }
}

const RECORD_COLUMNS: &str = "lease_id, eid, icam_subject, nad_identity, \
    authorization_groups, verifier, lookup_token, idempotency_token, \
    request_fingerprint, status, EXTRACT(EPOCH FROM issued_at)::bigint AS issued_at, \
    EXTRACT(EPOCH FROM expires_at)::bigint AS expires_at";

async fn advisory_lock(
    transaction: &mut Transaction<'_, Postgres>,
    token: &str,
) -> Result<(), StoreError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(token)
        .execute(&mut **transaction)
        .await
        .map_err(store_unavailable)?;
    Ok(())
}

async fn insert_record(
    transaction: &mut Transaction<'_, Postgres>,
    record: &StoredLease,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO jitpw.jit_leases (lease_id, eid, icam_subject, nad_identity, \
         authorization_groups, verifier, lookup_token, idempotency_token, \
         request_fingerprint, status, issued_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'active', \
         to_timestamp($10), to_timestamp($11))",
    )
    .bind(record.metadata.lease_id)
    .bind(record.metadata.eid.as_str())
    .bind(&record.metadata.icam_subject)
    .bind(record.metadata.nad_identity.as_str())
    .bind(sqlx::types::Json(&record.metadata.authorization_groups))
    .bind(&record.verifier)
    .bind(&record.lookup_token)
    .bind(&record.idempotency_token)
    .bind(&record.request_fingerprint)
    .bind(record.metadata.issued_at as i64)
    .bind(record.metadata.expires_at as i64)
    .execute(&mut **transaction)
    .await
    .map_err(store_unavailable)?;
    Ok(())
}

async fn fetch_by_id(pool: &PgPool, lease_id: Uuid) -> Result<Option<StoredLease>, StoreError> {
    let query = format!("SELECT {RECORD_COLUMNS} FROM jitpw.jit_leases WHERE lease_id = $1");
    let row = sqlx::query(&query)
        .bind(lease_id)
        .fetch_optional(pool)
        .await
        .map_err(store_unavailable)?;
    row.map(decode_row).transpose()
}

async fn fetch_by_lookup(
    pool: &PgPool,
    lookup_token: &str,
) -> Result<Option<StoredLease>, StoreError> {
    let query = format!(
        "SELECT {RECORD_COLUMNS} FROM jitpw.jit_leases \
         WHERE lookup_token = $1 AND status = 'active'"
    );
    let row = sqlx::query(&query)
        .bind(lookup_token)
        .fetch_optional(pool)
        .await
        .map_err(store_unavailable)?;
    row.map(decode_row).transpose()
}

async fn fetch_by_idempotency(
    transaction: &mut Transaction<'_, Postgres>,
    idempotency_token: &str,
) -> Result<Option<StoredLease>, StoreError> {
    let query =
        format!("SELECT {RECORD_COLUMNS} FROM jitpw.jit_leases WHERE idempotency_token = $1");
    let row = sqlx::query(&query)
        .bind(idempotency_token)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(store_unavailable)?;
    row.map(decode_row).transpose()
}

fn decode_row(row: sqlx::postgres::PgRow) -> Result<StoredLease, StoreError> {
    let eid_value: String = row.try_get("eid").map_err(corrupt_row)?;
    let nad_value: String = row.try_get("nad_identity").map_err(corrupt_row)?;
    let status_value: String = row.try_get("status").map_err(corrupt_row)?;
    let groups: sqlx::types::Json<Vec<String>> =
        row.try_get("authorization_groups").map_err(corrupt_row)?;
    validate_subject(
        row.try_get::<&str, _>("icam_subject")
            .map_err(corrupt_row)?,
    )?;
    validate_groups(&groups.0)?;
    let verifier: Vec<u8> = row.try_get("verifier").map_err(corrupt_row)?;
    let lookup_token: String = row.try_get("lookup_token").map_err(corrupt_row)?;
    let idempotency_token: String = row.try_get("idempotency_token").map_err(corrupt_row)?;
    let request_fingerprint: String = row.try_get("request_fingerprint").map_err(corrupt_row)?;
    if verifier.len() != 32
        || !valid_opaque_token(&lookup_token)
        || !valid_opaque_token(&idempotency_token)
        || !valid_opaque_token(&request_fingerprint)
    {
        return Err(StoreError::CorruptRecord);
    }
    Ok(StoredLease {
        metadata: LeaseMetadata {
            lease_id: row.try_get("lease_id").map_err(corrupt_row)?,
            eid: CanonicalEid::parse(&eid_value)?,
            icam_subject: row.try_get("icam_subject").map_err(corrupt_row)?,
            nad_identity: NadIdentity::parse(&nad_value)?,
            authorization_groups: groups.0,
            issued_at: database_time(row.try_get("issued_at").map_err(corrupt_row)?)?,
            expires_at: database_time(row.try_get("expires_at").map_err(corrupt_row)?)?,
            status: match status_value.as_str() {
                "active" => LeaseStatus::Active,
                "revoked" => LeaseStatus::Revoked,
                "expired" => LeaseStatus::Expired,
                _ => return Err(StoreError::CorruptRecord),
            },
        },
        verifier,
        lookup_token,
        idempotency_token,
        request_fingerprint,
    })
}

fn database_time(value: i64) -> Result<u64, StoreError> {
    value.try_into().map_err(|_| StoreError::CorruptRecord)
}

fn current_metadata(mut metadata: LeaseMetadata) -> Result<LeaseMetadata, StoreError> {
    if metadata.status == LeaseStatus::Active && metadata.expires_at <= unix_time()? {
        metadata.status = LeaseStatus::Expired;
    }
    Ok(metadata)
}

fn store_unavailable(_: sqlx::Error) -> StoreError {
    StoreError::Unavailable
}

fn corrupt_row(_: sqlx::Error) -> StoreError {
    StoreError::CorruptRecord
}

fn valid_opaque_token(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Serialize)]
struct LeaseRequestFingerprint<'a> {
    eid: &'a CanonicalEid,
    icam_subject: &'a str,
    nad_identity: &'a NadIdentity,
    authorization_groups: &'a [String],
    ttl_seconds: u64,
    verifier: &'a [u8],
}

fn validate_store_config(url: &str) -> Result<(), StoreError> {
    let parsed =
        url::Url::parse(url).map_err(|_| StoreError::InvalidInput("invalid_jit_store_url"))?;
    if !matches!(parsed.scheme(), "postgresql" | "postgres") || parsed.host_str().is_none() {
        return Err(StoreError::InvalidInput("invalid_jit_store_url"));
    }
    if parsed.password().is_some() {
        return Err(StoreError::InvalidInput("jit_store_password_in_url"));
    }
    Ok(())
}

fn validate_create_input(input: &CreateLeaseInput) -> Result<(), StoreError> {
    validate_subject(&input.icam_subject)?;
    validate_groups(&input.authorization_groups)?;
    validate_idempotency_key(&input.idempotency_key)?;
    Ok(())
}

fn validate_subject(value: &str) -> Result<(), StoreError> {
    if value.is_empty() || value.len() > MAX_SUBJECT_BYTES || value.chars().any(char::is_control) {
        return Err(StoreError::InvalidInput("invalid_icam_subject"));
    }
    Ok(())
}

fn validate_groups(groups: &[String]) -> Result<(), StoreError> {
    if groups.len() > MAX_GROUPS {
        return Err(StoreError::InvalidInput("too_many_authorization_groups"));
    }
    let mut unique = std::collections::HashSet::with_capacity(groups.len());
    for group in groups {
        let valid = !group.is_empty()
            && group.len() <= MAX_GROUP_BYTES
            && group.bytes().all(valid_group_byte);
        if !valid {
            return Err(StoreError::InvalidInput("invalid_authorization_group"));
        }
        if !unique.insert(group) {
            return Err(StoreError::InvalidInput("duplicate_authorization_group"));
        }
    }
    Ok(())
}

fn valid_group_byte(value: u8) -> bool {
    value.is_ascii_alphanumeric() || matches!(value, b'.' | b'_' | b':' | b'@' | b'/' | b'-')
}

fn validate_idempotency_key(value: &str) -> Result<(), StoreError> {
    let valid_length = value.len() >= MIN_IDEMPOTENCY_BYTES && value.len() <= MAX_IDEMPOTENCY_BYTES;
    let valid_bytes = value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'));
    if !valid_length || !valid_bytes {
        return Err(StoreError::InvalidInput("invalid_idempotency_key"));
    }
    Ok(())
}

fn unix_time() -> Result<u64, StoreError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| StoreError::Unavailable)
}

fn fips_uuid() -> Result<Uuid, StoreError> {
    use aws_lc_rs::rand::{SecureRandom, SystemRandom};
    let mut bytes = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| StoreError::Unavailable)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(Uuid::from_bytes(bytes))
}

fn rejected_authentication() -> LeaseAuthentication {
    LeaseAuthentication {
        authenticated: false,
        metadata: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store(pool: PgPool) -> JitLeaseStore {
        let key = VerifierKey::new(Zeroizing::new(vec![0x5a; 32])).unwrap();
        JitLeaseStore {
            pool,
            verifier_key: Arc::new(key),
        }
    }

    fn test_input(idempotency_key: &str, password_byte: u8) -> CreateLeaseInput {
        CreateLeaseInput {
            eid: CanonicalEid::parse("john.e.willman3.mil").unwrap(),
            icam_subject: "icam-subject-123".to_owned(),
            nad_identity: NadIdentity::parse("router-a.example.mil").unwrap(),
            authorization_groups: vec!["network:admins".to_owned()],
            ttl: LeaseTtl::new(900).unwrap(),
            idempotency_key: idempotency_key.to_owned(),
            password: Zeroizing::new(vec![password_byte; 32]),
        }
    }

    #[test]
    fn store_requires_tls_url() {
        assert!(validate_store_config("postgresql://tacacs@db.example.mil/tacacs").is_ok());
        assert_eq!(
            validate_store_config("postgresql://tacacs:secret@db.example.mil/tacacs").unwrap_err(),
            StoreError::InvalidInput("jit_store_password_in_url")
        );
        assert_eq!(
            validate_store_config("rediss://redis.example.mil:6379").unwrap_err(),
            StoreError::InvalidInput("invalid_jit_store_url")
        );
    }

    #[test]
    fn idempotency_keys_are_bounded_ascii() {
        assert!(validate_idempotency_key("1234567890abcdef").is_ok());
        assert!(validate_idempotency_key("short").is_err());
        assert!(validate_idempotency_key("1234567890abcde!").is_err());
    }

    #[test]
    fn opaque_database_tokens_require_sha256_hex() {
        assert!(valid_opaque_token(&"a5".repeat(32)));
        assert!(!valid_opaque_token(&"a5".repeat(31)));
        assert!(!valid_opaque_token(&format!("{}!", "a5".repeat(31))));
    }

    #[test]
    fn group_validation_matches_contract() {
        assert!(validate_groups(&["network:admins".to_string()]).is_ok());
        assert!(validate_groups(&["network admins".to_string()]).is_err());
    }

    #[test]
    fn generated_identifier_is_uuid_v4() {
        let id = fips_uuid().unwrap();
        assert_eq!(id.get_version_num(), 4);
        assert_eq!(id.get_variant(), uuid::Variant::RFC4122);
    }

    #[sqlx::test]
    async fn postgres_lease_lifecycle(pool: PgPool) {
        let store = test_store(pool);
        let created = store
            .create(test_input("lifecycle-key-001", 0x41))
            .await
            .unwrap();
        let metadata = match created {
            CreateLeaseOutcome::Created(value) => value,
            CreateLeaseOutcome::Replay(_) => panic!("first request must create a lease"),
        };

        let authenticated = store
            .authenticate(
                &CanonicalEid::parse("john.e.willman3.mil").unwrap(),
                &NadIdentity::parse("router-a.example.mil").unwrap(),
                &[0x41; 32],
            )
            .await
            .unwrap();
        assert!(authenticated.authenticated);

        store.revoke(metadata.lease_id).await.unwrap();
        store.revoke(metadata.lease_id).await.unwrap();
        let rejected = store
            .authenticate(
                &CanonicalEid::parse("john.e.willman3.mil").unwrap(),
                &NadIdentity::parse("router-a.example.mil").unwrap(),
                &[0x41; 32],
            )
            .await
            .unwrap();
        assert!(!rejected.authenticated);
        assert_eq!(
            store.get(metadata.lease_id).await.unwrap().unwrap().status,
            LeaseStatus::Revoked
        );
    }

    #[sqlx::test]
    async fn postgres_idempotency_replays_only_identical_request(pool: PgPool) {
        let store = test_store(pool);
        let first = store
            .create(test_input("idempotency-key-001", 0x41))
            .await
            .unwrap();
        let replay = store
            .create(test_input("idempotency-key-001", 0x41))
            .await
            .unwrap();
        assert!(matches!(first, CreateLeaseOutcome::Created(_)));
        assert!(matches!(replay, CreateLeaseOutcome::Replay(_)));
        assert_eq!(
            store
                .create(test_input("idempotency-key-001", 0x42))
                .await
                .unwrap_err(),
            StoreError::Conflict
        );
    }

    #[sqlx::test]
    async fn postgres_concurrent_issuance_allows_one_active_lease(pool: PgPool) {
        let first_store = test_store(pool.clone());
        let second_store = test_store(pool);
        let (first, second) = tokio::join!(
            first_store.create(test_input("concurrent-key-001", 0x41)),
            second_store.create(test_input("concurrent-key-002", 0x42))
        );
        let outcomes = [first, second];
        assert_eq!(
            outcomes
                .iter()
                .filter(|result| matches!(result, Ok(CreateLeaseOutcome::Created(_))))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|result| matches!(result, Err(StoreError::Conflict)))
                .count(),
            1
        );
    }

    #[sqlx::test]
    async fn postgres_store_outage_fails_closed(pool: PgPool) {
        let store = test_store(pool.clone());
        pool.close().await;
        assert_eq!(
            store.get(fips_uuid().unwrap()).await.unwrap_err(),
            StoreError::Unavailable
        );
    }
}
