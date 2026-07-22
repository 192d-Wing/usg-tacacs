// SPDX-License-Identifier: Apache-2.0
//! Fail-closed Redis authority for JITPW credential leases.
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
use redis::Script;
use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use zeroize::Zeroizing;

const MAX_GROUPS: usize = 64;
const MAX_GROUP_BYTES: usize = 128;
const MAX_SUBJECT_BYTES: usize = 256;
const MIN_IDEMPOTENCY_BYTES: usize = 16;
const MAX_IDEMPOTENCY_BYTES: usize = 128;
const CREATE_SCRIPT: &str = r#"
local prior = redis.call('GET', KEYS[3])
if prior then
  local prior_id = string.sub(prior, 1, 36)
  local prior_fingerprint = string.sub(prior, 38)
  if prior_fingerprint == ARGV[2] then return {1, prior_id} end
  return {3, ''}
end
local active = redis.call('GET', KEYS[2])
if active then return {2, active} end
redis.call('SET', KEYS[1], ARGV[3], 'EX', ARGV[4])
redis.call('SET', KEYS[2], ARGV[1], 'EX', ARGV[4])
redis.call('SET', KEYS[3], ARGV[1] .. ':' .. ARGV[2], 'EX', ARGV[4])
return {0, ARGV[1]}
"#;
const LOOKUP_SCRIPT: &str = r#"
local lease_id = redis.call('GET', KEYS[1])
if not lease_id then return nil end
return redis.call('GET', ARGV[1] .. lease_id)
"#;
const REVOKE_SCRIPT: &str = r#"
local record = redis.call('GET', KEYS[1])
if not record then return 0 end
redis.call('DEL', KEYS[1], KEYS[2], KEYS[3])
return 1
"#;

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

#[derive(Clone, Serialize, Deserialize)]
struct StoredLease {
    metadata: LeaseMetadata,
    verifier_hex: String,
    lookup_token: String,
    idempotency_token: String,
}

#[derive(Clone)]
pub struct JitLeaseStore {
    connection: ConnectionManager,
    verifier_key: Arc<VerifierKey>,
    key_prefix: String,
}

impl JitLeaseStore {
    pub async fn connect(
        url: &str,
        password: Option<&str>,
        key_prefix: &str,
        verifier_key: Arc<VerifierKey>,
    ) -> Result<Self, StoreError> {
        validate_store_config(url, key_prefix)?;
        let connection_info = build_connection_info(url, password)?;
        let client = redis::Client::open(connection_info).map_err(|_| StoreError::Unavailable)?;
        let connection = ConnectionManager::new(client)
            .await
            .map_err(|_| StoreError::Unavailable)?;
        Ok(Self {
            connection,
            verifier_key,
            key_prefix: key_prefix.to_owned(),
        })
    }

    pub async fn create(&self, input: CreateLeaseInput) -> Result<CreateLeaseOutcome, StoreError> {
        validate_create_input(&input)?;
        let record = self.build_record(&input)?;
        let serialized = serde_json::to_string(&record).map_err(|_| StoreError::CorruptRecord)?;
        let keys = self.record_keys(&record);
        let fingerprint = self.request_fingerprint(&record, input.ttl)?;
        let mut connection = self.connection.clone();
        let response: (i64, String) = Script::new(CREATE_SCRIPT)
            .key(&keys.lease)
            .key(&keys.lookup)
            .key(&keys.idempotency)
            .arg(record.metadata.lease_id.to_string())
            .arg(fingerprint)
            .arg(serialized)
            .arg(input.ttl.seconds())
            .invoke_async(&mut connection)
            .await
            .map_err(|_| StoreError::Unavailable)?;
        self.create_outcome(response, record.metadata).await
    }

    pub async fn get(&self, lease_id: Uuid) -> Result<Option<LeaseMetadata>, StoreError> {
        let mut connection = self.connection.clone();
        let payload: Option<String> = redis::cmd("GET")
            .arg(self.lease_key(lease_id))
            .query_async(&mut connection)
            .await
            .map_err(|_| StoreError::Unavailable)?;
        payload
            .map(|value| decode_record(&value).map(|record| record.metadata))
            .transpose()
    }

    pub async fn revoke(&self, lease_id: Uuid) -> Result<(), StoreError> {
        let record = self.get_record(lease_id).await?;
        let keys = self.record_keys(&record);
        let mut connection = self.connection.clone();
        let removed: i64 = Script::new(REVOKE_SCRIPT)
            .key(keys.lease)
            .key(keys.lookup)
            .key(keys.idempotency)
            .invoke_async(&mut connection)
            .await
            .map_err(|_| StoreError::Unavailable)?;
        if removed == 0 {
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
        let lookup = self.lookup_key(eid, nad)?;
        let mut connection = self.connection.clone();
        let payload: Option<String> = Script::new(LOOKUP_SCRIPT)
            .key(lookup)
            .arg(format!("{}:lease:", self.key_prefix))
            .invoke_async(&mut connection)
            .await
            .map_err(|_| StoreError::Unavailable)?;
        let Some(payload) = payload else {
            return Ok(rejected_authentication());
        };
        let record = decode_record(&payload)?;
        self.verify_record(record, eid, nad, password)
    }

    async fn create_outcome(
        &self,
        response: (i64, String),
        created: LeaseMetadata,
    ) -> Result<CreateLeaseOutcome, StoreError> {
        match response.0 {
            0 => Ok(CreateLeaseOutcome::Created(created)),
            1 => {
                let id = Uuid::parse_str(&response.1).map_err(|_| StoreError::CorruptRecord)?;
                let metadata = self.get(id).await?.ok_or(StoreError::CorruptRecord)?;
                Ok(CreateLeaseOutcome::Replay(metadata))
            }
            2 | 3 => Err(StoreError::Conflict),
            _ => Err(StoreError::CorruptRecord),
        }
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
            verifier_hex: verifier.to_hex(),
            lookup_token,
            idempotency_token,
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
        let verifier = PasswordVerifier::from_hex(&record.verifier_hex)?;
        let authenticated = self.verifier_key.verify(eid, nad, password, &verifier);
        let metadata = authenticated.then_some(record.metadata);
        Ok(LeaseAuthentication {
            authenticated,
            metadata,
        })
    }

    async fn get_record(&self, lease_id: Uuid) -> Result<StoredLease, StoreError> {
        let mut connection = self.connection.clone();
        let payload: Option<String> = redis::cmd("GET")
            .arg(self.lease_key(lease_id))
            .query_async(&mut connection)
            .await
            .map_err(|_| StoreError::Unavailable)?;
        decode_record(&payload.ok_or(StoreError::NotFound)?)
    }

    fn record_keys(&self, record: &StoredLease) -> RecordKeys {
        RecordKeys {
            lease: self.lease_key(record.metadata.lease_id),
            lookup: format!("{}:lookup:{}", self.key_prefix, record.lookup_token),
            idempotency: format!("{}:idem:{}", self.key_prefix, record.idempotency_token),
        }
    }

    fn lease_key(&self, lease_id: Uuid) -> String {
        format!("{}:lease:{lease_id}", self.key_prefix)
    }

    fn lookup_key(&self, eid: &CanonicalEid, nad: &NadIdentity) -> Result<String, StoreError> {
        Ok(format!(
            "{}:lookup:{}",
            self.key_prefix,
            self.lookup_token(eid, nad)?
        ))
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
            verifier_hex: &record.verifier_hex,
        };
        let serialized =
            serde_json::to_vec(&stable_request).map_err(|_| StoreError::CorruptRecord)?;
        Ok(self.verifier_key.opaque_token("request", &serialized)?)
    }
}

#[derive(Serialize)]
struct LeaseRequestFingerprint<'a> {
    eid: &'a CanonicalEid,
    icam_subject: &'a str,
    nad_identity: &'a NadIdentity,
    authorization_groups: &'a [String],
    ttl_seconds: u64,
    verifier_hex: &'a str,
}

struct RecordKeys {
    lease: String,
    lookup: String,
    idempotency: String,
}

fn validate_store_config(url: &str, key_prefix: &str) -> Result<(), StoreError> {
    if !url.starts_with("rediss://") {
        return Err(StoreError::InvalidInput("jit_store_requires_tls"));
    }
    if key_prefix.is_empty() || key_prefix.len() > 64 || !key_prefix.is_ascii() {
        return Err(StoreError::InvalidInput("invalid_jit_store_prefix"));
    }
    Ok(())
}

fn build_connection_info(
    url: &str,
    password: Option<&str>,
) -> Result<redis::ConnectionInfo, StoreError> {
    use redis::IntoConnectionInfo;
    let mut info = url
        .into_connection_info()
        .map_err(|_| StoreError::InvalidInput("invalid_jit_store_url"))?;
    if let Some(value) = password {
        info.redis.password = Some(value.to_owned());
    }
    Ok(info)
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

fn decode_record(payload: &str) -> Result<StoredLease, StoreError> {
    let record: StoredLease =
        serde_json::from_str(payload).map_err(|_| StoreError::CorruptRecord)?;
    PasswordVerifier::from_hex(&record.verifier_hex)?;
    validate_subject(&record.metadata.icam_subject)?;
    validate_groups(&record.metadata.authorization_groups)?;
    Ok(record)
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

    #[test]
    fn store_requires_tls_url() {
        assert!(validate_store_config("rediss://redis.example.mil:6379", "jitpw").is_ok());
        assert_eq!(
            validate_store_config("redis://redis.example.mil:6379", "jitpw").unwrap_err(),
            StoreError::InvalidInput("jit_store_requires_tls")
        );
    }

    #[test]
    fn idempotency_keys_are_bounded_ascii() {
        assert!(validate_idempotency_key("1234567890abcdef").is_ok());
        assert!(validate_idempotency_key("short").is_err());
        assert!(validate_idempotency_key("1234567890abcde!").is_err());
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
}
