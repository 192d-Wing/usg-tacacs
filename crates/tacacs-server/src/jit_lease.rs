// SPDX-License-Identifier: Apache-2.0
//! Validated JITPW credential lease domain types and password verifiers.
//!
//! # NIST SP 800-53 Rev. 5 Security Controls
//!
//! | Control | Family | Status | Validated | Primary Functions |
//! |---------|--------|--------|-----------|-------------------|
//! | IA-4 | Identification and Authentication | Implemented | 2026-07-22 | [`CanonicalEid::parse`] |
//! | IA-5 | Identification and Authentication | Implemented | 2026-07-22 | [`VerifierKey::sign`], [`VerifierKey::verify`] |
//! | SC-13 | System and Communications Protection | Implemented | 2026-07-22 | [`VerifierKey::sign`] |
//! | SI-10 | System and Information Integrity | Implemented | 2026-07-22 | All constructors |

use aws_lc_rs::hmac;
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

pub const MAX_LEASE_TTL_SECONDS: u64 = 900;
pub const MIN_PASSWORD_BYTES: usize = 24;
pub const MAX_PASSWORD_BYTES: usize = 128;
const MAX_EID_BYTES: usize = 128;
const MAX_NAD_BYTES: usize = 253;
const MIN_VERIFIER_KEY_BYTES: usize = 32;
const MAX_VERIFIER_KEY_BYTES: usize = 64;
const MAX_OPAQUE_TOKEN_INPUT_BYTES: usize = 16_384;

/// Stable input-validation failure without echoing rejected values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidationError {
    code: &'static str,
}

impl ValidationError {
    const fn new(code: &'static str) -> Self {
        Self { code }
    }

    pub const fn code(self) -> &'static str {
        self.code
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code)
    }
}

impl std::error::Error for ValidationError {}

/// Lowercase ASCII enterprise identifier asserted by ICAM.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CanonicalEid(String);

impl CanonicalEid {
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        if !valid_name(value, MAX_EID_BYTES, true) {
            return Err(ValidationError::new("invalid_eid"));
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Trusted configured identity of one network access device.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NadIdentity(String);

impl NadIdentity {
    pub fn parse(value: &str) -> Result<Self, ValidationError> {
        if !valid_name(value, MAX_NAD_BYTES, false) {
            return Err(ValidationError::new("invalid_nad_identity"));
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Positive lease lifetime bounded to fifteen minutes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LeaseTtl(u64);

impl LeaseTtl {
    pub fn new(seconds: u64) -> Result<Self, ValidationError> {
        if seconds == 0 || seconds > MAX_LEASE_TTL_SECONDS {
            return Err(ValidationError::new("invalid_lease_ttl"));
        }
        Ok(Self(seconds))
    }

    pub const fn seconds(self) -> u64 {
        self.0
    }
}

/// HMAC-SHA-256 verifier bytes persisted with a lease.
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordVerifier([u8; 32]);

impl PasswordVerifier {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(value: &str) -> Result<Self, ValidationError> {
        let decoded =
            hex::decode(value).map_err(|_| ValidationError::new("invalid_verifier_encoding"))?;
        let bytes = decoded
            .try_into()
            .map_err(|_| ValidationError::new("invalid_verifier_length"))?;
        Ok(Self(bytes))
    }
}

impl Drop for PasswordVerifier {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for PasswordVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PasswordVerifier([REDACTED])")
    }
}

/// Protected key used to derive device-bound password verifiers.
pub struct VerifierKey {
    bytes: Zeroizing<Vec<u8>>,
}

impl VerifierKey {
    pub fn new(bytes: Zeroizing<Vec<u8>>) -> Result<Self, ValidationError> {
        if bytes.len() < MIN_VERIFIER_KEY_BYTES || bytes.len() > MAX_VERIFIER_KEY_BYTES {
            return Err(ValidationError::new("invalid_verifier_key_length"));
        }
        Ok(Self { bytes })
    }

    pub fn sign(
        &self,
        eid: &CanonicalEid,
        nad: &NadIdentity,
        password: &[u8],
    ) -> Result<PasswordVerifier, ValidationError> {
        validate_password(password)?;
        let message = verifier_message(eid, nad, password);
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.bytes.as_slice());
        let tag = hmac::sign(&key, message.as_slice());
        let bytes: [u8; 32] = tag
            .as_ref()
            .try_into()
            .map_err(|_| ValidationError::new("invalid_verifier_length"))?;
        Ok(PasswordVerifier::from_bytes(bytes))
    }

    // Used when the TACACS authentication enforcement stage is connected.
    #[allow(dead_code)]
    pub fn verify(
        &self,
        eid: &CanonicalEid,
        nad: &NadIdentity,
        password: &[u8],
        expected: &PasswordVerifier,
    ) -> bool {
        if validate_password(password).is_err() {
            return false;
        }
        let message = verifier_message(eid, nad, password);
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.bytes.as_slice());
        hmac::verify(&key, message.as_slice(), &expected.0).is_ok()
    }

    pub fn opaque_token(&self, label: &str, input: &[u8]) -> Result<String, ValidationError> {
        if label.is_empty() || input.is_empty() || input.len() > MAX_OPAQUE_TOKEN_INPUT_BYTES {
            return Err(ValidationError::new("invalid_token_input"));
        }
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.bytes.as_slice());
        let mut context = hmac::Context::with_key(&key);
        context.update(label.as_bytes());
        context.update(&[0]);
        context.update(input);
        Ok(hex::encode(context.sign().as_ref()))
    }
}

fn valid_name(value: &str, max_bytes: usize, lowercase_only: bool) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > max_bytes {
        return false;
    }
    if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return false;
    }
    bytes.iter().all(|byte| {
        let allowed = byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-');
        allowed && (!lowercase_only || !byte.is_ascii_uppercase())
    })
}

fn validate_password(password: &[u8]) -> Result<(), ValidationError> {
    if password.len() < MIN_PASSWORD_BYTES || password.len() > MAX_PASSWORD_BYTES {
        return Err(ValidationError::new("invalid_password_length"));
    }
    Ok(())
}

fn verifier_message(eid: &CanonicalEid, nad: &NadIdentity, password: &[u8]) -> Zeroizing<Vec<u8>> {
    let capacity = 3 + eid.as_str().len() + nad.as_str().len() + password.len();
    let mut message = Zeroizing::new(Vec::with_capacity(capacity));
    message.extend_from_slice(b"v1\0");
    message.extend_from_slice(eid.as_str().as_bytes());
    message.push(0);
    message.extend_from_slice(nad.as_str().as_bytes());
    message.push(0);
    message.extend_from_slice(password);
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::rand::{SecureRandom, SystemRandom};

    fn random_bytes(length: usize) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(vec![0_u8; length]);
        SystemRandom::new().fill(bytes.as_mut_slice()).unwrap();
        bytes
    }

    #[test]
    fn eid_requires_lowercase_ascii() {
        assert!(CanonicalEid::parse("john.e.willman3.mil").is_ok());
        assert_eq!(
            CanonicalEid::parse("John.Mil").unwrap_err().code(),
            "invalid_eid"
        );
        assert!(CanonicalEid::parse("john_mil").is_err());
    }

    #[test]
    fn lease_ttl_is_bounded() {
        assert!(LeaseTtl::new(1).is_ok());
        assert_eq!(LeaseTtl::new(900).unwrap().seconds(), 900);
        assert!(LeaseTtl::new(0).is_err());
        assert!(LeaseTtl::new(901).is_err());
    }

    #[test]
    fn verifier_is_bound_to_eid_and_nad() {
        let key = VerifierKey::new(random_bytes(MIN_VERIFIER_KEY_BYTES)).unwrap();
        let eid = CanonicalEid::parse("john.e.willman3.mil").unwrap();
        let other_eid = CanonicalEid::parse("other.user.mil").unwrap();
        let nad = NadIdentity::parse("a-an-001.a.net.example.com").unwrap();
        let other_nad = NadIdentity::parse("a-an-002.a.net.example.com").unwrap();
        let password = random_bytes(MIN_PASSWORD_BYTES);
        let verifier = key.sign(&eid, &nad, password.as_slice()).unwrap();
        assert!(key.verify(&eid, &nad, password.as_slice(), &verifier));
        assert!(!key.verify(&other_eid, &nad, password.as_slice(), &verifier));
        assert!(!key.verify(&eid, &other_nad, password.as_slice(), &verifier));
    }

    #[test]
    fn verifier_rejects_wrong_password_and_redacts_debug() {
        let key = VerifierKey::new(random_bytes(MIN_VERIFIER_KEY_BYTES)).unwrap();
        let eid = CanonicalEid::parse("john.e.willman3.mil").unwrap();
        let nad = NadIdentity::parse("a-an-001.a.net.example.com").unwrap();
        let password = random_bytes(MIN_PASSWORD_BYTES);
        let wrong_password = random_bytes(MIN_PASSWORD_BYTES);
        let verifier = key.sign(&eid, &nad, password.as_slice()).unwrap();
        assert!(!key.verify(&eid, &nad, wrong_password.as_slice(), &verifier));
        assert_eq!(format!("{verifier:?}"), "PasswordVerifier([REDACTED])");
    }
}
