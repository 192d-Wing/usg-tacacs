// SPDX-License-Identifier: Apache-2.0
//! ICAM/OIDC external authentication module.
//!
//! Delegates credential validation to an enterprise Identity, Credential, and
//! Access Management (ICAM) system via the OIDC Resource Owner Password
//! Credentials (ROPC) grant.  The returned JWT access token is decoded to
//! extract group/role claims that drive TACACS+ authorization policy.
//!
//! # NIST SP 800-53 Rev. 5 Security Controls
//!
//! | Control | Family | Status | Validated | Primary Functions |
//! |---------|--------|--------|-----------|-------------------|
//! | IA-2 | Identification and Authentication | Implemented | 2026-06-04 | [`icam_authenticate`] |
//! | IA-5 | Identification and Authentication | Implemented | 2026-06-04 | [`icam_authenticate`] |
//! | IA-8 | Identification and Authentication | Implemented | 2026-06-04 | [`icam_authenticate`] |
//! | SC-8 | System and Communications Protection | Implemented | 2026-06-04 | [`icam_build_client`] |
//! | SC-13 | System and Communications Protection | Implemented | 2026-06-04 | [`icam_authenticate`] |
//! | AU-2 | Audit and Accountability | Implemented | 2026-06-04 | [`icam_authenticate`] |
//! | AU-12 | Audit and Accountability | Implemented | 2026-06-04 | [`icam_authenticate`] |
//! | SI-10 | System and Information Integrity | Implemented | 2026-06-04 | [`icam_decode_jwt_payload`] |
//! | AC-2 | Access Control | Implemented | 2026-06-04 | [`icam_extract_groups_from_claim`] |
//!
//! # Design
//!
//! 1. NAD sends PAP username+password to TACACS+.
//! 2. TACACS+ forwards credentials to ICAM token endpoint via ROPC grant.
//! 3. ICAM returns a JWT access token on success.
//! 4. TACACS+ decodes the JWT payload (no signature verification needed —
//!    the response is already authenticated by HTTPS/TLS) and extracts
//!    the configured groups claim.
//! 5. Groups are stored in per-connection state for use in authorization.

use base64::Engine as _;
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use std::path::PathBuf;
use std::time::Duration;

/// Maximum groups allowed from a single ICAM token (loop bound, Power of 10 rule 2).
const MAX_ICAM_GROUPS: usize = 256;

/// Maximum JWT payload segment size in bytes (DoS guard, NIST SC-5).
const MAX_JWT_PAYLOAD_BYTES: usize = 65536;

/// ICAM/OIDC provider configuration.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | IA-5 | Authenticator Management | client_secret redacted in Debug output |
/// | SC-8 | Transmission Confidentiality | HTTPS-only HTTP client built at startup |
#[derive(Clone)]
pub struct IcamConfig {
    /// OIDC token endpoint URL (e.g. `https://keycloak.example.com/realms/myrealm/protocol/openid-connect/token`).
    pub token_endpoint: String,
    /// OIDC client ID registered in the ICAM provider.
    pub client_id: String,
    /// OIDC client secret (never logged).
    pub client_secret: String,
    /// JWT claim name containing the user's groups/roles (default: `"groups"`).
    pub groups_claim: String,
    /// Request timeout for ICAM HTTP calls.
    pub timeout: Duration,
    /// Optional CA bundle path for ICAM TLS verification.
    pub ca_file: Option<PathBuf>,
    /// Shared HTTPS client (built once at startup, reused across requests).
    pub http_client: Client,
}

/// Redact client_secret from debug output.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | IA-5 | Authenticator Management | Prevents secret exposure in debug/log output |
impl std::fmt::Debug for IcamConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IcamConfig")
            .field("token_endpoint", &self.token_endpoint)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("groups_claim", &self.groups_claim)
            .field("timeout", &self.timeout)
            .field("ca_file", &self.ca_file)
            .finish()
    }
}

/// Result of an ICAM authentication attempt.
pub struct IcamAuthResult {
    /// True when ICAM accepted the credentials.
    pub authenticated: bool,
    /// Group/role strings extracted from the ICAM JWT, lowercased.
    pub groups: Vec<String>,
}

/// Subset of the OIDC token endpoint response fields we care about.
#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    error: Option<String>,
}

/// Build a reusable reqwest client for ICAM requests.
///
/// When `ca_pem` is provided the certificate is added as an additional trusted
/// root so internal PKI (e.g. oopl-ca) can be used with `https://` endpoints.
/// HTTPS-only is enforced when `https_only` is true (default for production).
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | SC-8 | Transmission Confidentiality | HTTPS-only enforced; custom CA supported for internal PKI |
pub fn icam_build_client(
    timeout: Duration,
    ca_pem: Option<&[u8]>,
    https_only: bool,
) -> Result<Client, reqwest::Error> {
    let mut builder = Client::builder().timeout(timeout).https_only(https_only);
    if let Some(pem) = ca_pem {
        if let Ok(cert) = reqwest::Certificate::from_pem(pem) {
            builder = builder.add_root_certificate(cert);
        }
    }
    builder.build()
}

/// Decode the base64url-encoded JWT payload segment (middle of three dots).
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | SI-10 | Information Input Validation | Rejects oversized or malformed JWT segments |
fn icam_decode_jwt_payload(token: &str) -> Option<Value> {
    let mut iter = token.splitn(3, '.');
    let _ = iter.next()?; // skip header
    let payload_b64 = iter.next()?;
    if payload_b64.len() > MAX_JWT_PAYLOAD_BYTES {
        tracing::warn!(
            len = payload_b64.len(),
            limit = MAX_JWT_PAYLOAD_BYTES,
            "ICAM JWT payload segment exceeds size limit; rejecting"
        );
        return None;
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .ok()?;
    serde_json::from_slice(&decoded).ok()
}

/// Extract group strings from a JSON claim value (array or single string).
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-2 | Account Management | Maps ICAM groups to TACACS+ policy group identifiers |
fn icam_extract_groups_from_claim(claim_val: &Value) -> Vec<String> {
    match claim_val {
        Value::Array(arr) => arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
            .take(MAX_ICAM_GROUPS)
            .collect(),
        Value::String(s) if !s.is_empty() => vec![s.to_lowercase()],
        _ => Vec::new(),
    }
}

/// POST credentials to the OIDC token endpoint using ROPC grant.
///
/// Returns the raw JWT access token string on success, None on any failure.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | IA-2 | Identification and Authentication | Delegates credential validation to ICAM |
/// | SC-8 | Transmission Confidentiality | Credentials transmitted only over HTTPS |
/// | SC-13 | Cryptographic Protection | TLS enforced by the HTTPS-only client |
async fn icam_call_token_endpoint(
    client: &Client,
    endpoint: &str,
    client_id: &str,
    client_secret: &str,
    username: &str,
    password: &str,
) -> Option<String> {
    if endpoint.is_empty() {
        tracing::error!("ICAM token endpoint URL is empty; cannot authenticate");
        return None;
    }
    let form = [
        ("grant_type", "password"),
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("username", username),
        ("password", password),
        ("scope", "openid"),
    ];
    let response = client
        .post(endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|e| {
            tracing::debug!(error = %e, endpoint = %endpoint, "ICAM token endpoint request failed");
        })
        .ok()?;
    if !response.status().is_success() {
        tracing::debug!(
            status = %response.status(),
            endpoint = %endpoint,
            "ICAM token endpoint returned non-success status"
        );
        return None;
    }
    let token_resp: TokenResponse = response
        .json()
        .await
        .map_err(|e| {
            tracing::debug!(error = %e, "ICAM token response parse failed");
        })
        .ok()?;
    if token_resp.error.is_some() {
        tracing::debug!("ICAM token response contained error field");
        return None;
    }
    token_resp.access_token
}

/// Authenticate a user against the ICAM OIDC provider via ROPC grant.
///
/// On success, returns the authenticated flag and group memberships extracted
/// from the JWT `groups_claim` field.  The ICAM token endpoint is called over
/// HTTPS; credentials never traverse plaintext channels.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | IA-2 | Identification and Authentication | Enterprise OIDC ROPC authentication |
/// | IA-5 | Authenticator Management | Credential forwarding only over HTTPS |
/// | IA-8 | Non-Organizational User Auth | ICAM integration for enterprise identity |
/// | AU-2 | Audit Events | Auth attempts logged with outcome |
/// | AU-12 | Audit Generation | Instrumented via tracing span |
#[tracing::instrument(
    skip(cfg, password),
    fields(
        icam.endpoint = %cfg.token_endpoint,
        icam.client_id = %cfg.client_id,
    )
)]
pub async fn icam_authenticate(
    cfg: &IcamConfig,
    username: &str,
    password: &str,
) -> IcamAuthResult {
    if username.is_empty() {
        tracing::warn!("ICAM authenticate called with empty username; returning fail");
        return IcamAuthResult {
            authenticated: false,
            groups: Vec::new(),
        };
    }
    let token_opt = icam_call_token_endpoint(
        &cfg.http_client,
        &cfg.token_endpoint,
        &cfg.client_id,
        &cfg.client_secret,
        username,
        password,
    )
    .await;
    let Some(token_str) = token_opt else {
        tracing::debug!(user = username, "ICAM authentication failed");
        return IcamAuthResult {
            authenticated: false,
            groups: Vec::new(),
        };
    };
    let groups = icam_decode_jwt_payload(&token_str)
        .and_then(|payload| payload.get(&cfg.groups_claim).cloned())
        .map(|val| icam_extract_groups_from_claim(&val))
        .unwrap_or_default();
    tracing::debug!(
        user = username,
        group_count = groups.len(),
        "ICAM authentication succeeded"
    );
    IcamAuthResult {
        authenticated: true,
        groups,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extract_groups_from_array_claim() {
        let val = json!(["netops", "Admins", "READ-ONLY"]);
        let groups = icam_extract_groups_from_claim(&val);
        assert_eq!(groups, vec!["netops", "admins", "read-only"]);
    }

    #[test]
    fn extract_groups_from_string_claim() {
        let val = json!("NetOps");
        let groups = icam_extract_groups_from_claim(&val);
        assert_eq!(groups, vec!["netops"]);
    }

    #[test]
    fn extract_groups_from_empty_string_returns_empty() {
        let val = json!("");
        let groups = icam_extract_groups_from_claim(&val);
        assert!(groups.is_empty());
    }

    #[test]
    fn extract_groups_from_null_returns_empty() {
        let val = json!(null);
        let groups = icam_extract_groups_from_claim(&val);
        assert!(groups.is_empty());
    }

    #[test]
    fn extract_groups_respects_max_limit() {
        let big: Vec<Value> = (0..300).map(|i| json!(format!("group{i}"))).collect();
        let val = Value::Array(big);
        let groups = icam_extract_groups_from_claim(&val);
        assert_eq!(groups.len(), MAX_ICAM_GROUPS);
    }

    #[test]
    fn decode_jwt_payload_valid() {
        // Build a minimal JWT: header.payload.sig
        // payload = {"sub":"alice","groups":["netops"]}
        let payload_json = r#"{"sub":"alice","groups":["netops"]}"#;
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(payload_json.as_bytes());
        let token = format!("eyJhbGciOiJSUzI1NiJ9.{payload_b64}.fakesig");
        let result = icam_decode_jwt_payload(&token);
        assert!(result.is_some());
        let claims = result.unwrap();
        assert_eq!(claims["sub"], "alice");
    }

    #[test]
    fn decode_jwt_payload_too_few_segments_returns_none() {
        let result = icam_decode_jwt_payload("only.twoparts");
        assert!(result.is_none());
    }

    #[test]
    fn decode_jwt_payload_invalid_base64_returns_none() {
        let result = icam_decode_jwt_payload("header.!!!invalid!!!.sig");
        assert!(result.is_none());
    }

    #[test]
    fn decode_jwt_payload_oversized_returns_none() {
        let big_b64 = "A".repeat(MAX_JWT_PAYLOAD_BYTES + 1);
        let token = format!("header.{big_b64}.sig");
        let result = icam_decode_jwt_payload(&token);
        assert!(result.is_none());
    }

    #[test]
    fn icam_config_debug_redacts_secret() {
        let cfg = IcamConfig {
            token_endpoint: "https://example.com/token".into(),
            client_id: "tacacs".into(),
            client_secret: "supersecret".into(),
            groups_claim: "groups".into(),
            timeout: Duration::from_secs(5),
            ca_file: None,
            http_client: Client::new(),
        };
        let debug_str = format!("{cfg:?}");
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("supersecret"));
    }
}
