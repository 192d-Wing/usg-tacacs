// SPDX-License-Identifier: Apache-2.0
//! RFC 8628 Device Authorization Grant for browser-based CAC authentication.
//!
//! Implements the device flow feature gate: instead of collecting username and
//! password over the TACACS+ ASCII protocol, the server initiates a device
//! authorization request to ICAM, returns a verification URL to the user (via
//! the NAD terminal), and polls for completion when the user presses ENTER.
//!
//! # NIST SP 800-53 Rev. 5 Security Controls
//!
//! | Control | Family | Status | Validated | Primary Functions |
//! |---------|--------|--------|-----------|-------------------|
//! | IA-2 | Identification and Authentication | Implemented | 2026-06-04 | [`icam_device_auth_start`] |
//! | IA-5 | Authenticator Management | Implemented | 2026-06-04 | [`DeviceFlowConfig`] |
//! | IA-8 | Non-Organizational User Auth | Implemented | 2026-06-04 | [`icam_device_auth_start`] |
//! | SC-8 | System and Communications Protection | Implemented | 2026-06-04 | [`DeviceFlowConfig`] |
//! | SC-13 | System and Communications Protection | Implemented | 2026-06-04 | [`icam_device_auth_start`] |
//! | AU-2 | Audit and Accountability | Implemented | 2026-06-04 | [`icam_device_auth_start`] |
//! | AU-12 | Audit and Accountability | Implemented | 2026-06-04 | [`icam_device_poll_token`] |
//!
//! # Design
//!
//! 1. NAD sends ASCII START to TACACS+.
//! 2. TACACS+ calls the ICAM device authorization endpoint → receives URL + device_code.
//! 3. TACACS+ returns `AUTHEN_STATUS_GETDATA` with the URL in `server_msg`.
//! 4. User opens browser, completes CAC authentication, then presses ENTER.
//! 5. NAD sends ASCII CONTINUE → TACACS+ calls the ICAM token endpoint with device_code.
//! 6. If authorized → PASS (groups extracted from JWT); if pending → re-prompt; if denied → FAIL.

use reqwest::Client;
use serde::Deserialize;
use std::path::PathBuf;

/// Maximum device_code length in bytes (DoS guard, NIST SC-5).
const MAX_DEVICE_CODE_BYTES: usize = 1024;

/// Maximum verification_uri length in bytes (display guard, NIST SC-5).
const MAX_VERIFICATION_URI_BYTES: usize = 2048;

/// Configuration for the RFC 8628 Device Authorization Grant feature gate.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | IA-5 | Authenticator Management | client_secret redacted in Debug output |
/// | SC-8 | Transmission Confidentiality | HTTPS-only HTTP client enforced at build time |
#[derive(Clone)]
pub struct DeviceFlowConfig {
    /// OIDC device authorization endpoint URL (RFC 8628 §3.1).
    pub device_auth_endpoint: String,
    /// OIDC token endpoint URL polled after user completes browser auth.
    pub token_endpoint: String,
    /// OIDC client ID registered in the ICAM provider.
    pub client_id: String,
    /// OIDC client secret (never logged).
    pub client_secret: String,
    /// JWT claim name containing user group memberships.
    pub groups_claim: String,
    /// Maximum ENTER-press poll cycles before the session expires (rule 2 loop bound).
    pub max_polls: u8,
    /// Optional CA bundle path for ICAM TLS verification.
    pub ca_file: Option<PathBuf>,
    /// Shared HTTPS client (built once at startup, reused across requests).
    pub http_client: Client,
}

/// Redact client_secret from debug output (NIST IA-5).
impl std::fmt::Debug for DeviceFlowConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceFlowConfig")
            .field("device_auth_endpoint", &self.device_auth_endpoint)
            .field("token_endpoint", &self.token_endpoint)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("groups_claim", &self.groups_claim)
            .field("max_polls", &self.max_polls)
            .field("ca_file", &self.ca_file)
            .finish()
    }
}

/// Raw JSON response from the device authorization endpoint (RFC 8628 §3.2).
#[derive(Deserialize)]
struct DeviceAuthRaw {
    device_code: Option<String>,
    user_code: Option<String>,
    verification_uri: Option<String>,
    /// Pre-filled URL with user_code embedded (RFC 8628 §3.3).
    verification_uri_complete: Option<String>,
    expires_in: Option<u64>,
}

/// Parsed response from the ICAM device authorization endpoint.
pub struct DeviceAuthResponse {
    /// Opaque code used to poll the token endpoint.
    pub device_code: String,
    /// Short code shown when no complete URI is available.
    pub user_code: String,
    /// Base URL — use `verification_uri_complete` when available.
    pub verification_uri: String,
    /// Pre-filled URL with the user_code baked in (RFC 8628 §3.3).
    /// When present, the user can click/copy this single URL with no separate code entry.
    pub verification_uri_complete: Option<String>,
    /// Seconds until device_code expires.
    pub expires_in: u64,
}

/// Raw JSON response from the token endpoint poll (RFC 8628 §3.5).
#[derive(Deserialize)]
struct PollRaw {
    access_token: Option<String>,
    error: Option<String>,
}

/// Result of one poll cycle against the ICAM token endpoint.
pub enum DevicePollResult {
    /// User has not yet completed browser authentication.
    Pending,
    /// Browser authentication succeeded; contains JWT access token.
    Authorized(String),
    /// Authorization was denied or the device_code expired.
    Denied,
}

/// Validate and extract fields from the raw device auth response.
///
/// Returns `None` if any required field is absent or invalid.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | SI-10 | Information Input Validation | Rejects oversized or missing fields |
fn parse_device_auth_response(raw: DeviceAuthRaw) -> Option<DeviceAuthResponse> {
    assert!(
        MAX_DEVICE_CODE_BYTES > 0,
        "device code size limit must be positive"
    );
    assert!(
        MAX_VERIFICATION_URI_BYTES > 0,
        "verification URI size limit must be positive"
    );
    let device_code = raw
        .device_code
        .filter(|s| !s.is_empty() && s.len() <= MAX_DEVICE_CODE_BYTES)?;
    let user_code = raw.user_code.filter(|s| !s.is_empty())?;
    let verification_uri = raw
        .verification_uri
        .filter(|s| !s.is_empty() && s.len() <= MAX_VERIFICATION_URI_BYTES)?;
    let verification_uri_complete = raw
        .verification_uri_complete
        .filter(|s| !s.is_empty() && s.len() <= MAX_VERIFICATION_URI_BYTES);
    let expires_in = raw.expires_in.unwrap_or(300);
    Some(DeviceAuthResponse {
        device_code,
        user_code,
        verification_uri,
        verification_uri_complete,
        expires_in,
    })
}

/// Interpret the raw token endpoint poll response (RFC 8628 §3.5 error codes).
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AU-12 | Audit Generation | Poll outcome logged via tracing |
fn interpret_poll_response(body: PollRaw) -> DevicePollResult {
    assert!(
        body.access_token.is_some() || body.error.is_some(),
        "poll response must contain access_token or error"
    );
    if let Some(token) = body.access_token.filter(|s| !s.is_empty()) {
        tracing::debug!("device token poll: authorization granted");
        return DevicePollResult::Authorized(token);
    }
    match body.error.as_deref() {
        Some("authorization_pending") | Some("slow_down") => {
            tracing::debug!("device token poll: authorization pending");
            DevicePollResult::Pending
        }
        Some(err) => {
            tracing::debug!(error = %err, "device token poll: authorization denied");
            DevicePollResult::Denied
        }
        None => {
            tracing::debug!("device token poll: no token and no error");
            DevicePollResult::Pending
        }
    }
}

/// POST to the ICAM device authorization endpoint to initiate the device flow.
///
/// Returns `Some(DeviceAuthResponse)` on success or `None` on any failure.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | IA-2 | Identification and Authentication | Initiates enterprise OIDC device authorization |
/// | SC-8 | Transmission Confidentiality | Credentials transmitted only over HTTPS |
/// | AU-2 | Audit Events | Initiation outcome logged with tracing span |
#[tracing::instrument(
    skip(cfg),
    fields(icam.device_endpoint = %cfg.device_auth_endpoint)
)]
pub async fn icam_device_auth_start(cfg: &DeviceFlowConfig) -> Option<DeviceAuthResponse> {
    assert!(
        !cfg.device_auth_endpoint.is_empty(),
        "device_auth_endpoint must not be empty"
    );
    assert!(!cfg.client_id.is_empty(), "client_id must not be empty");
    let form = [
        ("client_id", cfg.client_id.as_str()),
        ("client_secret", cfg.client_secret.as_str()),
        ("scope", "openid"),
    ];
    let response = cfg
        .http_client
        .post(&cfg.device_auth_endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|e| {
            tracing::debug!(
                error = %e,
                endpoint = %cfg.device_auth_endpoint,
                "device auth request failed"
            );
        })
        .ok()?;
    if !response.status().is_success() {
        tracing::debug!(
            status = %response.status(),
            "device auth endpoint returned non-success status"
        );
        return None;
    }
    let raw: DeviceAuthRaw = response
        .json()
        .await
        .map_err(|e| {
            tracing::debug!(error = %e, "device auth response parse failed");
        })
        .ok()?;
    let parsed = parse_device_auth_response(raw)?;
    tracing::debug!(
        uri = %parsed.verification_uri,
        user_code = %parsed.user_code,
        expires_in = parsed.expires_in,
        "device authorization initiated"
    );
    Some(parsed)
}

/// Poll the ICAM token endpoint to check device authorization completion.
///
/// Called once per user ENTER press. Returns `Pending` on network failure so the
/// user can retry rather than failing silently.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | IA-2 | Identification and Authentication | Polls for enterprise identity confirmation |
/// | SC-13 | Cryptographic Protection | TLS enforced by HTTPS-only client |
/// | AU-12 | Audit Generation | Poll outcomes logged via tracing span |
#[tracing::instrument(
    skip(cfg, device_code),
    fields(icam.token_endpoint = %cfg.token_endpoint)
)]
pub async fn icam_device_poll_token(
    cfg: &DeviceFlowConfig,
    device_code: &str,
) -> DevicePollResult {
    assert!(!device_code.is_empty(), "device_code must not be empty");
    assert!(
        device_code.len() <= MAX_DEVICE_CODE_BYTES,
        "device_code exceeds maximum length"
    );
    let form = [
        (
            "grant_type",
            "urn:ietf:params:oauth:grant-type:device_code",
        ),
        ("client_id", cfg.client_id.as_str()),
        ("client_secret", cfg.client_secret.as_str()),
        ("device_code", device_code),
    ];
    let response = match cfg
        .http_client
        .post(&cfg.token_endpoint)
        .form(&form)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(error = %e, "device token poll request failed");
            return DevicePollResult::Pending;
        }
    };
    let body: PollRaw = match response.json().await {
        Ok(b) => b,
        Err(e) => {
            tracing::debug!(error = %e, "device token poll response parse failed");
            return DevicePollResult::Pending;
        }
    };
    interpret_poll_response(body)
}

/// Build the user-facing message shown at the terminal during device flow.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | IA-6 | Authenticator Feedback | Does not echo credentials; presents URL only |
pub fn icam_device_format_prompt(response: &DeviceAuthResponse, poll: u8, max: u8) -> String {
    assert!(max > 0, "max polls must be positive");
    if poll == 0 {
        // Prefer verification_uri_complete (code pre-embedded in URL) when the ICAM
        // provider supplies it (RFC 8628 §3.3) — user copies one URL, no code entry needed.
        match &response.verification_uri_complete {
            Some(uri) => format!(
                "Authenticate with CAC at: {}\nPress ENTER when complete (expires in {}s).",
                uri, response.expires_in
            ),
            None => format!(
                "Authenticate with CAC at: {}\nCode: {}\nPress ENTER when complete (expires in {}s).",
                response.verification_uri, response.user_code, response.expires_in
            ),
        }
    } else {
        format!(
            "Still waiting for browser authentication ({}/{}).\nPress ENTER to check again.",
            poll, max
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_device_auth_response() {
        let raw = DeviceAuthRaw {
            device_code: Some("devcode123".into()),
            user_code: Some("ABCD-1234".into()),
            verification_uri: Some("https://icam.example.mil/device".into()),
            verification_uri_complete: None,
            expires_in: Some(300),
        };
        let parsed = parse_device_auth_response(raw);
        assert!(parsed.is_some());
        let r = parsed.unwrap();
        assert_eq!(r.device_code, "devcode123");
        assert_eq!(r.user_code, "ABCD-1234");
        assert_eq!(r.expires_in, 300);
    }

    #[test]
    fn parse_missing_device_code_returns_none() {
        let raw = DeviceAuthRaw {
            device_code: None,
            user_code: Some("ABCD-1234".into()),
            verification_uri: Some("https://icam.example.mil/device".into()),
            verification_uri_complete: None,
            expires_in: Some(300),
        };
        assert!(parse_device_auth_response(raw).is_none());
    }

    #[test]
    fn parse_oversized_device_code_returns_none() {
        let raw = DeviceAuthRaw {
            device_code: Some("x".repeat(MAX_DEVICE_CODE_BYTES + 1)),
            user_code: Some("ABCD-1234".into()),
            verification_uri: Some("https://icam.example.mil/device".into()),
            verification_uri_complete: None,
            expires_in: Some(300),
        };
        assert!(parse_device_auth_response(raw).is_none());
    }

    #[test]
    fn parse_missing_expires_in_defaults_to_300() {
        let raw = DeviceAuthRaw {
            device_code: Some("devcode".into()),
            user_code: Some("ABCD-1234".into()),
            verification_uri: Some("https://icam.example.mil/device".into()),
            verification_uri_complete: None,
            expires_in: None,
        };
        let parsed = parse_device_auth_response(raw).unwrap();
        assert_eq!(parsed.expires_in, 300);
    }

    #[test]
    fn interpret_authorized_token() {
        let body = PollRaw {
            access_token: Some("eyJhbGciOiJSUzI1NiJ9.payload.sig".into()),
            error: None,
        };
        let result = interpret_poll_response(body);
        assert!(matches!(result, DevicePollResult::Authorized(_)));
    }

    #[test]
    fn interpret_pending_authorization() {
        let body = PollRaw {
            access_token: None,
            error: Some("authorization_pending".into()),
        };
        let result = interpret_poll_response(body);
        assert!(matches!(result, DevicePollResult::Pending));
    }

    #[test]
    fn interpret_slow_down_as_pending() {
        let body = PollRaw {
            access_token: None,
            error: Some("slow_down".into()),
        };
        let result = interpret_poll_response(body);
        assert!(matches!(result, DevicePollResult::Pending));
    }

    #[test]
    fn interpret_expired_token_as_denied() {
        let body = PollRaw {
            access_token: None,
            error: Some("expired_token".into()),
        };
        let result = interpret_poll_response(body);
        assert!(matches!(result, DevicePollResult::Denied));
    }

    #[test]
    fn format_initial_prompt_contains_uri() {
        let resp = DeviceAuthResponse {
            device_code: "dc".into(),
            user_code: "ABCD-1234".into(),
            verification_uri: "https://icam.example.mil/device".into(),
            verification_uri_complete: None,
            expires_in: 300,
        };
        let msg = icam_device_format_prompt(&resp, 0, 48);
        assert!(msg.contains("https://icam.example.mil/device"));
        assert!(msg.contains("ABCD-1234"));
    }

    #[test]
    fn format_initial_prompt_uses_complete_uri_when_present() {
        let resp = DeviceAuthResponse {
            device_code: "dc".into(),
            user_code: "ABCD-1234".into(),
            verification_uri: "https://icam.example.mil/device".into(),
            verification_uri_complete: Some(
                "https://icam.example.mil/device?user_code=ABCD-1234".into(),
            ),
            expires_in: 300,
        };
        let msg = icam_device_format_prompt(&resp, 0, 48);
        assert!(msg.contains("?user_code=ABCD-1234"));
        assert!(!msg.contains("Code:"), "code should not appear separately when URI is complete");
    }

    #[test]
    fn format_retry_prompt_shows_count() {
        let resp = DeviceAuthResponse {
            device_code: "dc".into(),
            user_code: "ABCD-1234".into(),
            verification_uri: "https://icam.example.mil/device".into(),
            verification_uri_complete: None,
            expires_in: 300,
        };
        let msg = icam_device_format_prompt(&resp, 3, 48);
        assert!(msg.contains("3/48"));
    }
}
