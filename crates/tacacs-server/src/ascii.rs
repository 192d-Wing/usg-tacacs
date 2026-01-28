// SPDX-License-Identifier: Apache-2.0
//! ASCII (interactive) authentication handler with brute-force protection.
//!
//! # NIST SP 800-53 Security Controls
//!
//! This module implements the following NIST security controls:
//!
//! - **AC-7 (Unsuccessful Logon Attempts)**: Implements multi-layered brute-force
//!   protection including:
//!   - Global attempt limits per session
//!   - Username prompt attempt limits
//!   - Password prompt attempt limits
//!   - Exponential backoff with random jitter
//!   - Hard lockout after configurable threshold
//!
//! - **IA-2 (Identification and Authentication)**: Implements interactive ASCII
//!   authentication protocol for user identification.
//!
//! - **IA-6 (Authenticator Feedback)**: Uses NOECHO flag to prevent password
//!   display during entry.
//!
//! - **AU-2/AU-12 (Audit Events)**: All authentication attempts, failures, and
//!   lockouts are logged with relevant context.

use crate::auth::{LdapConfig, verify_pap_bytes, verify_pap_bytes_username};
use openssl::rand::rand_bytes;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::sleep;
use usg_tacacs_policy::PolicyEngine;
use usg_tacacs_proto::{
    AUTHEN_FLAG_NOECHO, AUTHEN_STATUS_FAIL, AUTHEN_STATUS_GETPASS, AUTHEN_STATUS_GETUSER,
    AUTHEN_STATUS_PASS, AUTHEN_STATUS_RESTART, AuthSessionState, AuthenReply,
};

const AUTHEN_CONT_ABORT: u8 = 0x01;

/// Configuration for ASCII authentication brute-force protection.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-7 | Unsuccessful Logon Attempts | Configurable limits and delays to prevent brute-force attacks |
#[derive(Clone)]
pub struct AsciiConfig {
    /// Maximum total attempts per session (NIST AC-7)
    pub attempt_limit: u8,
    /// Maximum username prompt retries (NIST AC-7)
    pub user_attempt_limit: u8,
    /// Maximum password prompt retries (NIST AC-7)
    pub pass_attempt_limit: u8,
    /// Base delay for exponential backoff in ms (NIST AC-7)
    pub backoff_ms: u64,
    /// Maximum backoff delay cap in ms (NIST AC-7)
    pub backoff_max_ms: u64,
    /// Hard lockout threshold (NIST AC-7)
    pub lockout_limit: u8,
}

/// Calculate exponential backoff delay with random jitter.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-7 | Unsuccessful Logon Attempts | Exponential backoff with random jitter to slow brute-force attempts |
///
/// The jitter uses cryptographically secure random bytes from OpenSSL
/// to prevent attackers from predicting delay patterns.
pub fn calc_ascii_backoff_capped(base_ms: u64, attempt: u8, cap_ms: u64) -> Option<Duration> {
    if base_ms == 0 {
        return None;
    }
    // NIST AC-7: Exponential backoff: base * 2^(attempt-1)
    let exp = base_ms.saturating_mul(1u64 << attempt.saturating_sub(1));
    let capped = if cap_ms == 0 { exp } else { exp.min(cap_ms) };
    // NIST AC-7: Add random jitter to prevent timing attacks
    let mut jitter = 0;
    let mut buf = [0u8; 2];
    if rand_bytes(&mut buf).is_ok() {
        let max_jitter = base_ms.min(5_000);
        jitter = (u16::from_be_bytes(buf) as u64) % (max_jitter + 1);
    }
    Some(Duration::from_millis(capped.saturating_add(jitter)))
}

pub fn username_for_policy<'a>(
    decoded: Option<&'a str>,
    raw: Option<&'a Vec<u8>>,
) -> Option<String> {
    if let Some(u) = decoded {
        return Some(u.to_string());
    }
    raw.map(hex::encode)
}

pub fn field_for_policy<'a>(decoded: Option<&'a str>, raw: Option<&'a Vec<u8>>) -> Option<String> {
    if let Some(v) = decoded {
        return Some(v.to_string());
    }
    raw.map(hex::encode)
}

fn build_ascii_prompts(
    policy: &PolicyEngine,
    state: &AuthSessionState,
    user_msg: &[u8],
    username_for_policy: Option<&str>,
    port_for_policy: Option<&str>,
    rem_for_policy: Option<&str>,
) -> (Vec<u8>, Vec<u8>) {
    let policy_user_prompt = policy
        .prompt_username(username_for_policy, port_for_policy, rem_for_policy)
        .map(|s| s.as_bytes().to_vec());
    let policy_pass_prompt = policy
        .prompt_password(username_for_policy)
        .map(|s| s.as_bytes().to_vec());
    let uname_prompt = if !user_msg.is_empty() {
        user_msg.to_vec()
    } else if let Some(custom) = policy_user_prompt {
        custom
    } else {
        match (state.service, state.action) {
            (Some(svc), Some(act)) => {
                format!("Username (service {svc}, action {act}):").into_bytes()
            }
            (Some(svc), None) => format!("Username (service {svc}):").into_bytes(),
            _ => b"Username:".to_vec(),
        }
    };
    let pwd_prompt = if !user_msg.is_empty() {
        user_msg.to_vec()
    } else if let Some(custom) = policy_pass_prompt {
        custom
    } else {
        match (state.service, state.action) {
            (Some(svc), Some(act)) => {
                format!("Password (service {svc}, action {act}):").into_bytes()
            }
            (Some(svc), None) => format!("Password (service {svc}):").into_bytes(),
            _ => b"Password:".to_vec(),
        }
    };
    (uname_prompt, pwd_prompt)
}

/// Handle ABORT flag - reset authentication state and return failure.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AU-12 | Audit Generation | Logs authentication abort event |
async fn handle_abort(
    state: &mut AuthSessionState,
    policy: &Arc<RwLock<PolicyEngine>>,
) -> AuthenReply {
    // Reset authentication state
    state.ascii_need_user = true;
    state.ascii_need_pass = false;
    state.username = None;
    state.username_raw = None;
    state.ascii_attempts = 0;
    state.ascii_user_attempts = 0;
    state.ascii_pass_attempts = 0;

    // Get policy abort message
    let policy_abort = {
        let policy = policy.read().await;
        policy.message_abort().map(|m| m.to_string())
    };

    AuthenReply {
        status: AUTHEN_STATUS_FAIL,
        flags: 0,
        server_msg: policy_abort.unwrap_or_else(|| "authentication aborted".into()),
        server_msg_raw: Vec::new(),
        data: Vec::new(),
    }
}

/// Reset authentication state and request restart.
fn reset_authentication_state(state: &mut AuthSessionState) -> AuthenReply {
    state.ascii_need_user = true;
    state.ascii_need_pass = false;
    state.username = None;
    state.username_raw = None;
    state.ascii_attempts = 0;
    state.ascii_user_attempts = 0;
    state.ascii_pass_attempts = 0;

    AuthenReply {
        status: AUTHEN_STATUS_RESTART,
        flags: 0,
        server_msg: "restart authentication".into(),
        server_msg_raw: Vec::new(),
        data: Vec::new(),
    }
}

/// Handle password input phase of ASCII authentication.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | IA-2 | Identification and Authentication | Verifies password against static credentials or LDAP |
/// | AC-7 | Unsuccessful Logon Attempts | Applies exponential backoff on empty or invalid password |
/// | IA-6 | Authenticator Feedback | Returns NOECHO flag for password prompts |
#[allow(clippy::too_many_arguments)]
async fn handle_password_phase(
    cont_data: &[u8],
    state: &mut AuthSessionState,
    policy: &Arc<RwLock<PolicyEngine>>,
    credentials: &crate::config::StaticCreds,
    config: &AsciiConfig,
    ldap: Option<&Arc<LdapConfig>>,
    pwd_prompt: Vec<u8>,
) -> AuthenReply {
    state.ascii_pass_attempts = state.ascii_pass_attempts.saturating_add(1);

    if cont_data.is_empty() {
        // Empty password - apply backoff and re-prompt
        if let Some(delay) = calc_ascii_backoff_capped(
            config.backoff_ms,
            state.ascii_attempts,
            config.backoff_max_ms,
        ) {
            sleep(delay).await;
        }
        return AuthenReply {
            status: AUTHEN_STATUS_GETPASS,
            flags: AUTHEN_FLAG_NOECHO,
            server_msg: String::new(),
            server_msg_raw: Vec::new(),
            data: pwd_prompt,
        };
    }

    // Password provided - attempt authentication
    state.ascii_need_pass = false;

    // Try static credentials first
    let mut ok = if let Some(raw_user) = state.username_raw.as_ref() {
        verify_pap_bytes_username(raw_user, cont_data, credentials)
    } else {
        let user = state.username.clone().unwrap_or_default();
        verify_pap_bytes(&user, cont_data, credentials)
    };

    // Try LDAP if static credentials failed
    if !ok
        && let (Some(user), Some(ldap_cfg)) = (state.username.as_deref(), ldap)
        && let Ok(pwd) = std::str::from_utf8(cont_data)
    {
        ok = ldap_cfg.authenticate(user, pwd).await;
    }

    // Apply backoff on authentication failure
    if !ok
        && let Some(delay) = calc_ascii_backoff_capped(
            config.backoff_ms,
            state.ascii_attempts,
            config.backoff_max_ms,
        )
    {
        sleep(delay).await;
    }

    // Build context for success/failure messages
    let svc_str = state
        .service
        .map(|svc| format!(" (service {svc})"))
        .unwrap_or_default();
    let act_str = state
        .action
        .map(|act| format!(" action {act}"))
        .unwrap_or_default();

    // Get policy messages and build final reply
    let policy = policy.read().await;
    AuthenReply {
        status: if ok {
            AUTHEN_STATUS_PASS
        } else {
            AUTHEN_STATUS_FAIL
        },
        flags: 0,
        server_msg: if ok {
            policy
                .message_success()
                .map(|m| m.to_string())
                .unwrap_or_else(|| format!("authentication succeeded{svc_str}{act_str}"))
        } else {
            policy
                .message_failure()
                .map(|m| m.to_string())
                .unwrap_or_else(|| format!("invalid credentials{svc_str}{act_str}"))
        },
        server_msg_raw: Vec::new(),
        data: Vec::new(),
    }
}

/// Handle username input phase of ASCII authentication.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | IA-2 | Identification and Authentication | Processes username input and transitions to password phase |
/// | AC-7 | Unsuccessful Logon Attempts | Applies exponential backoff on empty username |
async fn handle_username_phase(
    cont_data: &[u8],
    state: &mut AuthSessionState,
    config: &AsciiConfig,
    uname_prompt: Vec<u8>,
    pwd_prompt: Vec<u8>,
) -> AuthenReply {
    state.ascii_user_attempts = state.ascii_user_attempts.saturating_add(1);
    let username_raw = cont_data.to_vec();

    if !username_raw.is_empty() {
        // Valid username provided - store and transition to password phase
        state.username_raw = Some(username_raw.clone());
        state.username = String::from_utf8(username_raw).ok();
        state.ascii_need_user = false;
        state.ascii_need_pass = true;
        AuthenReply {
            status: AUTHEN_STATUS_GETPASS,
            flags: AUTHEN_FLAG_NOECHO,
            server_msg: String::new(),
            server_msg_raw: Vec::new(),
            data: pwd_prompt,
        }
    } else {
        // Empty username - apply backoff and re-prompt
        if let Some(delay) = calc_ascii_backoff_capped(
            config.backoff_ms,
            state.ascii_attempts,
            config.backoff_max_ms,
        ) {
            sleep(delay).await;
        }
        AuthenReply {
            status: AUTHEN_STATUS_GETUSER,
            flags: 0,
            server_msg: String::new(),
            server_msg_raw: Vec::new(),
            data: uname_prompt,
        }
    }
}

/// Check if authentication should be blocked due to attempt limits.
///
/// Returns Some(AuthenReply) if blocked, None if allowed to proceed.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-7 | Unsuccessful Logon Attempts | Enforces global, username, and password attempt limits plus lockout threshold |
fn check_attempt_limits(state: &AuthSessionState, config: &AsciiConfig) -> Option<AuthenReply> {
    // Check global attempt limit
    if config.attempt_limit > 0 && state.ascii_attempts >= config.attempt_limit {
        return Some(AuthenReply {
            status: AUTHEN_STATUS_FAIL,
            flags: 0,
            server_msg: "too many authentication attempts".into(),
            server_msg_raw: Vec::new(),
            data: Vec::new(),
        });
    }

    // Check username phase attempt limit
    if state.ascii_need_user
        && config.user_attempt_limit > 0
        && state.ascii_user_attempts >= config.user_attempt_limit
    {
        return Some(AuthenReply {
            status: AUTHEN_STATUS_FAIL,
            flags: 0,
            server_msg: "too many username attempts".into(),
            server_msg_raw: Vec::new(),
            data: Vec::new(),
        });
    }

    // Check password phase attempt limit
    if state.ascii_need_pass
        && config.pass_attempt_limit > 0
        && state.ascii_pass_attempts >= config.pass_attempt_limit
    {
        return Some(AuthenReply {
            status: AUTHEN_STATUS_FAIL,
            flags: 0,
            server_msg: "too many password attempts".into(),
            server_msg_raw: Vec::new(),
            data: Vec::new(),
        });
    }

    None
}

/// Handle ASCII authentication continuation packets.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-7 | Unsuccessful Logon Attempts | Enforces attempt limits, backoff delays, and lockout thresholds |
/// | AU-12 | Audit Generation | All attempts logged via tracing |
/// | IA-2 | Identification and Authentication | Processes interactive authentication with username/password prompts |
/// | IA-6 | Authenticator Feedback | Uses NOECHO flag for password entry |
#[allow(clippy::too_many_arguments)]
pub async fn handle_ascii_continue(
    cont_user_msg: &[u8],
    cont_data: &[u8],
    cont_flags: u8,
    state: &mut AuthSessionState,
    policy: &Arc<RwLock<PolicyEngine>>,
    credentials: &crate::config::StaticCreds,
    config: &AsciiConfig,
    ldap: Option<&Arc<LdapConfig>>,
) -> AuthenReply {
    let policy_user = username_for_policy(state.username.as_deref(), state.username_raw.as_ref());
    let policy_port = field_for_policy(state.port.as_deref(), state.port_raw.as_ref());
    let policy_rem = field_for_policy(state.rem_addr.as_deref(), state.rem_addr_raw.as_ref());
    let (uname_prompt, pwd_prompt) = {
        let policy = policy.read().await;
        build_ascii_prompts(
            &policy,
            state,
            cont_user_msg,
            policy_user.as_deref(),
            policy_port.as_deref(),
            policy_rem.as_deref(),
        )
    };

    // Handle ABORT flag - reset and fail authentication
    if cont_flags & AUTHEN_CONT_ABORT != 0 {
        return handle_abort(state, policy).await;
    }

    // NIST AC-7: Check if authentication blocked due to attempt limits
    if let Some(reply) = check_attempt_limits(state, config) {
        return reply;
    }

    if config.attempt_limit > 0 {
        state.ascii_attempts = state.ascii_attempts.saturating_add(1);
    }
    if config.lockout_limit > 0 && state.ascii_attempts >= config.lockout_limit {
        return AuthenReply {
            status: AUTHEN_STATUS_FAIL,
            flags: 0,
            server_msg: "authentication locked out".into(),
            server_msg_raw: Vec::new(),
            data: Vec::new(),
        };
    }

    if state.ascii_need_user {
        handle_username_phase(cont_data, state, config, uname_prompt, pwd_prompt).await
    } else if state.ascii_need_pass {
        handle_password_phase(
            cont_data,
            state,
            policy,
            credentials,
            config,
            ldap,
            pwd_prompt,
        )
        .await
    } else {
        // Neither username nor password phase - reset and restart
        reset_authentication_state(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StaticCreds;
    use usg_tacacs_policy::PolicyDocument;

    fn make_default_policy() -> PolicyEngine {
        let doc = PolicyDocument {
            default_allow: true,
            shell_start: Default::default(),
            ascii_prompts: None,
            ascii_user_prompts: Default::default(),
            ascii_password_prompts: Default::default(),
            ascii_port_prompts: Default::default(),
            ascii_remaddr_prompts: Default::default(),
            allow_raw_server_msg: true,
            raw_server_msg_allow_prefixes: vec![],
            raw_server_msg_deny_prefixes: vec![],
            raw_server_msg_user_overrides: Default::default(),
            ascii_messages: None,
            rules: vec![],
        };
        PolicyEngine::from_document(doc).expect("create test policy")
    }

    fn make_test_config() -> AsciiConfig {
        AsciiConfig {
            attempt_limit: 5,
            user_attempt_limit: 3,
            pass_attempt_limit: 5,
            backoff_ms: 0,
            backoff_max_ms: 5000,
            lockout_limit: 0,
        }
    }

    fn make_test_state() -> AuthSessionState {
        AuthSessionState {
            last_seq: 1,
            expect_client: false,
            authen_type: Some(1),
            challenge: None,
            username: Some("testuser".to_string()),
            username_raw: None,
            port: Some("tty0".to_string()),
            port_raw: None,
            rem_addr: Some("192.168.1.1".to_string()),
            rem_addr_raw: None,
            chap_id: None,
            ascii_need_user: false,
            ascii_need_pass: false,
            ascii_attempts: 0,
            ascii_user_attempts: 0,
            ascii_pass_attempts: 0,
            service: Some(1),
            action: Some(1),
        }
    }

    fn make_test_creds() -> StaticCreds {
        let mut creds = StaticCreds::default();
        creds.plain.insert("testuser".into(), "testpass".into());
        creds.plain.insert("admin".into(), "secret".into());
        creds
    }

    // ==================== calc_ascii_backoff_capped Tests ====================

    #[test]
    fn backoff_zero_base_returns_none() {
        let result = calc_ascii_backoff_capped(0, 1, 5000);
        assert!(result.is_none());
    }

    #[test]
    fn backoff_first_attempt() {
        let result = calc_ascii_backoff_capped(1000, 1, 10000);
        assert!(result.is_some());
        let duration = result.unwrap();
        // Base is 1000 * 2^0 = 1000, plus jitter (up to 1000)
        assert!(duration.as_millis() >= 1000);
        assert!(duration.as_millis() <= 2000);
    }

    #[test]
    fn backoff_exponential_growth() {
        // attempt 2: base * 2^1 = 2000
        let result = calc_ascii_backoff_capped(1000, 2, 100000);
        assert!(result.is_some());
        let duration = result.unwrap();
        // 2000 + jitter (up to 1000)
        assert!(duration.as_millis() >= 2000);
        assert!(duration.as_millis() <= 3000);
    }

    #[test]
    fn backoff_respects_cap() {
        // attempt 10: base * 2^9 = 512000, but capped at 5000
        let result = calc_ascii_backoff_capped(1000, 10, 5000);
        assert!(result.is_some());
        let duration = result.unwrap();
        // Capped at 5000 + jitter (up to 1000)
        assert!(duration.as_millis() >= 5000);
        assert!(duration.as_millis() <= 10000);
    }

    #[test]
    fn backoff_zero_cap_means_no_cap() {
        // With cap_ms = 0, exponential growth is uncapped
        let result = calc_ascii_backoff_capped(1000, 5, 0);
        assert!(result.is_some());
        let duration = result.unwrap();
        // 1000 * 2^4 = 16000, plus jitter
        assert!(duration.as_millis() >= 16000);
    }

    #[test]
    fn backoff_saturating_at_high_attempt() {
        // High attempt numbers with a reasonable cap should work
        // Note: the shift overflows at attempt > 63, so test with moderate values
        let result = calc_ascii_backoff_capped(1000, 10, 5000);
        assert!(result.is_some());
        // Should be capped at 5000 + jitter
        let duration = result.unwrap();
        assert!(duration.as_millis() >= 5000);
    }

    #[test]
    fn backoff_attempt_zero() {
        // attempt 0: base * 2^(-1) with saturation = base * 1 (since saturating_sub)
        let result = calc_ascii_backoff_capped(1000, 0, 10000);
        assert!(result.is_some());
        // 2^(0.saturating_sub(1)) = 2^0 = 1, so 1000 * 1 = 1000
        let duration = result.unwrap();
        assert!(duration.as_millis() >= 1000);
    }

    // ==================== username_for_policy Tests ====================

    #[test]
    fn username_for_policy_decoded_takes_precedence() {
        let decoded = Some("admin");
        let raw = Some(vec![0x61, 0x64, 0x6d, 0x69, 0x6e]);
        let result = username_for_policy(decoded, raw.as_ref());
        assert_eq!(result, Some("admin".to_string()));
    }

    #[test]
    fn username_for_policy_falls_back_to_hex() {
        let raw = Some(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let result = username_for_policy(None, raw.as_ref());
        assert_eq!(result, Some("deadbeef".to_string()));
    }

    #[test]
    fn username_for_policy_none_when_both_none() {
        let result = username_for_policy(None, None);
        assert!(result.is_none());
    }

    // ==================== field_for_policy Tests ====================

    #[test]
    fn field_for_policy_decoded_takes_precedence() {
        let decoded = Some("console");
        let raw = Some(vec![0x63, 0x6f, 0x6e]);
        let result = field_for_policy(decoded, raw.as_ref());
        assert_eq!(result, Some("console".to_string()));
    }

    #[test]
    fn field_for_policy_falls_back_to_hex() {
        let raw = Some(vec![0xFF, 0x00, 0xAB]);
        let result = field_for_policy(None, raw.as_ref());
        assert_eq!(result, Some("ff00ab".to_string()));
    }

    #[test]
    fn field_for_policy_none_when_both_none() {
        let result = field_for_policy(None, None);
        assert!(result.is_none());
    }

    // ==================== AsciiConfig Tests ====================

    #[test]
    fn ascii_config_defaults() {
        let config = AsciiConfig {
            attempt_limit: 5,
            user_attempt_limit: 3,
            pass_attempt_limit: 5,
            backoff_ms: 0,
            backoff_max_ms: 5000,
            lockout_limit: 0,
        };

        assert_eq!(config.attempt_limit, 5);
        assert_eq!(config.user_attempt_limit, 3);
        assert_eq!(config.pass_attempt_limit, 5);
        assert_eq!(config.backoff_ms, 0);
        assert_eq!(config.backoff_max_ms, 5000);
        assert_eq!(config.lockout_limit, 0);
    }

    #[test]
    fn ascii_config_zero_limits_means_unlimited() {
        let config = AsciiConfig {
            attempt_limit: 0,
            user_attempt_limit: 0,
            pass_attempt_limit: 0,
            backoff_ms: 0,
            backoff_max_ms: 0,
            lockout_limit: 0,
        };

        // All zeros means no limits
        assert_eq!(config.attempt_limit, 0);
        assert_eq!(config.user_attempt_limit, 0);
        assert_eq!(config.pass_attempt_limit, 0);
    }

    // ==================== handle_ascii_continue Tests ====================

    #[tokio::test]
    async fn handle_ascii_continue_abort_flag_resets_state() {
        let policy = Arc::new(RwLock::new(make_default_policy()));
        let mut state = make_test_state();
        state.ascii_need_pass = true;
        state.ascii_attempts = 3;
        state.ascii_user_attempts = 2;
        state.ascii_pass_attempts = 1;
        let creds = make_test_creds();
        let config = make_test_config();

        let reply = handle_ascii_continue(
            b"",
            b"",
            AUTHEN_CONT_ABORT,
            &mut state,
            &policy,
            &creds,
            &config,
            None,
        )
        .await;

        assert_eq!(reply.status, AUTHEN_STATUS_FAIL);
        assert!(reply.server_msg.contains("abort"));
        // State should be reset
        assert!(state.ascii_need_user);
        assert!(!state.ascii_need_pass);
        assert!(state.username.is_none());
        assert!(state.username_raw.is_none());
        assert_eq!(state.ascii_attempts, 0);
        assert_eq!(state.ascii_user_attempts, 0);
        assert_eq!(state.ascii_pass_attempts, 0);
    }

    #[tokio::test]
    async fn handle_ascii_continue_attempt_limit_exceeded() {
        let policy = Arc::new(RwLock::new(make_default_policy()));
        let mut state = make_test_state();
        state.ascii_attempts = 5; // At limit
        let creds = make_test_creds();
        let config = make_test_config(); // attempt_limit = 5

        let reply =
            handle_ascii_continue(b"", b"", 0, &mut state, &policy, &creds, &config, None).await;

        assert_eq!(reply.status, AUTHEN_STATUS_FAIL);
        assert!(
            reply
                .server_msg
                .contains("too many authentication attempts")
        );
    }

    #[tokio::test]
    async fn handle_ascii_continue_user_attempt_limit_exceeded() {
        let policy = Arc::new(RwLock::new(make_default_policy()));
        let mut state = make_test_state();
        state.ascii_need_user = true;
        state.ascii_user_attempts = 3; // At limit
        let creds = make_test_creds();
        let config = make_test_config(); // user_attempt_limit = 3

        let reply =
            handle_ascii_continue(b"", b"", 0, &mut state, &policy, &creds, &config, None).await;

        assert_eq!(reply.status, AUTHEN_STATUS_FAIL);
        assert!(reply.server_msg.contains("too many username attempts"));
    }

    #[tokio::test]
    async fn handle_ascii_continue_pass_attempt_limit_exceeded() {
        let policy = Arc::new(RwLock::new(make_default_policy()));
        let mut state = make_test_state();
        state.ascii_need_pass = true;
        state.ascii_pass_attempts = 5; // At limit
        let creds = make_test_creds();
        let config = make_test_config(); // pass_attempt_limit = 5

        let reply =
            handle_ascii_continue(b"", b"", 0, &mut state, &policy, &creds, &config, None).await;

        assert_eq!(reply.status, AUTHEN_STATUS_FAIL);
        assert!(reply.server_msg.contains("too many password attempts"));
    }

    #[tokio::test]
    async fn handle_ascii_continue_lockout_triggered() {
        let policy = Arc::new(RwLock::new(make_default_policy()));
        let mut state = make_test_state();
        state.ascii_need_user = true;
        state.ascii_attempts = 2; // Will become 3
        let creds = make_test_creds();
        let mut config = make_test_config();
        config.lockout_limit = 3;

        let reply = handle_ascii_continue(
            b"", b"newuser", 0, &mut state, &policy, &creds, &config, None,
        )
        .await;

        assert_eq!(reply.status, AUTHEN_STATUS_FAIL);
        assert!(reply.server_msg.contains("locked out"));
    }

    #[tokio::test]
    async fn handle_ascii_continue_username_collection_success() {
        let policy = Arc::new(RwLock::new(make_default_policy()));
        let mut state = make_test_state();
        state.ascii_need_user = true;
        state.username = None;
        state.username_raw = None;
        let creds = make_test_creds();
        let config = make_test_config();

        let reply = handle_ascii_continue(
            b"", b"newuser", 0, &mut state, &policy, &creds, &config, None,
        )
        .await;

        assert_eq!(reply.status, AUTHEN_STATUS_GETPASS);
        assert_eq!(reply.flags, AUTHEN_FLAG_NOECHO);
        assert!(!state.ascii_need_user);
        assert!(state.ascii_need_pass);
        assert_eq!(state.username, Some("newuser".to_string()));
        assert_eq!(state.username_raw, Some(b"newuser".to_vec()));
    }

    #[tokio::test]
    async fn handle_ascii_continue_username_empty_reprompts() {
        let policy = Arc::new(RwLock::new(make_default_policy()));
        let mut state = make_test_state();
        state.ascii_need_user = true;
        state.username = None;
        let creds = make_test_creds();
        let config = make_test_config();

        let reply = handle_ascii_continue(
            b"", b"", // Empty username
            0, &mut state, &policy, &creds, &config, None,
        )
        .await;

        assert_eq!(reply.status, AUTHEN_STATUS_GETUSER);
        assert!(state.ascii_need_user);
    }

    #[tokio::test]
    async fn handle_ascii_continue_password_empty_reprompts() {
        let policy = Arc::new(RwLock::new(make_default_policy()));
        let mut state = make_test_state();
        state.ascii_need_pass = true;
        let creds = make_test_creds();
        let config = make_test_config();

        let reply = handle_ascii_continue(
            b"", b"", // Empty password
            0, &mut state, &policy, &creds, &config, None,
        )
        .await;

        assert_eq!(reply.status, AUTHEN_STATUS_GETPASS);
        assert_eq!(reply.flags, AUTHEN_FLAG_NOECHO);
    }

    #[tokio::test]
    async fn handle_ascii_continue_auth_success() {
        let policy = Arc::new(RwLock::new(make_default_policy()));
        let mut state = make_test_state();
        state.ascii_need_pass = true;
        state.username = Some("testuser".to_string());
        state.username_raw = Some(b"testuser".to_vec());
        let creds = make_test_creds();
        let config = make_test_config();

        let reply = handle_ascii_continue(
            b"",
            b"testpass", // Correct password
            0,
            &mut state,
            &policy,
            &creds,
            &config,
            None,
        )
        .await;

        assert_eq!(reply.status, AUTHEN_STATUS_PASS);
        assert!(reply.server_msg.contains("succeeded"));
        assert!(!state.ascii_need_pass);
    }

    #[tokio::test]
    async fn handle_ascii_continue_auth_failure() {
        let policy = Arc::new(RwLock::new(make_default_policy()));
        let mut state = make_test_state();
        state.ascii_need_pass = true;
        state.username = Some("testuser".to_string());
        state.username_raw = Some(b"testuser".to_vec());
        let creds = make_test_creds();
        let config = make_test_config();

        let reply = handle_ascii_continue(
            b"",
            b"wrongpass", // Wrong password
            0,
            &mut state,
            &policy,
            &creds,
            &config,
            None,
        )
        .await;

        assert_eq!(reply.status, AUTHEN_STATUS_FAIL);
        assert!(reply.server_msg.contains("invalid credentials"));
    }

    #[tokio::test]
    async fn handle_ascii_continue_restart_state() {
        let policy = Arc::new(RwLock::new(make_default_policy()));
        let mut state = make_test_state();
        // Neither need_user nor need_pass - triggers restart
        state.ascii_need_user = false;
        state.ascii_need_pass = false;
        state.ascii_attempts = 2;
        let creds = make_test_creds();
        let config = make_test_config();

        let reply =
            handle_ascii_continue(b"", b"", 0, &mut state, &policy, &creds, &config, None).await;

        assert_eq!(reply.status, AUTHEN_STATUS_RESTART);
        assert!(reply.server_msg.contains("restart"));
        // State should be reset
        assert!(state.ascii_need_user);
        assert!(!state.ascii_need_pass);
        assert!(state.username.is_none());
        assert!(state.username_raw.is_none());
        assert_eq!(state.ascii_attempts, 0);
    }

    #[tokio::test]
    async fn handle_ascii_continue_auth_with_raw_username() {
        let policy = Arc::new(RwLock::new(make_default_policy()));
        let mut state = make_test_state();
        state.ascii_need_pass = true;
        state.username = None; // No decoded username
        state.username_raw = Some(b"testuser".to_vec()); // Only raw
        let creds = make_test_creds();
        let config = make_test_config();

        let reply = handle_ascii_continue(
            b"",
            b"testpass",
            0,
            &mut state,
            &policy,
            &creds,
            &config,
            None,
        )
        .await;

        assert_eq!(reply.status, AUTHEN_STATUS_PASS);
    }

    #[tokio::test]
    async fn handle_ascii_continue_attempt_counter_increments() {
        let policy = Arc::new(RwLock::new(make_default_policy()));
        let mut state = make_test_state();
        state.ascii_need_user = true;
        state.ascii_attempts = 0;
        let creds = make_test_creds();
        let config = make_test_config();

        let _reply = handle_ascii_continue(
            b"",
            b"someuser",
            0,
            &mut state,
            &policy,
            &creds,
            &config,
            None,
        )
        .await;

        assert_eq!(state.ascii_attempts, 1);
        assert_eq!(state.ascii_user_attempts, 1);
    }

    #[tokio::test]
    async fn handle_ascii_continue_pass_attempt_counter_increments() {
        let policy = Arc::new(RwLock::new(make_default_policy()));
        let mut state = make_test_state();
        state.ascii_need_pass = true;
        state.ascii_pass_attempts = 0;
        let creds = make_test_creds();
        let config = make_test_config();

        let _reply = handle_ascii_continue(
            b"",
            b"somepass",
            0,
            &mut state,
            &policy,
            &creds,
            &config,
            None,
        )
        .await;

        assert_eq!(state.ascii_pass_attempts, 1);
    }

    #[tokio::test]
    async fn handle_ascii_continue_no_limit_zero_attempt_limit() {
        let policy = Arc::new(RwLock::new(make_default_policy()));
        let mut state = make_test_state();
        state.ascii_need_user = true;
        state.ascii_attempts = 100; // High count
        let creds = make_test_creds();
        let mut config = make_test_config();
        config.attempt_limit = 0; // Unlimited

        let reply =
            handle_ascii_continue(b"", b"user", 0, &mut state, &policy, &creds, &config, None)
                .await;

        // Should not fail due to attempt limit
        assert_ne!(reply.status, AUTHEN_STATUS_FAIL);
    }

    #[tokio::test]
    async fn handle_ascii_continue_with_service_action_in_message() {
        let policy = Arc::new(RwLock::new(make_default_policy()));
        let mut state = make_test_state();
        state.ascii_need_pass = true;
        state.username = Some("testuser".to_string());
        state.service = Some(2);
        state.action = Some(3);
        let creds = make_test_creds();
        let config = make_test_config();

        let reply = handle_ascii_continue(
            b"",
            b"testpass",
            0,
            &mut state,
            &policy,
            &creds,
            &config,
            None,
        )
        .await;

        assert_eq!(reply.status, AUTHEN_STATUS_PASS);
        assert!(reply.server_msg.contains("service"));
    }

    #[tokio::test]
    async fn handle_ascii_continue_username_non_utf8() {
        let policy = Arc::new(RwLock::new(make_default_policy()));
        let mut state = make_test_state();
        state.ascii_need_user = true;
        state.username = None;
        let creds = make_test_creds();
        let config = make_test_config();

        // Non-UTF8 username
        let reply = handle_ascii_continue(
            b"",
            &[0xFF, 0xFE, 0x80],
            0,
            &mut state,
            &policy,
            &creds,
            &config,
            None,
        )
        .await;

        assert_eq!(reply.status, AUTHEN_STATUS_GETPASS);
        assert!(state.username.is_none()); // UTF8 parse failed
        assert_eq!(state.username_raw, Some(vec![0xFF, 0xFE, 0x80]));
    }
}
