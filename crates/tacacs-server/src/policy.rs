// SPDX-License-Identifier: Apache-2.0
//! Policy enforcement for TACACS+ authorization decisions.
//!
//! # NIST SP 800-53 Security Controls
//!
//! This module implements the following NIST security controls:
//!
//! - **AC-3 (Access Enforcement)**: Enforces authorization policy decisions
//!   for command execution based on user, group, and command matching.
//!
//! - **AC-4 (Information Flow Enforcement)**: Controls server message flow
//!   with allowlists and denylists per user configuration.
//!
//! - **AU-2/AU-12 (Audit Events)**: Authorization decisions are logged with
//!   rule ID, user, command, and decision outcome.

use crate::ascii::{field_for_policy, username_for_policy};
use std::sync::Arc;
use tokio::sync::RwLock;
use usg_tacacs_policy::PolicyEngine;
use usg_tacacs_proto::{AUTHEN_STATUS_FAIL, AuthSessionState, AuthenReply};

/// Enforce server_msg_raw policy; clears/denies reply if blocked.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-4 | Information Flow Enforcement | Controls server message content based on allowlists/denylists |
/// | AU-12 | Audit Generation | Policy decisions logged via tracing |
#[tracing::instrument(skip(policy, state, reply), fields(username = ?state.username))]
pub async fn enforce_server_msg(
    policy: &Arc<RwLock<PolicyEngine>>,
    state: &AuthSessionState,
    reply: &mut AuthenReply,
) {
    if reply.server_msg_raw.is_empty() {
        return;
    }
    let policy = policy.read().await;
    let policy_user = username_for_policy(state.username.as_deref(), state.username_raw.as_ref());
    let policy_port = field_for_policy(state.port.as_deref(), state.port_raw.as_ref());
    let policy_rem = field_for_policy(state.rem_addr.as_deref(), state.rem_addr_raw.as_ref());
    if !policy.observe_server_msg(
        policy_user.as_deref(),
        policy_port.as_deref(),
        policy_rem.as_deref(),
        state.service,
        state.action,
        &reply.server_msg_raw,
    ) {
        reply.status = AUTHEN_STATUS_FAIL;
        reply.flags = 0;
        reply.server_msg = "server message blocked by policy".into();
        reply.server_msg_raw.clear();
        reply.data.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use usg_tacacs_policy::PolicyDocument;
    use usg_tacacs_proto::AUTHEN_STATUS_GETPASS;

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
            service: Some(1), // AUTHEN_SVC_LOGIN
            action: Some(1),  // TAC_PLUS_AUTHEN_LOGIN
        }
    }

    fn make_test_reply() -> AuthenReply {
        AuthenReply {
            status: AUTHEN_STATUS_GETPASS,
            flags: 0x01,
            server_msg: "Enter password:".to_string(),
            server_msg_raw: b"Enter password:".to_vec(),
            data: vec![1, 2, 3],
        }
    }

    // ==================== enforce_server_msg Tests ====================

    #[tokio::test]
    async fn enforce_server_msg_empty_raw_returns_early() {
        let policy = Arc::new(RwLock::new(make_default_policy()));
        let state = make_test_state();
        let mut reply = make_test_reply();
        reply.server_msg_raw.clear(); // Empty raw message

        enforce_server_msg(&policy, &state, &mut reply).await;

        // Reply should be unchanged
        assert_eq!(reply.status, AUTHEN_STATUS_GETPASS);
        assert_eq!(reply.flags, 0x01);
        assert_eq!(reply.server_msg, "Enter password:");
        assert_eq!(reply.data, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn enforce_server_msg_allowed_by_default_policy() {
        let policy = Arc::new(RwLock::new(make_default_policy()));
        let state = make_test_state();
        let mut reply = make_test_reply();

        enforce_server_msg(&policy, &state, &mut reply).await;

        // Default policy allows everything, so reply should be unchanged
        assert_eq!(reply.status, AUTHEN_STATUS_GETPASS);
        assert_eq!(reply.flags, 0x01);
        assert_eq!(reply.server_msg, "Enter password:");
        assert!(!reply.server_msg_raw.is_empty());
        assert_eq!(reply.data, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn enforce_server_msg_with_raw_username() {
        let policy = Arc::new(RwLock::new(make_default_policy()));
        let mut state = make_test_state();
        state.username = None;
        state.username_raw = Some(vec![0x80, 0x81, 0x82]); // Non-UTF8 username
        let mut reply = make_test_reply();

        enforce_server_msg(&policy, &state, &mut reply).await;

        // Default policy allows, reply unchanged
        assert_eq!(reply.status, AUTHEN_STATUS_GETPASS);
    }

    #[tokio::test]
    async fn enforce_server_msg_with_raw_port() {
        let policy = Arc::new(RwLock::new(make_default_policy()));
        let mut state = make_test_state();
        state.port = None;
        state.port_raw = Some(vec![0x80, 0x81]); // Non-UTF8 port
        let mut reply = make_test_reply();

        enforce_server_msg(&policy, &state, &mut reply).await;

        // Default policy allows, reply unchanged
        assert_eq!(reply.status, AUTHEN_STATUS_GETPASS);
    }

    #[tokio::test]
    async fn enforce_server_msg_with_raw_rem_addr() {
        let policy = Arc::new(RwLock::new(make_default_policy()));
        let mut state = make_test_state();
        state.rem_addr = None;
        state.rem_addr_raw = Some(vec![0x80]); // Non-UTF8 remote address
        let mut reply = make_test_reply();

        enforce_server_msg(&policy, &state, &mut reply).await;

        // Default policy allows, reply unchanged
        assert_eq!(reply.status, AUTHEN_STATUS_GETPASS);
    }

    #[tokio::test]
    async fn enforce_server_msg_with_none_username() {
        let policy = Arc::new(RwLock::new(make_default_policy()));
        let mut state = make_test_state();
        state.username = None;
        state.username_raw = None;
        let mut reply = make_test_reply();

        enforce_server_msg(&policy, &state, &mut reply).await;

        // Default policy allows, reply unchanged
        assert_eq!(reply.status, AUTHEN_STATUS_GETPASS);
    }

    #[tokio::test]
    async fn enforce_server_msg_with_none_port() {
        let policy = Arc::new(RwLock::new(make_default_policy()));
        let mut state = make_test_state();
        state.port = None;
        state.port_raw = None;
        let mut reply = make_test_reply();

        enforce_server_msg(&policy, &state, &mut reply).await;

        // Default policy allows, reply unchanged
        assert_eq!(reply.status, AUTHEN_STATUS_GETPASS);
    }

    #[tokio::test]
    async fn enforce_server_msg_with_none_rem_addr() {
        let policy = Arc::new(RwLock::new(make_default_policy()));
        let mut state = make_test_state();
        state.rem_addr = None;
        state.rem_addr_raw = None;
        let mut reply = make_test_reply();

        enforce_server_msg(&policy, &state, &mut reply).await;

        // Default policy allows, reply unchanged
        assert_eq!(reply.status, AUTHEN_STATUS_GETPASS);
    }

    #[tokio::test]
    async fn enforce_server_msg_preserves_action_and_service() {
        let policy = Arc::new(RwLock::new(make_default_policy()));
        let mut state = make_test_state();
        state.action = Some(0x02); // Different action
        state.service = Some(0x03); // Different service
        let mut reply = make_test_reply();

        enforce_server_msg(&policy, &state, &mut reply).await;

        // Default policy allows, reply unchanged
        assert_eq!(reply.status, AUTHEN_STATUS_GETPASS);
    }
}
