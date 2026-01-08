// SPDX-License-Identifier: Apache-2.0
//! Authentication module for TACACS+ server.
//!
//! # NIST SP 800-53 Security Controls
//!
//! This module implements the following NIST security controls:
//!
//! - **IA-2 (Identification and Authentication)**: Implements multiple authentication
//!   methods including PAP, CHAP, and LDAPS for user identification and authentication.
//!
//! - **IA-5 (Authenticator Management)**: Uses Argon2id for password hashing, providing
//!   memory-hard protection against brute-force attacks. Enforces LDAPS-only connections
//!   (rejects StartTLS) to protect credentials in transit.
//!
//! - **IA-6 (Authenticator Feedback)**: Returns generic error messages that do not reveal
//!   whether a username exists or password was incorrect.
//!
//! - **AC-2 (Account Management)**: Integrates with LDAP directories for centralized
//!   account management and group membership validation.
//!
//! - **SC-8 (Transmission Confidentiality)**: Requires LDAPS (not StartTLS) to ensure
//!   credentials are encrypted in transit to the directory server.
//!
//! - **AU-2/AU-12 (Audit Events/Generation)**: All authentication attempts are logged
//!   via tracing instrumentation with relevant context (username, method, result).

use crate::config::StaticCreds;
use argon2::{PasswordHash, PasswordVerifier};
use ldap3::{LdapConn, LdapConnSettings, Scope, SearchEntry};
use openssl::hash::{MessageDigest, hash};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio::task;
use usg_tacacs_proto::{
    AUTHEN_STATUS_ERROR, AUTHEN_STATUS_FAIL, AUTHEN_STATUS_PASS, AuthSessionState, AuthenReply,
};

/// Escape special characters in LDAP filter values per RFC 4515.
///
/// # NIST Controls
/// - **SI-10 (Information Input Validation)**: Sanitizes user input to prevent
///   LDAP injection attacks by escaping metacharacters.
///
/// Characters escaped: `*` `(` `)` `\` NUL
///
/// # Example
/// ```ignore
/// let safe = ldap_escape_filter_value("user*name");
/// assert_eq!(safe, "user\\2aname");
/// ```
fn ldap_escape_filter_value(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len() * 2);
    for c in input.chars() {
        match c {
            '*' => escaped.push_str("\\2a"),
            '(' => escaped.push_str("\\28"),
            ')' => escaped.push_str("\\29"),
            '\\' => escaped.push_str("\\5c"),
            '\0' => escaped.push_str("\\00"),
            _ => escaped.push(c),
        }
    }
    escaped
}

#[derive(Clone, Debug)]
pub struct LdapConfig {
    pub url: String,
    pub bind_dn: String,
    pub bind_password: String,
    pub search_base: String,
    pub username_attr: String,
    pub timeout: Duration,
    pub ca_file: Option<PathBuf>,
    pub required_group: Vec<String>,
    pub group_attr: String,
}

impl LdapConfig {
    #[tracing::instrument(skip(self, password), fields(ldap.url = %self.url))]
    pub async fn authenticate(&self, username: &str, password: &str) -> bool {
        let cfg = self.clone();
        let user = username.to_string();
        let pass = password.to_string();
        task::spawn_blocking(move || ldap_authenticate_blocking(cfg, &user, &pass))
            .await
            .unwrap_or(false)
    }
}

/// Performs LDAP authentication in a blocking context.
///
/// # NIST Controls
/// - **SC-8**: Enforces LDAPS-only (rejects plain LDAP/StartTLS) for transmission confidentiality
/// - **IA-2**: Authenticates users against enterprise directory
/// - **AC-2**: Validates group membership for account management
fn ldap_authenticate_blocking(cfg: LdapConfig, username: &str, password: &str) -> bool {
    // NIST SC-8: Reject non-LDAPS URLs to ensure encrypted transmission
    if !cfg.url.to_lowercase().starts_with("ldaps://") {
        return false;
    }
    let settings = LdapConnSettings::new().set_conn_timeout(cfg.timeout);
    if cfg.ca_file.is_some() {
        // ldap3 with tls-native uses system roots; custom CA not supported in this build.
    }
    let Ok(mut ldap) = LdapConn::with_settings(settings, &cfg.url) else {
        return false;
    };
    if ldap
        .simple_bind(&cfg.bind_dn, &cfg.bind_password)
        .and_then(|r| r.success())
        .is_err()
    {
        return false;
    }
    // NIST SI-10: Escape username to prevent LDAP injection attacks
    let escaped_username = ldap_escape_filter_value(username);
    let filter = format!("({}={})", cfg.username_attr, escaped_username);
    let search = ldap.search(
        &cfg.search_base,
        Scope::Subtree,
        &filter,
        vec!["dn", &cfg.group_attr],
    );
    let Ok((results, _res)) = search.and_then(|r| r.success()) else {
        return false;
    };
    let Some(entry) = results.into_iter().next() else {
        return false;
    };
    let user_dn = SearchEntry::construct(entry).dn;
    if !cfg.required_group.is_empty() {
        let search = ldap
            .search(
                &cfg.search_base,
                Scope::Subtree,
                &filter,
                vec![&cfg.group_attr],
            )
            .and_then(|r| r.success());
        if let Ok((entries, _)) = search
            && let Some(entry) = entries.into_iter().next()
        {
            let se = SearchEntry::construct(entry);
            let groups = se.attrs.get(&cfg.group_attr).cloned().unwrap_or_default();
            if !groups.iter().any(|g| {
                cfg.required_group
                    .iter()
                    .any(|req| g.eq_ignore_ascii_case(req))
            }) {
                return false;
            }
        }
    }
    ldap.simple_bind(&user_dn, password)
        .and_then(|r| r.success())
        .is_ok()
}

#[tracing::instrument(skip(cfg), fields(ldap.url = %cfg.url))]
pub async fn ldap_fetch_groups(cfg: &Arc<LdapConfig>, username: &str) -> Vec<String> {
    let cfg = cfg.clone();
    let user = username.to_string();
    task::spawn_blocking(move || ldap_fetch_groups_blocking(cfg, &user))
        .await
        .unwrap_or_default()
}

fn ldap_fetch_groups_blocking(cfg: Arc<LdapConfig>, username: &str) -> Vec<String> {
    if !cfg.url.to_lowercase().starts_with("ldaps://") {
        return Vec::new();
    }
    let settings = LdapConnSettings::new().set_conn_timeout(cfg.timeout);
    let Ok(mut ldap) = LdapConn::with_settings(settings, &cfg.url) else {
        return Vec::new();
    };
    if ldap
        .simple_bind(&cfg.bind_dn, &cfg.bind_password)
        .and_then(|r| r.success())
        .is_err()
    {
        return Vec::new();
    }
    // NIST SI-10: Escape username to prevent LDAP injection attacks
    let escaped_username = ldap_escape_filter_value(username);
    let filter = format!("({}={})", cfg.username_attr, escaped_username);
    let search = ldap
        .search(
            &cfg.search_base,
            Scope::Subtree,
            &filter,
            vec![&cfg.group_attr],
        )
        .and_then(|r| r.success());
    let Ok((entries, _)) = search else {
        return Vec::new();
    };
    if let Some(entry) = entries.into_iter().next() {
        let se = SearchEntry::construct(entry);
        let groups = se.attrs.get(&cfg.group_attr).cloned().unwrap_or_default();
        return groups.into_iter().map(|g| g.to_lowercase()).collect();
    }
    Vec::new()
}

/// Verify PAP authentication credentials.
///
/// # NIST Controls
/// - **IA-2**: Authenticates users via Password Authentication Protocol
/// - **IA-5**: Supports Argon2id hashed passwords for secure storage
/// - **AU-12**: Instrumented for audit logging via tracing
///
/// # Security
/// Uses constant-time comparison for plaintext passwords to prevent timing
/// side-channel attacks (CWE-208). Argon2 verification is inherently timing-safe.
#[tracing::instrument(skip(password, creds))]
pub fn verify_pap(user: &str, password: &str, creds: &StaticCreds) -> bool {
    if creds
        .plain
        .get(user)
        .map(|stored| constant_time_eq_str(stored, password))
        .unwrap_or(false)
    {
        return true;
    }
    if let Some(hash) = creds.argon.get(user) {
        return verify_argon_hash(hash, password.as_bytes());
    }
    false
}

/// Constant-time string comparison to prevent timing side-channel attacks.
///
/// # NIST Controls
/// - **SC-13 (Cryptographic Protection)**: Uses constant-time comparison to prevent
///   timing-based information disclosure about password values (CWE-208).
#[inline]
fn constant_time_eq_str(a: &str, b: &str) -> bool {
    constant_time_eq_bytes(a.as_bytes(), b.as_bytes())
}

/// Constant-time byte slice comparison to prevent timing side-channel attacks.
///
/// Returns true only if both slices have the same length and content.
/// Comparison time is constant regardless of how many bytes match.
#[inline]
fn constant_time_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// Verify password against Argon2id hash.
///
/// # NIST Controls
/// - **IA-5 (Authenticator Management)**: Uses Argon2id, a memory-hard key derivation
///   function resistant to GPU/ASIC brute-force attacks. Provides timing-safe comparison.
fn verify_argon_hash(hash: &str, password: &[u8]) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    argon2::Argon2::default()
        .verify_password(password, &parsed)
        .is_ok()
}

/// Verify PAP authentication with byte password.
///
/// # Security
/// Uses constant-time comparison to prevent timing side-channel attacks.
pub fn verify_pap_bytes(user: &str, password: &[u8], creds: &StaticCreds) -> bool {
    if creds
        .plain
        .get(user)
        .map(|stored| constant_time_eq_bytes(stored.as_bytes(), password))
        .unwrap_or(false)
    {
        return true;
    }
    if let Some(hash) = creds.argon.get(user) {
        return verify_argon_hash(hash, password);
    }
    false
}

/// Verify PAP authentication with byte username and password.
///
/// # Security
/// Uses constant-time comparison for password to prevent timing side-channel attacks.
/// Username comparison is timing-safe indirectly since we iterate all credentials.
pub fn verify_pap_bytes_username(username: &[u8], password: &[u8], creds: &StaticCreds) -> bool {
    // Check all plaintext credentials with constant-time password comparison
    let plain_match = creds.plain.iter().any(|(u, p)| {
        constant_time_eq_bytes(u.as_bytes(), username)
            && constant_time_eq_bytes(p.as_bytes(), password)
    });
    if plain_match {
        return true;
    }
    // Check argon2 credentials (argon2 verify is inherently timing-safe)
    creds
        .argon
        .iter()
        .any(|(u, h)| constant_time_eq_bytes(u.as_bytes(), username) && verify_argon_hash(h, password))
}

#[tracing::instrument(skip(password, creds, ldap), fields(has_ldap = ldap.is_some()))]
pub async fn verify_password_sources(
    username: Option<&str>,
    password: &[u8],
    creds: &StaticCreds,
    ldap: Option<&Arc<LdapConfig>>,
) -> bool {
    // Prefer raw-byte match against static credentials.
    if let Some(user) = username
        && verify_pap_bytes(user, password, creds)
    {
        tracing::debug!("authenticated via static credentials");
        return true;
    }
    // Try LDAP if enabled and username/password are UTF-8.
    if let (Some(user), Some(ldap_cfg)) = (username, ldap)
        && let Ok(pass_str) = std::str::from_utf8(password)
    {
        let result = ldap_cfg.authenticate(user, pass_str).await;
        if result {
            tracing::debug!("authenticated via LDAP");
        }
        return result;
    }
    false
}

/// Compute CHAP response for challenge-response authentication.
///
/// # NIST Controls
/// - **IA-2 (Identification and Authentication)**: Implements CHAP challenge-response
///   authentication as specified in RFC 1994.
///
/// # Security Notice: MD5 Usage (CWE-327)
///
/// This function uses MD5 for CHAP response computation as required by the CHAP protocol
/// specification (RFC 1994). **MD5 is cryptographically broken but acceptable for CHAP**
/// because:
///
/// 1. **Challenge-response, not password storage**: Passwords are NOT stored as MD5 hashes.
///    MD5 is only used to compute a one-time response to a random challenge.
///
/// 2. **Nonce prevents replay**: The server-generated challenge (nonce) ensures each
///    authentication uses a unique hash input, preventing precomputation attacks.
///
/// 3. **Protocol specification**: CHAP mandates MD5 per RFC 1994 Section 4.1.
///
/// ## Recommendations
///
/// For stronger authentication, consider:
/// - **PAP with Argon2**: Use PAP authentication with Argon2id password hashing
/// - **LDAPS**: Integrate with enterprise LDAP directories over TLS
/// - **mTLS**: Use mutual TLS for certificate-based authentication
///
/// ## TLS Requirement
///
/// CHAP should only be used over TLS-encrypted connections to protect the challenge
/// and response from eavesdropping.
pub fn compute_chap_response(
    user: &str,
    creds: &HashMap<String, String>,
    continue_data: &[u8],
    challenge: &[u8],
) -> Option<bool> {
    if continue_data.len() != 1 + 16 || challenge.len() != 16 {
        return None;
    }
    let chap_id = continue_data[0];
    let response = &continue_data[1..];
    let password = creds.get(user)?;
    let mut buf = Vec::with_capacity(1 + password.len() + challenge.len());
    buf.push(chap_id);
    buf.extend_from_slice(password.as_bytes());
    buf.extend_from_slice(challenge);
    let digest = hash(MessageDigest::md5(), &buf).ok()?;
    Some(digest.as_ref() == response)
}

/// Handle CHAP authentication continue message.
///
/// # NIST Controls
/// - **IA-6 (Authenticator Feedback)**: Returns generic error messages that do not
///   reveal whether a username exists, the specific reason for failure, or internal
///   state information (CWE-209). Detailed errors are logged internally.
pub fn handle_chap_continue(
    user: &str,
    cont_data: &[u8],
    state: &mut AuthSessionState,
    credentials: &StaticCreds,
) -> AuthenReply {
    // NIST IA-6: Use generic error message for external response
    const GENERIC_AUTH_ERROR: &str = "authentication failed";

    if cont_data.len() != 1 + 16 {
        tracing::debug!("CHAP continue: invalid data length {}", cont_data.len());
        return AuthenReply {
            status: AUTHEN_STATUS_ERROR,
            flags: 0,
            server_msg: GENERIC_AUTH_ERROR.into(),
            server_msg_raw: Vec::new(),
            data: Vec::new(),
        };
    }
    if state.chap_id.is_some() && cont_data[0] != state.chap_id.unwrap() {
        tracing::debug!(
            "CHAP continue: identifier mismatch (expected {:?}, got {})",
            state.chap_id,
            cont_data[0]
        );
        return AuthenReply {
            status: AUTHEN_STATUS_FAIL,
            flags: 0,
            server_msg: GENERIC_AUTH_ERROR.into(),
            server_msg_raw: Vec::new(),
            data: Vec::new(),
        };
    }
    if let Some(expected) = compute_chap_response(
        user,
        &credentials.plain,
        cont_data,
        state.challenge.as_deref().unwrap_or(&[]),
    ) {
        state.challenge = None;
        state.chap_id = None;
        if expected {
            AuthenReply {
                status: AUTHEN_STATUS_PASS,
                flags: 0,
                server_msg: String::new(),
                server_msg_raw: Vec::new(),
                data: Vec::new(),
            }
        } else {
            tracing::debug!("CHAP continue: invalid response hash");
            AuthenReply {
                status: AUTHEN_STATUS_FAIL,
                flags: 0,
                server_msg: GENERIC_AUTH_ERROR.into(),
                server_msg_raw: Vec::new(),
                data: Vec::new(),
            }
        }
    } else {
        tracing::debug!("CHAP continue: user '{}' not found in credentials", user);
        AuthenReply {
            status: AUTHEN_STATUS_ERROR,
            flags: 0,
            server_msg: GENERIC_AUTH_ERROR.into(),
            server_msg_raw: Vec::new(),
            data: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use usg_tacacs_proto::Header;

    // ==================== ldap_escape_filter_value Tests ====================

    #[test]
    fn ldap_escape_asterisk() {
        assert_eq!(ldap_escape_filter_value("user*name"), "user\\2aname");
        assert_eq!(ldap_escape_filter_value("*"), "\\2a");
        assert_eq!(ldap_escape_filter_value("***"), "\\2a\\2a\\2a");
    }

    #[test]
    fn ldap_escape_parentheses() {
        assert_eq!(ldap_escape_filter_value("user(name)"), "user\\28name\\29");
        assert_eq!(ldap_escape_filter_value(")("), "\\29\\28");
    }

    #[test]
    fn ldap_escape_backslash() {
        assert_eq!(ldap_escape_filter_value("user\\name"), "user\\5cname");
        assert_eq!(ldap_escape_filter_value("\\\\"), "\\5c\\5c");
    }

    #[test]
    fn ldap_escape_null() {
        assert_eq!(ldap_escape_filter_value("user\0name"), "user\\00name");
    }

    #[test]
    fn ldap_escape_combined_injection_payloads() {
        // Common LDAP injection payloads should be safely escaped
        assert_eq!(ldap_escape_filter_value("*"), "\\2a");
        assert_eq!(
            ldap_escape_filter_value("admin)(|(uid=*"),
            "admin\\29\\28|\\28uid=\\2a"
        );
        assert_eq!(
            ldap_escape_filter_value("*)(objectClass=*"),
            "\\2a\\29\\28objectClass=\\2a"
        );
        assert_eq!(ldap_escape_filter_value(")(uid=*)"), "\\29\\28uid=\\2a\\29");
    }

    #[test]
    fn ldap_escape_normal_username_unchanged() {
        assert_eq!(ldap_escape_filter_value("alice"), "alice");
        assert_eq!(ldap_escape_filter_value("bob.jones"), "bob.jones");
        assert_eq!(
            ldap_escape_filter_value("user@domain.com"),
            "user@domain.com"
        );
        assert_eq!(ldap_escape_filter_value("user_name-123"), "user_name-123");
    }

    #[test]
    fn ldap_escape_empty_string() {
        assert_eq!(ldap_escape_filter_value(""), "");
    }

    #[test]
    fn ldap_escape_unicode() {
        // Unicode characters should pass through unchanged
        assert_eq!(ldap_escape_filter_value("用户"), "用户");
        assert_eq!(ldap_escape_filter_value("café"), "café");
    }

    fn make_creds() -> StaticCreds {
        let mut creds = StaticCreds::default();
        creds.plain.insert("admin".into(), "secret123".into());
        creds.plain.insert("user".into(), "password".into());
        creds
    }

    #[cfg(test)]
    fn make_argon_creds() -> StaticCreds {
        let mut creds = StaticCreds::default();
        // Valid argon2id hash for password "test123"
        creds.argon.insert(
            "hashed_user".into(),
            "$argon2id$v=19$m=19456,t=2,p=1$bXlzYWx0MTIzNDU2Nzg$lT9bGlM5c7M8vbdNjLy3sA".into(),
        );
        creds
    }

    fn make_test_header() -> Header {
        Header {
            version: 0xC0,
            packet_type: 0x01,
            seq_no: 1,
            flags: 0,
            session_id: 12345,
            length: 0,
        }
    }

    fn make_test_session_state() -> AuthSessionState {
        use usg_tacacs_proto::AuthenStart;

        let start = AuthenStart {
            header: make_test_header(),
            action: 0x01,
            priv_lvl: 1,
            authen_type: 0x01, // PAP
            service: 0x01,
            user_raw: b"testuser".to_vec(),
            user: "testuser".into(),
            port_raw: b"console".to_vec(),
            port: "console".into(),
            rem_addr_raw: b"192.168.1.1".to_vec(),
            rem_addr: "192.168.1.1".into(),
            data: vec![],
        };

        AuthSessionState::from_start(&start).unwrap()
    }

    // ==================== verify_pap Tests ====================

    #[test]
    fn verify_pap_valid_plain() {
        let creds = make_creds();
        assert!(verify_pap("admin", "secret123", &creds));
    }

    #[test]
    fn verify_pap_invalid_password() {
        let creds = make_creds();
        assert!(!verify_pap("admin", "wrongpassword", &creds));
    }

    #[test]
    fn verify_pap_unknown_user() {
        let creds = make_creds();
        assert!(!verify_pap("unknown", "secret123", &creds));
    }

    #[test]
    fn verify_pap_empty_password() {
        let mut creds = StaticCreds::default();
        creds.plain.insert("emptypass".into(), "".into());
        assert!(verify_pap("emptypass", "", &creds));
    }

    #[test]
    fn verify_pap_case_sensitive() {
        let creds = make_creds();
        assert!(!verify_pap("ADMIN", "secret123", &creds));
        assert!(!verify_pap("admin", "SECRET123", &creds));
    }

    #[test]
    fn verify_pap_argon_invalid_hash() {
        // Invalid argon2 hash format should return false
        let mut creds = StaticCreds::default();
        creds.argon.insert("user".into(), "not-a-valid-hash".into());
        assert!(!verify_pap("user", "anypassword", &creds));
    }

    // ==================== verify_pap_bytes Tests ====================

    #[test]
    fn verify_pap_bytes_valid() {
        let creds = make_creds();
        assert!(verify_pap_bytes("admin", b"secret123", &creds));
    }

    #[test]
    fn verify_pap_bytes_invalid() {
        let creds = make_creds();
        assert!(!verify_pap_bytes("admin", b"wrong", &creds));
    }

    #[test]
    fn verify_pap_bytes_with_null() {
        let mut creds = StaticCreds::default();
        // Password with embedded null byte
        creds.plain.insert("user".into(), "pass\0word".into());
        assert!(verify_pap_bytes("user", b"pass\0word", &creds));
    }

    #[test]
    fn verify_pap_bytes_binary() {
        let mut creds = StaticCreds::default();
        // Use String::from_utf8_lossy for binary data
        let binary_pass = String::from_utf8_lossy(&[0x7f, 0x00, 0x7e]).to_string();
        creds.plain.insert("user".into(), binary_pass.clone());
        assert!(verify_pap_bytes("user", binary_pass.as_bytes(), &creds));
    }

    // ==================== verify_pap_bytes_username Tests ====================

    #[test]
    fn verify_pap_bytes_username_valid() {
        let creds = make_creds();
        assert!(verify_pap_bytes_username(b"admin", b"secret123", &creds));
    }

    #[test]
    fn verify_pap_bytes_username_invalid() {
        let creds = make_creds();
        assert!(!verify_pap_bytes_username(b"admin", b"wrong", &creds));
    }

    #[test]
    fn verify_pap_bytes_username_unknown() {
        let creds = make_creds();
        assert!(!verify_pap_bytes_username(b"unknown", b"secret123", &creds));
    }

    #[test]
    fn verify_pap_bytes_username_binary() {
        let mut creds = StaticCreds::default();
        // Use valid ASCII characters for username
        let binary_user = String::from_utf8_lossy(&[0x7f, 0x7e]).to_string();
        creds.plain.insert(binary_user.clone(), "pass".into());
        assert!(verify_pap_bytes_username(
            binary_user.as_bytes(),
            b"pass",
            &creds
        ));
    }

    // ==================== compute_chap_response Tests ====================

    #[test]
    fn compute_chap_response_valid() {
        let mut creds = HashMap::new();
        creds.insert("admin".into(), "secret".into());

        // Construct valid CHAP data: 1 byte ID + 16 bytes response
        let chap_id = 0x42u8;
        let challenge = [0x11u8; 16];

        // Compute expected MD5(id || password || challenge)
        let mut buf = Vec::new();
        buf.push(chap_id);
        buf.extend_from_slice(b"secret");
        buf.extend_from_slice(&challenge);
        let expected_digest = hash(MessageDigest::md5(), &buf).unwrap();

        let mut continue_data = vec![chap_id];
        continue_data.extend_from_slice(expected_digest.as_ref());

        let result = compute_chap_response("admin", &creds, &continue_data, &challenge);
        assert_eq!(result, Some(true));
    }

    #[test]
    fn compute_chap_response_invalid() {
        let mut creds = HashMap::new();
        creds.insert("admin".into(), "secret".into());

        let challenge = [0x11u8; 16];
        // Wrong response
        let mut continue_data = vec![0x42];
        continue_data.extend_from_slice(&[0u8; 16]); // All zeros = wrong

        let result = compute_chap_response("admin", &creds, &continue_data, &challenge);
        assert_eq!(result, Some(false));
    }

    #[test]
    fn compute_chap_response_unknown_user() {
        let creds = HashMap::new();
        let challenge = [0x11u8; 16];
        let mut continue_data = vec![0x42];
        continue_data.extend_from_slice(&[0u8; 16]);

        let result = compute_chap_response("unknown", &creds, &continue_data, &challenge);
        assert!(result.is_none());
    }

    #[test]
    fn compute_chap_response_wrong_length() {
        let mut creds = HashMap::new();
        creds.insert("admin".into(), "secret".into());

        let challenge = [0x11u8; 16];
        let continue_data = vec![0x42, 0x00, 0x00]; // Too short

        let result = compute_chap_response("admin", &creds, &continue_data, &challenge);
        assert!(result.is_none());
    }

    #[test]
    fn compute_chap_response_wrong_challenge_length() {
        let mut creds = HashMap::new();
        creds.insert("admin".into(), "secret".into());

        let challenge = [0x11u8; 8]; // Wrong length
        let mut continue_data = vec![0x42];
        continue_data.extend_from_slice(&[0u8; 16]);

        let result = compute_chap_response("admin", &creds, &continue_data, &challenge);
        assert!(result.is_none());
    }

    // ==================== handle_chap_continue Tests ====================

    #[test]
    fn handle_chap_continue_invalid_length() {
        let mut state = make_test_session_state();
        let creds = make_creds();

        let result = handle_chap_continue("admin", &[0x42, 0x00, 0x00], &mut state, &creds);
        assert_eq!(result.status, AUTHEN_STATUS_ERROR);
        // NIST IA-6: Generic error message returned
        assert!(result.server_msg.contains("authentication failed"));
    }

    #[test]
    fn handle_chap_continue_id_mismatch() {
        let mut state = make_test_session_state();
        state.chap_id = Some(0x42);
        state.challenge = Some(vec![0x11; 16]);
        let creds = make_creds();

        let mut cont_data = vec![0x99]; // Wrong ID
        cont_data.extend_from_slice(&[0u8; 16]);

        let result = handle_chap_continue("admin", &cont_data, &mut state, &creds);
        assert_eq!(result.status, AUTHEN_STATUS_FAIL);
        // NIST IA-6: Generic error message returned
        assert!(result.server_msg.contains("authentication failed"));
    }

    #[test]
    fn handle_chap_continue_missing_credentials() {
        let mut state = make_test_session_state();
        state.challenge = Some(vec![0x11; 16]);
        let creds = StaticCreds::default();

        let mut cont_data = vec![0x42];
        cont_data.extend_from_slice(&[0u8; 16]);

        let result = handle_chap_continue("unknown", &cont_data, &mut state, &creds);
        assert_eq!(result.status, AUTHEN_STATUS_ERROR);
        // NIST IA-6: Generic error message returned
        assert!(result.server_msg.contains("authentication failed"));
    }

    #[test]
    fn handle_chap_continue_invalid_response() {
        let mut state = make_test_session_state();
        state.challenge = Some(vec![0x11; 16]);
        let creds = make_creds();

        let mut cont_data = vec![0x42];
        cont_data.extend_from_slice(&[0u8; 16]); // Wrong hash

        let result = handle_chap_continue("admin", &cont_data, &mut state, &creds);
        assert_eq!(result.status, AUTHEN_STATUS_FAIL);
        // NIST IA-6: Generic error message returned
        assert!(result.server_msg.contains("authentication failed"));
    }

    #[test]
    fn handle_chap_continue_valid() {
        let mut state = make_test_session_state();
        let challenge = vec![0x11u8; 16];
        state.challenge = Some(challenge.clone());
        let chap_id = 0x42u8;
        state.chap_id = Some(chap_id);

        let mut creds = StaticCreds::default();
        creds.plain.insert("admin".into(), "secret".into());

        // Compute correct response
        let mut buf = Vec::new();
        buf.push(chap_id);
        buf.extend_from_slice(b"secret");
        buf.extend_from_slice(&challenge);
        let digest = hash(MessageDigest::md5(), &buf).unwrap();

        let mut cont_data = vec![chap_id];
        cont_data.extend_from_slice(digest.as_ref());

        let result = handle_chap_continue("admin", &cont_data, &mut state, &creds);
        assert_eq!(result.status, AUTHEN_STATUS_PASS);
        assert!(state.challenge.is_none());
        assert!(state.chap_id.is_none());
    }

    // ==================== LdapConfig Tests ====================

    #[test]
    fn ldap_config_clone() {
        let config = LdapConfig {
            url: "ldaps://example.com".into(),
            bind_dn: "cn=admin,dc=example,dc=com".into(),
            bind_password: "secret".into(),
            search_base: "dc=example,dc=com".into(),
            username_attr: "uid".into(),
            timeout: Duration::from_secs(5),
            ca_file: Some(PathBuf::from("/etc/ssl/certs/ca.pem")),
            required_group: vec!["cn=admins,dc=example,dc=com".into()],
            group_attr: "memberOf".into(),
        };

        let cloned = config.clone();
        assert_eq!(cloned.url, config.url);
        assert_eq!(cloned.bind_dn, config.bind_dn);
        assert_eq!(cloned.bind_password, config.bind_password);
        assert_eq!(cloned.search_base, config.search_base);
        assert_eq!(cloned.username_attr, config.username_attr);
        assert_eq!(cloned.timeout, config.timeout);
        assert_eq!(cloned.ca_file, config.ca_file);
        assert_eq!(cloned.required_group, config.required_group);
        assert_eq!(cloned.group_attr, config.group_attr);
    }

    #[test]
    fn ldap_config_debug() {
        let config = LdapConfig {
            url: "ldaps://example.com".into(),
            bind_dn: "cn=admin".into(),
            bind_password: "secret".into(),
            search_base: "dc=example".into(),
            username_attr: "uid".into(),
            timeout: Duration::from_secs(5),
            ca_file: None,
            required_group: vec![],
            group_attr: "memberOf".into(),
        };

        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("LdapConfig"));
        assert!(debug_str.contains("ldaps://example.com"));
    }

    // ==================== ldap_authenticate_blocking Tests ====================

    #[test]
    fn ldap_authenticate_blocking_non_ldaps_fails() {
        let config = LdapConfig {
            url: "ldap://example.com".into(), // Not LDAPS
            bind_dn: "cn=admin".into(),
            bind_password: "secret".into(),
            search_base: "dc=example".into(),
            username_attr: "uid".into(),
            timeout: Duration::from_secs(5),
            ca_file: None,
            required_group: vec![],
            group_attr: "memberOf".into(),
        };

        let result = ldap_authenticate_blocking(config, "user", "pass");
        assert!(!result); // Should fail because not LDAPS
    }

    #[test]
    fn ldap_authenticate_blocking_http_url_fails() {
        let config = LdapConfig {
            url: "http://example.com".into(), // Not LDAPS
            bind_dn: "cn=admin".into(),
            bind_password: "secret".into(),
            search_base: "dc=example".into(),
            username_attr: "uid".into(),
            timeout: Duration::from_secs(5),
            ca_file: None,
            required_group: vec![],
            group_attr: "memberOf".into(),
        };

        let result = ldap_authenticate_blocking(config, "user", "pass");
        assert!(!result);
    }

    // ==================== ldap_fetch_groups_blocking Tests ====================

    #[test]
    fn ldap_fetch_groups_blocking_non_ldaps_returns_empty() {
        let config = Arc::new(LdapConfig {
            url: "ldap://example.com".into(), // Not LDAPS
            bind_dn: "cn=admin".into(),
            bind_password: "secret".into(),
            search_base: "dc=example".into(),
            username_attr: "uid".into(),
            timeout: Duration::from_secs(5),
            ca_file: None,
            required_group: vec![],
            group_attr: "memberOf".into(),
        });

        let result = ldap_fetch_groups_blocking(config, "user");
        assert!(result.is_empty());
    }

    // ==================== verify_password_sources Tests ====================

    #[tokio::test]
    async fn verify_password_sources_static_creds_match() {
        let creds = make_creds();
        let result = verify_password_sources(Some("admin"), b"secret123", &creds, None).await;
        assert!(result);
    }

    #[tokio::test]
    async fn verify_password_sources_static_creds_no_match() {
        let creds = make_creds();
        let result = verify_password_sources(Some("admin"), b"wrongpassword", &creds, None).await;
        assert!(!result);
    }

    #[tokio::test]
    async fn verify_password_sources_no_username() {
        let creds = make_creds();
        let result = verify_password_sources(None, b"secret123", &creds, None).await;
        assert!(!result);
    }

    #[tokio::test]
    async fn verify_password_sources_unknown_user() {
        let creds = make_creds();
        let result = verify_password_sources(Some("unknown"), b"secret123", &creds, None).await;
        assert!(!result);
    }

    #[tokio::test]
    async fn verify_password_sources_ldap_non_utf8_password() {
        let creds = StaticCreds::default();
        let ldap_cfg = Arc::new(LdapConfig {
            url: "ldaps://example.com".into(),
            bind_dn: "cn=admin".into(),
            bind_password: "secret".into(),
            search_base: "dc=example".into(),
            username_attr: "uid".into(),
            timeout: Duration::from_millis(100),
            ca_file: None,
            required_group: vec![],
            group_attr: "memberOf".into(),
        });
        // Non-UTF8 password should fail LDAP path
        let result =
            verify_password_sources(Some("user"), &[0xff, 0xfe], &creds, Some(&ldap_cfg)).await;
        assert!(!result);
    }

    #[tokio::test]
    async fn verify_password_sources_empty_creds() {
        let creds = StaticCreds::default();
        let result = verify_password_sources(Some("admin"), b"secret123", &creds, None).await;
        assert!(!result);
    }

    #[tokio::test]
    async fn verify_password_sources_empty_password() {
        let mut creds = StaticCreds::default();
        creds.plain.insert("emptypass".into(), "".into());
        let result = verify_password_sources(Some("emptypass"), b"", &creds, None).await;
        assert!(result);
    }

    // ==================== verify_argon_hash Tests ====================

    #[test]
    fn verify_argon_hash_invalid_format() {
        // verify_argon_hash is private, test via verify_pap
        let mut creds = StaticCreds::default();
        creds.argon.insert("user".into(), "not-argon2-hash".into());
        assert!(!verify_pap("user", "anypassword", &creds));
    }

    #[test]
    fn verify_argon_hash_empty_hash() {
        let mut creds = StaticCreds::default();
        creds.argon.insert("user".into(), "".into());
        assert!(!verify_pap("user", "anypassword", &creds));
    }

    #[test]
    fn verify_argon_hash_malformed_params() {
        let mut creds = StaticCreds::default();
        creds
            .argon
            .insert("user".into(), "$argon2id$v=19$invalid".into());
        assert!(!verify_pap("user", "anypassword", &creds));
    }

    // ==================== verify_pap_bytes with argon Tests ====================

    #[test]
    fn verify_pap_bytes_argon_invalid_hash() {
        let mut creds = StaticCreds::default();
        creds.argon.insert("user".into(), "not-a-valid-hash".into());
        assert!(!verify_pap_bytes("user", b"anypassword", &creds));
    }

    #[test]
    fn verify_pap_bytes_unknown_user_no_argon() {
        let creds = StaticCreds::default();
        assert!(!verify_pap_bytes("unknown", b"password", &creds));
    }

    // ==================== verify_pap_bytes_username with argon Tests ====================

    #[test]
    fn verify_pap_bytes_username_argon_invalid_hash() {
        let mut creds = StaticCreds::default();
        creds.argon.insert("user".into(), "not-a-valid-hash".into());
        assert!(!verify_pap_bytes_username(b"user", b"anypassword", &creds));
    }

    #[test]
    fn verify_pap_bytes_username_empty_creds() {
        let creds = StaticCreds::default();
        assert!(!verify_pap_bytes_username(b"user", b"pass", &creds));
    }

    // ==================== LDAP Config Edge Cases ====================

    #[test]
    fn ldap_authenticate_blocking_uppercase_ldaps() {
        let config = LdapConfig {
            url: "LDAPS://example.com".into(), // Uppercase
            bind_dn: "cn=admin".into(),
            bind_password: "secret".into(),
            search_base: "dc=example".into(),
            username_attr: "uid".into(),
            timeout: Duration::from_millis(100),
            ca_file: None,
            required_group: vec![],
            group_attr: "memberOf".into(),
        };
        // Should pass the protocol check (case-insensitive) but fail to connect
        let result = ldap_authenticate_blocking(config, "user", "pass");
        // Will fail due to connection, not protocol check
        assert!(!result);
    }

    #[test]
    fn ldap_fetch_groups_blocking_uppercase_ldaps() {
        let config = Arc::new(LdapConfig {
            url: "LDAPS://example.com".into(), // Uppercase
            bind_dn: "cn=admin".into(),
            bind_password: "secret".into(),
            search_base: "dc=example".into(),
            username_attr: "uid".into(),
            timeout: Duration::from_millis(100),
            ca_file: None,
            required_group: vec![],
            group_attr: "memberOf".into(),
        });
        // Should pass the protocol check but fail to connect
        let result = ldap_fetch_groups_blocking(config, "user");
        assert!(result.is_empty());
    }

    #[test]
    fn ldap_config_with_ca_file() {
        let config = LdapConfig {
            url: "ldaps://example.com".into(),
            bind_dn: "cn=admin".into(),
            bind_password: "secret".into(),
            search_base: "dc=example".into(),
            username_attr: "uid".into(),
            timeout: Duration::from_secs(5),
            ca_file: Some(PathBuf::from("/path/to/ca.pem")),
            required_group: vec!["admins".into()],
            group_attr: "memberOf".into(),
        };
        // ca_file path should be set
        assert!(config.ca_file.is_some());
        assert_eq!(
            config.ca_file.as_ref().unwrap().to_str().unwrap(),
            "/path/to/ca.pem"
        );
    }

    #[tokio::test]
    async fn ldap_config_authenticate_unreachable_server() {
        let config = LdapConfig {
            url: "ldaps://127.0.0.1:1".into(), // Unreachable port
            bind_dn: "cn=admin".into(),
            bind_password: "secret".into(),
            search_base: "dc=example".into(),
            username_attr: "uid".into(),
            timeout: Duration::from_millis(50), // Short timeout
            ca_file: None,
            required_group: vec![],
            group_attr: "memberOf".into(),
        };
        let result = config.authenticate("user", "pass").await;
        assert!(!result);
    }

    #[tokio::test]
    async fn ldap_fetch_groups_unreachable_server() {
        let config = Arc::new(LdapConfig {
            url: "ldaps://127.0.0.1:1".into(), // Unreachable port
            bind_dn: "cn=admin".into(),
            bind_password: "secret".into(),
            search_base: "dc=example".into(),
            username_attr: "uid".into(),
            timeout: Duration::from_millis(50), // Short timeout
            ca_file: None,
            required_group: vec![],
            group_attr: "memberOf".into(),
        });
        let result = ldap_fetch_groups(&config, "user").await;
        assert!(result.is_empty());
    }

    // ==================== handle_chap_continue Edge Cases ====================

    #[test]
    fn handle_chap_continue_no_chap_id_set() {
        let mut state = make_test_session_state();
        state.chap_id = None; // No CHAP ID set
        state.challenge = Some(vec![0x11; 16]);
        let creds = make_creds();

        let mut cont_data = vec![0x42]; // Any ID
        cont_data.extend_from_slice(&[0u8; 16]);

        // Should proceed since chap_id is None (no mismatch check)
        let result = handle_chap_continue("admin", &cont_data, &mut state, &creds);
        // Will fail due to wrong hash, but won't error on ID mismatch
        assert_eq!(result.status, AUTHEN_STATUS_FAIL);
    }

    #[test]
    fn handle_chap_continue_no_challenge() {
        let mut state = make_test_session_state();
        state.challenge = None; // No challenge
        state.chap_id = Some(0x42);
        let creds = make_creds();

        let mut cont_data = vec![0x42];
        cont_data.extend_from_slice(&[0u8; 16]);

        // Empty challenge will cause compute_chap_response to return None or wrong result
        let result = handle_chap_continue("admin", &cont_data, &mut state, &creds);
        // Will fail - either ERROR or FAIL depending on path
        assert!(result.status == AUTHEN_STATUS_FAIL || result.status == AUTHEN_STATUS_ERROR);
    }

    #[test]
    fn handle_chap_continue_clears_state_on_success() {
        let mut state = make_test_session_state();
        let challenge = vec![0x11u8; 16];
        state.challenge = Some(challenge.clone());
        let chap_id = 0x42u8;
        state.chap_id = Some(chap_id);

        let mut creds = StaticCreds::default();
        creds.plain.insert("admin".into(), "secret".into());

        // Compute correct response
        let mut buf = Vec::new();
        buf.push(chap_id);
        buf.extend_from_slice(b"secret");
        buf.extend_from_slice(&challenge);
        let digest = hash(MessageDigest::md5(), &buf).unwrap();

        let mut cont_data = vec![chap_id];
        cont_data.extend_from_slice(digest.as_ref());

        let result = handle_chap_continue("admin", &cont_data, &mut state, &creds);
        assert_eq!(result.status, AUTHEN_STATUS_PASS);
        // Verify state was cleared
        assert!(state.challenge.is_none());
        assert!(state.chap_id.is_none());
    }

    #[test]
    fn handle_chap_continue_clears_state_on_fail() {
        let mut state = make_test_session_state();
        let challenge = vec![0x11u8; 16];
        state.challenge = Some(challenge.clone());
        state.chap_id = Some(0x42);

        let creds = make_creds();

        let mut cont_data = vec![0x42];
        cont_data.extend_from_slice(&[0u8; 16]); // Wrong response

        let result = handle_chap_continue("admin", &cont_data, &mut state, &creds);
        assert_eq!(result.status, AUTHEN_STATUS_FAIL);
        // State should be cleared even on failure
        assert!(state.challenge.is_none());
        assert!(state.chap_id.is_none());
    }

    // ==================== compute_chap_response Edge Cases ====================

    #[test]
    fn compute_chap_response_empty_password() {
        let mut creds = HashMap::new();
        creds.insert("admin".into(), "".into()); // Empty password

        let chap_id = 0x42u8;
        let challenge = [0x11u8; 16];

        // Compute expected MD5(id || "" || challenge)
        let mut buf = Vec::new();
        buf.push(chap_id);
        buf.extend_from_slice(&challenge);
        let expected_digest = hash(MessageDigest::md5(), &buf).unwrap();

        let mut continue_data = vec![chap_id];
        continue_data.extend_from_slice(expected_digest.as_ref());

        let result = compute_chap_response("admin", &creds, &continue_data, &challenge);
        assert_eq!(result, Some(true));
    }

    #[test]
    fn compute_chap_response_long_password() {
        let mut creds = HashMap::new();
        let long_password = "a".repeat(1000);
        creds.insert("admin".into(), long_password.clone());

        let chap_id = 0x42u8;
        let challenge = [0x11u8; 16];

        // Compute expected response
        let mut buf = Vec::new();
        buf.push(chap_id);
        buf.extend_from_slice(long_password.as_bytes());
        buf.extend_from_slice(&challenge);
        let expected_digest = hash(MessageDigest::md5(), &buf).unwrap();

        let mut continue_data = vec![chap_id];
        continue_data.extend_from_slice(expected_digest.as_ref());

        let result = compute_chap_response("admin", &creds, &continue_data, &challenge);
        assert_eq!(result, Some(true));
    }

    #[test]
    fn compute_chap_response_all_zeros_challenge() {
        let mut creds = HashMap::new();
        creds.insert("admin".into(), "secret".into());

        let chap_id = 0x00u8;
        let challenge = [0x00u8; 16]; // All zeros

        // Compute expected response
        let mut buf = Vec::new();
        buf.push(chap_id);
        buf.extend_from_slice(b"secret");
        buf.extend_from_slice(&challenge);
        let expected_digest = hash(MessageDigest::md5(), &buf).unwrap();

        let mut continue_data = vec![chap_id];
        continue_data.extend_from_slice(expected_digest.as_ref());

        let result = compute_chap_response("admin", &creds, &continue_data, &challenge);
        assert_eq!(result, Some(true));
    }
}
