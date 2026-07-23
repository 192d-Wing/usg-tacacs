// SPDX-License-Identifier: Apache-2.0
//! TACACS+ server connection handling and session management.
//!
//! # NIST SP 800-53 Rev. 5 Security Controls
//!
//! **Control Implementation Matrix**
//!
//! This module implements controls documented in
//! [../../../docs/NIST-CONTROLS-MAPPING.md](../../../docs/NIST-CONTROLS-MAPPING.md).
//!
//! | Control | Family | Status | Validated | Primary Functions |
//! |---------|--------|--------|-----------|-------------------|
//! | AC-10 | Access Control | Implemented | 2026-01-31 | See functions below |
//! | AC-11 | Access Control | Implemented | 2026-01-31 | See functions below |
//! | AC-12 | Access Control | Implemented | 2026-01-31 | See functions below |
//! | AC-3 | Access Control | Implemented | 2026-01-31 | See functions below |
//! | AC-6 | Access Control | Implemented | 2026-01-31 | See functions below |
//! | AC-7 | Access Control | Implemented | 2026-01-31 | See functions below |
//! | AU-12 | Audit and Accountability | Implemented | 2026-01-31 | See functions below |
//! | AU-2 | Audit and Accountability | Implemented | 2026-01-31 | See functions below |
//! | AU-3 | Audit and Accountability | Implemented | 2026-01-31 | See functions below |
//! | CM-3 | Configuration Management | Implemented | 2026-01-31 | See functions below |
//! | IA-11 | Identification and Authentication | Implemented | 2026-01-31 | See functions below |
//! | IA-2 | Identification and Authentication | Implemented | 2026-01-31 | See functions below |
//! | IA-3 | Identification and Authentication | Implemented | 2026-01-31 | See functions below |
//! | IA-4 | Identification and Authentication | Implemented | 2026-01-31 | See functions below |
//! | IA-5 | Identification and Authentication | Implemented | 2026-01-31 | See functions below |
//! | SC-17 | System and Communications Protection | Implemented | 2026-01-31 | See functions below |
//! | SC-23 | System and Communications Protection | Implemented | 2026-01-31 | See functions below |
//! | SC-7 | System and Communications Protection | Implemented | 2026-01-31 | See functions below |
//! | SC-8 | System and Communications Protection | Implemented | 2026-01-31 | See functions below |
//!
//! <details>
//! <summary><b>Validation Metadata (JSON)</b></summary>
//!
//! ```json
//! {
//!   "nist_framework": "NIST SP 800-53 Rev. 5",
//!   "software_version": "0.77.1",
//!   "last_validation": "2026-01-31",
//!   "control_families": [
//!     "AC",
//!     "AU",
//!     "CM",
//!     "IA",
//!     "SC"
//!   ],
//!   "total_controls": 19,
//!   "file_path": "crates/tacacs-server/src/server.rs"
//! }
//! ```
//!
//! </details>
//!
//! # NIST SP 800-53 Security Controls
//!
//! This module implements the following NIST security controls:
//!
//! - **AC-10 (Concurrent Session Control)**: Per-IP connection limiting via
//!   `ConnLimiter` with configurable maximum concurrent connections.
//!
//! - **AC-11/AC-12 (Session Lock/Termination)**: Idle timeout and keepalive
//!   timeout enforcement for session termination.
//!
//! - **SC-7 (Boundary Protection)**: Connection acceptance control, IP-based
//!   rate limiting, and network isolation support.
//!
//! - **SC-23 (Session Authenticity)**: Session ID validation and sequence
//!   number tracking per RFC 8907.
//!
//! - **IA-3 (Device Identification)**: Client certificate CN/SAN allowlist
//!   enforcement via `enforce_client_cert_policy()`.
//!
//! - **AU-2/AU-12 (Audit Events)**: Connection events, authentication attempts,
//!   and authorization decisions are logged via tracing.

use crate::ascii::{
    AsciiConfig, calc_ascii_backoff_capped, field_for_policy, handle_ascii_continue_jit,
    username_for_policy,
};
use crate::auth::{
    LdapConfig, handle_chap_continue, ldap_fetch_groups, verify_pap, verify_pap_bytes,
    verify_pap_bytes_username, verify_password_sources,
};
use crate::config::StaticCreds;
use crate::icam::{IcamAuthResult, IcamConfig, icam_authenticate};
use crate::icam_device::{DeviceFlowConfig, icam_device_auth_start, icam_device_format_prompt};
use crate::jit_lease::NadIdentity;
use crate::jit_lease_store::{JitLeaseStore, JitNadAuthenticator};
use crate::policy::enforce_server_msg;
use crate::session::{SingleConnectState, TaskIdTracker};
use crate::session_registry::SessionRegistry;
use crate::tls::build_tls_config;
use anyhow::{Context, Result};
use hmac::{Hmac, KeyInit, Mac};
use openssl::nid::Nid;
use openssl::rand::rand_bytes;
use openssl::x509::X509;
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{Mutex, RwLock};
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tracing::{debug, info, warn};
use usg_tacacs_policy::{PolicyEngine, validate_policy_file};
use usg_tacacs_proto::{
    ACCT_FLAG_START, ACCT_FLAG_STOP, ACCT_FLAG_WATCHDOG, ACCT_STATUS_ERROR, ACCT_STATUS_SUCCESS,
    AUTHEN_FLAG_NOECHO, AUTHEN_STATUS_ERROR, AUTHEN_STATUS_FAIL, AUTHEN_STATUS_FOLLOW,
    AUTHEN_STATUS_GETDATA, AUTHEN_STATUS_GETPASS, AUTHEN_STATUS_GETUSER, AUTHEN_STATUS_PASS,
    AUTHEN_STATUS_RESTART, AUTHEN_TYPE_ASCII, AUTHEN_TYPE_CHAP, AUTHEN_TYPE_PAP,
    AUTHOR_STATUS_ERROR, AUTHOR_STATUS_FAIL, AUTHOR_STATUS_PASS_ADD, AccountingRequest,
    AccountingResponse, AuthSessionState, AuthenContinue, AuthenData, AuthenPacket, AuthenReply,
    AuthenStart, AuthorizationRequest, AuthorizationResponse, CAPABILITY_FLAG_REQUEST,
    CAPABILITY_FLAG_RESPONSE, Capability, Packet, read_packet, validate_accounting_response_header,
    validate_author_response_header, write_accounting_response, write_authen_reply,
    write_author_response,
};

/// Normalize IPv4-mapped IPv6 addresses to their IPv4 equivalent.
///
/// This prevents bypass of per-IP limits by connecting via both
/// `127.0.0.1` and `::ffff:127.0.0.1`.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | SC-7 | Boundary Protection | Prevents rate-limit bypass via IPv4-mapped IPv6 |
pub(crate) fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        other => other,
    }
}

#[cfg(test)]
mod jit_nad_identity_tests {
    use super::*;

    #[test]
    fn selects_exact_managed_certificate_identity() {
        let names = vec![
            "unmanaged.example.mil".to_owned(),
            "router-01.example.mil".to_owned(),
        ];
        let managed = HashSet::from(["router-01.example.mil".to_owned()]);
        let selected = select_managed_nad_identity(&names, &managed)
            .expect("valid managed identity")
            .expect("matching identity");
        assert_eq!(selected.as_str(), "router-01.example.mil");
    }

    #[test]
    fn does_not_enable_jit_for_unmanaged_certificate() {
        let names = vec!["router-02.example.mil".to_owned()];
        let managed = HashSet::from(["router-01.example.mil".to_owned()]);
        let selected = select_managed_nad_identity(&names, &managed).expect("valid identity set");
        assert!(selected.is_none());
    }

    #[test]
    fn rejects_certificate_with_multiple_managed_identities() {
        let names = vec![
            "router-01.example.mil".to_owned(),
            "router-02.example.mil".to_owned(),
        ];
        let managed = HashSet::from([
            "router-01.example.mil".to_owned(),
            "router-02.example.mil".to_owned(),
        ]);
        assert!(select_managed_nad_identity(&names, &managed).is_err());
    }
}

/// Per-IP connection rate limiter.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-10 | Concurrent Session Control | Limits concurrent connections per IP |
/// | SC-7 | Boundary Protection | Prevents connection exhaustion attacks |
#[derive(Clone)]
pub(crate) struct ConnLimiter {
    max_per_ip: u32,
    counts: Arc<Mutex<HashMap<IpAddr, u32>>>,
}

impl ConnLimiter {
    pub(crate) fn new(max_per_ip: u32) -> Self {
        Self {
            max_per_ip,
            counts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Attempt to acquire a connection slot for the given IP.
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | AC-10 | Concurrent Session Control | Enforces maximum concurrent connections per IP |
    async fn try_acquire(&self, ip: IpAddr) -> Option<ConnGuard> {
        let normalized = normalize_ip(ip);
        if self.max_per_ip == 0 {
            return Some(ConnGuard {
                ip: normalized,
                limiter: self.clone(),
            });
        }
        let mut map = self.counts.lock().await;
        let entry = map.entry(normalized).or_insert(0);
        // NIST AC-10: Reject if connection limit exceeded
        if *entry >= self.max_per_ip {
            return None;
        }
        *entry += 1;
        drop(map);
        Some(ConnGuard {
            ip: normalized,
            limiter: self.clone(),
        })
    }

    async fn release(&self, ip: IpAddr) {
        let mut map = self.counts.lock().await;
        if let Some(v) = map.get_mut(&ip)
            && *v > 0
        {
            *v -= 1;
        }
    }
}

/// Connection state container for packet processing.
///
/// Encapsulates mutable state that is shared across the packet processing loop
/// within a single connection. This allows extracted handler functions to have
/// clean signatures while maintaining access to necessary state.
#[allow(dead_code)]
struct ConnectionContext<'a, S> {
    stream: &'a mut S,
    auth_states: &'a mut HashMap<u32, AuthSessionState>,
    single_connect: &'a mut SingleConnectState,
    task_tracker: &'a mut TaskIdTracker,
    peer: &'a str,
    peer_addr: SocketAddr,
    connection_id: u64,
}

/// Loop control flow result for packet processing.
///
/// Used by packet handlers to signal whether the connection loop should
/// continue processing packets or break (close the connection).
enum LoopControl {
    /// Continue processing packets
    Continue,
    /// Break the loop and close the connection
    Break,
}

struct ConnGuard {
    ip: IpAddr,
    limiter: ConnLimiter,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let ip = self.ip;
        let limiter = self.limiter.clone();
        tokio::spawn(async move {
            limiter.release(ip).await;
        });
    }
}

/// Configuration for connection-level settings.
///
/// Groups connection timeout, rate limiting, and ASCII authentication settings.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-7 | Unsuccessful Logon Attempts | Contains ASCII authentication limits |
/// | AC-10 | Concurrent Session Control | Contains connection rate limiter |
/// | AC-11/AC-12 | Session Lock/Termination | Contains idle/keepalive timeouts |
/// | SC-5 | Denial of Service Protection | Per-packet read timeout prevents slowloris |
#[derive(Clone)]
pub(crate) struct ConnectionConfig {
    /// Idle timeout for single-connect sessions (seconds)
    pub single_connect_idle_secs: u64,
    /// Keepalive timeout for single-connect sessions (seconds)
    pub single_connect_keepalive_secs: u64,
    /// Per-IP connection rate limiter
    pub conn_limiter: ConnLimiter,
    /// ASCII authentication configuration
    pub ascii: AsciiConfig,
    /// Per-packet read timeout in seconds (0 = disabled). NIST SC-5.
    pub packet_read_timeout_secs: u64,
}

/// Shared authentication context containing policy, credentials, and secrets.
///
/// Groups all authentication-related shared state.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-3 | Access Enforcement | Contains policy engine for authorization |
/// | IA-2 | Identification and Authentication | Contains credentials and LDAP config |
/// | SC-8 | Transmission Confidentiality | Contains shared secret for obfuscation |
#[derive(Clone)]
pub(crate) struct AuthContext {
    /// Policy engine for authorization decisions
    pub policy: Arc<RwLock<PolicyEngine>>,
    /// Shared secret for TACACS+ body obfuscation (legacy)
    pub secret: Option<Arc<Vec<u8>>>,
    /// Static credentials for PAP/CHAP authentication
    pub credentials: Arc<StaticCreds>,
    /// LDAP configuration for external authentication
    pub ldap: Option<Arc<LdapConfig>>,
    /// ICAM/OIDC configuration; when set, PAP and ASCII auth delegate to ICAM
    /// instead of checking local or LDAP credentials (IA-2, IA-8).
    pub icam: Option<Arc<IcamConfig>>,
    /// RFC 8628 Device Authorization Grant; when set, ASCII auth presents a
    /// browser URL instead of collecting credentials inline (IA-2, IA-8).
    pub device_flow: Option<Arc<DeviceFlowConfig>>,
    /// Per-username cross-IP authentication rate limiter (AC-7).
    pub username_limiter: Arc<crate::username_limiter::UsernameRateLimiter>,
    /// Per-source-IP failed-auth rate limiter (AC-7/SC-5); throttles spray
    /// across distinct usernames from one source.
    pub ip_limiter: Arc<crate::ip_limiter::IpRateLimiter>,
    /// HMAC-SHA256 key for audit event signing; `None` disables signing (AU-9).
    pub audit_hmac_key: Option<Arc<Vec<u8>>>,
    /// Authoritative JIT lease store, enabled only for explicitly managed NADs.
    pub jit_lease_store: Option<Arc<JitLeaseStore>>,
    /// Certificate identities that must use JIT authentication exclusively.
    pub jit_managed_nads: Arc<HashSet<String>>,
    /// Trusted NAD identity selected from the authenticated client certificate.
    pub jit_nad_identity: Option<NadIdentity>,
}

/// TLS-specific configuration for client certificate validation.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | IA-3 | Device Identification | Client certificate CN/SAN allowlists |
/// | SC-23 | Session Authenticity | Ensures only authorized devices connect |
#[derive(Clone, Default)]
pub(crate) struct TlsIdentityConfig {
    /// Allowed Common Names for client certificates
    pub allowed_cn: Vec<String>,
    /// Allowed Subject Alternative Names for client certificates
    pub allowed_san: Vec<String>,
}

/// Extract X509 certificate from TLS stream.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | IA-3 | Device Identification and Authentication | Extract client certificate for validation |
fn extract_cert_from_tls_stream(
    stream: &TlsStream<tokio::net::TcpStream>,
    peer: &SocketAddr,
) -> Result<X509> {
    let (_, conn) = stream.get_ref();
    let certs = conn
        .peer_certificates()
        .ok_or_else(|| anyhow::anyhow!("missing client certificate"))?;
    let leaf = certs
        .first()
        .ok_or_else(|| anyhow::anyhow!("no client certificate presented"))?;
    X509::from_der(leaf.as_ref()).with_context(|| format!("parsing client certificate from {peer}"))
}

/// Extract Common Names and Subject Alternative Names from certificate.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | IA-4 | Identifier Management | Extract certificate-based device identities |
fn extract_cert_names(x509: &X509) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();

    // Extract Common Name entries
    for entry in x509.subject_name().entries_by_nid(Nid::COMMONNAME) {
        if let Ok(val) = entry.data().as_utf8() {
            names.push(val.to_string());
        }
    }

    // Extract Subject Alternative Name entries
    if let Some(san) = x509.subject_alt_names() {
        for name in san {
            if let Some(dns) = name.dnsname() {
                names.push(dns.to_string());
            }
            if let Some(uri) = name.uri() {
                names.push(uri.to_string());
            }
            if let Some(ip) = name.ipaddress() {
                // Use try_from for safe conversion without panic
                match ip.len() {
                    4 => {
                        if let Ok(oct) = <[u8; 4]>::try_from(ip) {
                            names.push(std::net::Ipv4Addr::from(oct).to_string());
                        }
                    }
                    16 => {
                        if let Ok(oct) = <[u8; 16]>::try_from(ip) {
                            names.push(std::net::Ipv6Addr::from(oct).to_string());
                        }
                    }
                    _ => {
                        // Invalid IP address length, skip
                        tracing::warn!(
                            len = ip.len(),
                            "invalid IP address length in certificate SAN"
                        );
                    }
                }
            }
        }
    }

    names
}

/// Check if any certificate name matches allowlists.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | SC-23 | Session Authenticity | Enforce only authorized devices can connect |
fn check_cert_names_allowed(
    names: &[String],
    allowed_cn: &[String],
    allowed_san: &[String],
) -> Result<()> {
    let allowed = names
        .iter()
        .any(|n| allowed_cn.iter().any(|a| a == n) || allowed_san.iter().any(|a| a == n));

    if allowed {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "client certificate identity not allowed: {:?}",
            names
        ))
    }
}

/// Enforce client certificate identity policy (CN/SAN allowlists).
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | IA-3 | Device Identification and Authentication | Validates client certificate CN/SAN against allowlists |
/// | IA-4 | Identifier Management | Certificate-based device identity |
/// | SC-23 | Session Authenticity | Ensures only authorized devices connect |
fn enforce_client_cert_policy(
    stream: &TlsStream<tokio::net::TcpStream>,
    peer: &SocketAddr,
    allowed_cn: &[String],
    allowed_san: &[String],
) -> Result<Vec<String>> {
    let x509 = extract_cert_from_tls_stream(stream, peer)?;
    let names = extract_cert_names(&x509);
    if !allowed_cn.is_empty() || !allowed_san.is_empty() {
        check_cert_names_allowed(&names, allowed_cn, allowed_san)?;
    }
    Ok(names)
}

fn auth_ctx_with_nad_identity(base: AuthContext, cert_names: &[String]) -> Result<AuthContext> {
    let jit_nad_identity = select_managed_nad_identity(cert_names, &base.jit_managed_nads)?;
    Ok(AuthContext {
        jit_nad_identity,
        ..base
    })
}

fn select_managed_nad_identity(
    cert_names: &[String],
    managed_nads: &HashSet<String>,
) -> Result<Option<NadIdentity>> {
    let mut matches = cert_names
        .iter()
        .filter(|name| managed_nads.contains(name.as_str()))
        .collect::<HashSet<_>>();
    if matches.len() > 1 {
        return Err(anyhow::anyhow!(
            "client certificate matches multiple managed NAD identities"
        ));
    }
    matches
        .drain()
        .next()
        .map(|name| NadIdentity::parse(name))
        .transpose()
        .map_err(|error| anyhow::anyhow!(error))
}

/// Process-global HMAC key set once at startup; `None` = signing disabled.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AU-9 | Protection of Audit Information | Global key for log integrity signing |
static AUDIT_HMAC_KEY: OnceLock<Option<Vec<u8>>> = OnceLock::new();

/// Initialize the audit HMAC key from `AuthContext`.  Must be called once
/// before the first audit event is emitted.
pub(crate) fn init_audit_hmac(key: Option<&Arc<Vec<u8>>>) {
    let _ = AUDIT_HMAC_KEY.set(key.map(|k| k.as_ref().clone()));
}

/// Compute HMAC-SHA256 over the canonical audit event fields.
///
/// The input is `event|peer|user|session|status|reason|data` — pipe-delimited
/// so field boundaries are unambiguous.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AU-9 | Protection of Audit Information | HMAC-SHA256 detects log tampering |
/// | SC-13 | Cryptographic Protection | FIPS 198-1 compliant HMAC-SHA256 |
/// Build the canonical, pipe-delimited field string that the audit HMAC is
/// computed over. Every logged field (including `identity_source`) is included
/// so the signature covers the whole record; pipe delimiters keep field
/// boundaries unambiguous. Keep this in lock-step with the fields emitted by
/// [`emit_audit_event`].
#[allow(clippy::too_many_arguments)]
fn audit_canonical_fields(
    event: &str,
    peer: &str,
    user: &str,
    session: u32,
    status: &str,
    reason: &str,
    data: &str,
    identity_source: &str,
) -> String {
    format!("{event}|{peer}|{user}|{session}|{status}|{reason}|{data}|{identity_source}")
}

fn compute_audit_hmac(key: &[u8], fields: &str) -> String {
    assert!(!key.is_empty(), "HMAC key must not be empty");
    assert!(!fields.is_empty(), "audit fields must not be empty");
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(fields.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub(crate) fn audit_event(
    event: &str,
    peer: &str,
    user: &str,
    session: u32,
    status: &str,
    reason: &str,
    data: &str,
) {
    // Most events carry no identity source; delegate to the full emitter so
    // every `tacacs_audit` record flows through one signing path (AU-9).
    emit_audit_event(event, peer, user, session, status, reason, data, "");
}

/// Emit a signed `tacacs_audit` event. This is the single emission point for
/// audit records: all callers (including authentication-terminal events that
/// carry an `identity_source`) MUST route through here so the HMAC covers
/// every logged field. Adding a raw `info!` to the audit tracing target
/// elsewhere would produce an unsigned, forgeable record (AU-9).
///
/// `identity_source` is the empty string for events without one; it is always
/// included in both the canonical HMAC input and the emitted record so the
/// signature covers it.
#[allow(clippy::too_many_arguments)]
fn emit_audit_event(
    event: &str,
    peer: &str,
    user: &str,
    session: u32,
    status: &str,
    reason: &str,
    data: &str,
    identity_source: &str,
) {
    assert!(!event.is_empty(), "audit event name must not be empty");
    assert!(!status.is_empty(), "audit status must not be empty");
    let hmac_tag = AUDIT_HMAC_KEY.get().and_then(|k| k.as_deref()).map(|key| {
        let fields = audit_canonical_fields(
            event,
            peer,
            user,
            session,
            status,
            reason,
            data,
            identity_source,
        );
        compute_audit_hmac(key, &fields)
    });
    if let Some(ref tag) = hmac_tag {
        info!(
            target: "tacacs_audit",
            event,
            peer = %peer,
            user = %user,
            session = session,
            status = %status,
            reason = %reason,
            data = %data,
            identity_source = %identity_source,
            hmac = %tag,
            "audit event"
        );
    } else {
        info!(
            target: "tacacs_audit",
            event,
            peer = %peer,
            user = %user,
            session = session,
            status = %status,
            reason = %reason,
            data = %data,
            identity_source = %identity_source,
            "audit event"
        );
    }
}

fn authz_reason_response(
    status: u8,
    server_msg: impl Into<String>,
    reason: &'static str,
    detail: Option<String>,
) -> AuthorizationResponse {
    let mut data = format!("reason={reason}");
    if let Some(extra) = detail
        && !extra.is_empty()
    {
        data.push(';');
        data.push_str("detail=");
        data.push_str(&extra);
    }
    AuthorizationResponse {
        status,
        server_msg: server_msg.into(),
        data,
        args: Vec::new(),
    }
}

fn authz_context(req: &AuthorizationRequest) -> String {
    let attrs = req.attributes();
    let service = attrs
        .iter()
        .find(|a| a.name.eq_ignore_ascii_case("service"))
        .and_then(|a| a.value.as_deref())
        .unwrap_or("-");
    let protocol = attrs
        .iter()
        .find(|a| a.name.eq_ignore_ascii_case("protocol"))
        .and_then(|a| a.value.as_deref())
        .unwrap_or("-");
    let cmd = req.command_string().unwrap_or_else(|| "-".to_string());
    let args = req.args.len();
    format!("service={service};protocol={protocol};cmd={cmd};args={args}")
}

fn ensure_priv_attr(mut args: Vec<String>, priv_lvl: u8) -> Vec<String> {
    if !args
        .iter()
        .any(|a| a.to_lowercase().starts_with("priv-lvl="))
    {
        args.insert(0, format!("priv-lvl={priv_lvl}"));
    }
    args
}

fn authz_server_msg_with_detail(code: &str, msg: &str, detail: &str) -> String {
    if detail.is_empty() {
        format!("{code}: {msg}")
    } else {
        format!("{code}: {msg} ({detail})")
    }
}

fn acct_attr<'a>(args: &'a [String], name: &str) -> &'a str {
    let prefix = format!("{name}=");
    args.iter()
        .find_map(|a| {
            if a.to_lowercase().starts_with(&prefix) {
                a.split_once('=').map(|(_, v)| v)
            } else {
                None
            }
        })
        .unwrap_or("-")
}

fn accounting_success_response(req: &AccountingRequest) -> AccountingResponse {
    let acct_type = if req.flags & ACCT_FLAG_START != 0 {
        "start"
    } else if req.flags & ACCT_FLAG_STOP != 0 {
        "stop"
    } else if req.flags & ACCT_FLAG_WATCHDOG != 0 {
        "watchdog"
    } else {
        "unknown"
    };
    let server_msg = format!("accounting {acct_type} accepted");
    let data = format!(
        "type={acct_type};service={};cmd={};task_id={};status={};bytes_in={};bytes_out={}",
        acct_attr(&req.args, "service"),
        acct_attr(&req.args, "cmd"),
        acct_attr(&req.args, "task_id"),
        acct_attr(&req.args, "status"),
        acct_attr(&req.args, "bytes_in"),
        acct_attr(&req.args, "bytes_out")
    );
    AccountingResponse {
        status: ACCT_STATUS_SUCCESS,
        server_msg,
        data,
        args: Vec::new(),
    }
}

fn authz_semantic_detail(err: &AuthzSemanticError) -> (&'static str, String) {
    let msg = err.msg;
    let mut detail = msg.to_string();
    if let Some(idx) = err.offending_index {
        detail.push_str(&format!(";index={idx}"));
    }
    let code = match msg {
        "authorization must include exactly one service attribute" => "service-missing",
        "authorization service attribute must have a value" => "service-empty",
        "shell authorization requires protocol attribute" => "shell-protocol-missing",
        "shell authorization must not include cmd/cmd-arg attributes" => "shell-cmd-invalid",
        "authorization must include at most one protocol attribute" => "protocol-count",
        "authorization must include exactly one cmd attribute" => "cmd-missing",
        "cmd attribute must have a value" => "cmd-empty",
        "cmd-arg attributes must have values" => "cmd-arg-empty",
        "service attribute must precede command attributes" => "service-order",
        "service attribute must precede protocol attributes" => "service-order",
        "authorization service attribute value unknown" => "service-unknown",
        "authorization must include exactly one cmd attribute for non-shell services" => {
            "cmd-missing"
        }
        "authorization protocol attribute must have a value" => "protocol-empty",
        "authorization protocol attribute value unknown" => "protocol-unknown",
        "priv-lvl must be numeric" => "priv-nan",
        "priv-lvl must be 0-15" => "priv-range",
        "priv-lvl attribute must match header priv_lvl" => "priv-mismatch",
        _ => "semantic-invalid",
    };
    (code, detail)
}

/// Check if accounting request has required service or command attributes.
fn check_service_or_cmd_attrs(req: &AccountingRequest) -> bool {
    let attrs = req.attributes();
    attrs.iter().any(|a| {
        let name = a.name.as_str();
        name.eq_ignore_ascii_case("service")
            || name.eq_ignore_ascii_case("cmd")
            || name.eq_ignore_ascii_case("cmd-arg")
    })
}

/// Validate required attributes for accounting record types.
fn validate_acct_required_attrs(
    is_start: bool,
    is_stop: bool,
    is_watchdog: bool,
    req: &AccountingRequest,
) -> Result<(), &'static str> {
    // Only task_id is required (start/stop correlation key). elapsed_time,
    // status, bytes_in, bytes_out etc. are OPTIONAL per RFC 8907 §8.3; Cisco
    // command accounting (`aaa accounting commands`) STOP records carry none of
    // them, so mandating them wrongly rejects legitimate command accounting.
    // Mirrors usg_tacacs_proto::validate_accounting_request; keep both in sync.
    let attrs = req.attributes();
    let has_task = attrs.iter().any(|a| a.name.eq_ignore_ascii_case("task_id"));

    if is_start && !has_task {
        return Err("start accounting requires task_id attribute");
    }
    if is_stop && !has_task {
        return Err("stop accounting requires task_id attribute");
    }
    if is_watchdog && !has_task {
        return Err("watchdog accounting requires task_id attribute");
    }
    Ok(())
}

/// Validate numeric accounting attributes and status code ranges.
fn validate_acct_numeric_attrs(is_stop: bool, req: &AccountingRequest) -> Result<(), &'static str> {
    let attrs = req.attributes();
    let parse_u32 = |key: &str| -> Result<Option<u32>, &'static str> {
        if let Some(attr) = attrs.iter().find(|a| a.name.eq_ignore_ascii_case(key)) {
            let val = attr.value.as_deref().unwrap_or("");
            if key.eq_ignore_ascii_case("status") && val.eq_ignore_ascii_case("follow") {
                return Err("accounting FOLLOW status deprecated and rejected");
            }
            let parsed: u32 = val
                .parse()
                .map_err(|_| "accounting attributes must be numeric where required")?;
            return Ok(Some(parsed));
        }
        Ok(None)
    };

    // Validate required numeric fields
    parse_u32("task_id")?;
    parse_u32("elapsed_time")?;

    if let Some(code) = parse_u32("status")? {
        if code > 0x0f {
            return Err("accounting status code must be 0-15");
        }
        // RFC Appendix B: 0=success, 1-15 error/other; treat >=1 as non-success.
        if code >= 1 && !is_stop {
            return Err("non-success accounting status is only valid on stop records");
        }
    }

    // Optional traffic/elapsed attrs: ensure numeric if present.
    for key in ["bytes_in", "bytes_out", "elapsed_seconds"].iter() {
        parse_u32(key)?;
    }
    Ok(())
}

fn validate_accounting_semantics(req: &AccountingRequest) -> Result<(), &'static str> {
    let is_start = req.flags & ACCT_FLAG_START != 0;
    let is_stop = req.flags & ACCT_FLAG_STOP != 0;
    let is_watchdog = req.flags & ACCT_FLAG_WATCHDOG != 0;

    // RFC expects one of the flags; parse already enforced exclusivity.
    if (is_start || is_stop || is_watchdog) && req.args.is_empty() {
        return Err("accounting records require attributes");
    }

    if !check_service_or_cmd_attrs(req) {
        return Err("accounting requires service or command attributes");
    }

    validate_acct_required_attrs(is_start, is_stop, is_watchdog, req)?;
    validate_acct_numeric_attrs(is_stop, req)?;

    Ok(())
}

struct AuthzSemanticError {
    msg: &'static str,
    offending_index: Option<usize>,
}

/// Validate that exactly one service attribute exists with a known value.
///
/// # NIST SP 800-53 Controls
///
/// | Control | Implementation |
/// |---------|----------------|
/// | AC-3 | Service-based access control validation |
fn validate_service_attribute(
    req: &AuthorizationRequest,
    extra_services: &[String],
) -> Result<String, AuthzSemanticError> {
    let attrs = req.attributes();
    let service_attrs: Vec<_> = attrs
        .iter()
        .filter(|a| a.name.eq_ignore_ascii_case("service"))
        .collect();
    if service_attrs.len() != 1 {
        return Err(AuthzSemanticError {
            msg: "authorization must include exactly one service attribute",
            offending_index: None,
        });
    }
    let service_val = service_attrs[0].value.as_deref().unwrap_or("");
    if service_val.is_empty() {
        return Err(AuthzSemanticError {
            msg: "authorization service attribute must have a value",
            offending_index: None,
        });
    }
    let known = usg_tacacs_proto::header::is_known_service(service_val)
        || extra_services
            .iter()
            .any(|s| s.eq_ignore_ascii_case(service_val));
    if !known {
        return Err(AuthzSemanticError {
            msg: "authorization service attribute value unknown",
            offending_index: None,
        });
    }
    Ok(service_val.to_string())
}

/// Semantic validation for a configured vendor (non-RFC) service such as
/// `service=PaloAlto`. This is an attribute request: no `cmd` is required and
/// the vendor `protocol` value is not constrained to the RFC enumeration. A
/// duplicated or empty-valued `protocol` is still rejected.
///
/// # NIST SP 800-53 Controls
///
/// | Control | Implementation |
/// |---------|----------------|
/// | AC-3 | Vendor service-specific validation |
fn validate_vendor_service(req: &AuthorizationRequest) -> Result<(), AuthzSemanticError> {
    let attrs = req.attributes();
    let protocol_attrs: Vec<_> = attrs
        .iter()
        .filter(|a| a.name.eq_ignore_ascii_case("protocol"))
        .collect();
    if protocol_attrs.len() > 1 {
        return Err(AuthzSemanticError {
            msg: "authorization must include at most one protocol attribute",
            offending_index: None,
        });
    }
    if let Some(proto) = protocol_attrs.first()
        && proto.value.as_deref().unwrap_or("").is_empty()
    {
        return Err(AuthzSemanticError {
            msg: "authorization protocol attribute must have a value",
            offending_index: None,
        });
    }
    Ok(())
}

/// Validate shell (service=shell) authorization requirements.
///
/// Covers both flavors a NAS sends with `service=shell` (RFC 8907 §8, Cisco):
///   - Exec / shell-start authorization: `cmd` absent or empty (`cmd=`). Returns
///     session attributes such as priv-lvl. A `cmd-arg` without a command is
///     invalid.
///   - Command authorization: `cmd=<value>` with optional `cmd-arg`s, each of
///     which must carry a value.
///
/// The `protocol` attribute is optional and `cmd` is permitted (unlike the prior
/// implementation, which required protocol and forbade cmd — incompatible with
/// real NAS exec/command authorization).
///
/// # NIST SP 800-53 Controls
///
/// | Control | Implementation |
/// |---------|----------------|
/// | AC-3 | Shell service-specific validation |
fn validate_shell_service(req: &AuthorizationRequest) -> Result<(), AuthzSemanticError> {
    let attrs = req.attributes();
    let cmd_attrs: Vec<_> = attrs
        .iter()
        .filter(|a| a.name.eq_ignore_ascii_case("cmd"))
        .collect();
    let cmd_arg_attrs: Vec<_> = attrs
        .iter()
        .filter(|a| a.name.eq_ignore_ascii_case("cmd-arg"))
        .collect();
    if cmd_attrs.len() > 1 {
        return Err(AuthzSemanticError {
            msg: "authorization must include at most one cmd attribute",
            offending_index: None,
        });
    }
    let cmd_is_empty = cmd_attrs
        .first()
        .map(|a| a.value.as_deref().unwrap_or("").is_empty())
        .unwrap_or(true);
    if cmd_is_empty {
        // Exec / shell-start: cmd-arg without a command is meaningless.
        if !cmd_arg_attrs.is_empty() {
            return Err(AuthzSemanticError {
                msg: "shell authorization cmd-arg present without a command",
                offending_index: None,
            });
        }
    } else if cmd_arg_attrs
        .iter()
        .any(|a| a.value.as_deref().unwrap_or("").is_empty())
    {
        // Command authorization: every cmd-arg must carry a value.
        return Err(AuthzSemanticError {
            msg: "cmd-arg attributes must have values",
            offending_index: None,
        });
    }
    Ok(())
}

/// Validate protocol attribute for non-shell services.
///
/// At most one protocol attribute allowed, must have known value if present.
///
/// # NIST SP 800-53 Controls
///
/// | Control | Implementation |
/// |---------|----------------|
/// | AC-3 | Protocol-based access control validation |
fn validate_protocol_attribute(req: &AuthorizationRequest) -> Result<(), AuthzSemanticError> {
    let attrs = req.attributes();
    let protocol_attr = attrs
        .iter()
        .find(|a| a.name.eq_ignore_ascii_case("protocol"));
    let protocol_count = attrs
        .iter()
        .filter(|a| a.name.eq_ignore_ascii_case("protocol"))
        .count();
    if protocol_count > 1 {
        return Err(AuthzSemanticError {
            msg: "authorization must include at most one protocol attribute",
            offending_index: None,
        });
    }
    if let Some(proto) = protocol_attr.and_then(|p| p.value.as_deref()) {
        if proto.is_empty() {
            return Err(AuthzSemanticError {
                msg: "authorization protocol attribute must have a value",
                offending_index: None,
            });
        }
        let allowed = [
            "ip", "ipv6", "lat", "mop", "vpdn", "xremote", "pad", "shell", "ppp", "arap", "none",
        ];
        if !allowed.iter().any(|p| proto.eq_ignore_ascii_case(p)) {
            return Err(AuthzSemanticError {
                msg: "authorization protocol attribute value unknown",
                offending_index: None,
            });
        }
    }
    Ok(())
}

/// Validate cmd and cmd-arg attributes for non-shell services.
///
/// Exactly one cmd required with a value, all cmd-args must have values.
///
/// # NIST SP 800-53 Controls
///
/// | Control | Implementation |
/// |---------|----------------|
/// | AC-3 | Command-based access control validation |
fn validate_cmd_attributes(req: &AuthorizationRequest) -> Result<(), AuthzSemanticError> {
    let attrs = req.attributes();
    let cmd_attrs: Vec<_> = attrs
        .iter()
        .filter(|a| a.name.eq_ignore_ascii_case("cmd"))
        .collect();
    let cmd_arg_attrs: Vec<_> = attrs
        .iter()
        .filter(|a| a.name.eq_ignore_ascii_case("cmd-arg"))
        .collect();
    if cmd_attrs.len() != 1 {
        return Err(AuthzSemanticError {
            msg: "authorization must include exactly one cmd attribute for non-shell services",
            offending_index: None,
        });
    }
    if cmd_attrs[0].value.as_deref().unwrap_or("").is_empty() {
        return Err(AuthzSemanticError {
            msg: "cmd attribute must have a value",
            offending_index: None,
        });
    }
    if cmd_arg_attrs
        .iter()
        .any(|a| a.value.as_deref().unwrap_or("").is_empty())
    {
        return Err(AuthzSemanticError {
            msg: "cmd-arg attributes must have values",
            offending_index: None,
        });
    }
    Ok(())
}

/// Validate attribute ordering in the authorization request.
///
/// Service attribute must appear before protocol and command attributes.
///
/// # NIST SP 800-53 Controls
///
/// | Control | Implementation |
/// |---------|----------------|
/// | AC-3 | Enforce RFC 8907 attribute ordering requirements |
fn validate_attribute_ordering(req: &AuthorizationRequest) -> Result<(), AuthzSemanticError> {
    let service_pos = req
        .args
        .iter()
        .position(|a| a.to_lowercase().starts_with("service="))
        .unwrap_or(0);
    let mut protocol_positions = req
        .args
        .iter()
        .enumerate()
        .filter(|(_, a)| a.to_lowercase().starts_with("protocol="))
        .map(|(i, _)| i);
    if protocol_positions.clone().any(|i| i < service_pos) {
        let offending = protocol_positions.find(|i| *i < service_pos);
        return Err(AuthzSemanticError {
            msg: "service attribute must precede protocol attributes",
            offending_index: offending,
        });
    }
    let mut cmd_positions = req
        .args
        .iter()
        .enumerate()
        .filter(|(_, a)| a.to_lowercase().starts_with("cmd"))
        .map(|(i, _)| i);
    if cmd_positions.clone().any(|i| i < service_pos) {
        let offending = cmd_positions.find(|i| *i < service_pos);
        return Err(AuthzSemanticError {
            msg: "service attribute must precede command attributes",
            offending_index: offending,
        });
    }
    Ok(())
}

/// Validate optional priv-lvl attribute if present.
///
/// Must be numeric, in range 0-15, and match the header privilege level.
///
/// # NIST SP 800-53 Controls
///
/// | Control | Implementation |
/// |---------|----------------|
/// | AC-6 | Privilege level validation for least privilege |
fn validate_priv_lvl(req: &AuthorizationRequest) -> Result<(), AuthzSemanticError> {
    let attrs = req.attributes();
    if let Some(attr) = attrs
        .iter()
        .find(|a| a.name.eq_ignore_ascii_case("priv-lvl"))
        && let Some(val) = attr.value.as_deref()
    {
        let parsed: u32 = val.parse().map_err(|_| AuthzSemanticError {
            msg: "priv-lvl must be numeric",
            offending_index: None,
        })?;
        if parsed > 0x0f {
            return Err(AuthzSemanticError {
                msg: "priv-lvl must be 0-15",
                offending_index: None,
            });
        }
        if parsed as u8 != req.priv_lvl {
            return Err(AuthzSemanticError {
                msg: "priv-lvl attribute must match header priv_lvl",
                offending_index: None,
            });
        }
    }
    Ok(())
}

fn validate_authorization_semantics(
    req: &AuthorizationRequest,
    extra_services: &[String],
) -> Result<(), AuthzSemanticError> {
    let service_val = validate_service_attribute(req, extra_services)?;

    // Shell service has special validation rules
    if service_val.eq_ignore_ascii_case("shell") {
        return validate_shell_service(req);
    }

    // Configured vendor service (e.g. PaloAlto): attribute request, lenient.
    if !usg_tacacs_proto::header::is_known_service(&service_val) {
        return validate_vendor_service(req);
    }

    // Non-shell RFC services: validate all aspects
    validate_protocol_attribute(req)?;
    validate_cmd_attributes(req)?;
    validate_attribute_ordering(req)?;
    validate_priv_lvl(req)?;
    Ok(())
}

/// Serve TACACS+ over TLS connections.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-10 | Concurrent Session Control | Registers connections with session registry |
/// | IA-3 | Device Identification | Client certificate validation |
/// | SC-8 | Transmission Confidentiality | TLS 1.3 encryption |
pub async fn serve_tls(
    addr: SocketAddr,
    acceptor: Arc<RwLock<TlsAcceptor>>,
    auth_ctx: AuthContext,
    conn_cfg: ConnectionConfig,
    tls_identity: TlsIdentityConfig,
    registry: Arc<SessionRegistry>,
) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding TLS listener {}", addr))?;
    info!("listening for TLS TACACS+ on {}", addr);
    loop {
        let (socket, peer_addr) = listener.accept().await?;
        let conn_acceptor = acceptor.read().await.clone();
        let conn_auth_ctx = auth_ctx.clone();
        let conn_cfg = conn_cfg.clone();
        let conn_tls_identity = tls_identity.clone();
        let conn_registry = registry.clone();
        tokio::spawn(async move {
            let peer_ip = peer_addr.ip();
            let guard = match conn_cfg.conn_limiter.try_acquire(peer_ip).await {
                Some(g) => g,
                None => {
                    warn!(peer = %peer_addr, "connection rejected: per-peer limit exceeded");
                    return;
                }
            };
            match conn_acceptor.accept(socket).await {
                Ok(stream) => {
                    let cert_names = match enforce_client_cert_policy(
                        &stream,
                        &peer_addr,
                        &conn_tls_identity.allowed_cn,
                        &conn_tls_identity.allowed_san,
                    ) {
                        Ok(names) => names,
                        Err(err) => {
                            warn!(error = %err, peer = %peer_addr, "TLS client cert rejected");
                            return;
                        }
                    };
                    let conn_auth_ctx = match auth_ctx_with_nad_identity(conn_auth_ctx, &cert_names)
                    {
                        Ok(context) => context,
                        Err(err) => {
                            warn!(error = %err, peer = %peer_addr, "ambiguous JIT NAD identity");
                            return;
                        }
                    };
                    if let Err(err) = handle_connection(
                        stream,
                        peer_addr,
                        conn_auth_ctx,
                        &conn_cfg,
                        guard,
                        conn_registry,
                    )
                    .await
                    {
                        warn!(error = %err, peer = %peer_addr, "connection closed with error");
                    }
                }
                Err(err) => warn!(error = %err, peer = %peer_addr, "TLS handshake failed"),
            }
        });
    }
}

/// Serve TACACS+ over legacy (non-TLS) connections.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-10 | Concurrent Session Control | Registers connections with session registry |
/// | SC-7 | Boundary Protection | Per-NAD secret enforcement |
/// Determine the active identity source label for audit events.
fn resolve_identity_source(
    icam: &Option<Arc<IcamConfig>>,
    ldap: &Option<Arc<LdapConfig>>,
) -> &'static str {
    if icam.is_some() {
        "icam"
    } else if ldap.is_some() {
        "ldap"
    } else {
        "local"
    }
}

/// Build a per-NAD legacy `AuthContext` from trusted source configuration.
fn auth_ctx_with_legacy_nad(
    base: AuthContext,
    secret: Option<Arc<Vec<u8>>>,
    jit_nad_identity: Option<NadIdentity>,
) -> AuthContext {
    AuthContext {
        policy: base.policy.clone(),
        secret,
        credentials: base.credentials.clone(),
        ldap: base.ldap.clone(),
        icam: base.icam.clone(),
        device_flow: base.device_flow.clone(),
        username_limiter: base.username_limiter.clone(),
        ip_limiter: base.ip_limiter.clone(),
        audit_hmac_key: base.audit_hmac_key.clone(),
        jit_lease_store: base.jit_lease_store.clone(),
        jit_managed_nads: base.jit_managed_nads.clone(),
        jit_nad_identity,
    }
}

pub async fn serve_legacy(
    addr: SocketAddr,
    auth_ctx: AuthContext,
    conn_cfg: ConnectionConfig,
    nad_secrets: Arc<HashMap<IpAddr, Arc<Vec<u8>>>>,
    jit_legacy_nads: Arc<HashMap<IpAddr, NadIdentity>>,
    registry: Arc<SessionRegistry>,
) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding legacy listener {}", addr))?;
    info!("listening for legacy TACACS+ on {}", addr);
    loop {
        let (socket, peer_addr) = listener.accept().await?;
        let conn_auth_ctx = auth_ctx.clone();
        let conn_cfg = conn_cfg.clone();
        let conn_nad_secrets = nad_secrets.clone();
        let conn_jit_legacy_nads = jit_legacy_nads.clone();
        let conn_registry = registry.clone();
        tokio::spawn(async move {
            let peer_ip = peer_addr.ip();
            let guard = match conn_cfg.conn_limiter.try_acquire(peer_ip).await {
                Some(g) => g,
                None => {
                    warn!(peer = %peer_addr, "connection rejected: per-peer limit exceeded");
                    return;
                }
            };
            // For legacy connections, use per-NAD secret if configured, otherwise default
            let conn_secret = if conn_nad_secrets.is_empty() {
                conn_auth_ctx.secret.clone()
            } else {
                conn_nad_secrets.get(&normalize_ip(peer_addr.ip())).cloned()
            };
            if conn_secret.is_none() {
                warn!(peer = %peer_addr, "legacy connection rejected: NAD not in allowlist");
                return;
            }
            let jit_nad_identity = conn_jit_legacy_nads
                .get(&normalize_ip(peer_addr.ip()))
                .cloned();
            let per_nad_auth_ctx =
                auth_ctx_with_legacy_nad(conn_auth_ctx, conn_secret, jit_nad_identity);
            if let Err(err) = handle_connection(
                socket,
                peer_addr,
                per_nad_auth_ctx,
                &conn_cfg,
                guard,
                conn_registry,
            )
            .await
            {
                warn!(error = %err, peer = %peer_addr, "connection closed with error");
            }
        });
    }
}

/// Initialize a connection by registering with the session registry.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-10 | Concurrent Session Control | Registers connection with session registry |
/// | AU-2 | Audit Events | Logs connection acceptance and rejection |
///
/// Returns the connection ID on success, or returns early if session limit exceeded.
async fn initialize_connection(
    peer_addr: SocketAddr,
    registry: &Arc<SessionRegistry>,
) -> Result<u64> {
    // NIST AC-10: Register connection with session registry (enforces session limits)
    let connection_id = match registry.try_register_connection(peer_addr).await {
        Ok(id) => id,
        Err(e) => {
            warn!(peer = %peer_addr, error = %e, "connection rejected: session limit exceeded");
            audit_event(
                "conn_reject",
                &peer_addr.to_string(),
                "",
                0,
                "error",
                "session-limit",
                &e.to_string(),
            );
            return Ok(0); // Return 0 as sentinel for rejection
        }
    };

    let peer = peer_addr.to_string();
    audit_event(
        "conn_open",
        &peer,
        "",
        0,
        "info",
        "open",
        "connection started",
    );

    Ok(connection_id)
}

/// Clean up connection by unregistering from the session registry.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-10 | Concurrent Session Control | Unregisters connection from session registry |
/// | AU-2 | Audit Events | Logs connection close |
async fn cleanup_connection(connection_id: u64, peer: &str, registry: &Arc<SessionRegistry>) {
    // NIST AC-10: Unregister connection from session registry
    registry.unregister_connection(connection_id).await;
    audit_event("conn_close", peer, "", 0, "info", "loop-exit", "");
}

/// Validate single-connect constraints for authorization requests.
///
/// Returns error message if validation fails, None if validation passes.
/// Validate single-connect authorization request against the established session.
///
/// RFC 8907 §5.3: in single-connect mode, auth, authz, and accounting are
/// independent TACACS+ sessions that share one TCP connection and each carry
/// their own randomly-generated `session_id`.  The `session_id` fields are
/// NOT required to match across transaction types; only the bound username
/// must be consistent.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | IA-11 | Re-authentication | Enforces user binding across sessions on a connection |
fn validate_authz_single_connect(
    single_connect: &SingleConnectState,
    request: &AuthorizationRequest,
    peer: &str,
) -> Option<String> {
    let authz_single = request.header.flags & usg_tacacs_proto::FLAG_SINGLE_CONNECT != 0;

    if single_connect.active && !authz_single {
        warn!(peer = %peer, user = %request.user, session = request.header.session_id,
            "single-connect violation: flag missing on authorization");
        return Some("single-connection flag required after authentication".into());
    }

    if !authz_single {
        return None;
    }

    // RFC 8907 §6: an authorization request is an independent transaction that
    // MAY arrive on a connection where no authentication has occurred — it carries
    // its own `user`, which policy evaluates. A standalone authz (e.g. `aaa
    // authorization commands` over a freshly opened connection) is therefore
    // permitted. Only enforce consistency when a user is already bound to this
    // connection; each transaction still carries its own session_id, so we never
    // compare session_ids across transaction types.
    if let Some(ref bound_user) = single_connect.user
        && bound_user != &request.user
    {
        warn!(peer = %peer, user = %request.user, bound_user = %bound_user,
            session = request.header.session_id, "single-connect violation: user mismatch on authorization");
        return Some("single-connection user mismatch".into());
    }

    None
}

/// Validate single-connect constraints for authentication requests.
///
/// Returns error message if validation fails, None if validation passes.
fn validate_authen_single_connect(
    single_connect: &SingleConnectState,
    packet: &AuthenPacket,
    session_id: u32,
    peer: &str,
) -> Option<String> {
    let authen_single = match packet {
        AuthenPacket::Start(s) => s.header.flags & usg_tacacs_proto::FLAG_SINGLE_CONNECT != 0,
        AuthenPacket::Continue(c) => c.header.flags & usg_tacacs_proto::FLAG_SINGLE_CONNECT != 0,
    };

    if single_connect.active && !authen_single {
        warn!(peer = %peer, session = session_id, "single-connect violation: flag missing on authentication");
        return Some("single-connection flag required after authentication".into());
    }

    if let AuthenPacket::Start(start) = packet {
        if !single_connect.active {
            return None;
        }

        if let Some(ref bound_user) = single_connect.user {
            if bound_user != &start.user {
                warn!(peer = %peer, user = %start.user, bound_user = %bound_user,
                    session = session_id, "single-connect violation: user mismatch on authentication");
                return Some("single-connection user mismatch".into());
            }
        } else {
            warn!(peer = %peer, user = %start.user, session = session_id,
                "single-connect violation: authentication with missing bound user");
            return Some("single-connection not authenticated".into());
        }

        if single_connect.locked {
            warn!(peer = %peer, user = %start.user, session = session_id,
                "single-connect violation: repeated authentication after lock");
            return Some("single-connection already authenticated".into());
        }

        if let Some(bound) = single_connect.session
            && bound != start.header.session_id
        {
            warn!(peer = %peer, user = %start.user, session = session_id,
                    bound_session = bound, "single-connect violation: session-id mismatch on authentication");
            return Some("session-id mismatch".into());
        }
    }

    None
}

/// Validate single-connect constraints for accounting requests.
///
/// Returns error message if validation fails, None if validation passes.
/// Validate single-connect accounting request against the established session.
///
/// Accounting transactions generate their own session_id even on a shared
/// single-connect TCP connection (RFC 8907 §5.3); only the bound username
/// must be consistent across transactions.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AU-12 | Audit Generation | Validates accounting requests are from authenticated sessions |
fn validate_acct_single_connect(
    single_connect: &SingleConnectState,
    request: &AccountingRequest,
    peer: &str,
) -> Option<String> {
    let acct_single = request.header.flags & usg_tacacs_proto::FLAG_SINGLE_CONNECT != 0;

    if single_connect.active && !acct_single {
        warn!(peer = %peer, user = %request.user, session = request.header.session_id,
            "single-connect violation: flag missing on accounting");
        return Some("single-connection flag required after authentication".into());
    }

    if !acct_single {
        return None;
    }

    // RFC 8907 §7: accounting is an independent transaction that MAY arrive on a
    // connection where no authentication has occurred (it carries its own `user`).
    // A standalone accounting record is therefore permitted; accounting also
    // carries its own session_id (RFC 8907 §5.3), so we never compare session_ids
    // across transaction types. Only enforce consistency when a user is bound.
    if let Some(ref bound_user) = single_connect.user
        && bound_user != &request.user
    {
        warn!(peer = %peer, user = %request.user, bound_user = %bound_user,
            session = request.header.session_id, "single-connect violation: user mismatch on accounting");
        return Some("single-connection user mismatch".into());
    }

    None
}

/// Handle capability exchange packet.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AU-12 | Audit Generation | Logs capability exchange |
async fn handle_capability_packet<S>(
    stream: &mut S,
    cap: &Capability,
    peer: &str,
    secret: Option<&[u8]>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    audit_event(
        "capability_rx",
        peer,
        "",
        cap.header.session_id,
        "info",
        if cap.flags & CAPABILITY_FLAG_REQUEST != 0 {
            "request"
        } else if cap.flags & CAPABILITY_FLAG_RESPONSE != 0 {
            "response"
        } else {
            "unknown"
        },
        &format!(
            "vendor=0x{:04x};caps=0x{:08x}",
            cap.vendor, cap.capabilities.0
        ),
    );

    if cap.flags & CAPABILITY_FLAG_REQUEST != 0 {
        let resp = Capability {
            header: cap.header.clone(),
            version: cap.version,
            flags: CAPABILITY_FLAG_RESPONSE,
            vendor: cap.vendor,
            capabilities: cap.capabilities,
            tlvs: Vec::new(),
        };
        usg_tacacs_proto::write_capability(stream, &cap.header, &resp, secret).await?;
    }

    Ok(())
}

/// Return the value of the single `service` attribute, if present.
///
/// Used to route configured vendor services (e.g. `service=PaloAlto`) to the
/// vendor-attribute authorization path. The RFC/semantic validators have
/// already ensured at most one well-formed service attribute by this point.
fn author_service_name(req: &AuthorizationRequest) -> Option<String> {
    req.attributes()
        .iter()
        .find(|a| a.name.eq_ignore_ascii_case("service"))
        .and_then(|a| a.value.clone())
}

/// Authorize a configured vendor-service attribute request (e.g.
/// `service=PaloAlto`) by returning the policy-resolved vendor AV-pairs
/// (`PaloAlto-Admin-Role=…`, optionally `PaloAlto-Admin-Access-Domain=…`)
/// for the user's IdP groups.
///
/// A match returns `PASS_ADD` with the AV-pairs; no match returns `FAIL`,
/// which the NAS treats as "no role granted" (access denied).
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-3 | Access Enforcement | Returns vendor role/scope per identity |
/// | AC-6 | Least Privilege | Role granted is bounded by IdP group membership |
/// | AU-12 | Audit Generation | Logs allow/deny decision |
fn audit_vendor_authz(
    request: &AuthorizationRequest,
    peer: &str,
    response: &AuthorizationResponse,
    allowed: bool,
) {
    assert!(!peer.is_empty(), "peer must not be empty");
    assert!(!response.data.is_empty(), "audit data must not be empty");
    let (event, status, reason) = if allowed {
        ("authz_policy_allow", "pass", "policy-vendor")
    } else if request.user.is_empty() {
        ("authz_policy_deny", "fail", "vendor-no-user")
    } else {
        ("authz_policy_deny", "fail", "vendor-no-mapping")
    };
    audit_event(
        event,
        peer,
        &request.user,
        request.header.session_id,
        status,
        reason,
        &response.data,
    );
}

fn vendor_no_user_response(request: &AuthorizationRequest, peer: &str) -> AuthorizationResponse {
    assert!(request.user.is_empty(), "user must be empty");
    assert!(!peer.is_empty(), "peer must not be empty");
    let response = authz_reason_response(
        AUTHOR_STATUS_FAIL,
        "authorization request missing user".to_string(),
        "vendor-no-user",
        None,
    );
    audit_vendor_authz(request, peer, &response, false);
    response
}

fn vendor_mapping_response(
    request: &AuthorizationRequest,
    service: &str,
    context: &str,
    attributes: Option<Vec<String>>,
    peer: &str,
) -> AuthorizationResponse {
    assert!(!request.user.is_empty(), "user must not be empty");
    assert!(!service.is_empty(), "service must not be empty");
    let (response, allowed) = match attributes {
        Some(args) => (
            AuthorizationResponse {
                status: AUTHOR_STATUS_PASS_ADD,
                server_msg: String::new(),
                data: format!("reason=policy-vendor;service={service};ctx={context}"),
                args,
            },
            true,
        ),
        None => (
            authz_reason_response(
                AUTHOR_STATUS_FAIL,
                format!("no {service} role mapping for user"),
                "vendor-no-mapping",
                None,
            ),
            false,
        ),
    };
    audit_vendor_authz(request, peer, &response, allowed);
    response
}

fn authorize_vendor_service(
    request: &AuthorizationRequest,
    policy: &PolicyEngine,
    groups: &[String],
    service: &str,
    peer: &str,
) -> AuthorizationResponse {
    assert!(!service.is_empty(), "service must not be empty");
    assert!(!peer.is_empty(), "peer must not be empty");
    // RFC validation does not require a non-empty user, but the policy resolver
    // does; deny (rather than panic) a request that names no user.
    if request.user.is_empty() {
        return vendor_no_user_response(request, peer);
    }
    let attributes = policy.service_attributes_for_with_groups(service, &request.user, groups);
    let context = authz_context(request);
    vendor_mapping_response(request, service, &context, attributes, peer)
}

/// Authorize shell start command.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-3 | Access Enforcement | Shell attribute retrieval from policy |
/// | AU-12 | Audit Generation | Logs authorization decision |
fn authorize_shell_command(
    request: &AuthorizationRequest,
    policy: &PolicyEngine,
    groups: &[String],
    nad_groups: &[String],
    peer: &str,
) -> AuthorizationResponse {
    let _ = nad_groups; // shell-start priv-lvl uses user groups; NAD groups reserved for future use
    let ctx = authz_context(request);
    let attrs = policy
        .shell_attributes_for_with_groups(&request.user, groups)
        .unwrap_or_else(|| vec!["service=shell".to_string(), "protocol=shell".to_string()]);
    let attrs = ensure_priv_attr(attrs, request.priv_lvl);
    let resp = AuthorizationResponse {
        status: AUTHOR_STATUS_PASS_ADD,
        server_msg: String::new(),
        data: format!("reason=policy-shell;ctx={ctx}"),
        args: attrs,
    };
    audit_event(
        "authz_policy_allow",
        peer,
        &request.user,
        request.header.session_id,
        "pass",
        "policy-shell",
        &resp.data,
    );
    resp
}

/// Authorize user command with policy and LDAP group evaluation.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-3 | Access Enforcement | Policy-based command authorization |
/// | AU-12 | Audit Generation | Logs allow/deny decisions |
/// Build authorization allow response with policy metadata.
fn build_authz_allow_response(
    request: &AuthorizationRequest,
    matched_rule: Option<String>,
    ldap_groups: &[String],
    ctx: &str,
    peer: &str,
) -> AuthorizationResponse {
    let mut data = String::from("reason=policy-allow");
    if let Some(rule) = matched_rule {
        data.push_str(";rule=");
        data.push_str(&rule);
    }
    data.push_str(";ctx=");
    data.push_str(ctx);
    let ldap_data = if !ldap_groups.is_empty() {
        format!(";groups={}", ldap_groups.join(","))
    } else {
        String::new()
    };
    // Command authorization: PASS_ADD with NO av-pairs is the portable
    // "permit the command as typed" response (RFC 8907 §6.2). Returning
    // PASS_REPL while echoing the command back (`cmd=…`, `cmd-arg=…`) makes
    // Cisco IOS treat the response as an argument *replacement* it cannot map,
    // so it silently refuses the command and returns to the prompt with no
    // message. The session's privilege level is already established by exec
    // (shell-start) authorization, so no attributes need to be returned here.
    let resp = AuthorizationResponse {
        status: AUTHOR_STATUS_PASS_ADD,
        server_msg: String::new(),
        data: format!("{data}{ldap_data}"),
        args: Vec::new(),
    };
    audit_event(
        "authz_policy_allow",
        peer,
        &request.user,
        request.header.session_id,
        "pass",
        "policy-allow",
        &resp.data,
    );
    resp
}

/// Build authorization deny response with policy metadata.
fn build_authz_deny_response(
    request: &AuthorizationRequest,
    matched_rule: Option<String>,
    cmd: &str,
    ctx: &str,
    peer: &str,
) -> AuthorizationResponse {
    let mut resp = authz_reason_response(
        AUTHOR_STATUS_FAIL,
        format!("command '{cmd}' denied by policy"),
        "policy-deny",
        Some(cmd.to_string()),
    );
    if let Some(rule) = matched_rule {
        resp.data.push_str(";rule=");
        resp.data.push_str(&rule);
    }
    resp.data.push_str(";ctx=");
    resp.data.push_str(ctx);
    audit_event(
        "authz_policy_deny",
        peer,
        &request.user,
        request.header.session_id,
        "fail",
        &resp.server_msg,
        &resp.data,
    );
    resp
}

fn authorize_user_command(
    request: &AuthorizationRequest,
    policy: &PolicyEngine,
    ldap_groups: &[String],
    nad_groups: &[String],
    cmd: &str,
    peer: &str,
) -> AuthorizationResponse {
    let ctx = authz_context(request);
    let decision = policy.authorize_with_nad(&request.user, ldap_groups, nad_groups, cmd);

    if decision.allowed {
        build_authz_allow_response(request, decision.matched_rule, ldap_groups, &ctx, peer)
    } else {
        build_authz_deny_response(request, decision.matched_rule, cmd, &ctx, peer)
    }
}

/// Handle authorization packet processing.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-3 | Access Enforcement | Authorization request validation and processing |
/// | AU-12 | Audit Generation | Logs all authorization events |
/// | SC-23 | Session Authenticity | Single-connect validation |
/// Handle RFC validation error for authorization request.
async fn handle_authz_rfc_error<S>(
    stream: &mut S,
    request: &AuthorizationRequest,
    secret: Option<&[u8]>,
    peer: &str,
    err: anyhow::Error,
) -> Result<LoopControl>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    warn!(peer = %peer, user = %request.user, session = request.header.session_id, error = %err, "authorization request failed RFC validation");
    let response = authz_reason_response(
        AUTHOR_STATUS_ERROR,
        err.to_string(),
        "rfc-validate",
        Some(err.to_string()),
    );
    audit_event(
        "authz_rfc_invalid",
        peer,
        &request.user,
        request.header.session_id,
        "error",
        "rfc-validate",
        &response.data,
    );
    let _ = write_author_response(stream, &request.header, &response, secret).await;
    Ok(LoopControl::Break)
}

/// Handle single-connect validation error for authorization.
async fn handle_authz_single_connect_error<S>(
    stream: &mut S,
    request: &AuthorizationRequest,
    secret: Option<&[u8]>,
    err_msg: String,
) -> Result<LoopControl>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let response = authz_reason_response(
        AUTHOR_STATUS_ERROR,
        err_msg,
        "single-connect",
        Some("violation".into()),
    );
    let _ = write_author_response(stream, &request.header, &response, secret).await;
    Ok(LoopControl::Break)
}

/// Build authorization response for semantic validation failure.
fn build_authz_semantic_error_response(
    request: &AuthorizationRequest,
    msg: AuthzSemanticError,
    peer: &str,
) -> AuthorizationResponse {
    warn!(peer = %peer, user = %request.user, session = request.header.session_id, reason = %msg.msg, "authorization request rejected by semantic checks");
    let (code, detail) = authz_semantic_detail(&msg);
    let ctx = authz_context(request);
    let resp = authz_reason_response(
        AUTHOR_STATUS_ERROR,
        authz_server_msg_with_detail(code, msg.msg, &detail),
        code,
        Some(detail.clone()),
    );
    let meta = format!("{};ctx={ctx}", resp.data);
    audit_event(
        "authz_semantic_reject",
        peer,
        &request.user,
        request.header.session_id,
        "error",
        code,
        &meta,
    );
    audit_event(
        "authz_error",
        peer,
        &request.user,
        request.header.session_id,
        "error",
        "authz-error",
        &resp.data,
    );
    resp
}

/// Resolve the effective groups for an authorization decision.
///
/// Preference order: (1) groups bound to this connection's authentication, the
/// fast path; (2) the shared login→authz cache, which covers a standalone
/// command-authorization request arriving on a separate connection or replica
/// with no JWT; (3) a live LDAP query for LDAP-only deployments; (4) empty.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-3 | Access Enforcement | Supplies groups for the policy decision |
/// | AC-2 | Account Management | Group memberships drive authorization |
async fn resolve_authz_groups(
    icam_groups: &[String],
    ldap: &Option<Arc<LdapConfig>>,
    user: &str,
) -> Vec<String> {
    if !icam_groups.is_empty() {
        return icam_groups.to_vec();
    }
    if let Some(cache) = crate::group_cache::group_cache()
        && let Some(groups) = cache.get(user).await
        && !groups.is_empty()
    {
        return groups;
    }
    if let Some(ldap_cfg) = ldap.as_ref() {
        return ldap_fetch_groups(ldap_cfg, user).await;
    }
    Vec::new()
}

/// Execute authorization decision based on request type.
///
/// Groups are resolved via [`resolve_authz_groups`] (connection auth → shared
/// cache → LDAP), then matched against policy rules.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-3 | Access Enforcement | Policy evaluated with ICAM or LDAP groups |
/// | AC-2 | Account Management | Group memberships drive authorization decisions |
async fn execute_authorization_decision(
    request: &AuthorizationRequest,
    policy: &Arc<RwLock<PolicyEngine>>,
    ldap: &Option<Arc<LdapConfig>>,
    icam_groups: &[String],
    peer: &str,
) -> AuthorizationResponse {
    // Resolve groups before acquiring the policy lock to avoid holding it
    // across a potentially slow network call (cache/LDAP).
    let effective_groups = resolve_authz_groups(icam_groups, ldap, &request.user).await;

    let policy_guard = policy.read().await;

    // Resolve the NAD's policy group based on its source IP (AC-3).
    let nad_groups = policy_guard.resolve_nad_groups(peer);

    // Configured vendor service (e.g. service=PaloAlto): return vendor AV-pairs
    // resolved from the user's IdP groups. Checked before shell/command because
    // a vendor request carries no `cmd` and would otherwise be misrouted.
    // An RFC-known service name (shell/login/…) is never treated as a vendor
    // service even if mis-configured in author_service_attributes, so a stray
    // entry cannot hijack standard shell/command authorization.
    if let Some(service) = author_service_name(request)
        && !usg_tacacs_proto::header::is_known_service(&service)
        && policy_guard.is_custom_author_service(&service)
    {
        return authorize_vendor_service(request, &policy_guard, &effective_groups, &service, peer);
    }

    if request.is_shell_start() {
        authorize_shell_command(request, &policy_guard, &effective_groups, &nad_groups, peer)
    } else if let Some(cmd) = request.command_string() {
        authorize_user_command(
            request,
            &policy_guard,
            &effective_groups,
            &nad_groups,
            &cmd,
            peer,
        )
    } else {
        authz_reason_response(
            AUTHOR_STATUS_ERROR,
            "unsupported request",
            "unsupported",
            None,
        )
    }
}

async fn handle_authorization_packet<S>(
    stream: &mut S,
    request: &AuthorizationRequest,
    single_connect: &SingleConnectState,
    policy: &Arc<RwLock<PolicyEngine>>,
    ldap: &Option<Arc<LdapConfig>>,
    secret: Option<&[u8]>,
    peer: &str,
) -> Result<LoopControl>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // Configured vendor services (e.g. PaloAlto) must be accepted by both the
    // RFC validator and the semantic validator, neither of which can see the
    // policy. Snapshot the names under a short read lock and pass them in.
    let custom_services = { policy.read().await.custom_author_services() };

    if let Err(err) =
        usg_tacacs_proto::validate_author_request_with_services(request, &custom_services)
    {
        return handle_authz_rfc_error(stream, request, secret, peer, err).await;
    }

    if let Some(err_msg) = validate_authz_single_connect(single_connect, request, peer) {
        return handle_authz_single_connect_error(stream, request, secret, err_msg).await;
    }

    let decision = match validate_authorization_semantics(request, &custom_services) {
        Ok(()) => {
            execute_authorization_decision(request, policy, ldap, &single_connect.icam_groups, peer)
                .await
        }
        Err(msg) => build_authz_semantic_error_response(request, msg, peer),
    };

    if let Err(err) = request
        .header
        .response(0)
        .and_then(|h| validate_author_response_header(&h))
    {
        warn!(error = %err, peer = %peer, "authorization header invalid");
    }

    write_author_response(stream, &request.header, &decision, secret)
        .await
        .with_context(|| "sending TACACS+ response")?;

    Ok(LoopControl::Continue)
}

/// Track task_id for accounting START/STOP/WATCHDOG records per RFC 8907.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AU-12 | Audit Generation | Validates task_id sequence integrity |
fn track_task_id(
    task_tracker: &mut TaskIdTracker,
    request: &AccountingRequest,
    peer: &str,
) -> Result<(), &'static str> {
    let attrs = request.attributes();
    let task_id: Option<u32> = attrs
        .iter()
        .find(|a| a.name.eq_ignore_ascii_case("task_id"))
        .and_then(|a| a.value.as_deref())
        .and_then(|v| v.parse().ok());
    if let Some(tid) = task_id {
        if request.flags & ACCT_FLAG_START != 0 {
            task_tracker.start(tid)?;
        } else if request.flags & ACCT_FLAG_STOP != 0 {
            if let Err(e) = task_tracker.stop(tid) {
                warn!(peer = %peer, task_id = tid, error = %e, "task_id tracking warning");
            }
        } else if request.flags & ACCT_FLAG_WATCHDOG != 0
            && let Err(e) = task_tracker.watchdog(tid)
        {
            warn!(peer = %peer, task_id = tid, error = %e, "task_id tracking warning");
        }
    }
    Ok(())
}

/// Determine accounting type from flags.
fn determine_acct_type(flags: u8) -> &'static str {
    if flags & ACCT_FLAG_START != 0 {
        "start"
    } else if flags & ACCT_FLAG_STOP != 0 {
        "stop"
    } else if flags & ACCT_FLAG_WATCHDOG != 0 {
        "watchdog"
    } else {
        "unknown"
    }
}

/// Extracted accounting attributes for audit logging.
struct AcctAttributes {
    service: String,
    cmd: String,
    task_id: String,
    status: String,
    bytes_in: String,
    bytes_out: String,
}

/// Extract key accounting attributes from request.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AU-3 | Content of Audit Records | Extract structured accounting data |
fn extract_acct_attributes(request: &AccountingRequest) -> AcctAttributes {
    let attrs = request.attributes();

    let service = attrs
        .iter()
        .find(|a| a.name.eq_ignore_ascii_case("service"))
        .and_then(|a| a.value.as_deref())
        .unwrap_or("-")
        .to_string();
    let cmd = attrs
        .iter()
        .find(|a| a.name.eq_ignore_ascii_case("cmd"))
        .and_then(|a| a.value.as_deref())
        .unwrap_or("-")
        .to_string();
    let task_id = attrs
        .iter()
        .find(|a| a.name.eq_ignore_ascii_case("task_id"))
        .and_then(|a| a.value.as_deref())
        .unwrap_or("-")
        .to_string();
    let status = attrs
        .iter()
        .find(|a| a.name.eq_ignore_ascii_case("status"))
        .and_then(|a| a.value.as_deref())
        .unwrap_or("-")
        .to_string();
    let bytes_in = attrs
        .iter()
        .find(|a| a.name.eq_ignore_ascii_case("bytes_in"))
        .and_then(|a| a.value.as_deref())
        .unwrap_or("-")
        .to_string();
    let bytes_out = attrs
        .iter()
        .find(|a| a.name.eq_ignore_ascii_case("bytes_out"))
        .and_then(|a| a.value.as_deref())
        .unwrap_or("-")
        .to_string();

    AcctAttributes {
        service,
        cmd,
        task_id,
        status,
        bytes_in,
        bytes_out,
    }
}

/// Build audit metadata string for accounting record.
fn build_acct_audit_data(
    acct_type: &str,
    flags: u8,
    attr_count: usize,
    attrs: &AcctAttributes,
) -> String {
    format!(
        "type={};flags=0x{:02x};attrs={};service={};cmd={};task_id={};status={};bytes_in={};bytes_out={}",
        acct_type,
        flags,
        attr_count,
        attrs.service,
        attrs.cmd,
        attrs.task_id,
        attrs.status,
        attrs.bytes_in,
        attrs.bytes_out
    )
}

/// Log successful accounting record with extracted attributes.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AU-12 | Audit Generation | Extracts and logs accounting attributes |
fn log_accounting_success(request: &AccountingRequest, peer: &str) {
    let acct_type = determine_acct_type(request.flags);
    let attrs = extract_acct_attributes(request);
    let data = build_acct_audit_data(acct_type, request.flags, request.args.len(), &attrs);

    audit_event(
        "acct_accept",
        peer,
        &request.user,
        request.header.session_id,
        "success",
        "semantic-ok",
        &data,
    );
}

/// Handle accounting packet processing.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AU-12 | Audit Generation | Accounting record validation and logging |
/// | SC-23 | Session Authenticity | Single-connect validation |
/// Handle RFC validation failure for accounting request.
async fn handle_acct_rfc_validation_error<S>(
    stream: &mut S,
    request: &AccountingRequest,
    err: &str,
    secret: Option<&[u8]>,
    peer: &str,
) -> Result<LoopControl>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    warn!(peer = %peer, user = %request.user, session = request.header.session_id, error = %err, "accounting request failed RFC validation");
    let response = AccountingResponse {
        status: ACCT_STATUS_ERROR,
        server_msg: err.to_string(),
        data: format!("reason=rfc-validate;detail={err}"),
        args: Vec::new(),
    };
    // Include the validation detail so the rejection reason is visible in the
    // audit pipeline (not only the warn log) for NAD-compatibility debugging.
    let meta = format!(
        "flags=0x{:02x};attrs={};detail={err}",
        request.flags,
        request.args.len()
    );
    audit_event(
        "acct_rfc_invalid",
        peer,
        &request.user,
        request.header.session_id,
        "error",
        "rfc-validate",
        &meta,
    );
    let _ = write_accounting_response(stream, &request.header, &response, secret).await;
    Ok(LoopControl::Break)
}

/// Handle task_id tracking rejection for accounting request.
fn build_acct_task_id_error_response(
    msg: &str,
    request: &AccountingRequest,
    peer: &str,
) -> AccountingResponse {
    warn!(
        peer = %peer, user = %request.user, session = request.header.session_id, reason = %msg,
        "accounting request rejected by task_id tracking (RFC 8907)"
    );
    audit_event(
        "acct_task_id_reuse",
        peer,
        &request.user,
        request.header.session_id,
        "error",
        "task-id-reuse",
        msg,
    );
    AccountingResponse {
        status: ACCT_STATUS_ERROR,
        server_msg: msg.to_string(),
        data: format!("reason=task-id-reuse;detail={msg}"),
        args: Vec::new(),
    }
}

/// Handle semantic validation rejection for accounting request.
fn build_acct_semantic_error_response(
    msg: &str,
    request: &AccountingRequest,
    peer: &str,
) -> AccountingResponse {
    warn!(
        peer = %peer, user = %request.user, session = request.header.session_id, reason = %msg,
        "accounting request rejected by semantic checks"
    );
    let meta = format!(
        "flags=0x{:02x};attrs={};reason={}",
        request.flags,
        request.args.len(),
        msg
    );
    audit_event(
        "acct_semantic_reject",
        peer,
        &request.user,
        request.header.session_id,
        "error",
        msg,
        &meta,
    );
    let resp = AccountingResponse {
        status: ACCT_STATUS_ERROR,
        server_msg: msg.to_string(),
        data: format!("reason=semantic-invalid;detail={msg}"),
        args: Vec::new(),
    };
    audit_event(
        "acct_error",
        peer,
        &request.user,
        request.header.session_id,
        "error",
        "acct-error",
        &resp.data,
    );
    resp
}

/// Build accounting response based on validation results.
fn build_acct_response_from_validation(
    semantic_result: Result<(), &str>,
    task_tracking_result: Result<(), &str>,
    request: &AccountingRequest,
    peer: &str,
) -> AccountingResponse {
    match semantic_result {
        Ok(()) if task_tracking_result.is_ok() => accounting_success_response(request),
        Ok(()) => {
            let msg = task_tracking_result.unwrap_err();
            build_acct_task_id_error_response(msg, request, peer)
        }
        Err(msg) => build_acct_semantic_error_response(msg, request, peer),
    }
}

async fn handle_accounting_packet<S>(
    stream: &mut S,
    request: &AccountingRequest,
    single_connect: &SingleConnectState,
    task_tracker: &mut TaskIdTracker,
    secret: Option<&[u8]>,
    peer: &str,
) -> Result<LoopControl>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    if let Err(err) = usg_tacacs_proto::validate_accounting_request(request) {
        return handle_acct_rfc_validation_error(stream, request, &err.to_string(), secret, peer)
            .await;
    }

    if let Some(err_msg) = validate_acct_single_connect(single_connect, request, peer) {
        let response = AccountingResponse {
            status: ACCT_STATUS_ERROR,
            server_msg: err_msg,
            data: String::new(),
            args: Vec::new(),
        };
        let _ = write_accounting_response(stream, &request.header, &response, secret).await;
        return Ok(LoopControl::Break);
    }

    if let Err(err) = request
        .header
        .response(0)
        .and_then(|h| validate_accounting_response_header(&h))
    {
        warn!(error = %err, peer = %peer, "accounting header invalid");
    }

    let semantic_result = validate_accounting_semantics(request);
    let task_tracking_result = track_task_id(task_tracker, request, peer);
    let response =
        build_acct_response_from_validation(semantic_result, task_tracking_result, request, peer);

    if response.status == ACCT_STATUS_SUCCESS {
        log_accounting_success(request, peer);
    } else if response.status == ACCT_STATUS_ERROR {
        audit_event(
            "acct_error",
            peer,
            &request.user,
            request.header.session_id,
            "error",
            "acct-error",
            &response.data,
        );
    }

    write_accounting_response(stream, &request.header, &response, secret)
        .await
        .with_context(|| "sending TACACS+ accounting response")?;

    Ok(LoopControl::Continue)
}

/// State info snapshot for authentication finalization
#[derive(Clone)]
struct AuthStateSnapshot {
    username: Option<String>,
    username_raw: Option<Vec<u8>>,
    ascii_attempts: u8,
    ascii_user_attempts: u8,
    ascii_pass_attempts: u8,
    authen_type: Option<u8>,
    service: Option<u8>,
    action: Option<u8>,
}

impl AuthStateSnapshot {
    fn from_state(state: &AuthSessionState) -> Self {
        Self {
            username: state.username.clone(),
            username_raw: state.username_raw.clone(),
            ascii_attempts: state.ascii_attempts,
            ascii_user_attempts: state.ascii_user_attempts,
            ascii_pass_attempts: state.ascii_pass_attempts,
            authen_type: state.authen_type,
            service: state.service,
            action: state.action,
        }
    }
}

/// Validate RFC compliance for authentication packet and send error if invalid.
///
/// Returns Ok(true) if validation passed, Ok(false) if error was sent.
async fn validate_authen_rfc<S>(
    stream: &mut S,
    packet: &AuthenPacket,
    session_id: u32,
    secret: Option<&[u8]>,
    peer: &str,
) -> Result<bool>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    match packet {
        AuthenPacket::Start(start) => {
            if let Err(err) = usg_tacacs_proto::validate_authen_start(start) {
                warn!(peer = %peer, user = %start.user, session = session_id, error = %err, "authentication start failed RFC validation");
                let reply = AuthenReply {
                    status: AUTHEN_STATUS_ERROR,
                    flags: 0,
                    server_msg: err.to_string(),
                    server_msg_raw: Vec::new(),
                    data: Vec::new(),
                };
                audit_event(
                    "authn_rfc_invalid",
                    peer,
                    &start.user,
                    session_id,
                    "error",
                    "rfc-validate",
                    &err.to_string(),
                );
                let _ = write_authen_reply(stream, &start.header, &reply, secret).await;
                return Ok(false);
            }
        }
        AuthenPacket::Continue(cont) => {
            if let Err(err) = usg_tacacs_proto::validate_authen_continue(cont) {
                warn!(peer = %peer, session = session_id, error = %err, "authentication continue failed RFC validation");
                let reply = AuthenReply {
                    status: AUTHEN_STATUS_ERROR,
                    flags: 0,
                    server_msg: err.to_string(),
                    server_msg_raw: Vec::new(),
                    data: Vec::new(),
                };
                audit_event(
                    "authn_rfc_invalid",
                    peer,
                    "",
                    session_id,
                    "error",
                    "rfc-validate",
                    &err.to_string(),
                );
                let _ = write_authen_reply(stream, &cont.header, &reply, secret).await;
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// Create authentication session state from START packet.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | SC-23 | Session Authenticity | Initialize session state from START packet |
fn create_state_from_start(start: &AuthenStart) -> AuthSessionState {
    AuthSessionState::from_start(start).unwrap_or(AuthSessionState {
        last_seq: start.header.seq_no,
        expect_client: false,
        authen_type: Some(start.authen_type),
        challenge: None,
        username: if start.user_raw.is_empty() || start.user.is_empty() {
            None
        } else {
            Some(start.user.clone())
        },
        username_raw: if start.user_raw.is_empty() {
            None
        } else {
            Some(start.user_raw.clone())
        },
        port: Some(start.port.clone()),
        port_raw: if start.port_raw.is_empty() {
            None
        } else {
            Some(start.port_raw.clone())
        },
        rem_addr: Some(start.rem_addr.clone()),
        rem_addr_raw: if start.rem_addr_raw.is_empty() {
            None
        } else {
            Some(start.rem_addr_raw.clone())
        },
        service: Some(start.service),
        action: Some(start.action),
        priv_lvl: Some(start.priv_lvl),
        ascii_need_user: start.user.is_empty(),
        ascii_need_pass: start.data.is_empty(),
        chap_id: None,
        ascii_attempts: 0,
        ascii_user_attempts: 0,
        ascii_pass_attempts: 0,
        device_code: None,
        device_poll_count: 0,
        ascii_device_flow_pending: false,
    })
}

/// Create empty authentication session state from CONTINUE packet.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | SC-23 | Session Authenticity | Initialize minimal state for out-of-sequence CONTINUE |
fn create_state_from_continue(cont: &AuthenContinue) -> AuthSessionState {
    AuthSessionState {
        last_seq: cont.header.seq_no,
        expect_client: false,
        authen_type: None,
        challenge: None,
        username: None,
        username_raw: None,
        port_raw: None,
        port: None,
        rem_addr_raw: None,
        rem_addr: None,
        chap_id: None,
        ascii_need_user: true,
        ascii_need_pass: false,
        ascii_attempts: 0,
        ascii_user_attempts: 0,
        ascii_pass_attempts: 0,
        service: None,
        action: None,
        priv_lvl: None,
        device_code: None,
        device_poll_count: 0,
        ascii_device_flow_pending: false,
    }
}

/// Handle authentication sequence validation error.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | SC-23 | Session Authenticity | Reject out-of-sequence authentication packets |
/// | AU-12 | Audit Generation | Log sequence validation failures |
async fn handle_auth_sequence_error<S>(
    stream: &mut S,
    cont: &AuthenContinue,
    state: &AuthSessionState,
    session_id: u32,
    secret: Option<&[u8]>,
    peer: &str,
    err: anyhow::Error,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    warn!(error = %err, peer = %peer, "auth sequence invalid");
    let reply = AuthenReply {
        status: AUTHEN_STATUS_ERROR,
        flags: 0,
        server_msg: err.to_string(),
        server_msg_raw: Vec::new(),
        data: Vec::new(),
    };
    audit_event(
        "authn_sequence_error",
        peer,
        state.username.as_deref().unwrap_or(""),
        session_id,
        "error",
        "sequence",
        &err.to_string(),
    );
    let _ = write_authen_reply(stream, &cont.header, &reply, secret).await;
    Ok(())
}

/// Maximum number of concurrent authentication sessions per connection.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | SC-5 | Denial of Service Protection | Prevents auth state map exhaustion |
const MAX_AUTH_SESSIONS_PER_CONN: usize = 64;

/// Get or create authentication session state for the given packet.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | SC-23 | Session Authenticity | Session state tracking with sequence validation |
/// | SC-5 | Denial of Service Protection | Bounds auth session map size |
async fn get_or_create_auth_state<'a, S>(
    stream: &mut S,
    packet: &AuthenPacket,
    auth_states: &'a mut HashMap<u32, AuthSessionState>,
    session_id: u32,
    secret: Option<&[u8]>,
    peer: &str,
) -> Result<Option<&'a mut AuthSessionState>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // NIST SC-5: Reject new sessions if map is at capacity
    if !auth_states.contains_key(&session_id) && auth_states.len() >= MAX_AUTH_SESSIONS_PER_CONN {
        warn!(
            peer = %peer,
            session_id = session_id,
            limit = MAX_AUTH_SESSIONS_PER_CONN,
            "auth session limit exceeded, rejecting new session"
        );
        return Ok(None);
    }

    let state = auth_states
        .entry(session_id)
        .or_insert_with(|| match packet {
            AuthenPacket::Start(start) => create_state_from_start(start),
            AuthenPacket::Continue(cont) => create_state_from_continue(cont),
        });

    if let AuthenPacket::Continue(cont) = packet
        && let Err(err) = state.validate_client(&cont.header)
    {
        handle_auth_sequence_error(stream, cont, state, session_id, secret, peer, err).await?;
        return Ok(None);
    }

    Ok(Some(state))
}

/// Build PAP authentication result reply with policy messages.
///
/// # NIST SP 800-53 Controls
/// - AU-2: Audit event content
async fn build_pap_auth_result(
    ok: bool,
    service: u8,
    action: u8,
    policy: &Arc<RwLock<PolicyEngine>>,
) -> AuthenReply {
    let policy = policy.read().await;
    let svc_str = service.to_string();
    let act_str = action.to_string();

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
                .unwrap_or_else(|| {
                    format!("authentication succeeded (service {svc_str} action {act_str})")
                })
        } else {
            policy
                .message_failure()
                .map(|m| m.to_string())
                .unwrap_or_else(|| {
                    format!("invalid credentials (service {svc_str} action {act_str})")
                })
        },
        server_msg_raw: Vec::new(),
        data: Vec::new(),
    }
}

/// Handle PAP authentication START packet.
///
/// When ICAM is configured, credentials are forwarded to the ICAM OIDC token
/// endpoint exclusively (no fallback to static or LDAP credentials).
/// Groups returned from the JWT are placed in `icam_groups_out` for use
/// during subsequent authorization.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | IA-2 | Identification and Authentication | PAP verification via ICAM or local creds |
/// | IA-5 | Authenticator Management | Password verification via ICAM, static creds, or LDAP |
/// | IA-8 | Non-Organizational User Auth | ICAM delegation for enterprise identity |
#[allow(clippy::too_many_arguments)]
async fn handle_authen_start_pap(
    start: &AuthenStart,
    state: &mut AuthSessionState,
    policy: &Arc<RwLock<PolicyEngine>>,
    credentials: &Arc<StaticCreds>,
    ldap: &Option<Arc<LdapConfig>>,
    icam: &Option<Arc<IcamConfig>>,
    icam_groups_out: &mut Vec<String>,
    peer: &str,
    jit: Option<&JitNadAuthenticator>,
) -> Result<AuthenReply> {
    state.authen_type = Some(AUTHEN_TYPE_PAP);
    let password = match start.parsed_data() {
        AuthenData::Pap { password } => password,
        _ => {
            warn!(peer = %peer, user = %start.user, "invalid PAP authentication payload");
            return Ok(AuthenReply {
                status: AUTHEN_STATUS_ERROR,
                flags: 0,
                server_msg: "invalid PAP data".into(),
                server_msg_raw: Vec::new(),
                data: Vec::new(),
            });
        }
    };

    if let Some(authenticator) = jit {
        let result = authenticator
            .authenticate(&start.user, password.as_bytes())
            .await;
        let ok = match result {
            Ok(authentication) => {
                if let Some(metadata) = authentication.metadata {
                    *icam_groups_out = metadata.authorization_groups;
                }
                authentication.authenticated
            }
            Err(error) => {
                warn!(error = %error, peer = %peer, "JIT lease authentication failed closed");
                false
            }
        };
        return Ok(build_pap_auth_result(ok, start.service, start.action, policy).await);
    }

    // ICAM-delegated authentication: forward credentials to OIDC token endpoint.
    // When ICAM is configured it is the exclusive source; no fallback to local creds.
    if let Some(icam_cfg) = icam.as_ref() {
        let result: IcamAuthResult = icam_authenticate(icam_cfg, &start.user, &password).await;
        *icam_groups_out = result.groups;
        return Ok(build_pap_auth_result(
            result.authenticated,
            start.service,
            start.action,
            policy,
        )
        .await);
    }

    let ok = verify_pap(&start.user, &password, credentials).await
        || verify_password_sources(
            Some(&start.user),
            password.as_bytes(),
            credentials,
            ldap.as_ref(),
        )
        .await;

    Ok(build_pap_auth_result(ok, start.service, start.action, policy).await)
}

/// Handle CHAP authentication START packet.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | IA-2 | Identification and Authentication | CHAP challenge-response authentication |
/// | IA-5 | Authenticator Management | Secure random challenge generation |
async fn handle_authen_start_chap(
    start: &AuthenStart,
    state: &mut AuthSessionState,
    peer: &str,
) -> Result<AuthenReply> {
    if start.data.len() != 1 {
        warn!(peer = %peer, user = %start.user, "invalid CHAP start length");
        return Ok(AuthenReply {
            status: AUTHEN_STATUS_ERROR,
            flags: 0,
            server_msg: "invalid CHAP data length".into(),
            server_msg_raw: Vec::new(),
            data: Vec::new(),
        });
    }

    let chap_id = &start.data;
    let mut chal = [0u8; 16];
    let mut chap_id_bytes = [0u8; 1];
    chap_id_bytes.copy_from_slice(chap_id);

    if rand_bytes(&mut chal).is_err() || rand_bytes(&mut chap_id_bytes).is_err() {
        return Ok(AuthenReply {
            status: AUTHEN_STATUS_ERROR,
            flags: 0,
            server_msg: "failed to generate challenge".into(),
            server_msg_raw: Vec::new(),
            data: Vec::new(),
        });
    }

    state.challenge = Some(chal.to_vec());
    state.chap_id = Some(chap_id_bytes[0]);

    Ok(AuthenReply {
        status: AUTHEN_STATUS_GETDATA,
        flags: 0,
        server_msg: String::new(),
        server_msg_raw: Vec::new(),
        data: {
            let mut payload = Vec::with_capacity(1 + chal.len());
            payload.extend_from_slice(&chap_id_bytes);
            payload.extend_from_slice(&chal);
            payload
        },
    })
}

/// Handle ASCII authentication START packet.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | IA-2 | Identification and Authentication | ASCII login flow with username/password prompts |
/// | IA-5 | Authenticator Management | Password verification via static creds and LDAP |
#[allow(clippy::too_many_arguments)]
/// Fetch custom prompts from policy engine for ASCII authentication.
async fn fetch_ascii_prompts_from_policy(
    policy: &Arc<RwLock<PolicyEngine>>,
    state: &AuthSessionState,
) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    let policy = policy.read().await;
    let policy_user = username_for_policy(state.username.as_deref(), state.username_raw.as_ref());
    let policy_port = field_for_policy(state.port.as_deref(), state.port_raw.as_ref());
    let policy_rem = field_for_policy(state.rem_addr.as_deref(), state.rem_addr_raw.as_ref());
    (
        policy
            .prompt_username(
                policy_user.as_deref(),
                policy_port.as_deref(),
                policy_rem.as_deref(),
            )
            .map(|s| s.as_bytes().to_vec()),
        policy
            .prompt_password(policy_user.as_deref())
            .map(|s| s.as_bytes().to_vec()),
    )
}

/// Build username prompt with policy override or default.
fn build_ascii_username_prompt(policy_prompt: Option<&[u8]>, service: Option<u8>) -> Vec<u8> {
    if let Some(custom) = policy_prompt {
        custom.to_vec()
    } else {
        match service {
            Some(s) => format!("Username (service {s}):").into_bytes(),
            None => b"Username:".to_vec(),
        }
    }
}

/// Build password prompt with policy override or default.
fn build_ascii_password_prompt(policy_prompt: Option<&[u8]>, service: Option<u8>) -> Vec<u8> {
    if let Some(custom) = policy_prompt {
        custom.to_vec()
    } else {
        match service {
            Some(s) => format!("Password (service {s}):").into_bytes(),
            None => b"Password:".to_vec(),
        }
    }
}

/// Verify ASCII credentials using ICAM, static creds, or LDAP.
///
/// When ICAM is configured, credentials are forwarded exclusively to ICAM.
/// On ICAM success, `icam_groups_out` is populated with the JWT groups claim.
#[allow(clippy::too_many_arguments)]
async fn verify_ascii_credentials_all_sources(
    username: Option<&str>,
    username_raw: Option<&Vec<u8>>,
    password_data: &[u8],
    credentials: &Arc<StaticCreds>,
    ldap: &Option<Arc<LdapConfig>>,
    icam: &Option<Arc<IcamConfig>>,
    icam_groups_out: &mut Vec<String>,
    jit: Option<&JitNadAuthenticator>,
) -> bool {
    if let (Some(authenticator), Some(user)) = (jit, username) {
        return match authenticator.authenticate(user, password_data).await {
            Ok(authentication) => {
                if let Some(metadata) = authentication.metadata {
                    *icam_groups_out = metadata.authorization_groups;
                }
                authentication.authenticated
            }
            Err(error) => {
                warn!(error = %error, "JIT lease authentication failed closed");
                false
            }
        };
    }
    if let (Some(icam_cfg), Some(user)) = (icam.as_ref(), username)
        && let Ok(pwd) = std::str::from_utf8(password_data)
    {
        let result: IcamAuthResult = icam_authenticate(icam_cfg, user, pwd).await;
        *icam_groups_out = result.groups;
        return result.authenticated;
    }
    if let Some(raw) = username_raw {
        if verify_pap_bytes_username(raw, password_data, credentials) {
            return true;
        }
    } else if verify_pap_bytes(username.unwrap_or_default(), password_data, credentials).await {
        return true;
    }
    if let Some(user) = username {
        verify_password_sources(Some(user), password_data, credentials, ldap.as_ref()).await
    } else {
        false
    }
}

/// Build authentication result reply with policy messages.
async fn build_ascii_auth_result_reply(
    ok: bool,
    service: Option<u8>,
    action: Option<u8>,
    policy: &Arc<RwLock<PolicyEngine>>,
) -> AuthenReply {
    let svc_str = service
        .map(|svc| format!(" (service {svc})"))
        .unwrap_or_default();
    let act_str = action
        .map(|act| format!(" action {act})"))
        .unwrap_or_default();
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

fn extract_ascii_username_from_start(start: &AuthenStart, state: &mut AuthSessionState) {
    let decoded_username = if start.user_raw.is_empty() || start.user.is_empty() {
        None
    } else {
        Some(start.user.clone())
    };
    state.username = decoded_username;
    state.username_raw = if start.user_raw.is_empty() {
        None
    } else {
        Some(start.user_raw.clone())
    };
}

fn build_getuser_reply(prompt: Option<&[u8]>, service: Option<u8>) -> AuthenReply {
    AuthenReply {
        status: AUTHEN_STATUS_GETUSER,
        flags: 0,
        server_msg: String::new(),
        // RFC 8907 §5.2: the prompt shown to the user goes in server_msg, not
        // data. Cisco IOS displays server_msg; an empty one shows no prompt.
        server_msg_raw: build_ascii_username_prompt(prompt, service),
        data: Vec::new(),
    }
}

fn build_getpass_reply(prompt: Option<&[u8]>, service: Option<u8>) -> AuthenReply {
    AuthenReply {
        status: AUTHEN_STATUS_GETPASS,
        flags: AUTHEN_FLAG_NOECHO,
        server_msg: String::new(),
        // RFC 8907 §5.2: prompt goes in server_msg, not data.
        server_msg_raw: build_ascii_password_prompt(prompt, service),
        data: Vec::new(),
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_authen_start_ascii(
    start: &AuthenStart,
    state: &mut AuthSessionState,
    policy: &Arc<RwLock<PolicyEngine>>,
    credentials: &Arc<StaticCreds>,
    ldap: &Option<Arc<LdapConfig>>,
    icam: &Option<Arc<IcamConfig>>,
    device_flow: &Option<Arc<DeviceFlowConfig>>,
    icam_groups_out: &mut Vec<String>,
    ascii_cfg: &AsciiConfig,
    jit: Option<&JitNadAuthenticator>,
) -> AuthenReply {
    state.authen_type = Some(AUTHEN_TYPE_ASCII);
    state.service = Some(start.service);
    state.action = Some(start.action);

    // Device flow feature gate: route based on username from START packet.
    // Returns Some on GETUSER-defer or device-flow URL; None when excluded
    // (falls through to password auth below).
    if let Some(df_cfg) = device_flow.as_deref()
        && let Some(reply) = try_route_device_flow(start, state, policy, df_cfg).await
    {
        return reply;
    }

    extract_ascii_username_from_start(start, state);
    let (policy_user_prompt, policy_pass_prompt) =
        fetch_ascii_prompts_from_policy(policy, state).await;
    state.ascii_need_user = state.username.is_none();
    if state.ascii_need_user {
        return build_getuser_reply(policy_user_prompt.as_deref(), state.service);
    }
    if !start.data.is_empty() {
        let ok = verify_ascii_credentials_all_sources(
            state.username.as_deref(),
            state.username_raw.as_ref(),
            &start.data,
            credentials,
            ldap,
            icam,
            icam_groups_out,
            jit,
        )
        .await;
        if !ok
            && let Some(delay) = calc_ascii_backoff_capped(
                ascii_cfg.backoff_ms,
                state.ascii_attempts,
                ascii_cfg.backoff_max_ms,
            )
        {
            sleep(delay).await;
        }
        build_ascii_auth_result_reply(ok, state.service, state.action, policy).await
    } else {
        state.ascii_need_pass = true;
        build_getpass_reply(policy_pass_prompt.as_deref(), state.service)
    }
}

/// Initiate RFC 8628 device authorization and return GETDATA reply with verification URL.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | IA-2 | Identification and Authentication | Initiates ICAM device authorization |
/// | IA-6 | Authenticator Feedback | Returns URL; never echoes credentials |
/// | AU-2 | Audit Events | Initiation outcome logged via tracing |
/// Route ASCII auth to device flow or password based on username + exclude list.
///
/// Returns `Some(reply)` to short-circuit (GETUSER defer or device flow URL),
/// `None` when the user is excluded and should fall through to password auth.
async fn try_route_device_flow(
    start: &AuthenStart,
    state: &mut AuthSessionState,
    policy: &Arc<RwLock<PolicyEngine>>,
    df_cfg: &DeviceFlowConfig,
) -> Option<AuthenReply> {
    let username = start.user.trim();
    if username.is_empty() {
        state.ascii_device_flow_pending = true;
        let (user_prompt, _) = fetch_ascii_prompts_from_policy(policy, state).await;
        state.ascii_need_user = true;
        return Some(build_getuser_reply(user_prompt.as_deref(), state.service));
    }
    let excluded = policy.read().await.is_device_flow_excluded(username);
    extract_ascii_username_from_start(start, state);
    if excluded {
        None
    } else {
        Some(handle_ascii_device_flow_start(state, df_cfg).await)
    }
}

async fn handle_ascii_device_flow_start(
    state: &mut AuthSessionState,
    cfg: &DeviceFlowConfig,
) -> AuthenReply {
    assert!(cfg.max_polls > 0, "max_polls must be positive");
    match icam_device_auth_start(cfg).await {
        Some(resp) => {
            let msg = icam_device_format_prompt(&resp, 0, cfg.max_polls);
            state.device_code = Some(resp.device_code);
            state.device_poll_count = 0;
            AuthenReply {
                status: AUTHEN_STATUS_GETDATA,
                flags: 0,
                server_msg: msg,
                server_msg_raw: Vec::new(),
                data: Vec::new(),
            }
        }
        None => {
            tracing::warn!("device auth start failed; cannot present browser URL");
            AuthenReply {
                status: AUTHEN_STATUS_FAIL,
                flags: 0,
                server_msg: "device authorization initialization failed".into(),
                server_msg_raw: Vec::new(),
                data: Vec::new(),
            }
        }
    }
}

/// Finalize authentication: audit terminal status, write reply, cleanup state, activate single-connect.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AU-12 | Audit Generation | Terminal authentication status audit logging |
/// | SC-23 | Session Authenticity | Single-connect activation on successful authentication |
/// Determine authentication failure reason from status and message.
fn determine_authen_failure_reason(status: u8, server_msg: &str) -> &'static str {
    match status {
        AUTHEN_STATUS_PASS => "success",
        AUTHEN_STATUS_FAIL => {
            let msg_lc = server_msg.to_lowercase();
            if msg_lc.contains("too many authentication attempts") {
                "attempt-limit"
            } else if msg_lc.contains("too many username attempts") {
                "user-attempt-limit"
            } else if msg_lc.contains("too many password attempts") {
                "pass-attempt-limit"
            } else if msg_lc.contains("authentication locked out") {
                "lockout"
            } else {
                "credential-mismatch"
            }
        }
        AUTHEN_STATUS_ERROR => "error",
        AUTHEN_STATUS_FOLLOW => "follow",
        AUTHEN_STATUS_RESTART => "restart",
        _ => "other",
    }
}

/// Build audit message data from authentication state and reply.
fn build_authen_audit_message(reply: &AuthenReply, state_snapshot: &AuthStateSnapshot) -> String {
    let msg_data = if !reply.server_msg.is_empty() {
        reply.server_msg.clone()
    } else if !reply.server_msg_raw.is_empty() {
        format!("raw={}", hex::encode(&reply.server_msg_raw))
    } else {
        String::new()
    };
    let attempts = format!(
        "attempts_total={};user_attempts={};pass_attempts={}",
        state_snapshot.ascii_attempts,
        state_snapshot.ascii_user_attempts,
        state_snapshot.ascii_pass_attempts
    );
    let authn_type = match state_snapshot.authen_type {
        Some(AUTHEN_TYPE_ASCII) => "ascii",
        Some(AUTHEN_TYPE_PAP) => "pap",
        Some(AUTHEN_TYPE_CHAP) => "chap",
        Some(_) => "other",
        None => "unknown",
    };
    let svc = state_snapshot
        .service
        .map(|s| s.to_string())
        .unwrap_or_else(|| "-".into());
    let action = state_snapshot
        .action
        .map(|a| a.to_string())
        .unwrap_or_else(|| "-".into());
    let reason = determine_authen_failure_reason(reply.status, &reply.server_msg);

    if msg_data.is_empty() {
        format!("{attempts};type={authn_type};service={svc};action={action};reason={reason}")
    } else {
        format!(
            "{attempts};type={authn_type};service={svc};action={action};reason={reason};msg={msg_data}"
        )
    }
}

/// Log terminal authentication status with detailed audit information.
///
/// `identity_source` is one of `"icam"`, `"ldap"`, or `"local"` and reflects
/// which backend was used to validate the credential (AU-3: audit record content).
///
/// # NIST SP 800-53 Controls
///
/// | Control | Implementation |
/// |---------|----------------|
/// | AU-12 | Audit Generation - Terminal authentication events |
/// | AU-3 | Content of Audit Records - User, session, status, identity source |
fn log_terminal_authen_status(
    reply: &AuthenReply,
    state_snapshot: &AuthStateSnapshot,
    session_id: u32,
    peer: &str,
    identity_source: &str,
) {
    let status_label = match reply.status {
        AUTHEN_STATUS_PASS => "pass",
        AUTHEN_STATUS_FAIL => "fail",
        AUTHEN_STATUS_ERROR => "error",
        AUTHEN_STATUS_FOLLOW => "follow",
        AUTHEN_STATUS_RESTART => "restart",
        _ => "other",
    };
    let user_for_log = state_snapshot.username.as_deref().unwrap_or_else(|| {
        state_snapshot
            .username_raw
            .as_ref()
            .map(|_| "<raw>")
            .unwrap_or("")
    });
    let msg_data = build_authen_audit_message(reply, state_snapshot);

    // Route through the signed emitter so the authentication-outcome record is
    // HMAC-covered like every other audit event (AU-9). The identity_source is
    // carried as a dedicated field included in the signature.
    emit_audit_event(
        "authn_terminal",
        peer,
        user_for_log,
        session_id,
        status_label,
        "terminal",
        &msg_data,
        identity_source,
    );
}

/// Activate single-connect mode on successful authentication.
///
/// # NIST SP 800-53 Controls
///
/// | Control | Implementation |
/// Apply per-username rate-limit checks and record outcome (AC-7).
///
/// Overrides `reply.status` to FAIL when the username is locked out, and
/// records success/failure so the limiter can update its sliding window.
/// Parse the source `IpAddr` from a peer socket-address string (e.g.
/// `"10.0.100.7:5000"` or `"[::ffff:10.0.100.7]:5000"`), normalizing
/// IPv4-mapped IPv6 to the IPv4 form so the limiter keys match the conn limiter.
fn parse_peer_ip(peer: &str) -> Option<IpAddr> {
    peer.parse::<SocketAddr>()
        .ok()
        .map(|sa| normalize_ip(sa.ip()))
}

/// Apply per-username and per-source-IP authentication rate limiting (AC-7,
/// SC-5). Recording decisions use the *original* reply status so the two
/// limiters do not feed each other; either limiter being locked overrides the
/// reply to FAIL. The "locked out" wording is masked before the wire by
/// [`sanitize_locked_out_message`] (finding #7).
async fn apply_auth_rate_limits(
    username_limiter: &Arc<crate::username_limiter::UsernameRateLimiter>,
    ip_limiter: &Arc<crate::ip_limiter::IpRateLimiter>,
    username: Option<&str>,
    peer: &str,
    reply: &mut AuthenReply,
) {
    let was_pass = matches!(reply.status, AUTHEN_STATUS_PASS);
    let was_fail = matches!(reply.status, AUTHEN_STATUS_FAIL);

    // Per-source-IP throttle: independent of username, so a spray that rotates
    // usernames from one source is caught (the username limiter cannot see it).
    if let Some(ip) = parse_peer_ip(peer) {
        if ip_limiter.is_locked(ip).await {
            reply.status = AUTHEN_STATUS_FAIL;
            reply.server_msg = "authentication locked out".into();
        } else if was_pass {
            ip_limiter.record_success(ip).await;
        } else if was_fail {
            ip_limiter.record_failure(ip).await;
        }
    }

    // Per-username throttle (cross-IP).
    if let Some(user) = username {
        assert!(!user.is_empty(), "username must not be empty");
        if username_limiter.is_locked(user).await {
            reply.status = AUTHEN_STATUS_FAIL;
            reply.server_msg = "authentication locked out".into();
        } else if was_pass {
            username_limiter.record_success(user).await;
        } else if was_fail {
            username_limiter.record_failure(user).await;
        }
    }
}

/// |---------|----------------|
/// | IA-11 | Re-authentication - Single-connect session binding |
#[allow(clippy::too_many_arguments)]
async fn activate_single_connect_on_success(
    reply: &AuthenReply,
    single_connect_flag: bool,
    single_user: Option<String>,
    single_connect: &mut SingleConnectState,
    session_id: u32,
    connection_id: u64,
    registry: &Arc<SessionRegistry>,
    peer: &str,
) {
    if matches!(reply.status, AUTHEN_STATUS_PASS)
        && single_connect_flag
        && let Some(user) = single_user
    {
        single_connect.activate(user.clone(), session_id);
        registry
            .update_authentication(connection_id, user.clone(), session_id)
            .await;
        info!(peer = %peer, user = %user, session = session_id, "single-connect established");
    }
}

/// Extract packet header from authentication packet.
fn extract_packet_header(packet: &AuthenPacket) -> &usg_tacacs_proto::Header {
    match packet {
        AuthenPacket::Start(start) => &start.header,
        AuthenPacket::Continue(cont) => &cont.header,
    }
}

/// Check if authentication status is terminal.
fn is_terminal_status(status: u8) -> bool {
    matches!(
        status,
        AUTHEN_STATUS_PASS
            | AUTHEN_STATUS_FAIL
            | AUTHEN_STATUS_ERROR
            | AUTHEN_STATUS_FOLLOW
            | AUTHEN_STATUS_RESTART
    )
}

/// Enforce server message policy and log raw bytes if present.
///
/// # NIST SP 800-53 Controls
///
/// | Control | Implementation |
/// |---------|----------------|
/// | AU-12 | Audit Generation - Log raw server message bytes |
async fn enforce_server_msg_policy(
    policy: &Arc<RwLock<PolicyEngine>>,
    auth_states: &HashMap<u32, AuthSessionState>,
    session_id: u32,
    reply: &mut AuthenReply,
    peer: &str,
) {
    if !reply.server_msg_raw.is_empty()
        && let Some(state) = auth_states.get(&session_id)
    {
        enforce_server_msg(policy, state, reply).await;
        debug!(
            peer = %peer, session = session_id,
            raw_len = reply.server_msg_raw.len(),
            server_msg_raw_hex = %hex::encode(&reply.server_msg_raw),
            "auth reply carried raw server_msg bytes"
        );
    }
}

/// Clean up terminal authentication state.
///
/// # NIST SP 800-53 Controls
///
/// | Control | Implementation |
/// |---------|----------------|
/// | SC-23 | Session Authenticity - Remove completed auth sessions |
fn cleanup_terminal_auth_state(
    auth_states: &mut HashMap<u32, AuthSessionState>,
    single_connect: &mut SingleConnectState,
    session_id: u32,
    status: u8,
) {
    auth_states.remove(&session_id);
    if status != AUTHEN_STATUS_PASS {
        single_connect.reset();
    }
}

/// Generic credential-failure text used when the policy sets no failure
/// message; chosen to match the default normal-failure wording.
const DEFAULT_AUTH_FAILURE_MSG: &str = "invalid credentials";

/// Replace a lockout failure message with the same generic message a normal
/// credential failure returns, so a locked-out user is indistinguishable on
/// the wire from an ordinary bad-credential failure (finding #7 — information
/// disclosure / AC-7). The real "lockout" reason is preserved in the audit log
/// because `log_terminal_authen_status` runs before this sanitization. No-op
/// for non-FAIL replies and for failures that do not reveal lockout state.
fn sanitize_locked_out_message(reply: &mut AuthenReply, failure_msg: &str) {
    assert!(
        !failure_msg.is_empty(),
        "generic failure message must not be empty"
    );
    if reply.status != AUTHEN_STATUS_FAIL {
        return;
    }
    if reply.server_msg.to_lowercase().contains("locked out") {
        reply.server_msg = failure_msg.to_string();
        reply.server_msg_raw = Vec::new();
    }
}

#[allow(clippy::too_many_arguments)]
// NASA-RULE4-EXEMPT: length driven by 16-param signature + finalize fan-out, not logic complexity
async fn finalize_authentication<S>(
    stream: &mut S,
    packet: &AuthenPacket,
    mut reply: AuthenReply,
    session_id: u32,
    state_snapshot: AuthStateSnapshot,
    auth_states: &mut HashMap<u32, AuthSessionState>,
    single_connect: &mut SingleConnectState,
    single_connect_flag: bool,
    icam_groups: Vec<String>,
    identity_source: &str,
    username_limiter: &Arc<crate::username_limiter::UsernameRateLimiter>,
    ip_limiter: &Arc<crate::ip_limiter::IpRateLimiter>,
    connection_id: u64,
    registry: &Arc<SessionRegistry>,
    policy: &Arc<RwLock<PolicyEngine>>,
    secret: Option<&[u8]>,
    peer: &str,
) -> Result<LoopControl>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let header = extract_packet_header(packet);
    let is_terminal = is_terminal_status(reply.status);
    let single_user = state_snapshot.username.clone();

    // Per-username and per-source-IP rate limiting (AC-7, SC-5).
    if is_terminal {
        apply_auth_rate_limits(
            username_limiter,
            ip_limiter,
            state_snapshot.username.as_deref(),
            peer,
            &mut reply,
        )
        .await;
    }

    if is_terminal {
        log_terminal_authen_status(&reply, &state_snapshot, session_id, peer, identity_source);
        // #7: after the real reason is audited, mask lockout state on the wire
        // so a locked-out user looks like an ordinary credential failure.
        let failure_msg = policy
            .read()
            .await
            .message_failure()
            .unwrap_or(DEFAULT_AUTH_FAILURE_MSG)
            .to_string();
        sanitize_locked_out_message(&mut reply, &failure_msg);
    }

    write_authen_reply(stream, header, &reply, secret)
        .await
        .with_context(|| "sending TACACS+ auth reply")?;

    if !is_terminal && let Some(st) = auth_states.get_mut(&session_id) {
        st.last_seq = header.seq_no.wrapping_add(1); // RFC 8907 §5.4.1
        st.expect_client = true;
    }
    enforce_server_msg_policy(policy, auth_states, session_id, &mut reply, peer).await;
    if is_terminal {
        cleanup_terminal_auth_state(auth_states, single_connect, session_id, reply.status);
    }
    if matches!(reply.status, AUTHEN_STATUS_PASS) && !icam_groups.is_empty() {
        // Persist to the shared cache so a standalone command-authorization
        // request on a separate connection or replica can resolve this user's
        // groups even though it carries no JWT (AC-2, AC-3).
        if let Some(cache) = crate::group_cache::group_cache()
            && let Some(user) = state_snapshot.username.as_deref()
        {
            cache.put(user, &icam_groups).await;
        }
        single_connect.icam_groups = icam_groups; // AC-2, AC-3: cache for authz
    }
    activate_single_connect_on_success(
        &reply,
        single_connect_flag,
        single_user,
        single_connect,
        session_id,
        connection_id,
        registry,
        peer,
    )
    .await;

    Ok(LoopControl::Continue)
}

/// Extract single-connect flag from authentication packet.
fn extract_authen_single_connect_flag(packet: &AuthenPacket) -> bool {
    match packet {
        AuthenPacket::Start(start) => {
            start.header.flags & usg_tacacs_proto::FLAG_SINGLE_CONNECT != 0
        }
        AuthenPacket::Continue(cont) => {
            cont.header.flags & usg_tacacs_proto::FLAG_SINGLE_CONNECT != 0
        }
    }
}

/// Handle single-connect validation error for authentication.
async fn handle_authen_single_connect_error<S>(
    stream: &mut S,
    packet: &AuthenPacket,
    err_msg: String,
    secret: Option<&[u8]>,
) -> Result<LoopControl>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let header = match packet {
        AuthenPacket::Start(start) => &start.header,
        AuthenPacket::Continue(cont) => &cont.header,
    };
    let reply = AuthenReply {
        status: AUTHEN_STATUS_ERROR,
        flags: 0,
        server_msg: err_msg,
        server_msg_raw: Vec::new(),
        data: Vec::new(),
    };
    let _ = write_authen_reply(stream, header, &reply, secret).await;
    Ok(LoopControl::Break)
}

/// Process AUTHEN_START packet and return reply.
#[allow(clippy::too_many_arguments)]
async fn process_authen_start_packet(
    start: &AuthenStart,
    state: &mut AuthSessionState,
    policy: &Arc<RwLock<PolicyEngine>>,
    credentials: &Arc<StaticCreds>,
    ldap: &Option<Arc<LdapConfig>>,
    icam: &Option<Arc<IcamConfig>>,
    device_flow: &Option<Arc<DeviceFlowConfig>>,
    icam_groups_out: &mut Vec<String>,
    ascii_cfg: &AsciiConfig,
    peer: &str,
    jit: Option<&JitNadAuthenticator>,
) -> Result<AuthenReply, LoopControl> {
    match start.authen_type {
        AUTHEN_TYPE_ASCII => Ok(handle_authen_start_ascii(
            start,
            state,
            policy,
            credentials,
            ldap,
            icam,
            device_flow,
            icam_groups_out,
            ascii_cfg,
            jit,
        )
        .await),
        AUTHEN_TYPE_PAP => handle_authen_start_pap(
            start,
            state,
            policy,
            credentials,
            ldap,
            icam,
            icam_groups_out,
            peer,
            jit,
        )
        .await
        .map_err(|_| LoopControl::Break),
        AUTHEN_TYPE_CHAP => handle_authen_start_chap(start, state, peer)
            .await
            .map_err(|_| LoopControl::Break),
        _ => Ok(AuthenReply {
            status: AUTHEN_STATUS_FOLLOW,
            flags: 0,
            server_msg: "unsupported auth type - fallback".into(),
            server_msg_raw: Vec::new(),
            data: Vec::new(),
        }),
    }
}

/// Process AUTHEN_CONTINUE packet and return reply.
#[allow(clippy::too_many_arguments)]
async fn process_authen_continue_packet(
    cont: &usg_tacacs_proto::AuthenContinue,
    state: &mut AuthSessionState,
    policy: &Arc<RwLock<PolicyEngine>>,
    credentials: &Arc<StaticCreds>,
    ldap: &Option<Arc<LdapConfig>>,
    icam: &Option<Arc<IcamConfig>>,
    device_flow: &Option<Arc<DeviceFlowConfig>>,
    icam_groups_out: &mut Vec<String>,
    ascii_cfg: &AsciiConfig,
    jit: Option<&JitNadAuthenticator>,
) -> AuthenReply {
    match state.authen_type {
        Some(AUTHEN_TYPE_ASCII) => {
            handle_ascii_continue_jit(
                cont.user_msg.as_slice(),
                cont.data.as_slice(),
                cont.flags,
                state,
                policy,
                credentials,
                ascii_cfg,
                ldap.as_ref(),
                icam.as_deref(),
                device_flow.as_deref(),
                icam_groups_out,
                jit,
            )
            .await
        }
        _ if state.challenge.is_some() => {
            let user = state.username.clone().unwrap_or_default();
            match state.authen_type {
                Some(AUTHEN_TYPE_CHAP) => {
                    handle_chap_continue(&user, cont.data.as_slice(), state, credentials)
                }
                _ => AuthenReply {
                    status: AUTHEN_STATUS_FAIL,
                    flags: 0,
                    server_msg: "unexpected continue".into(),
                    server_msg_raw: Vec::new(),
                    data: Vec::new(),
                },
            }
        }
        _ => AuthenReply {
            status: AUTHEN_STATUS_FAIL,
            flags: 0,
            server_msg: format!(
                "unexpected authentication continue (flags {:02x})",
                cont.flags
            ),
            server_msg_raw: Vec::new(),
            data: Vec::new(),
        },
    }
}

/// Handle authentication packet processing.
///
/// Note: This function is large (600+ lines) and will be further decomposed in Phase 5
/// into type-specific handlers (ASCII, PAP, CHAP, continue, finalize).
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | IA-2 | Identification and Authentication | Multi-method authentication |
/// | IA-5 | Authenticator Management | Password verification across sources |
/// | AU-12 | Audit Generation | Comprehensive authentication logging |
/// | SC-23 | Session Authenticity | Single-connect validation and activation |
#[allow(clippy::too_many_arguments)]
fn extract_session_id(packet: &AuthenPacket) -> u32 {
    match packet {
        AuthenPacket::Start(start) => start.header.session_id,
        AuthenPacket::Continue(cont) => cont.header.session_id,
    }
}

async fn validate_authen_packet<S>(
    stream: &mut S,
    packet: &AuthenPacket,
    single_connect: &mut SingleConnectState,
    session_id: u32,
    secret: Option<&[u8]>,
    peer: &str,
) -> Result<Option<LoopControl>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    if !validate_authen_rfc(stream, packet, session_id, secret, peer).await? {
        return Ok(Some(LoopControl::Break));
    }
    if let Some(err_msg) = validate_authen_single_connect(single_connect, packet, session_id, peer)
    {
        return Ok(Some(
            handle_authen_single_connect_error(stream, packet, err_msg, secret).await?,
        ));
    }
    Ok(None)
}

#[allow(clippy::too_many_arguments)]
async fn process_authen_packet(
    packet: &AuthenPacket,
    state: &mut AuthSessionState,
    policy: &Arc<RwLock<PolicyEngine>>,
    credentials: &Arc<StaticCreds>,
    ldap: &Option<Arc<LdapConfig>>,
    icam: &Option<Arc<IcamConfig>>,
    device_flow: &Option<Arc<DeviceFlowConfig>>,
    icam_groups_out: &mut Vec<String>,
    ascii_cfg: &AsciiConfig,
    peer: &str,
    jit: Option<&JitNadAuthenticator>,
) -> Result<AuthenReply, LoopControl> {
    match packet {
        AuthenPacket::Start(start) => {
            process_authen_start_packet(
                start,
                state,
                policy,
                credentials,
                ldap,
                icam,
                device_flow,
                icam_groups_out,
                ascii_cfg,
                peer,
                jit,
            )
            .await
        }
        AuthenPacket::Continue(cont) => {
            let reply = process_authen_continue_packet(
                cont,
                state,
                policy,
                credentials,
                ldap,
                icam,
                device_flow,
                icam_groups_out,
                ascii_cfg,
                jit,
            )
            .await;
            Ok(reply)
        }
    }
}

// NASA-RULE4-EXEMPT: length is driven by 15-param dispatch signature, not logic complexity
#[allow(clippy::too_many_arguments)]
async fn handle_authentication_packet<S>(
    stream: &mut S,
    packet: AuthenPacket,
    auth_states: &mut HashMap<u32, AuthSessionState>,
    single_connect: &mut SingleConnectState,
    connection_id: u64,
    registry: &Arc<SessionRegistry>,
    policy: &Arc<RwLock<PolicyEngine>>,
    credentials: &Arc<StaticCreds>,
    ldap: &Option<Arc<LdapConfig>>,
    icam: &Option<Arc<IcamConfig>>,
    device_flow: &Option<Arc<DeviceFlowConfig>>,
    username_limiter: &Arc<crate::username_limiter::UsernameRateLimiter>,
    ip_limiter: &Arc<crate::ip_limiter::IpRateLimiter>,
    ascii_cfg: &AsciiConfig,
    secret: Option<&[u8]>,
    peer: &str,
    jit: Option<&JitNadAuthenticator>,
) -> Result<LoopControl>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let session_id = extract_session_id(&packet);
    if let Some(ctrl) =
        validate_authen_packet(stream, &packet, single_connect, session_id, secret, peer).await?
    {
        return Ok(ctrl);
    }
    let single_connect_flag = extract_authen_single_connect_flag(&packet);
    let state =
        match get_or_create_auth_state(stream, &packet, auth_states, session_id, secret, peer)
            .await?
        {
            Some(s) => s,
            None => return Ok(LoopControl::Break),
        };
    let mut icam_groups: Vec<String> = Vec::new();
    let identity_source = if jit.is_some() {
        "jit"
    } else {
        resolve_identity_source(icam, ldap)
    };
    let reply = match process_authen_packet(
        &packet,
        state,
        policy,
        credentials,
        ldap,
        icam,
        device_flow,
        &mut icam_groups,
        ascii_cfg,
        peer,
        jit,
    )
    .await
    {
        Ok(r) => r,
        Err(ctrl) => return Ok(ctrl),
    };
    finalize_authentication(
        stream,
        &packet,
        reply,
        session_id,
        AuthStateSnapshot::from_state(state),
        auth_states,
        single_connect,
        single_connect_flag,
        icam_groups,
        identity_source,
        username_limiter,
        ip_limiter,
        connection_id,
        registry,
        policy,
        secret,
        peer,
    )
    .await
}

/// Read packet with optional timeout for single-connect keepalive.
async fn read_packet_with_keepalive<S>(
    stream: &mut S,
    secret: Option<&[u8]>,
    single_connect: &SingleConnectState,
    keepalive_deadline: u64,
    peer: &str,
) -> Result<Option<Packet>, anyhow::Error>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let read_future = read_packet(stream, secret);
    if single_connect.active && keepalive_deadline > 0 {
        match timeout(Duration::from_secs(keepalive_deadline), read_future).await {
            Ok(res) => res,
            Err(_) => {
                warn!(peer = %peer, idle_secs = keepalive_deadline,
                    "single-connect keepalive/idle timeout reached; closing");
                audit_event(
                    "conn_close",
                    peer,
                    "",
                    0,
                    "error",
                    "keepalive-timeout",
                    &format!("idle_secs={keepalive_deadline}"),
                );
                Err(anyhow::anyhow!("keepalive timeout"))
            }
        }
    } else {
        read_future.await
    }
}

// NASA-RULE4-EXEMPT: length is driven by 15-param dispatch signature, not logic complexity
/// Dispatch packet to appropriate handler and return loop control.
#[allow(clippy::too_many_arguments)]
async fn dispatch_packet_to_handler<S>(
    stream: &mut S,
    packet: Packet,
    auth_states: &mut HashMap<u32, AuthSessionState>,
    single_connect: &mut SingleConnectState,
    task_tracker: &mut TaskIdTracker,
    connection_id: u64,
    registry: &Arc<SessionRegistry>,
    policy: &Arc<RwLock<PolicyEngine>>,
    credentials: &Arc<StaticCreds>,
    ldap: &Option<Arc<LdapConfig>>,
    icam: &Option<Arc<IcamConfig>>,
    device_flow: &Option<Arc<DeviceFlowConfig>>,
    username_limiter: &Arc<crate::username_limiter::UsernameRateLimiter>,
    ip_limiter: &Arc<crate::ip_limiter::IpRateLimiter>,
    ascii_cfg: &AsciiConfig,
    secret: Option<&[u8]>,
    peer: &str,
    jit: Option<&JitNadAuthenticator>,
) -> Result<LoopControl>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    match packet {
        Packet::Authorization(request) => {
            handle_authorization_packet(
                stream,
                &request,
                single_connect,
                policy,
                ldap,
                secret,
                peer,
            )
            .await
        }
        Packet::Authentication(packet) => {
            handle_authentication_packet(
                stream,
                packet,
                auth_states,
                single_connect,
                connection_id,
                registry,
                policy,
                credentials,
                ldap,
                icam,
                device_flow,
                username_limiter,
                ip_limiter,
                ascii_cfg,
                secret,
                peer,
                jit,
            )
            .await
        }
        Packet::Capability(cap) => {
            handle_capability_packet(stream, &cap, peer, secret)
                .await
                .ok();
            Ok(LoopControl::Continue)
        }
        Packet::Accounting(req) => {
            handle_accounting_packet(stream, &req, single_connect, task_tracker, secret, peer).await
        }
    }
}

/// Handle errors from packet reading (client close or read error).
fn handle_packet_read_error(err: anyhow::Error, peer: &str) -> Result<()> {
    warn!(error = %err, peer = %peer, "failed to read TACACS+ packet");
    audit_event(
        "conn_close",
        peer,
        "",
        0,
        "error",
        "read-error",
        &err.to_string(),
    );
    Ok(())
}

/// Main packet processing loop for a TACACS+ connection.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-12 | Session Termination | Checks for API-initiated termination |
/// | AU-12 | Audit Generation | Connection close events logged |
#[allow(clippy::too_many_arguments)]
fn calculate_keepalive_deadline(
    single_connect_idle_secs: u64,
    single_connect_keepalive_secs: u64,
) -> u64 {
    if single_connect_keepalive_secs > 0 {
        single_connect_keepalive_secs
    } else {
        single_connect_idle_secs
    }
}

fn handle_client_close(peer: &str) {
    debug!(peer = %peer, "client closed connection");
    audit_event("conn_close", peer, "", 0, "info", "client-close", "");
}

async fn check_api_termination(
    registry: &Arc<SessionRegistry>,
    connection_id: u64,
    peer: &str,
) -> bool {
    if registry.is_termination_requested(connection_id).await {
        info!(peer = %peer, connection_id = connection_id, "session terminated via API");
        audit_event(
            "conn_close",
            peer,
            "",
            0,
            "info",
            "api-terminated",
            "session terminated via management API",
        );
        true
    } else {
        false
    }
}

/// Read the next packet, applying an optional per-packet timeout (NIST SC-5).
///
/// Returns `Ok(None)` when the connection should close cleanly.
async fn read_packet_guarded<S>(
    stream: &mut S,
    secret: Option<&[u8]>,
    single_connect: &SingleConnectState,
    deadline: u64,
    timeout_secs: u64,
    peer: &str,
) -> Result<Option<Packet>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let future = read_packet_with_keepalive(stream, secret, single_connect, deadline, peer);
    let result = if timeout_secs > 0 && !single_connect.active {
        match timeout(Duration::from_secs(timeout_secs), future).await {
            Ok(r) => r,
            Err(_) => {
                warn!(peer = %peer, timeout_secs, "packet read timeout exceeded (SC-5)");
                return Ok(None);
            }
        }
    } else {
        future.await
    };
    match result {
        Ok(Some(p)) => Ok(Some(p)),
        Ok(None) => {
            handle_client_close(peer);
            Ok(None)
        }
        Err(e) => {
            handle_packet_read_error(e, peer)?;
            Ok(None)
        }
    }
}

#[allow(clippy::too_many_arguments)]
// NASA-RULE4-EXEMPT: length driven by 15-param dispatch fan-out, not logic complexity
async fn connection_loop<S>(
    stream: &mut S,
    connection_id: u64,
    auth_states: &mut HashMap<u32, AuthSessionState>,
    single_connect: &mut SingleConnectState,
    task_tracker: &mut TaskIdTracker,
    registry: &Arc<SessionRegistry>,
    policy: &Arc<RwLock<PolicyEngine>>,
    credentials: &Arc<StaticCreds>,
    ldap: &Option<Arc<LdapConfig>>,
    icam: &Option<Arc<IcamConfig>>,
    device_flow: &Option<Arc<DeviceFlowConfig>>,
    username_limiter: &Arc<crate::username_limiter::UsernameRateLimiter>,
    ip_limiter: &Arc<crate::ip_limiter::IpRateLimiter>,
    ascii_cfg: &AsciiConfig,
    secret: Option<&[u8]>,
    peer: &str,
    single_connect_idle_secs: u64,
    single_connect_keepalive_secs: u64,
    packet_read_timeout_secs: u64,
    jit: Option<&JitNadAuthenticator>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        let deadline =
            calculate_keepalive_deadline(single_connect_idle_secs, single_connect_keepalive_secs);
        let Some(packet) = read_packet_guarded(
            stream,
            secret,
            single_connect,
            deadline,
            packet_read_timeout_secs,
            peer,
        )
        .await?
        else {
            break;
        };
        let ctrl = dispatch_packet_to_handler(
            stream,
            packet,
            auth_states,
            single_connect,
            task_tracker,
            connection_id,
            registry,
            policy,
            credentials,
            ldap,
            icam,
            device_flow,
            username_limiter,
            ip_limiter,
            ascii_cfg,
            secret,
            peer,
            jit,
        )
        .await;
        if matches!(ctrl, Ok(LoopControl::Break) | Err(_)) {
            break;
        }
        if check_api_termination(registry, connection_id, peer).await {
            break;
        }
        registry.record_activity(connection_id).await;
    }
    Ok(())
}

/// Handle a single TACACS+ connection.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-10 | Concurrent Session Control | Registers connection with session registry |
/// | AC-12 | Session Termination | Checks for termination requests and unregisters on close |
/// | AU-2/AU-12 | Audit Events | Connection lifecycle logging |
async fn handle_connection<S>(
    mut stream: S,
    peer_addr: SocketAddr,
    auth_ctx: AuthContext,
    conn_cfg: &ConnectionConfig,
    _guard: ConnGuard,
    registry: Arc<SessionRegistry>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let connection_id = initialize_connection(peer_addr, &registry).await?;
    if connection_id == 0 {
        return Ok(()); // Session limit exceeded, already logged
    }
    let peer = peer_addr.to_string();

    // Extract references for convenience
    let policy = &auth_ctx.policy;
    let secret = &auth_ctx.secret;
    let credentials = &auth_ctx.credentials;
    let ldap = &auth_ctx.ldap;
    let icam = &auth_ctx.icam;
    let device_flow = &auth_ctx.device_flow;
    let jit = match (
        auth_ctx.jit_lease_store.clone(),
        auth_ctx.jit_nad_identity.clone(),
    ) {
        (Some(store), Some(nad_identity)) => Some(JitNadAuthenticator::new(store, nad_identity)),
        _ => None,
    };
    let username_limiter = auth_ctx.username_limiter.clone();
    let ip_limiter = auth_ctx.ip_limiter.clone();
    // Audit HMAC key is initialized once at startup in run_server (AU-9), not
    // per-connection, so the first conn_open event is already signed.
    let single_connect_idle_secs = conn_cfg.single_connect_idle_secs;
    let single_connect_keepalive_secs = conn_cfg.single_connect_keepalive_secs;
    let packet_read_timeout_secs = conn_cfg.packet_read_timeout_secs;
    let ascii_cfg = &conn_cfg.ascii;

    use std::collections::HashMap;
    let mut auth_states: HashMap<u32, AuthSessionState> = HashMap::new();
    let mut single_connect = SingleConnectState::default();
    let mut task_tracker = TaskIdTracker::default();

    connection_loop(
        &mut stream,
        connection_id,
        &mut auth_states,
        &mut single_connect,
        &mut task_tracker,
        &registry,
        policy,
        credentials,
        ldap,
        icam,
        device_flow,
        &username_limiter,
        &ip_limiter,
        ascii_cfg,
        secret.as_deref().map(|s| s.as_slice()),
        &peer,
        single_connect_idle_secs,
        single_connect_keepalive_secs,
        packet_read_timeout_secs,
        jit.as_ref(),
    )
    .await?;

    cleanup_connection(connection_id, &peer, &registry).await;
    Ok(())
}

/// Policy reload request from API or SIGHUP.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AU-12 | Audit Generation | Log reload source and result |
/// | CM-3 | Configuration Change Control | Audit trail for policy changes |
#[derive(Debug)]
pub enum PolicyReloadRequest {
    /// Reload policy from disk
    FromDisk {
        path: PathBuf,
        schema: Option<PathBuf>,
    },
    /// Load policy from JSON content (API upload)
    FromJson {
        content: String,
        schema: Option<PathBuf>,
    },
}

/// Request to reload TLS certificates from files.
///
/// Used to dynamically update server TLS certificates without restarting,
/// supporting EST certificate renewal and manual certificate rotation.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | CM-3 | Configuration Change Control | Audit trail for certificate changes |
/// | IA-5 | Authenticator Management | Certificate lifecycle management |
/// | SC-17 | PKI Certificates | Dynamic certificate reload |
#[derive(Debug)]
pub enum CertificateReloadRequest {
    /// Reload certificates from disk files
    FromFiles {
        cert_path: PathBuf,
        key_path: PathBuf,
        client_ca_path: PathBuf,
        extra_trust_roots: Vec<PathBuf>,
    },
}

/// Watch for certificate reload requests.
///
/// Monitors certificate reload requests and atomically updates the TLS acceptor
/// configuration when new certificates are available. Typically triggered by:
/// - EST certificate renewal
/// - Manual certificate rotation via API
/// - External certificate management systems
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | IA-5 | Authenticator Management | Automated certificate lifecycle |
/// | SC-17 | PKI Certificates | Hot-reload without service interruption |
/// | AU-12 | Audit Generation | Logs all reload attempts with outcome |
/// Update certificate metrics from PEM file.
///
/// Reads certificate and updates Prometheus metrics for expiration tracking.
fn update_certificate_metrics(cert_path: &PathBuf) {
    use tokio_rustls::rustls::pki_types::{CertificateDer, pem::PemObject};
    use x509_cert::Certificate;
    use x509_cert::der::Decode;

    let metrics = crate::metrics::metrics();

    // Try to read and parse certificate
    let cert_result = (|| -> Result<Certificate> {
        // Read first certificate from PEM
        let mut certs = CertificateDer::pem_file_iter(cert_path)
            .with_context(|| format!("opening certificate file {}", cert_path.display()))?;
        let cert_der = certs
            .next()
            .ok_or_else(|| anyhow::anyhow!("no certificate found in PEM file"))??;

        // Parse DER to x509
        Certificate::from_der(&cert_der)
            .map_err(|e| anyhow::anyhow!("failed to parse certificate: {}", e))
    })();

    match cert_result {
        Ok(cert) => {
            // Extract expiration time (notAfter)
            let not_after = cert.tbs_certificate.validity.not_after.to_unix_duration();
            let expiry_secs = not_after.as_secs();

            // Calculate days until expiration
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let days_remaining = if expiry_secs > now {
                ((expiry_secs - now) as f64) / 86400.0
            } else {
                0.0 // Expired
            };

            // Update metrics
            metrics.certificate_expiry_timestamp.set(expiry_secs as f64);
            metrics.certificate_validity_days.set(days_remaining);

            info!(
                expires_at = expiry_secs,
                days_remaining = %format!("{:.1}", days_remaining),
                "certificate metrics updated"
            );
        }
        Err(e) => {
            warn!(error = %e, cert_path = ?cert_path, "failed to parse certificate for metrics");
        }
    }
}

pub async fn watch_certificate_changes(
    mut reload_rx: tokio::sync::mpsc::Receiver<CertificateReloadRequest>,
    tls_acceptor: Arc<RwLock<TlsAcceptor>>,
) {
    info!("certificate reload watcher started");

    while let Some(request) = reload_rx.recv().await {
        match request {
            CertificateReloadRequest::FromFiles {
                cert_path,
                key_path,
                client_ca_path,
                extra_trust_roots,
            } => {
                match build_tls_config(&cert_path, &key_path, &client_ca_path, &extra_trust_roots) {
                    Ok(new_config) => {
                        *tls_acceptor.write().await = TlsAcceptor::from(Arc::new(new_config));
                        crate::metrics::metrics()
                            .certificate_renewal_total
                            .with_label_values(&["success", "reload"])
                            .inc();

                        // Update certificate expiration metrics
                        update_certificate_metrics(&cert_path);

                        info!(
                            cert_path = ?cert_path,
                            "TLS certificates reloaded successfully"
                        );
                    }
                    Err(err) => {
                        crate::metrics::metrics()
                            .certificate_renewal_total
                            .with_label_values(&["failure", "reload"])
                            .inc();
                        warn!(
                            error = %err,
                            cert_path = ?cert_path,
                            "failed to reload TLS certificates"
                        );
                    }
                }
            }
        }
    }

    info!("certificate reload watcher stopped");
}

/// Update policy metrics after successful reload.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AU-12 | Audit Generation | Record policy reload metrics |
fn update_policy_metrics(rule_count: usize) {
    crate::metrics::metrics()
        .policy_rules_count
        .set(rule_count as f64);
    crate::metrics::metrics()
        .policy_reload_total
        .with_label_values(&["success"])
        .inc();
}

/// Record policy reload failure in metrics.
fn record_policy_failure() {
    crate::metrics::metrics()
        .policy_reload_total
        .with_label_values(&["failure"])
        .inc();
}

/// Reload policy from disk file.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | CM-3 | Configuration Change Control | Load policy from file with validation |
async fn reload_policy_from_disk(
    path: &PathBuf,
    schema: &Option<PathBuf>,
    policy: &Arc<RwLock<PolicyEngine>>,
    source: &str,
) {
    match PolicyEngine::from_path(path, schema.as_ref()) {
        Ok(new_policy) => {
            let rule_count = new_policy.rule_count();
            *policy.write().await = new_policy;
            update_policy_metrics(rule_count);
            info!(
                source = source,
                rules = rule_count,
                "policy reloaded successfully"
            );
        }
        Err(err) => {
            record_policy_failure();
            warn!(source = source, error = %err, "failed to reload policy");
        }
    }
}

/// Reload policy from JSON string.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | CM-3 | Configuration Change Control | Load policy from JSON with validation |
async fn reload_policy_from_json(
    content: &str,
    schema: &Option<PathBuf>,
    policy: &Arc<RwLock<PolicyEngine>>,
    source: &str,
) {
    match PolicyEngine::from_json_str(content, schema.as_ref()) {
        Ok(new_policy) => {
            let rule_count = new_policy.rule_count();
            *policy.write().await = new_policy;
            update_policy_metrics(rule_count);
            info!(
                source = source,
                rules = rule_count,
                "policy uploaded successfully from JSON"
            );
        }
        Err(err) => {
            record_policy_failure();
            warn!(source = source, error = %err, "failed to load policy from JSON");
        }
    }
}

/// Handle policy reload request from any source.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | CM-3 | Configuration Change Control | Dispatch reload to appropriate handler |
async fn handle_policy_reload(
    request: &PolicyReloadRequest,
    policy: &Arc<RwLock<PolicyEngine>>,
    source: &str,
) {
    match request {
        PolicyReloadRequest::FromDisk { path, schema } => {
            reload_policy_from_disk(path, schema, policy, source).await;
        }
        PolicyReloadRequest::FromJson { content, schema } => {
            reload_policy_from_json(content, schema, policy, source).await;
        }
    }
}

/// Run policy watch loop with SIGHUP and channel support.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | CM-3 | Configuration Change Control | Multi-source policy reload event loop |
async fn run_policy_watch_loop(
    initial_path: PathBuf,
    schema: Option<PathBuf>,
    policy: Arc<RwLock<PolicyEngine>>,
    mut reload_rx: tokio::sync::mpsc::Receiver<PolicyReloadRequest>,
    mut sighup_stream: tokio::signal::unix::Signal,
) {
    info!("policy reload watcher started (SIGHUP + channel)");
    loop {
        tokio::select! {
            // Handle channel-based reload requests from API
            Some(request) = reload_rx.recv() => {
                handle_policy_reload(&request, &policy, "api").await;
            }
            // Handle SIGHUP for backward compatibility
            Some(_) = sighup_stream.recv() => {
                let request = PolicyReloadRequest::FromDisk {
                    path: initial_path.clone(),
                    schema: schema.clone(),
                };
                handle_policy_reload(&request, &policy, "sighup").await;
            }
        }
    }
}

/// Watch for policy changes from SIGHUP or internal channel.
///
/// This function handles both traditional SIGHUP-based reloads and
/// channel-based reloads from the Management API, providing a unified
/// policy update mechanism.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AU-12 | Audit Generation | Logs all reload attempts with source |
/// | CM-3 | Configuration Change Control | Handles policy updates from multiple sources |
pub async fn watch_policy_changes(
    initial_path: PathBuf,
    schema: Option<PathBuf>,
    policy: Arc<RwLock<PolicyEngine>>,
    mut reload_rx: tokio::sync::mpsc::Receiver<PolicyReloadRequest>,
) {
    match signal(SignalKind::hangup()) {
        Ok(sighup_stream) => {
            run_policy_watch_loop(initial_path, schema, policy, reload_rx, sighup_stream).await;
        }
        Err(err) => {
            warn!(error = %err, "failed to install SIGHUP handler, using channel-only mode");
            // Fall back to channel-only mode
            while let Some(request) = reload_rx.recv().await {
                handle_policy_reload(&request, &policy, "api").await;
            }
        }
    }
}

pub fn validate_policy(path: &PathBuf, schema: Option<&PathBuf>) -> Result<()> {
    let schema_path = schema.context("schema is required to validate policy")?;
    let document = validate_policy_file(path, schema_path)?;
    PolicyEngine::from_document(document)?;
    Ok(())
}

pub fn tls_acceptor(
    cert: &PathBuf,
    key: &PathBuf,
    ca: &PathBuf,
    extra_trust_roots: &[PathBuf],
) -> Result<TlsAcceptor> {
    let tls_config = build_tls_config(cert, key, ca, extra_trust_roots)?;
    Ok(TlsAcceptor::from(Arc::new(tls_config)))
}

/// Single-connect validation tests for authorization and accounting.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-3 | Access Enforcement | Standalone authz/acct permitted per RFC 8907 |
/// | IA-11 | Re-authentication | User-binding consistency enforced across sessions |
#[cfg(test)]
mod audit_signing_tests {
    use super::*;

    const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";

    #[test]
    fn canonical_fields_include_identity_source() {
        // identity_source must be part of the signed input, else it could be
        // tampered with undetected (AU-9).
        let fields = audit_canonical_fields(
            "authn_terminal",
            "1.2.3.4:1",
            "alice",
            7,
            "pass",
            "terminal",
            "type=pap",
            "icam",
        );
        assert!(
            fields.ends_with("|icam"),
            "identity_source missing: {fields}"
        );
        assert_eq!(
            fields.matches('|').count(),
            7,
            "expected 8 pipe-delimited fields"
        );
    }

    #[test]
    fn hmac_covers_identity_source() {
        // Two records identical except for identity_source MUST produce
        // different signatures, proving the field is authenticated.
        let base = |src: &str| {
            let f = audit_canonical_fields(
                "authn_terminal",
                "1.2.3.4:1",
                "alice",
                7,
                "pass",
                "terminal",
                "type=pap",
                src,
            );
            compute_audit_hmac(KEY, &f)
        };
        assert_ne!(base("icam"), base("local"));
    }

    #[test]
    fn hmac_is_deterministic() {
        let f = audit_canonical_fields(
            "conn_open",
            "1.2.3.4:1",
            "",
            0,
            "info",
            "open",
            "connection started",
            "",
        );
        assert_eq!(compute_audit_hmac(KEY, &f), compute_audit_hmac(KEY, &f));
    }

    #[test]
    fn no_raw_tacacs_audit_emissions_outside_emitter() {
        // Regression guard for AU-9: every audit record must flow through
        // emit_audit_event so it is HMAC-signed. The audit tracing target
        // literal may appear only in the two info! branches inside
        // emit_audit_event itself; a new raw emission elsewhere would produce
        // an unsigned, forgeable record and must fail this test. (This comment
        // deliberately avoids writing the literal so it is not self-counted.)
        let src = include_str!("server.rs");
        let needle = format!("target: {}tacacs_audit{}", '"', '"');
        let count = src.matches(&needle).count();
        assert_eq!(
            count, 2,
            "found {count} `target: \"tacacs_audit\"` sites; expected exactly 2 \
             (both inside emit_audit_event). Route new audit events through \
             emit_audit_event so they are signed (AU-9)."
        );
    }
}

#[cfg(test)]
mod lockout_message_tests {
    use super::*;

    fn fail(msg: &str) -> AuthenReply {
        AuthenReply {
            status: AUTHEN_STATUS_FAIL,
            flags: 0,
            server_msg: msg.into(),
            server_msg_raw: vec![1, 2, 3],
            data: Vec::new(),
        }
    }

    #[test]
    fn lockout_message_is_masked_as_generic_failure() {
        // #7: a locked-out reply must be indistinguishable from a normal
        // credential failure on the wire.
        let mut r = fail("authentication locked out");
        sanitize_locked_out_message(&mut r, "invalid credentials");
        assert_eq!(r.server_msg, "invalid credentials");
        assert!(r.server_msg_raw.is_empty());
        assert_eq!(r.status, AUTHEN_STATUS_FAIL);
    }

    #[test]
    fn ordinary_failure_is_unchanged() {
        let mut r = fail("invalid credentials");
        sanitize_locked_out_message(&mut r, "invalid credentials");
        assert_eq!(r.server_msg, "invalid credentials");
    }

    #[test]
    fn non_fail_reply_is_unchanged() {
        // A PASS that somehow mentions lockout must not be rewritten.
        let mut r = AuthenReply {
            status: AUTHEN_STATUS_PASS,
            flags: 0,
            server_msg: "locked out".into(),
            server_msg_raw: Vec::new(),
            data: Vec::new(),
        };
        sanitize_locked_out_message(&mut r, "invalid credentials");
        assert_eq!(r.server_msg, "locked out");
    }

    #[test]
    fn parse_peer_ip_handles_v4_v6_and_mapped() {
        assert_eq!(
            parse_peer_ip("10.0.100.7:5000"),
            Some("10.0.100.7".parse().unwrap())
        );
        // IPv4-mapped IPv6 normalizes to the v4 form (matches ConnLimiter keys).
        assert_eq!(
            parse_peer_ip("[::ffff:10.0.100.7]:49"),
            Some("10.0.100.7".parse().unwrap())
        );
        assert_eq!(
            parse_peer_ip("[2601:443:c200:570::5]:300"),
            Some("2601:443:c200:570::5".parse().unwrap())
        );
        assert_eq!(parse_peer_ip("not-a-socket-addr"), None);
    }
}

#[cfg(test)]
mod acct_semantics_tests {
    use super::*;
    use usg_tacacs_proto::{ACCT_FLAG_STOP, AccountingRequest};

    #[test]
    fn cisco_command_stop_passes_semantics() {
        // service=shell + cmd + task_id + priv-lvl + start_time, no
        // elapsed_time/status/bytes — must pass (was rejected as
        // acct_semantic_reject / acct_error before the fix).
        let req = AccountingRequest::builder(123, ACCT_FLAG_STOP)
            .with_service("shell")
            .with_task_id("4321")
            .add_arg("cmd=show running-config".to_string())
            .add_arg("priv-lvl=15".to_string())
            .add_arg("start_time=1717689600".to_string());
        assert!(validate_accounting_semantics(&req).is_ok());
    }

    #[test]
    fn stop_without_task_id_is_rejected() {
        let req = AccountingRequest::builder(123, ACCT_FLAG_STOP).with_service("shell");
        let err = validate_accounting_semantics(&req).unwrap_err();
        assert!(err.contains("task_id"));
    }

    // ============ Vendor-service (PaloAlto) authorization ============

    const PALOALTO_POLICY: &str = r#"{
        "default_allow": false,
        "rules": [],
        "author_service_attributes": {
            "paloalto": { "groups": { "netops": ["PaloAlto-Admin-Role=superuser"] } }
        }
    }"#;

    #[test]
    fn vendor_service_semantics_accepts_configured_paloalto() {
        // Real PAN-OS shape: service=PaloAlto, protocol=firewall, no cmd.
        let req = AuthorizationRequest::builder(123)
            .with_service("PaloAlto")
            .with_protocol("firewall");
        let services = vec!["paloalto".to_string()];
        assert!(validate_authorization_semantics(&req, &services).is_ok());
        // Unknown unless the service is configured.
        assert!(validate_authorization_semantics(&req, &[]).is_err());
    }

    #[test]
    fn vendor_service_returns_role_for_group() {
        let engine = PolicyEngine::from_json_str(PALOALTO_POLICY, None::<&str>).unwrap();
        let req = AuthorizationRequest::builder(123)
            .with_service("PaloAlto")
            .with_protocol("firewall")
            .with_user("operator".to_string());
        let groups = vec!["netops".to_string()];
        let resp = authorize_vendor_service(&req, &engine, &groups, "PaloAlto", "10.0.100.52:49");
        assert_eq!(resp.status, AUTHOR_STATUS_PASS_ADD);
        assert!(
            resp.args
                .contains(&"PaloAlto-Admin-Role=superuser".to_string())
        );
    }

    #[test]
    fn vendor_service_denies_unmapped_group() {
        let engine = PolicyEngine::from_json_str(PALOALTO_POLICY, None::<&str>).unwrap();
        let req = AuthorizationRequest::builder(123)
            .with_service("PaloAlto")
            .with_user("bob".to_string());
        let groups = vec!["helpdesk".to_string()];
        let resp = authorize_vendor_service(&req, &engine, &groups, "PaloAlto", "10.0.100.52:49");
        assert_eq!(resp.status, AUTHOR_STATUS_FAIL);
        assert!(resp.args.is_empty());
    }

    #[test]
    fn author_service_name_extracts_service() {
        let req = AuthorizationRequest::builder(123).with_service("PaloAlto");
        assert_eq!(author_service_name(&req).as_deref(), Some("PaloAlto"));
    }

    #[test]
    fn vendor_service_empty_user_denied_not_panicked() {
        // RFC validation does not require a user; the vendor path must deny
        // gracefully (not panic in the policy resolver) when user is empty.
        let engine = PolicyEngine::from_json_str(PALOALTO_POLICY, None::<&str>).unwrap();
        let req = AuthorizationRequest::builder(123).with_service("PaloAlto");
        assert!(req.user.is_empty(), "precondition: empty user");
        let resp = authorize_vendor_service(&req, &engine, &[], "PaloAlto", "10.0.100.52:49");
        assert_eq!(resp.status, AUTHOR_STATUS_FAIL);
        assert!(resp.args.is_empty());
    }

    #[test]
    fn rfc_known_service_is_not_a_vendor_service() {
        // Guard for the dispatch: shell/login/etc. are RFC-known, so even if
        // mis-configured under author_service_attributes they are never routed
        // to the vendor path (which is gated on !is_known_service).
        assert!(usg_tacacs_proto::header::is_known_service("shell"));
        assert!(usg_tacacs_proto::header::is_known_service("login"));
        assert!(!usg_tacacs_proto::header::is_known_service("paloalto"));
    }
}

#[cfg(test)]
mod single_connect_validation_tests {
    use super::*;
    use usg_tacacs_proto::{FLAG_SINGLE_CONNECT, Header};

    fn header(flags: u8) -> Header {
        Header {
            version: 0xc0,
            packet_type: 2,
            seq_no: 1,
            flags,
            session_id: 4242,
            length: 0,
        }
    }

    fn authz_req(user: &str, single_connect: bool) -> AuthorizationRequest {
        let flags = if single_connect {
            FLAG_SINGLE_CONNECT
        } else {
            0
        };
        AuthorizationRequest {
            header: header(flags),
            authen_method: 6,
            priv_lvl: 15,
            authen_type: 1,
            authen_service: 1,
            user: user.to_string(),
            port: "tty0".into(),
            rem_addr: "10.0.0.1".into(),
            args: vec!["service=shell".into(), "cmd=show".into()],
        }
    }

    fn acct_req(user: &str, single_connect: bool) -> AccountingRequest {
        let flags = if single_connect {
            FLAG_SINGLE_CONNECT
        } else {
            0
        };
        AccountingRequest {
            header: header(flags),
            flags: ACCT_FLAG_START,
            authen_method: 6,
            priv_lvl: 15,
            authen_type: 1,
            authen_service: 1,
            user: user.to_string(),
            port: "tty0".into(),
            rem_addr: "10.0.0.1".into(),
            args: vec!["service=shell".into()],
        }
    }

    fn bound_state(user: &str) -> SingleConnectState {
        let mut s = SingleConnectState::default();
        s.activate(user.to_string(), 4242);
        assert!(s.active, "bound state must be active");
        assert!(s.user.is_some(), "bound state must carry a user");
        s
    }

    /// Regression: a single-connect authorization request on a connection with no
    /// prior authentication (e.g. `aaa authorization commands` over a fresh
    /// connection) MUST be permitted — it carries its own user for policy.
    #[test]
    fn standalone_authz_no_bound_user_is_allowed() {
        let state = SingleConnectState::default();
        assert!(state.user.is_none(), "precondition: no bound user");
        let result =
            validate_authz_single_connect(&state, &authz_req("operator", true), "10.0.0.1:49");
        assert!(
            result.is_none(),
            "standalone authz must be allowed, got {result:?}"
        );
    }

    /// Regression: a standalone single-connect accounting record (no prior authn
    /// on the connection) MUST be permitted.
    #[test]
    fn standalone_acct_no_bound_user_is_allowed() {
        let state = SingleConnectState::default();
        assert!(state.user.is_none(), "precondition: no bound user");
        let result =
            validate_acct_single_connect(&state, &acct_req("operator", true), "10.0.0.1:49");
        assert!(
            result.is_none(),
            "standalone acct must be allowed, got {result:?}"
        );
    }

    /// A bound connection still rejects an authz request for a different user.
    #[test]
    fn authz_user_mismatch_still_rejected() {
        let state = bound_state("alice");
        let result = validate_authz_single_connect(&state, &authz_req("bob", true), "10.0.0.1:49");
        let msg = result.expect("user mismatch must be rejected");
        assert!(
            msg.contains("mismatch"),
            "expected mismatch error, got {msg}"
        );
    }

    /// A bound connection still rejects an accounting record for a different user.
    #[test]
    fn acct_user_mismatch_still_rejected() {
        let state = bound_state("alice");
        let result = validate_acct_single_connect(&state, &acct_req("bob", true), "10.0.0.1:49");
        let msg = result.expect("user mismatch must be rejected");
        assert!(
            msg.contains("mismatch"),
            "expected mismatch error, got {msg}"
        );
    }

    /// An active single-connect session still requires the flag on authz packets.
    #[test]
    fn authz_missing_flag_when_active_is_rejected() {
        let state = bound_state("alice");
        assert!(state.active, "precondition: session active");
        let result =
            validate_authz_single_connect(&state, &authz_req("alice", false), "10.0.0.1:49");
        assert!(
            result.is_some(),
            "missing single-connect flag must be rejected"
        );
    }

    /// A matching bound user with the flag set is allowed (happy path).
    #[test]
    fn authz_matching_bound_user_is_allowed() {
        let state = bound_state("alice");
        let result =
            validate_authz_single_connect(&state, &authz_req("alice", true), "10.0.0.1:49");
        assert!(
            result.is_none(),
            "matching bound user must be allowed, got {result:?}"
        );
    }
}

/// Command-authorization response-format tests.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AC-3 | Access Enforcement | Permitted commands return a portable PASS_ADD |
#[cfg(test)]
mod authz_response_format_tests {
    use super::*;
    use usg_tacacs_proto::Header;

    fn cmd_authz_req() -> AuthorizationRequest {
        AuthorizationRequest {
            header: Header {
                version: 0xc0,
                packet_type: 2,
                seq_no: 1,
                flags: 0,
                session_id: 7,
                length: 0,
            },
            authen_method: 6,
            priv_lvl: 15,
            authen_type: 1,
            authen_service: 1,
            user: "operator".into(),
            port: "tty0".into(),
            rem_addr: "10.0.0.1".into(),
            args: vec![
                "service=shell".into(),
                "cmd=configure".into(),
                "cmd-arg=terminal".into(),
            ],
        }
    }

    /// A permitted command must be PASS_ADD with NO av-pairs. PASS_REPL while
    /// echoing the command back makes Cisco IOS silently refuse the command.
    #[test]
    fn command_allow_is_pass_add_with_no_args() {
        let req = cmd_authz_req();
        let resp = build_authz_allow_response(
            &req,
            Some("allow-netops".into()),
            &["netops".into()],
            "service=shell",
            "10.0.0.1:49",
        );
        assert_eq!(
            resp.status, AUTHOR_STATUS_PASS_ADD,
            "command allow must be PASS_ADD"
        );
        assert!(
            resp.args.is_empty(),
            "command allow must carry no av-pairs, got {:?}",
            resp.args
        );
    }

    /// The audit/reason metadata still records the matched rule and groups.
    #[test]
    fn command_allow_records_rule_and_groups() {
        let req = cmd_authz_req();
        let resp = build_authz_allow_response(
            &req,
            Some("allow-netops".into()),
            &["netops".into()],
            "service=shell",
            "10.0.0.1:49",
        );
        assert!(
            resp.data.contains("rule=allow-netops"),
            "data must record the matched rule"
        );
        assert!(
            resp.data.contains("groups=netops"),
            "data must record resolved groups"
        );
    }
}
