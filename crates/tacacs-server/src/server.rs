// SPDX-License-Identifier: Apache-2.0
//! TACACS+ server connection handling and session management.
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
    AsciiConfig, calc_ascii_backoff_capped, field_for_policy, handle_ascii_continue,
    username_for_policy,
};
use crate::auth::{
    LdapConfig, handle_chap_continue, ldap_fetch_groups, verify_pap, verify_pap_bytes,
    verify_pap_bytes_username, verify_password_sources,
};
use crate::config::StaticCreds;
use crate::policy::enforce_server_msg;
use crate::session::{SingleConnectState, TaskIdTracker};
use crate::session_registry::SessionRegistry;
use crate::tls::build_tls_config;
use anyhow::{Context, Result};
use openssl::nid::Nid;
use openssl::rand::rand_bytes;
use openssl::x509::X509;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
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
    AUTHOR_STATUS_ERROR, AUTHOR_STATUS_FAIL, AUTHOR_STATUS_PASS_ADD, AUTHOR_STATUS_PASS_REPL,
    AccountingRequest, AccountingResponse, AuthSessionState, AuthenData, AuthenPacket, AuthenReply,
    AuthorizationRequest, AuthorizationResponse, CAPABILITY_FLAG_REQUEST, CAPABILITY_FLAG_RESPONSE,
    Capability, Packet, read_packet, validate_accounting_response_header,
    validate_author_response_header, write_accounting_response, write_authen_reply,
    write_author_response,
};

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
    counts: Arc<Mutex<HashMap<String, u32>>>,
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
    async fn try_acquire(&self, ip: &str) -> Option<ConnGuard> {
        if self.max_per_ip == 0 {
            return Some(ConnGuard {
                ip: ip.to_string(),
                limiter: self.clone(),
            });
        }
        let mut map = self.counts.lock().await;
        let entry = map.entry(ip.to_string()).or_insert(0);
        // NIST AC-10: Reject if connection limit exceeded
        if *entry >= self.max_per_ip {
            return None;
        }
        *entry += 1;
        drop(map);
        Some(ConnGuard {
            ip: ip.to_string(),
            limiter: self.clone(),
        })
    }

    async fn release(&self, ip: &str) {
        let mut map = self.counts.lock().await;
        if let Some(v) = map.get_mut(ip)
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
    ip: String,
    limiter: ConnLimiter,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let ip = self.ip.clone();
        let limiter = self.limiter.clone();
        tokio::spawn(async move {
            limiter.release(&ip).await;
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
) -> Result<()> {
    // NIST IA-3: Skip if no allowlists configured (allow all valid certs)
    if allowed_cn.is_empty() && allowed_san.is_empty() {
        return Ok(());
    }
    let (_, conn) = stream.get_ref();
    let certs = conn
        .peer_certificates()
        .ok_or_else(|| anyhow::anyhow!("missing client certificate"))?;
    let leaf = certs
        .first()
        .ok_or_else(|| anyhow::anyhow!("no client certificate presented"))?;
    let x509 = X509::from_der(leaf.as_ref())
        .with_context(|| format!("parsing client certificate from {peer}"))?;
    let mut names: Vec<String> = Vec::new();
    for entry in x509.subject_name().entries_by_nid(Nid::COMMONNAME) {
        if let Ok(val) = entry.data().as_utf8() {
            names.push(val.to_string());
        }
    }
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
    let mut allowed = false;
    for n in &names {
        if allowed_cn.iter().any(|a| a == n) || allowed_san.iter().any(|a| a == n) {
            allowed = true;
            break;
        }
    }
    if !allowed {
        Err(anyhow::anyhow!(
            "client certificate identity not allowed: {:?}",
            names
        ))
    } else {
        Ok(())
    }
}

fn audit_event(
    event: &str,
    peer: &str,
    user: &str,
    session: u32,
    status: &str,
    reason: &str,
    data: &str,
) {
    info!(
        target: "tacacs_audit",
        event,
        peer = %peer,
        user = %user,
        session = session,
        status = %status,
        reason = %reason,
        data = %data,
        "audit event"
    );
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

fn authz_allow_attrs(req: &AuthorizationRequest) -> Vec<String> {
    let mut out = Vec::new();
    out.push(format!("priv-lvl={}", req.priv_lvl));
    let attrs = req.attributes();
    if let Some(service) = attrs
        .iter()
        .find(|a| a.name.eq_ignore_ascii_case("service"))
        .and_then(|a| a.value.as_deref())
    {
        out.push(format!("service={service}"));
    }
    if let Some(protocol) = attrs
        .iter()
        .find(|a| a.name.eq_ignore_ascii_case("protocol"))
        .and_then(|a| a.value.as_deref())
    {
        out.push(format!("protocol={protocol}"));
    }
    for attr in attrs.iter().filter(|a| a.name.eq_ignore_ascii_case("cmd")) {
        if let Some(val) = attr.value.as_deref() {
            out.push(format!("cmd={val}"));
        }
    }
    for attr in attrs
        .iter()
        .filter(|a| a.name.eq_ignore_ascii_case("cmd-arg"))
    {
        if let Some(val) = attr.value.as_deref() {
            out.push(format!("cmd-arg={val}"));
        }
    }
    out
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

fn validate_accounting_semantics(req: &AccountingRequest) -> Result<(), &'static str> {
    let is_start = req.flags & ACCT_FLAG_START != 0;
    let is_stop = req.flags & ACCT_FLAG_STOP != 0;
    let is_watchdog = req.flags & ACCT_FLAG_WATCHDOG != 0;
    // RFC expects one of the flags; parse already enforced exclusivity.
    if (is_start || is_stop || is_watchdog) && req.args.is_empty() {
        return Err("accounting records require attributes");
    }
    let attrs = req.attributes();
    let has_service_or_cmd = attrs.iter().any(|a| {
        let name = a.name.as_str();
        name.eq_ignore_ascii_case("service")
            || name.eq_ignore_ascii_case("cmd")
            || name.eq_ignore_ascii_case("cmd-arg")
    });
    if !has_service_or_cmd {
        return Err("accounting requires service or command attributes");
    }
    let has_task = attrs.iter().any(|a| a.name.eq_ignore_ascii_case("task_id"));
    let has_elapsed = attrs
        .iter()
        .any(|a| a.name.eq_ignore_ascii_case("elapsed_time"));
    let has_status = attrs.iter().any(|a| a.name.eq_ignore_ascii_case("status"));
    let has_bytes_in = attrs
        .iter()
        .any(|a| a.name.eq_ignore_ascii_case("bytes_in"));
    let has_bytes_out = attrs
        .iter()
        .any(|a| a.name.eq_ignore_ascii_case("bytes_out"));
    if is_start && !has_task {
        return Err("start accounting requires task_id attribute");
    }
    if is_stop && (!has_task || !has_elapsed || !has_status) {
        return Err("stop accounting requires task_id, elapsed_time, and status attributes");
    }
    if is_stop && (!has_bytes_in || !has_bytes_out) {
        return Err("stop accounting requires bytes_in and bytes_out attributes");
    }
    if is_watchdog && !has_task {
        return Err("watchdog accounting requires task_id attribute");
    }
    // Numeric fields should be valid unsigned integers and within expected ranges.
    let mut status_val: Option<u32> = None;
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
    if has_task {
        parse_u32("task_id")?;
    }
    if has_elapsed {
        parse_u32("elapsed_time")?;
    }
    if has_status {
        status_val = parse_u32("status")?;
    }
    if let Some(code) = status_val {
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

struct AuthzSemanticError {
    msg: &'static str,
    offending_index: Option<usize>,
}

fn validate_authorization_semantics(req: &AuthorizationRequest) -> Result<(), AuthzSemanticError> {
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
    if !usg_tacacs_proto::header::is_known_service(service_val) {
        return Err(AuthzSemanticError {
            msg: "authorization service attribute value unknown",
            offending_index: None,
        });
    }

    let protocol_attr = attrs
        .iter()
        .find(|a| a.name.eq_ignore_ascii_case("protocol"));
    let cmd_attrs: Vec<_> = attrs
        .iter()
        .filter(|a| a.name.eq_ignore_ascii_case("cmd"))
        .collect();
    let cmd_arg_attrs: Vec<_> = attrs
        .iter()
        .filter(|a| a.name.eq_ignore_ascii_case("cmd-arg"))
        .collect();

    if service_val.eq_ignore_ascii_case("shell") {
        if protocol_attr.is_none() {
            return Err(AuthzSemanticError {
                msg: "shell authorization requires protocol attribute",
                offending_index: None,
            });
        }
        if let Some(proto) = protocol_attr.and_then(|p| p.value.as_deref())
            && proto.is_empty()
        {
            return Err(AuthzSemanticError {
                msg: "authorization protocol attribute must have a value",
                offending_index: None,
            });
        }
        if !cmd_attrs.is_empty() || !cmd_arg_attrs.is_empty() {
            return Err(AuthzSemanticError {
                msg: "shell authorization must not include cmd/cmd-arg attributes",
                offending_index: None,
            });
        }
        return Ok(());
    }

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
    // Enforce service attribute appears before command attributes in the arg list.
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
    // Optional priv-lvl attribute must be numeric and match header priv.
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
            let peer_ip = peer_addr.ip().to_string();
            let guard = match conn_cfg.conn_limiter.try_acquire(&peer_ip).await {
                Some(g) => g,
                None => {
                    warn!(peer = %peer_addr, "connection rejected: per-peer limit exceeded");
                    return;
                }
            };
            match conn_acceptor.accept(socket).await {
                Ok(stream) => {
                    if let Err(err) = enforce_client_cert_policy(
                        &stream,
                        &peer_addr,
                        &conn_tls_identity.allowed_cn,
                        &conn_tls_identity.allowed_san,
                    ) {
                        warn!(error = %err, peer = %peer_addr, "TLS client cert rejected");
                        return;
                    }
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
pub async fn serve_legacy(
    addr: SocketAddr,
    auth_ctx: AuthContext,
    conn_cfg: ConnectionConfig,
    nad_secrets: Arc<HashMap<IpAddr, Arc<Vec<u8>>>>,
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
        let conn_registry = registry.clone();
        tokio::spawn(async move {
            let peer_ip = peer_addr.ip().to_string();
            let guard = match conn_cfg.conn_limiter.try_acquire(&peer_ip).await {
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
                conn_nad_secrets.get(&peer_addr.ip()).cloned()
            };
            if conn_secret.is_none() {
                warn!(peer = %peer_addr, "legacy connection rejected: NAD not in allowlist");
                return;
            }
            // Create a modified auth context with the per-NAD secret
            let per_nad_auth_ctx = AuthContext {
                policy: conn_auth_ctx.policy.clone(),
                secret: conn_secret,
                credentials: conn_auth_ctx.credentials.clone(),
                ldap: conn_auth_ctx.ldap.clone(),
            };
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
async fn cleanup_connection(
    connection_id: u64,
    peer: &str,
    registry: &Arc<SessionRegistry>,
) {
    // NIST AC-10: Unregister connection from session registry
    registry.unregister_connection(connection_id).await;
    audit_event("conn_close", peer, "", 0, "info", "loop-exit", "");
}

/// Validate single-connect constraints for authorization requests.
///
/// Returns error message if validation fails, None if validation passes.
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

    if let Some(bound) = single_connect.session {
        if bound != request.header.session_id {
            warn!(peer = %peer, user = %request.user, session = request.header.session_id,
                bound_session = bound, "single-connect violation: session-id mismatch on authorization");
            return Some("session-id mismatch".into());
        }
    }

    if let Some(ref bound_user) = single_connect.user {
        if bound_user != &request.user {
            warn!(peer = %peer, user = %request.user, bound_user = %bound_user,
                session = request.header.session_id, "single-connect violation: user mismatch on authorization");
            return Some("single-connection user mismatch".into());
        }
    } else {
        warn!(peer = %peer, user = %request.user, session = request.header.session_id,
            "single-connect violation: authorization before authentication");
        return Some("single-connection not authenticated".into());
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

        if let Some(bound) = single_connect.session {
            if bound != start.header.session_id {
                warn!(peer = %peer, user = %start.user, session = session_id,
                    bound_session = bound, "single-connect violation: session-id mismatch on authentication");
                return Some("session-id mismatch".into());
            }
        }
    }

    None
}

/// Validate single-connect constraints for accounting requests.
///
/// Returns error message if validation fails, None if validation passes.
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

    if let Some(bound) = single_connect.session {
        if bound != request.header.session_id {
            warn!(peer = %peer, user = %request.user, session = request.header.session_id,
                bound_session = bound, "single-connect violation: session-id mismatch on accounting");
            return Some("session-id mismatch".into());
        }
    }

    if let Some(ref bound_user) = single_connect.user {
        if bound_user != &request.user {
            warn!(peer = %peer, user = %request.user, bound_user = %bound_user,
                session = request.header.session_id, "single-connect violation: user mismatch on accounting");
            return Some("single-connection user mismatch".into());
        }
    } else {
        warn!(peer = %peer, user = %request.user, session = request.header.session_id,
            "single-connect violation: accounting before authentication");
        return Some("single-connection not authenticated".into());
    }

    None
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
    let single_connect_idle_secs = conn_cfg.single_connect_idle_secs;
    let single_connect_keepalive_secs = conn_cfg.single_connect_keepalive_secs;
    let ascii_cfg = &conn_cfg.ascii;

    use std::collections::HashMap;
    let mut auth_states: HashMap<u32, AuthSessionState> = HashMap::new();
    let mut single_connect = SingleConnectState::default();
    let mut task_tracker = TaskIdTracker::default();

    loop {
        let read_future = read_packet(&mut stream, secret.as_deref().map(|s| s.as_slice()));
        let keepalive_deadline = if single_connect_keepalive_secs > 0 {
            single_connect_keepalive_secs
        } else {
            single_connect_idle_secs
        };
        let packet_result = if single_connect.active && keepalive_deadline > 0 {
            match timeout(Duration::from_secs(keepalive_deadline), read_future).await {
                Ok(res) => res,
                Err(_) => {
                    warn!(
                        peer = %peer,
                        idle_secs = keepalive_deadline,
                        "single-connect keepalive/idle timeout reached; closing"
                    );
                    audit_event(
                        "conn_close",
                        &peer,
                        "",
                        0,
                        "error",
                        "keepalive-timeout",
                        &format!("idle_secs={keepalive_deadline}"),
                    );
                    break;
                }
            }
        } else {
            read_future.await
        };
        match packet_result {
            Ok(Some(Packet::Authorization(request))) => {
                if let Err(err) = usg_tacacs_proto::validate_author_request(&request) {
                    warn!(peer = %peer, user = %request.user, session = request.header.session_id, error = %err, "authorization request failed RFC validation");
                    let response = authz_reason_response(
                        AUTHOR_STATUS_ERROR,
                        err.to_string(),
                        "rfc-validate",
                        Some(err.to_string()),
                    );
                    audit_event(
                        "authz_rfc_invalid",
                        &peer,
                        &request.user,
                        request.header.session_id,
                        "error",
                        "rfc-validate",
                        &response.data,
                    );
                    let _ = write_author_response(
                        &mut stream,
                        &request.header,
                        &response,
                        secret.as_deref().map(|s| s.as_slice()),
                    )
                    .await;
                    break;
                }

                // Validate single-connect constraints
                if let Some(err_msg) = validate_authz_single_connect(&single_connect, &request, &peer) {
                    let response = authz_reason_response(
                        AUTHOR_STATUS_ERROR,
                        err_msg,
                        "single-connect",
                        Some("violation".into()),
                    );
                    let _ = write_author_response(
                        &mut stream,
                        &request.header,
                        &response,
                        secret.as_deref().map(|s| s.as_slice()),
                    )
                    .await;
                    break;
                }

                let decision = match validate_authorization_semantics(&request) {
                    Ok(()) => {
                        let policy = policy.read().await;
                        let ctx = authz_context(&request);
                        let ldap_groups = if let Some(ldap_cfg) = ldap.as_ref() {
                            ldap_fetch_groups(ldap_cfg, &request.user).await
                        } else {
                            Vec::new()
                        };
                        if request.is_shell_start() {
                            let attrs =
                                policy
                                    .shell_attributes_for(&request.user)
                                    .unwrap_or_else(|| {
                                        vec![
                                            "service=shell".to_string(),
                                            "protocol=shell".to_string(),
                                        ]
                                    });
                            let attrs = ensure_priv_attr(attrs, request.priv_lvl);
                            let resp = AuthorizationResponse {
                                status: AUTHOR_STATUS_PASS_ADD,
                                server_msg: String::new(),
                                data: format!("reason=policy-shell;ctx={ctx}"),
                                args: attrs,
                            };
                            audit_event(
                                "authz_policy_allow",
                                &peer,
                                &request.user,
                                request.header.session_id,
                                "pass",
                                "policy-shell",
                                &resp.data,
                            );
                            resp
                        } else if let Some(cmd) = request.command_string() {
                            let decision =
                                policy.authorize_with_groups(&request.user, &ldap_groups, &cmd);
                            if decision.allowed {
                                let mut data = String::from("reason=policy-allow");
                                if let Some(rule) = decision.matched_rule.clone() {
                                    data.push_str(";rule=");
                                    data.push_str(&rule);
                                }
                                data.push_str(";ctx=");
                                data.push_str(&ctx);
                                let ldap_data = if !ldap_groups.is_empty() {
                                    format!(";groups={}", ldap_groups.join(","))
                                } else {
                                    String::new()
                                };
                                let resp = AuthorizationResponse {
                                    status: AUTHOR_STATUS_PASS_REPL,
                                    server_msg: String::new(),
                                    data: format!("{data}{ldap_data}"),
                                    args: authz_allow_attrs(&request),
                                };
                                audit_event(
                                    "authz_policy_allow",
                                    &peer,
                                    &request.user,
                                    request.header.session_id,
                                    "pass",
                                    "policy-allow",
                                    &resp.data,
                                );
                                resp
                            } else {
                                let mut resp = authz_reason_response(
                                    AUTHOR_STATUS_FAIL,
                                    format!("command '{cmd}' denied by policy"),
                                    "policy-deny",
                                    Some(cmd),
                                );
                                if let Some(rule) = decision.matched_rule {
                                    resp.data.push_str(";rule=");
                                    resp.data.push_str(&rule);
                                }
                                resp.data.push_str(";ctx=");
                                resp.data.push_str(&ctx);
                                audit_event(
                                    "authz_policy_deny",
                                    &peer,
                                    &request.user,
                                    request.header.session_id,
                                    "fail",
                                    &resp.server_msg,
                                    &resp.data,
                                );
                                resp
                            }
                        } else {
                            authz_reason_response(
                                AUTHOR_STATUS_ERROR,
                                "unsupported request",
                                "unsupported",
                                None,
                            )
                        }
                    }
                    Err(msg) => {
                        warn!(
                            peer = %peer,
                            user = %request.user,
                            session = request.header.session_id,
                            reason = %msg.msg,
                            "authorization request rejected by semantic checks"
                        );
                        let (code, detail) = authz_semantic_detail(&msg);
                        let ctx = authz_context(&request);
                        let resp = authz_reason_response(
                            AUTHOR_STATUS_ERROR,
                            authz_server_msg_with_detail(code, msg.msg, &detail),
                            code,
                            Some(detail.clone()),
                        );
                        let meta = format!("{};ctx={ctx}", resp.data);
                        audit_event(
                            "authz_semantic_reject",
                            &peer,
                            &request.user,
                            request.header.session_id,
                            "error",
                            code,
                            &meta,
                        );
                        audit_event(
                            "authz_error",
                            &peer,
                            &request.user,
                            request.header.session_id,
                            "error",
                            "authz-error",
                            &resp.data,
                        );
                        resp
                    }
                };

                if let Err(err) = validate_author_response_header(&request.header.response(0)) {
                    warn!(error = %err, peer = %peer, "authorization header invalid");
                }
                write_author_response(
                    &mut stream,
                    &request.header,
                    &decision,
                    secret.as_deref().map(|s| s.as_slice()),
                )
                .await
                .with_context(|| "sending TACACS+ response")?;
            }
            Ok(Some(Packet::Authentication(packet))) => {
                let session_id = match &packet {
                    AuthenPacket::Start(start) => start.header.session_id,
                    AuthenPacket::Continue(cont) => cont.header.session_id,
                };
                match &packet {
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
                                &peer,
                                &start.user,
                                session_id,
                                "error",
                                "rfc-validate",
                                &err.to_string(),
                            );
                            let _ = write_authen_reply(
                                &mut stream,
                                &start.header,
                                &reply,
                                secret.as_deref().map(|s| s.as_slice()),
                            )
                            .await;
                            break;
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
                                &peer,
                                "",
                                session_id,
                                "error",
                                "rfc-validate",
                                &err.to_string(),
                            );
                            let _ = write_authen_reply(
                                &mut stream,
                                &cont.header,
                                &reply,
                                secret.as_deref().map(|s| s.as_slice()),
                            )
                            .await;
                            break;
                        }
                    }
                }

                // Validate single-connect constraints
                if let Some(err_msg) = validate_authen_single_connect(&single_connect, &packet, session_id, &peer) {
                    let header = match &packet {
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
                    let _ = write_authen_reply(
                        &mut stream,
                        header,
                        &reply,
                        secret.as_deref().map(|s| s.as_slice()),
                    )
                    .await;
                    break;
                }

                let single_connect_flag = match &packet {
                    AuthenPacket::Start(start) => {
                        start.header.flags & usg_tacacs_proto::FLAG_SINGLE_CONNECT != 0
                    }
                    AuthenPacket::Continue(cont) => {
                        cont.header.flags & usg_tacacs_proto::FLAG_SINGLE_CONNECT != 0
                    }
                };

                let state = auth_states
                    .entry(session_id)
                    .or_insert_with(|| match &packet {
                        AuthenPacket::Start(start) => AuthSessionState::from_start(start)
                            .unwrap_or(AuthSessionState {
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
                                ascii_need_user: start.user.is_empty(),
                                ascii_need_pass: start.data.is_empty(),
                                chap_id: None,
                                ascii_attempts: 0,
                                ascii_user_attempts: 0,
                                ascii_pass_attempts: 0,
                            }),
                        AuthenPacket::Continue(cont) => AuthSessionState {
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
                        },
                    });
                if let AuthenPacket::Continue(ref cont) = packet
                    && let Err(err) = state.validate_client(&cont.header)
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
                        &peer,
                        state.username.as_deref().unwrap_or(""),
                        session_id,
                        "error",
                        "sequence",
                        &err.to_string(),
                    );
                    let _ = write_authen_reply(
                        &mut stream,
                        &cont.header,
                        &reply,
                        secret.as_deref().map(|s| s.as_slice()),
                    )
                    .await;
                    break;
                }

                let mut reply = match packet {
                    AuthenPacket::Start(ref start) => match start.authen_type {
                        AUTHEN_TYPE_ASCII => {
                            state.authen_type = Some(AUTHEN_TYPE_ASCII);
                            state.service = Some(start.service);
                            state.action = Some(start.action);
                            let decoded_username =
                                if start.user_raw.is_empty() || start.user.is_empty() {
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
                            let (policy_user_prompt, policy_pass_prompt) = {
                                let policy = policy.read().await;
                                let policy_user = username_for_policy(
                                    state.username.as_deref(),
                                    state.username_raw.as_ref(),
                                );
                                let policy_port = field_for_policy(
                                    state.port.as_deref(),
                                    state.port_raw.as_ref(),
                                );
                                let policy_rem = field_for_policy(
                                    state.rem_addr.as_deref(),
                                    state.rem_addr_raw.as_ref(),
                                );
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
                            };
                            let username_prompt = |client_msg: Option<&[u8]>,
                                                   service: Option<u8>|
                             -> Vec<u8> {
                                if let Some(msg) = client_msg
                                    && !msg.is_empty()
                                {
                                    return msg.to_vec();
                                }
                                if let Some(custom) = policy_user_prompt.as_ref() {
                                    return custom.clone();
                                }
                                match service {
                                    Some(svc) => format!("Username (service {svc}):").into_bytes(),
                                    None => b"Username:".to_vec(),
                                }
                            };
                            let password_prompt = |client_msg: Option<&[u8]>,
                                                   service: Option<u8>|
                             -> Vec<u8> {
                                if let Some(msg) = client_msg
                                    && !msg.is_empty()
                                {
                                    return msg.to_vec();
                                }
                                if let Some(custom) = policy_pass_prompt.as_ref() {
                                    return custom.clone();
                                }
                                match service {
                                    Some(svc) => format!("Password (service {svc}):").into_bytes(),
                                    None => b"Password:".to_vec(),
                                }
                            };
                            state.ascii_need_user = state.username.is_none();
                            if state.ascii_need_user {
                                AuthenReply {
                                    status: AUTHEN_STATUS_GETUSER,
                                    flags: 0,
                                    server_msg: String::new(),
                                    server_msg_raw: Vec::new(),
                                    data: username_prompt(None, state.service),
                                }
                            } else if !start.data.is_empty() {
                                let ok = if let Some(raw) = state.username_raw.as_ref() {
                                    verify_pap_bytes_username(raw, &start.data, credentials)
                                } else {
                                    verify_pap_bytes(
                                        state.username.as_deref().unwrap_or_default(),
                                        &start.data,
                                        credentials,
                                    )
                                } || {
                                    if let Some(user) = state.username.as_deref() {
                                        verify_password_sources(
                                            Some(user),
                                            &start.data,
                                            credentials,
                                            ldap.as_ref(),
                                        )
                                        .await
                                    } else {
                                        false
                                    }
                                };
                                if !ok
                                    && let Some(delay) = calc_ascii_backoff_capped(
                                        ascii_cfg.backoff_ms,
                                        state.ascii_attempts,
                                        ascii_cfg.backoff_max_ms,
                                    )
                                {
                                    sleep(delay).await;
                                }
                                let svc_str = state
                                    .service
                                    .map(|svc| format!(" (service {svc})"))
                                    .unwrap_or_default();
                                let act_str = state
                                    .action
                                    .map(|act| format!(" action {act}"))
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
                                            .unwrap_or_else(|| {
                                                format!(
                                                    "authentication succeeded{svc_str}{act_str}"
                                                )
                                            })
                                    } else {
                                        policy
                                            .message_failure()
                                            .map(|m| m.to_string())
                                            .unwrap_or_else(|| {
                                                format!("invalid credentials{svc_str}{act_str}")
                                            })
                                    },
                                    server_msg_raw: Vec::new(),
                                    data: Vec::new(),
                                }
                            } else {
                                state.ascii_need_pass = true;
                                AuthenReply {
                                    status: AUTHEN_STATUS_GETPASS,
                                    flags: AUTHEN_FLAG_NOECHO,
                                    server_msg: String::new(),
                                    server_msg_raw: Vec::new(),
                                    data: password_prompt(None, state.service),
                                }
                            }
                        }
                        AUTHEN_TYPE_PAP => {
                            state.authen_type = Some(AUTHEN_TYPE_PAP);
                            let password = match start.parsed_data() {
                                AuthenData::Pap { password } => password,
                                _ => {
                                    warn!(peer = %peer, user = %start.user, "invalid PAP authentication payload");
                                    return Ok(());
                                }
                            };
                            let ok = verify_pap(&start.user, &password, credentials)
                                || verify_password_sources(
                                    Some(&start.user),
                                    password.as_bytes(),
                                    credentials,
                                    ldap.as_ref(),
                                )
                                .await;
                            let policy = policy.read().await;
                            let svc_str = start.service.to_string();
                            let act_str = start.action.to_string();
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
                        AUTHEN_TYPE_CHAP => {
                            if start.data.len() != 1 {
                                warn!(peer = %peer, user = %start.user, "invalid CHAP start length");
                                return Ok(());
                            }
                            let chap_id = &start.data;
                            let mut chal = [0u8; 16];
                            let mut chap_id_bytes = [0u8; 1];
                            chap_id_bytes.copy_from_slice(chap_id);
                            if rand_bytes(&mut chal).is_err()
                                || rand_bytes(&mut chap_id_bytes).is_err()
                            {
                                AuthenReply {
                                    status: AUTHEN_STATUS_ERROR,
                                    flags: 0,
                                    server_msg: "failed to generate challenge".into(),
                                    server_msg_raw: Vec::new(),
                                    data: Vec::new(),
                                }
                            } else {
                                state.challenge = Some(chal.clone().to_vec());
                                state.chap_id = Some(chap_id_bytes[0]);
                                AuthenReply {
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
                                }
                            }
                        }
                        _ => AuthenReply {
                            status: AUTHEN_STATUS_FOLLOW,
                            flags: 0,
                            server_msg: "unsupported auth type - fallback".into(),
                            server_msg_raw: Vec::new(),
                            data: Vec::new(),
                        },
                    },
                    AuthenPacket::Continue(ref cont) => match state.authen_type {
                        Some(AUTHEN_TYPE_ASCII) => {
                            handle_ascii_continue(
                                cont.user_msg.as_slice(),
                                cont.data.as_slice(),
                                cont.flags,
                                state,
                                policy,
                                credentials,
                                ascii_cfg,
                                ldap.as_ref(),
                            )
                            .await
                        }
                        _ if state.challenge.is_some() => {
                            let user = state.username.clone().unwrap_or_default();
                            match state.authen_type {
                                Some(AUTHEN_TYPE_CHAP) => handle_chap_continue(
                                    &user,
                                    cont.data.as_slice(),
                                    state,
                                    credentials,
                                ),
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
                    },
                };

                let header = match &packet {
                    AuthenPacket::Start(start) => &start.header,
                    AuthenPacket::Continue(cont) => &cont.header,
                };
                let terminal = matches!(
                    reply.status,
                    AUTHEN_STATUS_PASS
                        | AUTHEN_STATUS_FAIL
                        | AUTHEN_STATUS_ERROR
                        | AUTHEN_STATUS_FOLLOW
                        | AUTHEN_STATUS_RESTART
                );
                let single_user = state.username.clone();
                if terminal {
                    let status_label = match reply.status {
                        AUTHEN_STATUS_PASS => "pass",
                        AUTHEN_STATUS_FAIL => "fail",
                        AUTHEN_STATUS_ERROR => "error",
                        AUTHEN_STATUS_FOLLOW => "follow",
                        AUTHEN_STATUS_RESTART => "restart",
                        _ => "other",
                    };
                    let user_for_log = state.username.as_deref().unwrap_or_else(|| {
                        state.username_raw.as_ref().map(|_| "<raw>").unwrap_or("")
                    });
                    let msg_data = if !reply.server_msg.is_empty() {
                        reply.server_msg.clone()
                    } else if !reply.server_msg_raw.is_empty() {
                        format!("raw={}", hex::encode(&reply.server_msg_raw))
                    } else {
                        String::new()
                    };
                    let attempts = format!(
                        "attempts_total={};user_attempts={};pass_attempts={}",
                        state.ascii_attempts, state.ascii_user_attempts, state.ascii_pass_attempts
                    );
                    let authn_type = match state.authen_type {
                        Some(AUTHEN_TYPE_ASCII) => "ascii",
                        Some(AUTHEN_TYPE_PAP) => "pap",
                        Some(AUTHEN_TYPE_CHAP) => "chap",
                        Some(_) => "other",
                        None => "unknown",
                    };
                    let svc = state
                        .service
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "-".into());
                    let action = state
                        .action
                        .map(|a| a.to_string())
                        .unwrap_or_else(|| "-".into());
                    let reason = match reply.status {
                        AUTHEN_STATUS_PASS => "success",
                        AUTHEN_STATUS_FAIL => {
                            let msg_lc = reply.server_msg.to_lowercase();
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
                    };
                    let msg_data = if msg_data.is_empty() {
                        format!(
                            "{attempts};type={authn_type};service={svc};action={action};reason={reason}"
                        )
                    } else {
                        format!(
                            "{attempts};type={authn_type};service={svc};action={action};reason={reason};msg={msg_data}"
                        )
                    };
                    audit_event(
                        "authn_terminal",
                        &peer,
                        user_for_log,
                        session_id,
                        status_label,
                        "terminal",
                        &msg_data,
                    );
                }

                write_authen_reply(
                    &mut stream,
                    header,
                    &reply,
                    secret.as_deref().map(|s| s.as_slice()),
                )
                .await
                .with_context(|| "sending TACACS+ auth reply")?;
                if !reply.server_msg_raw.is_empty() {
                    enforce_server_msg(policy, state, &mut reply).await;
                    debug!(
                        peer = %peer,
                        session = session_id,
                        raw_len = reply.server_msg_raw.len(),
                        server_msg_raw_hex = %hex::encode(&reply.server_msg_raw),
                        "auth reply carried raw server_msg bytes"
                    );
                }
                if terminal {
                    auth_states.remove(&session_id);
                    if reply.status != AUTHEN_STATUS_PASS {
                        single_connect.reset();
                    }
                }
                if matches!(reply.status, AUTHEN_STATUS_PASS)
                    && single_connect_flag
                    && let Some(user) = single_user
                {
                    single_connect.activate(user.clone(), session_id);
                    // NIST AC-10: Update session registry with authenticated user
                    registry
                        .update_authentication(connection_id, user.clone(), session_id)
                        .await;
                    info!(peer = %peer, user = %user, session = session_id, "single-connect established");
                }
            }
            Ok(Some(Packet::Capability(cap))) => {
                audit_event(
                    "capability_rx",
                    &peer,
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
                    let _ = usg_tacacs_proto::write_capability(
                        &mut stream,
                        &cap.header,
                        &resp,
                        secret.as_deref().map(|s| s.as_slice()),
                    )
                    .await;
                }
            }
            Ok(Some(Packet::Accounting(request))) => {
                if let Err(err) = usg_tacacs_proto::validate_accounting_request(&request) {
                    warn!(peer = %peer, user = %request.user, session = request.header.session_id, error = %err, "accounting request failed RFC validation");
                    let response = AccountingResponse {
                        status: ACCT_STATUS_ERROR,
                        server_msg: err.to_string(),
                        data: format!("reason=rfc-validate;detail={err}"),
                        args: Vec::new(),
                    };
                    let meta =
                        format!("flags=0x{:02x};attrs={}", request.flags, request.args.len());
                    audit_event(
                        "acct_rfc_invalid",
                        &peer,
                        &request.user,
                        request.header.session_id,
                        "error",
                        "rfc-validate",
                        &meta,
                    );
                    let _ = write_accounting_response(
                        &mut stream,
                        &request.header,
                        &response,
                        secret.as_deref().map(|s| s.as_slice()),
                    )
                    .await;
                    break;
                }

                // Validate single-connect constraints
                if let Some(err_msg) = validate_acct_single_connect(&single_connect, &request, &peer) {
                    let response = AccountingResponse {
                        status: ACCT_STATUS_ERROR,
                        server_msg: err_msg,
                        data: String::new(),
                        args: Vec::new(),
                    };
                    let _ = write_accounting_response(
                        &mut stream,
                        &request.header,
                        &response,
                        secret.as_deref().map(|s| s.as_slice()),
                    )
                    .await;
                    break;
                }

                if let Err(err) = validate_accounting_response_header(&request.header.response(0)) {
                    warn!(error = %err, peer = %peer, "accounting header invalid");
                }
                // RFC 8907: Track task_ids to prevent reuse in start records
                let task_tracking_result: Result<(), &'static str> = (|| {
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
                                // Warn but don't fail for orphan stops (some NADs misbehave)
                                warn!(peer = %peer, task_id = tid, error = %e, "task_id tracking warning");
                            }
                        } else if request.flags & ACCT_FLAG_WATCHDOG != 0
                            && let Err(e) = task_tracker.watchdog(tid)
                        {
                            // Warn but don't fail for orphan watchdogs
                            warn!(peer = %peer, task_id = tid, error = %e, "task_id tracking warning");
                        }
                    }
                    Ok(())
                })();
                let response = match validate_accounting_semantics(&request) {
                    Ok(()) if task_tracking_result.is_ok() => accounting_success_response(&request),
                    Ok(()) => {
                        // Semantic validation passed but task_id tracking failed (reuse)
                        let msg = task_tracking_result.unwrap_err();
                        warn!(
                            peer = %peer,
                            user = %request.user,
                            session = request.header.session_id,
                            reason = %msg,
                            "accounting request rejected by task_id tracking (RFC 8907)"
                        );
                        let resp = AccountingResponse {
                            status: ACCT_STATUS_ERROR,
                            server_msg: msg.to_string(),
                            data: format!("reason=task-id-reuse;detail={msg}"),
                            args: Vec::new(),
                        };
                        audit_event(
                            "acct_task_id_reuse",
                            &peer,
                            &request.user,
                            request.header.session_id,
                            "error",
                            "task-id-reuse",
                            msg,
                        );
                        resp
                    }
                    Err(msg) => {
                        warn!(
                            peer = %peer,
                            user = %request.user,
                            session = request.header.session_id,
                            reason = %msg,
                            "accounting request rejected by semantic checks"
                        );
                        let resp = AccountingResponse {
                            status: ACCT_STATUS_ERROR,
                            server_msg: msg.to_string(),
                            data: format!("reason=semantic-invalid;detail={msg}"),
                            args: Vec::new(),
                        };
                        let meta = format!(
                            "flags=0x{:02x};attrs={};reason={}",
                            request.flags,
                            request.args.len(),
                            msg
                        );
                        audit_event(
                            "acct_semantic_reject",
                            &peer,
                            &request.user,
                            request.header.session_id,
                            "error",
                            msg,
                            &meta,
                        );
                        if resp.status == ACCT_STATUS_ERROR {
                            audit_event(
                                "acct_error",
                                &peer,
                                &request.user,
                                request.header.session_id,
                                "error",
                                "acct-error",
                                &resp.data,
                            );
                        }
                        resp
                    }
                };
                if response.status == ACCT_STATUS_SUCCESS {
                    let acct_type = if request.flags & ACCT_FLAG_START != 0 {
                        "start"
                    } else if request.flags & ACCT_FLAG_STOP != 0 {
                        "stop"
                    } else if request.flags & ACCT_FLAG_WATCHDOG != 0 {
                        "watchdog"
                    } else {
                        "unknown"
                    };
                    let attrs = request.attributes();
                    let service = attrs
                        .iter()
                        .find(|a| a.name.eq_ignore_ascii_case("service"))
                        .and_then(|a| a.value.as_deref())
                        .unwrap_or("-");
                    let cmd = attrs
                        .iter()
                        .find(|a| a.name.eq_ignore_ascii_case("cmd"))
                        .and_then(|a| a.value.as_deref())
                        .unwrap_or("-");
                    let task = attrs
                        .iter()
                        .find(|a| a.name.eq_ignore_ascii_case("task_id"))
                        .and_then(|a| a.value.as_deref())
                        .unwrap_or("-");
                    let status_attr = attrs
                        .iter()
                        .find(|a| a.name.eq_ignore_ascii_case("status"))
                        .and_then(|a| a.value.as_deref())
                        .unwrap_or("-");
                    let bytes_in = attrs
                        .iter()
                        .find(|a| a.name.eq_ignore_ascii_case("bytes_in"))
                        .and_then(|a| a.value.as_deref())
                        .unwrap_or("-");
                    let bytes_out = attrs
                        .iter()
                        .find(|a| a.name.eq_ignore_ascii_case("bytes_out"))
                        .and_then(|a| a.value.as_deref())
                        .unwrap_or("-");
                    let data = format!(
                        "type={};flags=0x{:02x};attrs={};service={};cmd={};task_id={};status={};bytes_in={};bytes_out={}",
                        acct_type,
                        request.flags,
                        request.args.len(),
                        service,
                        cmd,
                        task,
                        status_attr,
                        bytes_in,
                        bytes_out
                    );
                    audit_event(
                        "acct_accept",
                        &peer,
                        &request.user,
                        request.header.session_id,
                        "success",
                        "semantic-ok",
                        &data,
                    );
                } else if response.status == ACCT_STATUS_ERROR {
                    audit_event(
                        "acct_error",
                        &peer,
                        &request.user,
                        request.header.session_id,
                        "error",
                        "acct-error",
                        &response.data,
                    );
                }
                write_accounting_response(
                    &mut stream,
                    &request.header,
                    &response,
                    secret.as_deref().map(|s| s.as_slice()),
                )
                .await
                .with_context(|| "sending TACACS+ accounting response")?;
            }
            Ok(None) => {
                debug!(peer = %peer, "client closed connection");
                audit_event("conn_close", &peer, "", 0, "info", "client-close", "");
                break;
            }
            Err(err) => {
                warn!(error = %err, peer = %peer, "failed to read TACACS+ packet");
                audit_event(
                    "conn_close",
                    &peer,
                    "",
                    0,
                    "error",
                    "read-error",
                    &err.to_string(),
                );
                break;
            }
        }

        // NIST AC-12: Check for API-initiated session termination
        if registry.is_termination_requested(connection_id).await {
            info!(peer = %peer, connection_id = connection_id, "session terminated via API");
            audit_event(
                "conn_close",
                &peer,
                "",
                0,
                "info",
                "api-terminated",
                "session terminated via management API",
            );
            break;
        }

        // Record activity for session tracking
        registry.record_activity(connection_id).await;
    }

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
                .unwrap()
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
    // Helper to handle reload requests
    async fn handle_reload(
        request: &PolicyReloadRequest,
        policy: &Arc<RwLock<PolicyEngine>>,
        source: &str,
    ) {
        match request {
            PolicyReloadRequest::FromDisk { path, schema } => {
                match PolicyEngine::from_path(path, schema.as_ref()) {
                    Ok(new_policy) => {
                        let rule_count = new_policy.rule_count();
                        *policy.write().await = new_policy;
                        crate::metrics::metrics()
                            .policy_rules_count
                            .set(rule_count as f64);
                        crate::metrics::metrics()
                            .policy_reload_total
                            .with_label_values(&["success"])
                            .inc();
                        info!(
                            source = source,
                            rules = rule_count,
                            "policy reloaded successfully"
                        );
                    }
                    Err(err) => {
                        crate::metrics::metrics()
                            .policy_reload_total
                            .with_label_values(&["failure"])
                            .inc();
                        warn!(
                            source = source,
                            error = %err,
                            "failed to reload policy"
                        );
                    }
                }
            }
            PolicyReloadRequest::FromJson { content, schema } => {
                match PolicyEngine::from_json_str(content, schema.as_ref()) {
                    Ok(new_policy) => {
                        let rule_count = new_policy.rule_count();
                        *policy.write().await = new_policy;
                        crate::metrics::metrics()
                            .policy_rules_count
                            .set(rule_count as f64);
                        crate::metrics::metrics()
                            .policy_reload_total
                            .with_label_values(&["success"])
                            .inc();
                        info!(
                            source = source,
                            rules = rule_count,
                            "policy uploaded successfully from JSON"
                        );
                    }
                    Err(err) => {
                        crate::metrics::metrics()
                            .policy_reload_total
                            .with_label_values(&["failure"])
                            .inc();
                        warn!(
                            source = source,
                            error = %err,
                            "failed to load policy from JSON"
                        );
                    }
                }
            }
        }
    }

    match signal(SignalKind::hangup()) {
        Ok(mut sighup_stream) => {
            info!("policy reload watcher started (SIGHUP + channel)");
            loop {
                tokio::select! {
                    // Handle channel-based reload requests from API
                    Some(request) = reload_rx.recv() => {
                        handle_reload(&request, &policy, "api").await;
                    }
                    // Handle SIGHUP for backward compatibility
                    Some(_) = sighup_stream.recv() => {
                        let request = PolicyReloadRequest::FromDisk {
                            path: initial_path.clone(),
                            schema: schema.clone(),
                        };
                        handle_reload(&request, &policy, "sighup").await;
                    }
                }
            }
        }
        Err(err) => {
            warn!(error = %err, "failed to install SIGHUP handler, using channel-only mode");
            // Fall back to channel-only mode
            while let Some(request) = reload_rx.recv().await {
                handle_reload(&request, &policy, "api").await;
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
