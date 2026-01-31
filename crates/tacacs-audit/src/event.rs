// SPDX-License-Identifier: Apache-2.0
//! Audit event types and structures.
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
//! | AU-2 | Audit and Accountability | Implemented | 2026-01-31 | See functions below |
//! | AU-3 | Audit and Accountability | Implemented | 2026-01-31 | See functions below |
//! | AU-8 | Audit and Accountability | Implemented | 2026-01-31 | See functions below |
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
//!     "AU"
//!   ],
//!   "total_controls": 3,
//!   "file_path": "crates/tacacs-audit/src/event.rs"
//! }
//! ```
//!
//! </details>
//!
//! # NIST SP 800-53 Security Controls
//!
//! Implements AU-3 (Content of Audit Records) by defining comprehensive
//! audit event structures with all required fields.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// Audit event types tracked by the TACACS+ server.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AU-2 | Event Logging | Defines all security-relevant event types per ROADMAP Phase 6.2 |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    /// Authentication success
    AuthnSuccess,
    /// Authentication failure
    AuthnFailure,
    /// Authorization allow
    AuthzAllow,
    /// Authorization deny
    AuthzDeny,
    /// Accounting start
    AcctStart,
    /// Accounting stop
    AcctStop,
    /// Accounting watchdog (interim update)
    AcctWatchdog,
    /// Configuration reload
    ConfigReload,
    /// Policy reload
    PolicyReload,
    /// Session start
    SessionStart,
    /// Session end
    SessionEnd,
    /// Rate limit triggered
    RatelimitTriggered,
    /// Account lockout activated
    LockoutActivated,
}

impl std::fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthnSuccess => write!(f, "authn.success"),
            Self::AuthnFailure => write!(f, "authn.failure"),
            Self::AuthzAllow => write!(f, "authz.allow"),
            Self::AuthzDeny => write!(f, "authz.deny"),
            Self::AcctStart => write!(f, "acct.start"),
            Self::AcctStop => write!(f, "acct.stop"),
            Self::AcctWatchdog => write!(f, "acct.watchdog"),
            Self::ConfigReload => write!(f, "config.reload"),
            Self::PolicyReload => write!(f, "policy.reload"),
            Self::SessionStart => write!(f, "session.start"),
            Self::SessionEnd => write!(f, "session.end"),
            Self::RatelimitTriggered => write!(f, "ratelimit.triggered"),
            Self::LockoutActivated => write!(f, "lockout.activated"),
        }
    }
}

/// Outcome of an audit event.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AU-3 | Audit Record Content | Captures success/failure outcome for all events |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditOutcome {
    /// Event succeeded
    Success,
    /// Event failed
    Failure,
}

impl std::fmt::Display for AuditOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success => write!(f, "success"),
            Self::Failure => write!(f, "failure"),
        }
    }
}

/// A comprehensive audit event.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AU-3 | Audit Record Content | Complete audit record with all required fields per NIST SP 800-53 |
/// | AU-8 | Time Stamps | ISO 8601 UTC timestamps for all events |
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Event timestamp (UTC)
    pub timestamp: DateTime<Utc>,

    /// Event type
    pub event_type: AuditEventType,

    /// Event outcome
    pub outcome: AuditOutcome,

    /// Location identifier (e.g., "NYC01")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,

    /// Source IP address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<IpAddr>,

    /// Username (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    /// Device/port (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_port: Option<String>,

    /// Remote address from TACACS+ packet (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_addr: Option<String>,

    /// Session ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<u32>,

    /// Command (for authorization events)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,

    /// Privilege level (for authorization/authentication)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priv_lvl: Option<u8>,

    /// LDAP groups (for LDAP-based authentication)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ldap_groups: Option<Vec<String>>,

    /// Reason/message (for failures, denials, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// Additional event-specific metadata
    #[serde(flatten)]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl AuditEvent {
    /// Create a new audit event with the current timestamp.
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | AU-8 | Time Stamps | Automatically captures current UTC time for event timestamp |
    pub fn new(event_type: AuditEventType, outcome: AuditOutcome) -> Self {
        Self {
            timestamp: Utc::now(),
            event_type,
            outcome,
            location: None,
            source_ip: None,
            username: None,
            device_port: None,
            remote_addr: None,
            session_id: None,
            command: None,
            priv_lvl: None,
            ldap_groups: None,
            reason: None,
            metadata: HashMap::new(),
        }
    }

    /// Builder pattern: set location
    pub fn with_location(mut self, location: String) -> Self {
        self.location = Some(location);
        self
    }

    /// Builder pattern: set source IP
    pub fn with_source_ip(mut self, ip: IpAddr) -> Self {
        self.source_ip = Some(ip);
        self
    }

    /// Builder pattern: set username
    pub fn with_username(mut self, username: String) -> Self {
        self.username = Some(username);
        self
    }

    /// Builder pattern: set device port
    pub fn with_device_port(mut self, port: String) -> Self {
        self.device_port = Some(port);
        self
    }

    /// Builder pattern: set remote address
    pub fn with_remote_addr(mut self, addr: String) -> Self {
        self.remote_addr = Some(addr);
        self
    }

    /// Builder pattern: set session ID
    pub fn with_session_id(mut self, id: u32) -> Self {
        self.session_id = Some(id);
        self
    }

    /// Builder pattern: set command
    pub fn with_command(mut self, cmd: String) -> Self {
        self.command = Some(cmd);
        self
    }

    /// Builder pattern: set privilege level
    pub fn with_priv_lvl(mut self, priv_lvl: u8) -> Self {
        self.priv_lvl = Some(priv_lvl);
        self
    }

    /// Builder pattern: set LDAP groups
    pub fn with_ldap_groups(mut self, groups: Vec<String>) -> Self {
        self.ldap_groups = Some(groups);
        self
    }

    /// Builder pattern: set reason
    pub fn with_reason(mut self, reason: String) -> Self {
        self.reason = Some(reason);
        self
    }

    /// Builder pattern: add metadata field
    pub fn with_metadata(mut self, key: String, value: serde_json::Value) -> Self {
        self.metadata.insert(key, value);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_event_type_display() {
        assert_eq!(AuditEventType::AuthnSuccess.to_string(), "authn.success");
        assert_eq!(AuditEventType::AuthzDeny.to_string(), "authz.deny");
        assert_eq!(AuditEventType::AcctStart.to_string(), "acct.start");
        assert_eq!(AuditEventType::PolicyReload.to_string(), "policy.reload");
    }

    #[test]
    fn test_audit_outcome_display() {
        assert_eq!(AuditOutcome::Success.to_string(), "success");
        assert_eq!(AuditOutcome::Failure.to_string(), "failure");
    }

    #[test]
    fn test_audit_event_builder() {
        let event = AuditEvent::new(AuditEventType::AuthnSuccess, AuditOutcome::Success)
            .with_location("NYC01".to_string())
            .with_username("alice".to_string())
            .with_source_ip("10.1.1.5".parse().unwrap())
            .with_session_id(12345)
            .with_priv_lvl(15)
            .with_metadata("authen_type".to_string(), serde_json::json!("ASCII"));

        assert_eq!(event.event_type, AuditEventType::AuthnSuccess);
        assert_eq!(event.outcome, AuditOutcome::Success);
        assert_eq!(event.location, Some("NYC01".to_string()));
        assert_eq!(event.username, Some("alice".to_string()));
        assert_eq!(event.source_ip, Some("10.1.1.5".parse::<IpAddr>().unwrap()));
        assert_eq!(event.session_id, Some(12345));
        assert_eq!(event.priv_lvl, Some(15));
        assert_eq!(
            event.metadata.get("authen_type"),
            Some(&serde_json::json!("ASCII"))
        );
    }

    #[test]
    fn test_audit_event_serialization() {
        let event = AuditEvent::new(AuditEventType::AuthzDeny, AuditOutcome::Failure)
            .with_username("bob".to_string())
            .with_command("reload".to_string())
            .with_reason("Policy violation".to_string());

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"event_type\":\"authz_deny\""));
        assert!(json.contains("\"outcome\":\"failure\""));
        assert!(json.contains("\"username\":\"bob\""));
        assert!(json.contains("\"command\":\"reload\""));
        assert!(json.contains("\"reason\":\"Policy violation\""));
    }
}
