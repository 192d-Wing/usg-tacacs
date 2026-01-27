// SPDX-License-Identifier: Apache-2.0
//! Audit log forwarding for TACACS+ server.
//!
//! # NIST SP 800-53 Security Controls
//!
//! This module implements the following NIST security controls:
//!
//! - **AU-2 (Event Logging)**: Comprehensive audit event generation for all
//!   authentication, authorization, and accounting events.
//!
//! - **AU-3 (Content of Audit Records)**: Includes timestamp, event type,
//!   outcome, user identity, source IP, and event-specific details.
//!
//! - **AU-4 (Audit Log Storage)**: Forwards audit events to external SIEM/ELK
//!   systems to prevent local storage exhaustion.
//!
//! - **AU-6 (Audit Review)**: Enables centralized audit review and analysis
//!   via syslog and Elasticsearch integration.
//!
//! - **AU-9 (Protection of Audit Information)**: Syslog forwarding over TLS
//!   protects audit data in transit.
//!
//! - **AU-12 (Audit Record Generation)**: Automated audit record generation
//!   for all security-relevant events.

pub mod config;
pub mod elasticsearch;
pub mod event;
pub mod forwarder;
pub mod syslog;

pub use config::{AuditConfig, ElasticsearchConfig, SyslogConfig};
pub use event::{AuditEvent, AuditEventType, AuditOutcome};
pub use forwarder::AuditForwarder;

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Initialize the audit system with the given configuration.
///
/// Returns a channel sender for submitting audit events and a background task handle.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AU-2/AU-12 | Event Logging / Audit Generation | Initializes audit event processing pipeline |
/// | AU-4 | Audit Log Storage | Configures external forwarding to prevent local exhaustion |
pub async fn init_audit_system(
    config: AuditConfig,
) -> Result<(
    mpsc::UnboundedSender<AuditEvent>,
    tokio::task::JoinHandle<()>,
)> {
    let (tx, rx) = mpsc::unbounded_channel();
    let forwarder = Arc::new(AuditForwarder::new(config).await?);

    let task = tokio::spawn(async move {
        forwarder.run(rx).await;
    });

    Ok((tx, task))
}
