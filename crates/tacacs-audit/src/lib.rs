// SPDX-License-Identifier: Apache-2.0
//! Audit log forwarding for TACACS+ server.
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
//! | AU-12 | Audit and Accountability | Implemented | 2026-01-31 | See functions below |
//! | AU-2 | Audit and Accountability | Implemented | 2026-01-31 | See functions below |
//! | AU-3 | Audit and Accountability | Implemented | 2026-01-31 | See functions below |
//! | AU-4 | Audit and Accountability | Implemented | 2026-01-31 | See functions below |
//! | AU-6 | Audit and Accountability | Implemented | 2026-01-31 | See functions below |
//! | AU-9 | Audit and Accountability | Implemented | 2026-01-31 | See functions below |
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
//!   "total_controls": 6,
//!   "file_path": "crates/tacacs-audit/src/lib.rs"
//! }
//! ```
//!
//! </details>
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::warn;

/// Maximum capacity of the bounded audit event channel.
///
/// # NIST Controls
/// - **AU-4 (Audit Log Storage)**: Bounds memory usage for audit queue
const AUDIT_CHANNEL_CAPACITY: usize = 10_000;

/// Counter for audit events dropped due to channel backpressure.
static AUDIT_EVENTS_DROPPED: AtomicU64 = AtomicU64::new(0);

/// Send an audit event, dropping it with a warning if the channel is full.
///
/// Returns true if the event was sent, false if dropped.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AU-4 | Audit Log Storage | Prevents unbounded memory growth in audit queue |
pub fn try_send_audit_event(tx: &mpsc::Sender<AuditEvent>, event: AuditEvent) -> bool {
    match tx.try_send(event) {
        Ok(()) => true,
        Err(mpsc::error::TrySendError::Full(_)) => {
            let dropped = AUDIT_EVENTS_DROPPED.fetch_add(1, Ordering::Relaxed) + 1;
            warn!(
                total_dropped = dropped,
                "audit event dropped: channel full (capacity={})", AUDIT_CHANNEL_CAPACITY
            );
            false
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            warn!("audit event dropped: channel closed");
            false
        }
    }
}

/// Initialize the audit system with the given configuration.
///
/// Returns a bounded channel sender for submitting audit events and a
/// background task handle. The channel is bounded to [`AUDIT_CHANNEL_CAPACITY`]
/// to prevent unbounded memory growth under load.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AU-2/AU-12 | Event Logging / Audit Generation | Initializes audit event processing pipeline |
/// | AU-4 | Audit Log Storage | Bounded channel prevents memory exhaustion |
pub async fn init_audit_system(
    config: AuditConfig,
) -> Result<(mpsc::Sender<AuditEvent>, tokio::task::JoinHandle<()>)> {
    let (tx, rx) = mpsc::channel(AUDIT_CHANNEL_CAPACITY);
    let forwarder = Arc::new(AuditForwarder::new(config).await?);

    let task = tokio::spawn(async move {
        forwarder.run(rx).await;
    });

    Ok((tx, task))
}
