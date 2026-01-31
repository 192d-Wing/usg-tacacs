// SPDX-License-Identifier: Apache-2.0
//! Main audit forwarder that orchestrates syslog and Elasticsearch forwarding.
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
//! | AU-4 | Audit and Accountability | Implemented | 2026-01-31 | See functions below |
//! | CM-6 | Configuration Management | Implemented | 2026-01-31 | See functions below |
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
//!     "AU",
//!     "CM"
//!   ],
//!   "total_controls": 4,
//!   "file_path": "crates/tacacs-audit/src/forwarder.rs"
//! }
//! ```
//!
//! </details>
//!
//! # NIST SP 800-53 Security Controls
//!
//! Implements AU-2, AU-4, AU-12 (comprehensive audit event forwarding).

use crate::config::AuditConfig;
use crate::elasticsearch::ElasticsearchForwarder;
use crate::event::AuditEvent;
use crate::syslog::SyslogForwarder;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

/// Main audit forwarder that sends events to configured destinations.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AU-2/AU-12 | Event Logging / Audit Generation | Processes and forwards all audit events |
/// | AU-4 | Audit Log Storage | Coordinates multi-destination forwarding (syslog + Elasticsearch) |
pub struct AuditForwarder {
    syslog: Option<SyslogForwarder>,
    elasticsearch: Option<Arc<ElasticsearchForwarder>>,
}

impl AuditForwarder {
    /// Create a new audit forwarder from configuration.
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | CM-6 | Configuration Settings | Initializes audit destinations per configuration |
    pub async fn new(config: AuditConfig) -> Result<Self> {
        let mut syslog = None;
        let mut elasticsearch = None;

        // Initialize syslog forwarder if enabled
        if let Some(syslog_config) = config.syslog {
            if syslog_config.enabled {
                debug!("initializing syslog forwarder");
                let forwarder = SyslogForwarder::new(syslog_config)?;

                // Connect immediately
                forwarder.connect().await?;

                syslog = Some(forwarder);
            }
        }

        // Initialize Elasticsearch forwarder if enabled
        if let Some(es_config) = config.elasticsearch {
            if es_config.enabled {
                debug!("initializing Elasticsearch forwarder");
                let forwarder = Arc::new(ElasticsearchForwarder::new(es_config).await?);

                // Start background flush task
                let forwarder_clone = Arc::clone(&forwarder);
                forwarder_clone.start_flush_task();

                elasticsearch = Some(forwarder);
            }
        }

        if syslog.is_none() && elasticsearch.is_none() {
            warn!("no audit destinations enabled");
        }

        Ok(Self {
            syslog,
            elasticsearch,
        })
    }

    /// Forward an audit event to all configured destinations.
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | AU-2 | Event Logging | Sends audit events to all configured destinations |
    pub async fn forward(&self, event: &AuditEvent) {
        let mut errors = Vec::new();

        // Send to syslog
        if let Some(ref syslog) = self.syslog {
            if let Err(e) = syslog.send(event).await {
                error!(error = %e, event_type = %event.event_type, "failed to send audit event to syslog");
                errors.push(("syslog", e));
            }
        }

        // Send to Elasticsearch
        if let Some(ref es) = self.elasticsearch {
            if let Err(e) = es.buffer_event(event.clone()).await {
                error!(error = %e, event_type = %event.event_type, "failed to buffer audit event for Elasticsearch");
                errors.push(("elasticsearch", e));
            }
        }

        if errors.is_empty() {
            debug!(event_type = %event.event_type, "audit event forwarded");
        } else {
            warn!(
                event_type = %event.event_type,
                failed_destinations = errors.len(),
                "audit event partially forwarded"
            );
        }
    }

    /// Run the forwarder, consuming events from the channel.
    ///
    /// This is the main event loop for the audit forwarder.
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | AU-2/AU-12 | Event Logging | Continuous processing of audit events |
    pub async fn run(self: Arc<Self>, mut rx: mpsc::UnboundedReceiver<AuditEvent>) {
        debug!("audit forwarder started");

        while let Some(event) = rx.recv().await {
            self.forward(&event).await;
        }

        // Flush Elasticsearch on shutdown
        if let Some(ref es) = self.elasticsearch {
            debug!("flushing Elasticsearch buffer on shutdown");
            if let Err(e) = es.flush().await {
                error!(error = %e, "failed to flush Elasticsearch buffer on shutdown");
            }
        }

        debug!("audit forwarder stopped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ElasticsearchConfig, SyslogConfig, SyslogFacility, SyslogProtocol};

    #[tokio::test]
    async fn test_audit_forwarder_no_destinations() {
        let config = AuditConfig {
            syslog: None,
            elasticsearch: None,
        };

        let forwarder = AuditForwarder::new(config).await.unwrap();

        assert!(forwarder.syslog.is_none());
        assert!(forwarder.elasticsearch.is_none());
    }

    #[tokio::test]
    async fn test_audit_forwarder_disabled_destinations() {
        let config = AuditConfig {
            syslog: Some(SyslogConfig {
                enabled: false,
                host: "localhost".to_string(),
                port: 514,
                protocol: SyslogProtocol::Tcp,
                facility: SyslogFacility::Auth,
                app_name: "test".to_string(),
                tls_ca_file: None,
                tls_client_cert: None,
                tls_client_key: None,
                timeout_secs: 5,
                reconnect: false,
                reconnect_interval_secs: 30,
            }),
            elasticsearch: Some(ElasticsearchConfig {
                enabled: false,
                hosts: vec!["http://localhost:9200".to_string()],
                index: "test".to_string(),
                api_key: None,
                username: None,
                password: None,
                ca_cert_file: None,
                timeout_secs: 30,
                batch_size: 100,
                flush_interval_secs: 10,
            }),
        };

        let forwarder = AuditForwarder::new(config).await.unwrap();

        assert!(forwarder.syslog.is_none());
        assert!(forwarder.elasticsearch.is_none());
    }
}
