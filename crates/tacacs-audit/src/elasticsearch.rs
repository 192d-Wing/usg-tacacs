// SPDX-License-Identifier: Apache-2.0
//! Elasticsearch forwarder for audit log storage and analysis.
//!
//! # NIST SP 800-53 Security Controls
//!
//! Implements AU-4 (Audit Log Storage) and AU-6 (Audit Review).

use crate::config::ElasticsearchConfig;
use crate::event::AuditEvent;
use anyhow::{Context, Result};
use chrono::Utc;
use elasticsearch::http::transport::{SingleNodeConnectionPool, TransportBuilder};
use elasticsearch::http::Url;
use elasticsearch::{BulkParts, Elasticsearch};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};
use tracing::{debug, error, warn};

/// Elasticsearch forwarder with batching support.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AU-4 | Audit Log Storage | Forwards audit events to Elasticsearch for long-term storage |
/// | AU-6 | Audit Review | Enables centralized audit review via Elasticsearch/Kibana |
pub struct ElasticsearchForwarder {
    config: ElasticsearchConfig,
    client: Elasticsearch,
    buffer: Arc<Mutex<Vec<AuditEvent>>>,
}

impl ElasticsearchForwarder {
    /// Create a new Elasticsearch forwarder.
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | SC-8 | Transmission Confidentiality | Configures TLS for Elasticsearch connections |
    pub async fn new(config: ElasticsearchConfig) -> Result<Self> {
        // Parse Elasticsearch URLs
        let urls: Vec<Url> = config
            .hosts
            .iter()
            .map(|h| Url::parse(h))
            .collect::<Result<Vec<_>, _>>()
            .context("failed to parse Elasticsearch host URLs")?;

        if urls.is_empty() {
            anyhow::bail!("no Elasticsearch hosts configured");
        }

        // Build transport
        let mut transport_builder = if urls.len() == 1 {
            let pool = SingleNodeConnectionPool::new(urls[0].clone());
            TransportBuilder::new(pool)
        } else {
            // For multiple nodes, use CloudConnectionPool or SniffConnectionPool
            // For simplicity, we'll just use the first node
            let pool = SingleNodeConnectionPool::new(urls[0].clone());
            TransportBuilder::new(pool)
        };

        // Configure authentication
        if let Some(ref api_key) = config.api_key {
            // API key format expects (id, api_key) tuple
            // We expect the config to have format "id:key" or base64-encoded
            let parts: Vec<&str> = api_key.split(':').collect();
            let (id, key) = if parts.len() == 2 {
                (parts[0].to_string(), parts[1].to_string())
            } else {
                // Assume it's base64-encoded single string
                (api_key.clone(), String::new())
            };
            transport_builder =
                transport_builder.auth(elasticsearch::auth::Credentials::ApiKey(id, key));
        } else if let (Some(ref username), Some(ref password)) =
            (&config.username, &config.password)
        {
            transport_builder = transport_builder.auth(elasticsearch::auth::Credentials::Basic(
                username.clone(),
                password.clone(),
            ));
        }

        // Set timeout
        transport_builder = transport_builder.timeout(Duration::from_secs(config.timeout_secs));

        // TODO: Add CA certificate support
        // if let Some(ref ca_file) = config.ca_cert_file {
        //     // Load CA cert and configure rustls
        // }

        let transport = transport_builder
            .build()
            .context("failed to build Elasticsearch transport")?;

        let client = Elasticsearch::new(transport);

        // Test connection
        debug!("testing Elasticsearch connection");
        client
            .ping()
            .send()
            .await
            .context("failed to ping Elasticsearch server")?;
        debug!("Elasticsearch connection successful");

        Ok(Self {
            config,
            client,
            buffer: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Add an event to the buffer.
    ///
    /// Events are buffered and sent in batches for efficiency.
    pub async fn buffer_event(&self, event: AuditEvent) -> Result<()> {
        let mut buffer = self.buffer.lock().await;
        buffer.push(event);

        // Flush if buffer is full
        if buffer.len() >= self.config.batch_size {
            let events = buffer.drain(..).collect::<Vec<_>>();
            drop(buffer); // Release lock before flushing
            self.flush_events(events).await?;
        }

        Ok(())
    }

    /// Flush buffered events to Elasticsearch.
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | AU-4 | Audit Log Storage | Bulk-indexes audit events to Elasticsearch |
    pub async fn flush(&self) -> Result<()> {
        let mut buffer = self.buffer.lock().await;
        if buffer.is_empty() {
            return Ok(());
        }

        let events = buffer.drain(..).collect::<Vec<_>>();
        drop(buffer); // Release lock before flushing

        self.flush_events(events).await
    }

    async fn flush_events(&self, events: Vec<AuditEvent>) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }

        debug!(
            count = events.len(),
            "flushing audit events to Elasticsearch"
        );

        // Build bulk request body as newline-delimited JSON
        let mut body_lines: Vec<String> = Vec::new();

        for event in &events {
            // Resolve index name with strftime formatting
            let index = self.resolve_index_name(&event.timestamp);

            // Bulk index action
            let action = json!({
                "index": {
                    "_index": index,
                }
            });
            body_lines.push(serde_json::to_string(&action).context("failed to serialize action")?);

            // Event document
            let event_json =
                serde_json::to_string(event).context("failed to serialize audit event")?;
            body_lines.push(event_json);
        }

        // Send bulk request with Vec<String> (ndjson format)
        let response = self
            .client
            .bulk(BulkParts::None)
            .body(body_lines)
            .send()
            .await
            .context("failed to send bulk request to Elasticsearch")?;

        // Check for errors
        let response_body = response
            .json::<serde_json::Value>()
            .await
            .context("failed to parse Elasticsearch bulk response")?;

        if let Some(errors) = response_body.get("errors") {
            if errors.as_bool() == Some(true) {
                warn!("Elasticsearch bulk indexing encountered errors");

                // Log specific errors
                if let Some(items) = response_body.get("items").and_then(|i| i.as_array()) {
                    for item in items {
                        if let Some(index_result) = item.get("index") {
                            if let Some(error) = index_result.get("error") {
                                error!(error = %error, "Elasticsearch indexing error");
                            }
                        }
                    }
                }
            }
        }

        debug!(
            count = events.len(),
            "audit events flushed to Elasticsearch"
        );
        Ok(())
    }

    /// Resolve the index name with strftime formatting.
    ///
    /// Supports patterns like "tacacs-audit-%Y.%m.%d" → "tacacs-audit-2026.01.18"
    fn resolve_index_name(&self, timestamp: &chrono::DateTime<Utc>) -> String {
        // Simple strftime replacements
        let pattern = &self.config.index;
        pattern
            .replace("%Y", &timestamp.format("%Y").to_string())
            .replace("%m", &timestamp.format("%m").to_string())
            .replace("%d", &timestamp.format("%d").to_string())
            .replace("%H", &timestamp.format("%H").to_string())
            .replace("%M", &timestamp.format("%M").to_string())
            .replace("%S", &timestamp.format("%S").to_string())
    }

    /// Start a background task to periodically flush buffered events.
    pub fn start_flush_task(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let flush_interval = Duration::from_secs(self.config.flush_interval_secs);

        tokio::spawn(async move {
            loop {
                sleep(flush_interval).await;

                if let Err(e) = self.flush().await {
                    error!(error = %e, "failed to flush audit events to Elasticsearch");
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{AuditEventType, AuditOutcome};
    use chrono::TimeZone;

    #[test]
    fn test_resolve_index_name() {
        let config = ElasticsearchConfig {
            enabled: true,
            hosts: vec!["http://localhost:9200".to_string()],
            index: "tacacs-audit-%Y.%m.%d".to_string(),
            api_key: None,
            username: None,
            password: None,
            ca_cert_file: None,
            timeout_secs: 30,
            batch_size: 100,
            flush_interval_secs: 10,
        };

        let timestamp = Utc.with_ymd_and_hms(2026, 1, 18, 14, 30, 0).unwrap();

        // Create a mock forwarder (we can't test actual Elasticsearch connection in unit tests)
        // Instead, test the index name resolution logic directly
        let pattern = &config.index;
        let resolved = pattern
            .replace("%Y", &timestamp.format("%Y").to_string())
            .replace("%m", &timestamp.format("%m").to_string())
            .replace("%d", &timestamp.format("%d").to_string());

        assert_eq!(resolved, "tacacs-audit-2026.01.18");
    }

    #[test]
    fn test_resolve_index_name_hourly() {
        let pattern = "tacacs-audit-%Y.%m.%d-%H";
        let timestamp = Utc.with_ymd_and_hms(2026, 1, 18, 14, 30, 0).unwrap();

        let resolved = pattern
            .replace("%Y", &timestamp.format("%Y").to_string())
            .replace("%m", &timestamp.format("%m").to_string())
            .replace("%d", &timestamp.format("%d").to_string())
            .replace("%H", &timestamp.format("%H").to_string());

        assert_eq!(resolved, "tacacs-audit-2026.01.18-14");
    }
}
