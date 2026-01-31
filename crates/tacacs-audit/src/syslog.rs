// SPDX-License-Identifier: Apache-2.0
//! Syslog RFC 5424 forwarder with TLS support.
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
//!   "total_controls": 4,
//!   "file_path": "crates/tacacs-audit/src/syslog.rs"
//! }
//! ```
//!
//! </details>
//!
//! # NIST SP 800-53 Security Controls
//!
//! Implements AU-9 (Protection of Audit Information) via TLS encryption.

use crate::config::{SyslogConfig, SyslogProtocol};
use crate::event::AuditEvent;
use anyhow::{Context, Result};
use chrono::SecondsFormat;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, error, warn};

/// Syslog forwarder implementing RFC 5424.
///
/// # NIST Controls
///
/// | Control | Name | Implementation |
/// |---------|------|----------------|
/// | AU-4 | Audit Log Storage | Forwards audit events to remote syslog server |
/// | AU-9 | Protection of Audit Information | TLS encryption for audit data in transit |
pub struct SyslogForwarder {
    config: SyslogConfig,
    connection: Arc<Mutex<Option<SyslogConnection>>>,
    hostname: String,
}

enum SyslogConnection {
    Tcp(TcpStream),
    TcpTls(Box<TlsStream<TcpStream>>),
    Udp(tokio::net::UdpSocket),
}

impl SyslogForwarder {
    /// Create a new syslog forwarder.
    pub fn new(config: SyslogConfig) -> Result<Self> {
        let hostname = hostname::get()
            .context("failed to get hostname")?
            .to_string_lossy()
            .to_string();

        Ok(Self {
            config,
            connection: Arc::new(Mutex::new(None)),
            hostname,
        })
    }

    /// Build TLS root certificate store from CA file or system certs.
    fn build_tls_root_store(ca_file: Option<&std::path::Path>) -> Result<rustls::RootCertStore> {
        let mut root_store = rustls::RootCertStore::empty();

        if let Some(ca_path) = ca_file {
            let ca_certs = load_certs(ca_path)?;
            for cert in ca_certs {
                root_store.add(cert).context("failed to add CA cert")?;
            }
        } else {
            let cert_result = rustls_native_certs::load_native_certs();
            for cert in cert_result.certs {
                root_store
                    .add(cert)
                    .context("failed to add system CA cert")?;
            }
            if !cert_result.errors.is_empty() {
                warn!(
                    "encountered {} errors loading system CA certificates",
                    cert_result.errors.len()
                );
            }
        }

        Ok(root_store)
    }

    /// Establish TLS connection to syslog server.
    ///
    /// # NIST SP 800-53 Controls
    /// - AU-9: Protection of Audit Information via TLS encryption
    async fn connect_tls(&self, addr: &str) -> Result<SyslogConnection> {
        debug!("connecting to syslog server via TLS: {}", addr);

        let root_store = Self::build_tls_root_store(
            self.config.tls_ca_file.as_ref().map(|p| p.as_path()),
        )?;

        let config_builder = rustls::ClientConfig::builder().with_root_certificates(root_store);

        let tls_config = if let (Some(ref cert_file), Some(ref key_file)) =
            (&self.config.tls_client_cert, &self.config.tls_client_key)
        {
            let certs = load_certs(cert_file)?;
            let key = load_private_key(key_file)?;
            config_builder
                .with_client_auth_cert(certs, key)
                .context("failed to configure client auth")?
        } else {
            config_builder.with_no_client_auth()
        };

        let connector = TlsConnector::from(Arc::new(tls_config));
        let server_name = rustls::pki_types::ServerName::try_from(self.config.host.clone())
            .context("invalid server name for SNI")?
            .to_owned();

        let tcp_stream = tokio::time::timeout(
            std::time::Duration::from_secs(self.config.timeout_secs),
            TcpStream::connect(addr),
        )
        .await
        .context("TCP connection timeout")?
        .context("failed to connect to syslog server")?;

        let tls_stream = tokio::time::timeout(
            std::time::Duration::from_secs(self.config.timeout_secs),
            connector.connect(server_name, tcp_stream),
        )
        .await
        .context("TLS handshake timeout")?
        .context("TLS handshake failed")?;

        Ok(SyslogConnection::TcpTls(Box::new(tls_stream)))
    }

    /// Connect to the syslog server.
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | AU-9 | Protection of Audit Information | Establishes TLS connection for secure audit forwarding |
    pub async fn connect(&self) -> Result<()> {
        let addr = format!("{}:{}", self.config.host, self.config.port);

        let connection = match self.config.protocol {
            SyslogProtocol::Tcp => {
                debug!("connecting to syslog server via TCP: {}", addr);
                let stream = tokio::time::timeout(
                    std::time::Duration::from_secs(self.config.timeout_secs),
                    TcpStream::connect(&addr),
                )
                .await
                .context("TCP connection timeout")?
                .context("failed to connect to syslog server")?;

                SyslogConnection::Tcp(stream)
            }
            SyslogProtocol::TcpTls => self.connect_tls(&addr).await?,
            SyslogProtocol::Udp => {
                debug!("connecting to syslog server via UDP: {}", addr);
                let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
                    .await
                    .context("failed to bind UDP socket")?;

                socket
                    .connect(&addr)
                    .await
                    .context("failed to connect UDP socket")?;

                SyslogConnection::Udp(socket)
            }
        };

        let mut conn = self.connection.lock().await;
        *conn = Some(connection);

        debug!("syslog connection established");
        Ok(())
    }

    /// Send an audit event to the syslog server.
    ///
    /// # NIST Controls
    ///
    /// | Control | Name | Implementation |
    /// |---------|------|----------------|
    /// | AU-2/AU-12 | Event Logging | Formats and forwards audit events per RFC 5424 |
    pub async fn send(&self, event: &AuditEvent) -> Result<()> {
        let mut conn_guard = self.connection.lock().await;

        if conn_guard.is_none() {
            if self.config.reconnect {
                drop(conn_guard); // Release lock before reconnecting
                warn!("syslog connection lost, attempting reconnect");
                if let Err(e) = self.connect().await {
                    error!(error = %e, "failed to reconnect to syslog server");
                    return Err(e);
                }
                conn_guard = self.connection.lock().await;
            } else {
                anyhow::bail!("syslog connection not established");
            }
        }

        let message = self.format_rfc5424(event);

        match conn_guard.as_mut() {
            Some(SyslogConnection::Tcp(stream)) => {
                // RFC 5424: octet-counting framing: <length> <space> <message>
                let framed_message = format!("{} {}\n", message.len(), message);
                stream
                    .write_all(framed_message.as_bytes())
                    .await
                    .context("failed to write to TCP stream")?;
                stream.flush().await.context("failed to flush TCP stream")?;
            }
            Some(SyslogConnection::TcpTls(stream)) => {
                let framed_message = format!("{} {}\n", message.len(), message);
                stream
                    .write_all(framed_message.as_bytes())
                    .await
                    .context("failed to write to TLS stream")?;
                stream.flush().await.context("failed to flush TLS stream")?;
            }
            Some(SyslogConnection::Udp(socket)) => {
                // UDP: send raw message (no framing)
                socket
                    .send(message.as_bytes())
                    .await
                    .context("failed to send UDP datagram")?;
            }
            None => {
                anyhow::bail!("syslog connection not established");
            }
        }

        debug!(event_type = %event.event_type, "audit event sent to syslog");
        Ok(())
    }

    /// Format an audit event according to RFC 5424.
    ///
    /// Format: <priority>version timestamp hostname app-name procid msgid structured-data msg
    fn format_rfc5424(&self, event: &AuditEvent) -> String {
        // Priority = Facility * 8 + Severity
        // Severity: 6 = Informational (for success), 3 = Error (for failure)
        let severity = match event.outcome {
            crate::event::AuditOutcome::Success => 6,
            crate::event::AuditOutcome::Failure => 3,
        };
        let priority = self.config.facility.code() * 8 + severity;

        // Version (always 1 for RFC 5424)
        let version = 1;

        // Timestamp (ISO 8601)
        let timestamp = event.timestamp.to_rfc3339_opts(SecondsFormat::Millis, true);

        // Hostname
        let hostname = &self.hostname;

        // App name
        let app_name = &self.config.app_name;

        // Process ID (use "-" as we don't have a meaningful PID)
        let procid = "-";

        // Message ID (event type)
        let msgid = event.event_type.to_string();

        // Structured data (SD-ID: tacacs@32473 - using private enterprise number)
        let mut sd_elements = Vec::new();
        if let Some(ref location) = event.location {
            sd_elements.push(format!("location=\"{}\"", escape_sd_param(location)));
        }
        if let Some(ref source_ip) = event.source_ip {
            sd_elements.push(format!("sourceIP=\"{}\"", source_ip));
        }
        if let Some(ref username) = event.username {
            sd_elements.push(format!("username=\"{}\"", escape_sd_param(username)));
        }
        if let Some(session_id) = event.session_id {
            sd_elements.push(format!("sessionID=\"{}\"", session_id));
        }
        if let Some(priv_lvl) = event.priv_lvl {
            sd_elements.push(format!("privLvl=\"{}\"", priv_lvl));
        }

        let structured_data = if sd_elements.is_empty() {
            "-".to_string()
        } else {
            format!("[tacacs@32473 {}]", sd_elements.join(" "))
        };

        // Message (human-readable summary)
        let msg = self.format_message(event);

        format!(
            "<{}>{} {} {} {} {} {} {} {}",
            priority, version, timestamp, hostname, app_name, procid, msgid, structured_data, msg
        )
    }

    fn format_message(&self, event: &AuditEvent) -> String {
        let mut parts = Vec::new();

        parts.push(format!("outcome={}", event.outcome));

        if let Some(ref username) = event.username {
            parts.push(format!("user={}", username));
        }

        if let Some(ref source_ip) = event.source_ip {
            parts.push(format!("src={}", source_ip));
        }

        if let Some(ref command) = event.command {
            parts.push(format!("cmd={}", command));
        }

        if let Some(ref reason) = event.reason {
            parts.push(format!("reason={}", reason));
        }

        parts.join(" ")
    }
}

/// Escape special characters in structured data parameters per RFC 5424.
fn escape_sd_param(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace(']', "\\]")
}

/// Load PEM-encoded certificates from a file.
fn load_certs(path: &std::path::Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let cert_file = std::fs::File::open(path).context("failed to open certificate file")?;
    let mut reader = std::io::BufReader::new(cert_file);
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse certificates")
}

/// Load PEM-encoded private key from a file.
fn load_private_key(path: &std::path::Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let key_file = std::fs::File::open(path).context("failed to open private key file")?;
    let mut reader = std::io::BufReader::new(key_file);

    // Try reading as PKCS#8 first
    if let Some(key) = rustls_pemfile::pkcs8_private_keys(&mut reader).next() {
        return key
            .map(rustls::pki_types::PrivateKeyDer::Pkcs8)
            .context("failed to parse PKCS#8 private key");
    }

    // Try reading as RSA key
    let key_file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(key_file);
    if let Some(key) = rustls_pemfile::rsa_private_keys(&mut reader).next() {
        return key
            .map(rustls::pki_types::PrivateKeyDer::Pkcs1)
            .context("failed to parse RSA private key");
    }

    anyhow::bail!("no valid private key found in file")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SyslogFacility;
    use crate::event::{AuditEventType, AuditOutcome};

    #[test]
    fn test_escape_sd_param() {
        assert_eq!(escape_sd_param("normal"), "normal");
        assert_eq!(escape_sd_param("with\\slash"), "with\\\\slash");
        assert_eq!(escape_sd_param("with\"quote"), "with\\\"quote");
        assert_eq!(escape_sd_param("with]bracket"), "with\\]bracket");
        assert_eq!(
            escape_sd_param("all\\\"\\]special"),
            "all\\\\\\\"\\\\\\]special"
        );
    }

    #[test]
    fn test_format_rfc5424() {
        let config = SyslogConfig {
            enabled: true,
            host: "localhost".to_string(),
            port: 514,
            protocol: SyslogProtocol::Tcp,
            facility: SyslogFacility::Auth,
            app_name: "tacacs-test".to_string(),
            tls_ca_file: None,
            tls_client_cert: None,
            tls_client_key: None,
            timeout_secs: 5,
            reconnect: false,
            reconnect_interval_secs: 30,
        };

        let forwarder = SyslogForwarder::new(config).unwrap();

        let event = AuditEvent::new(AuditEventType::AuthnSuccess, AuditOutcome::Success)
            .with_location("NYC01".to_string())
            .with_username("alice".to_string())
            .with_source_ip("10.1.1.5".parse().unwrap())
            .with_session_id(12345);

        let message = forwarder.format_rfc5424(&event);

        // Priority: Auth (4) * 8 + Informational (6) = 38
        assert!(message.starts_with("<38>1 "));

        // Check structured data
        assert!(message.contains("[tacacs@32473"));
        assert!(message.contains("location=\"NYC01\""));
        assert!(message.contains("sourceIP=\"10.1.1.5\""));
        assert!(message.contains("username=\"alice\""));
        assert!(message.contains("sessionID=\"12345\""));

        // Check message
        assert!(message.contains("outcome=success"));
        assert!(message.contains("user=alice"));
        assert!(message.contains("src=10.1.1.5"));
    }

    #[test]
    fn test_format_rfc5424_failure() {
        let config = SyslogConfig {
            enabled: true,
            host: "localhost".to_string(),
            port: 514,
            protocol: SyslogProtocol::Tcp,
            facility: SyslogFacility::Auth,
            app_name: "tacacs-test".to_string(),
            tls_ca_file: None,
            tls_client_cert: None,
            tls_client_key: None,
            timeout_secs: 5,
            reconnect: false,
            reconnect_interval_secs: 30,
        };

        let forwarder = SyslogForwarder::new(config).unwrap();

        let event = AuditEvent::new(AuditEventType::AuthnFailure, AuditOutcome::Failure)
            .with_username("bob".to_string())
            .with_reason("Invalid password".to_string());

        let message = forwarder.format_rfc5424(&event);

        // Priority: Auth (4) * 8 + Error (3) = 35
        assert!(message.starts_with("<35>1 "));

        assert!(message.contains("authn.failure"));
        assert!(message.contains("outcome=failure"));
        assert!(message.contains("user=bob"));
        assert!(message.contains("reason=Invalid password"));
    }
}
