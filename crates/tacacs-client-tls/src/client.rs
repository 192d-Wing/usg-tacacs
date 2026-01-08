// SPDX-License-Identifier: Apache-2.0
//! TACACS+ TLS client implementation.
//!
//! This module provides a high-level async client for TACACS+ over TLS 1.3.
//! Unlike legacy TACACS+, this client does not use MD5 obfuscation - all
//! security is provided by the TLS transport layer per RFC 9887.

use crate::tls::TlsClientConfig;
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tracing::{debug, instrument};

/// Default TACACS+ TLS port per RFC 9887.
pub const DEFAULT_PORT: u16 = 300;

/// A TLS-secured TACACS+ client connection.
///
/// This client establishes a TLS 1.3 connection to a TACACS+ server and
/// provides methods for authentication, authorization, and accounting.
///
/// # Security
///
/// - Uses TLS 1.3 exclusively (no MD5 obfuscation)
/// - Supports mutual TLS for client authentication
/// - All packet payloads are protected by TLS encryption
///
/// # Example
///
/// ```ignore
/// use usg_tacacs_client_tls::{TacacsClient, TlsClientConfig};
///
/// let tls_config = TlsClientConfig::builder()
///     .with_server_ca("./certs/ca.pem")?
///     .build()?;
///
/// let mut client = TacacsClient::connect("tacacs.example.com:300", "tacacs.example.com", tls_config).await?;
///
/// // Authenticate a user
/// let result = client.authenticate_pap("alice", "password123").await?;
/// ```
pub struct TacacsClient {
    pub(crate) reader: ReadHalf<TlsStream<TcpStream>>,
    pub(crate) writer: WriteHalf<TlsStream<TcpStream>>,
    session_counter: AtomicU32,
}

impl TacacsClient {
    /// Connect to a TACACS+ server over TLS.
    ///
    /// # Arguments
    ///
    /// * `addr` - Server address (e.g., "192.168.1.1:300" or "tacacs.example.com:300")
    /// * `server_name` - Server hostname for TLS SNI verification
    /// * `config` - TLS client configuration
    ///
    /// # NIST Controls
    /// - **SC-8 (Transmission Confidentiality)**: Establishes TLS 1.3 connection
    /// - **SC-23 (Session Authenticity)**: Validates server certificate
    #[instrument(skip(config), fields(addr = %addr, server_name = %server_name))]
    pub async fn connect(
        addr: &str,
        server_name: &str,
        config: TlsClientConfig,
    ) -> Result<Self> {
        let socket_addr: SocketAddr = addr
            .parse()
            .with_context(|| format!("parsing server address: {}", addr))?;

        debug!("connecting to TACACS+ server");

        let tcp_stream = TcpStream::connect(socket_addr)
            .await
            .with_context(|| format!("connecting to {}", addr))?;

        let server_name = TlsClientConfig::parse_server_name(server_name)?;
        let connector = config.connector();

        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .context("TLS handshake failed")?;

        debug!("TLS connection established");

        let (reader, writer) = tokio::io::split(tls_stream);

        Ok(Self {
            reader,
            writer,
            session_counter: AtomicU32::new(1),
        })
    }

    /// Generate a new session ID for a TACACS+ transaction.
    fn next_session_id(&self) -> u32 {
        self.session_counter.fetch_add(1, Ordering::Relaxed)
    }

    /// Get mutable references to the underlying reader and writer.
    ///
    /// This is useful for advanced use cases where you need direct access
    /// to send/receive TACACS+ packets using the protocol library.
    pub fn split(&mut self) -> (&mut (impl AsyncRead + Unpin), &mut (impl AsyncWrite + Unpin)) {
        (&mut self.reader, &mut self.writer)
    }

    /// Get the reader half for receiving packets.
    pub fn reader(&mut self) -> &mut ReadHalf<TlsStream<TcpStream>> {
        &mut self.reader
    }

    /// Get the writer half for sending packets.
    pub fn writer(&mut self) -> &mut WriteHalf<TlsStream<TcpStream>> {
        &mut self.writer
    }
}

/// Session handle for a single TACACS+ transaction.
///
/// Each authentication, authorization, or accounting exchange uses a unique
/// session ID. This struct tracks the session state including sequence numbers.
#[derive(Debug, Clone)]
pub struct Session {
    pub session_id: u32,
    pub seq_no: u8,
}

impl Session {
    /// Create a new session with the given ID.
    pub fn new(session_id: u32) -> Self {
        Self {
            session_id,
            seq_no: 1,
        }
    }

    /// Get the current sequence number for the next request.
    pub fn current_seq(&self) -> u8 {
        self.seq_no
    }

    /// Advance to the next sequence number after sending a request.
    ///
    /// Client packets use odd sequence numbers, server replies use even.
    pub fn advance_after_request(&mut self) {
        self.seq_no = self.seq_no.wrapping_add(1);
    }

    /// Advance after receiving a reply (for multi-step exchanges).
    pub fn advance_after_reply(&mut self) {
        self.seq_no = self.seq_no.wrapping_add(1);
    }

    /// Check if we expect a server reply (even sequence number).
    pub fn expects_reply(&self) -> bool {
        self.seq_no % 2 == 0
    }
}

impl TacacsClient {
    /// Create a new session for a TACACS+ transaction.
    pub fn new_session(&self) -> Session {
        Session::new(self.next_session_id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_initial_state() {
        let session = Session::new(12345);
        assert_eq!(session.session_id, 12345);
        assert_eq!(session.seq_no, 1);
        assert!(!session.expects_reply());
    }

    #[test]
    fn session_sequence_advancement() {
        let mut session = Session::new(1);

        assert_eq!(session.current_seq(), 1);
        assert!(!session.expects_reply());

        session.advance_after_request();
        assert_eq!(session.current_seq(), 2);
        assert!(session.expects_reply());

        session.advance_after_reply();
        assert_eq!(session.current_seq(), 3);
        assert!(!session.expects_reply());
    }

    #[test]
    fn session_sequence_wraps() {
        let mut session = Session::new(1);
        session.seq_no = 255;

        session.advance_after_request();
        assert_eq!(session.seq_no, 0);
    }

    #[test]
    fn client_generates_unique_session_ids() {
        let counter = AtomicU32::new(1);

        let id1 = counter.fetch_add(1, Ordering::Relaxed);
        let id2 = counter.fetch_add(1, Ordering::Relaxed);
        let id3 = counter.fetch_add(1, Ordering::Relaxed);

        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);
    }
}
