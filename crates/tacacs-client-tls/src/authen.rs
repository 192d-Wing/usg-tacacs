// SPDX-License-Identifier: Apache-2.0
//! TACACS+ authentication operations for TLS client.
//!
//! This module provides high-level authentication methods including:
//! - PAP (Password Authentication Protocol)
//! - CHAP (Challenge-Handshake Authentication Protocol)
//! - ASCII (interactive login)
//!
//! # Security Note
//!
//! Unlike legacy TACACS+, credentials are protected by TLS 1.3 encryption
//! rather than MD5 obfuscation. This provides stronger security guarantees.

use crate::client::{Session, TacacsClient};
use anyhow::{Context, Result, bail};
use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, instrument};
use usg_tacacs_proto::{
    AUTHEN_STATUS_ERROR, AUTHEN_STATUS_FAIL, AUTHEN_STATUS_GETDATA, AUTHEN_STATUS_GETPASS,
    AUTHEN_STATUS_GETUSER, AUTHEN_STATUS_PASS, AUTHEN_TYPE_ASCII, AUTHEN_TYPE_CHAP,
    AUTHEN_TYPE_PAP, TYPE_AUTHEN, VERSION,
};

/// Authentication action: login.
pub const ACTION_LOGIN: u8 = 0x01;
/// Authentication action: enable (privilege escalation).
pub const ACTION_ENABLE: u8 = 0x02;

/// Authentication service: login.
pub const SERVICE_LOGIN: u8 = 0x01;
/// Authentication service: enable.
pub const SERVICE_ENABLE: u8 = 0x02;

/// Result of an authentication attempt.
#[derive(Debug, Clone)]
pub enum AuthenResult {
    /// Authentication succeeded.
    Pass {
        /// Optional server message.
        server_msg: String,
    },
    /// Authentication failed.
    Fail {
        /// Optional server message explaining failure.
        server_msg: String,
    },
    /// Server error occurred.
    Error {
        /// Error message from server.
        server_msg: String,
    },
    /// Server requests additional data (for interactive auth).
    GetData {
        /// Prompt to display to user.
        prompt: String,
        /// Whether to echo input.
        echo: bool,
    },
    /// Server requests username.
    GetUser {
        /// Prompt to display.
        prompt: String,
    },
    /// Server requests password.
    GetPass {
        /// Prompt to display.
        prompt: String,
        /// Whether to echo input.
        echo: bool,
    },
}

impl TacacsClient {
    /// Authenticate a user with PAP (Password Authentication Protocol).
    ///
    /// This is the simplest authentication method where the password is sent
    /// in a single request. The password is protected by TLS encryption.
    ///
    /// # Arguments
    ///
    /// * `username` - The username to authenticate
    /// * `password` - The user's password
    ///
    /// # Returns
    ///
    /// Returns `AuthenResult::Pass` on success, `AuthenResult::Fail` on failure.
    ///
    /// # NIST Controls
    /// - **IA-2 (Identification and Authentication)**: User authentication
    /// - **IA-5 (Authenticator Management)**: Password transmission (TLS protected)
    #[instrument(skip(self, password), fields(username = %username))]
    pub async fn authenticate_pap(&mut self, username: &str, password: &str) -> Result<AuthenResult> {
        let session = self.new_session();

        // Build authentication START packet for PAP
        let body = build_authen_start(
            ACTION_LOGIN,
            0, // priv_lvl
            AUTHEN_TYPE_PAP,
            SERVICE_LOGIN,
            username.as_bytes(),
            b"", // port
            b"", // rem_addr
            password.as_bytes(),
        );

        // Send request (no secret - TLS provides encryption)
        send_authen_packet(&mut self.writer, &session, &body).await?;

        // Read reply
        let reply = recv_authen_reply(&mut self.reader).await?;

        debug!(status = reply.status, "received authentication reply");

        Ok(parse_authen_result(&reply))
    }

    /// Authenticate a user with CHAP (Challenge-Handshake Authentication Protocol).
    ///
    /// CHAP uses a challenge-response mechanism. The client must compute the
    /// CHAP response using the challenge, password, and CHAP ID.
    ///
    /// # Arguments
    ///
    /// * `username` - The username to authenticate
    /// * `chap_id` - The CHAP identifier byte
    /// * `chap_response` - The computed CHAP response (typically MD5 hash)
    ///
    /// # NIST Controls
    /// - **IA-2 (Identification and Authentication)**: User authentication
    #[instrument(skip(self, chap_response), fields(username = %username))]
    pub async fn authenticate_chap(
        &mut self,
        username: &str,
        chap_id: u8,
        chap_response: &[u8],
    ) -> Result<AuthenResult> {
        let session = self.new_session();

        // CHAP data format: 1 byte CHAP ID + response
        let mut data = BytesMut::with_capacity(1 + chap_response.len());
        data.put_u8(chap_id);
        data.extend_from_slice(chap_response);

        let body = build_authen_start(
            ACTION_LOGIN,
            0,
            AUTHEN_TYPE_CHAP,
            SERVICE_LOGIN,
            username.as_bytes(),
            b"",
            b"",
            &data,
        );

        send_authen_packet(&mut self.writer, &session, &body).await?;
        let reply = recv_authen_reply(&mut self.reader).await?;

        debug!(status = reply.status, "received CHAP authentication reply");

        Ok(parse_authen_result(&reply))
    }

    /// Start an ASCII (interactive) authentication session.
    ///
    /// ASCII authentication is a multi-step process where the server may
    /// prompt for username, password, or other data. Use `continue_authen`
    /// to respond to server prompts.
    ///
    /// # Arguments
    ///
    /// * `username` - Initial username (can be empty if server will prompt)
    ///
    /// # Returns
    ///
    /// Returns the initial server response, which may be `Pass`, `Fail`, or
    /// a prompt for additional data.
    #[instrument(skip(self), fields(username = %username))]
    pub async fn authenticate_ascii_start(&mut self, username: &str) -> Result<(Session, AuthenResult)> {
        let mut session = self.new_session();

        let body = build_authen_start(
            ACTION_LOGIN,
            0,
            AUTHEN_TYPE_ASCII,
            SERVICE_LOGIN,
            username.as_bytes(),
            b"",
            b"",
            b"",
        );

        send_authen_packet(&mut self.writer, &session, &body).await?;
        session.advance_after_request();

        let reply = recv_authen_reply(&mut self.reader).await?;
        session.advance_after_reply();

        debug!(status = reply.status, "received ASCII authentication reply");

        Ok((session, parse_authen_result(&reply)))
    }

    /// Continue an ASCII authentication session with user input.
    ///
    /// Call this method to respond to `GetUser`, `GetPass`, or `GetData` prompts
    /// from the server.
    ///
    /// # Arguments
    ///
    /// * `session` - The session from `authenticate_ascii_start` or previous `continue_authen`
    /// * `user_msg` - The user's response to the server prompt
    #[instrument(skip(self, user_msg))]
    pub async fn continue_authen(
        &mut self,
        session: &mut Session,
        user_msg: &[u8],
    ) -> Result<AuthenResult> {
        let body = build_authen_continue(user_msg, b"", 0);

        send_authen_continue(&mut self.writer, session, &body).await?;
        session.advance_after_request();

        let reply = recv_authen_reply(&mut self.reader).await?;
        session.advance_after_reply();

        debug!(status = reply.status, "received continue reply");

        Ok(parse_authen_result(&reply))
    }

    /// Authenticate for privilege escalation (enable mode).
    ///
    /// Used to authenticate for elevated privileges, similar to Cisco "enable" command.
    ///
    /// # Arguments
    ///
    /// * `username` - The username requesting enable
    /// * `password` - The enable password
    /// * `priv_lvl` - The requested privilege level (0-15)
    #[instrument(skip(self, password), fields(username = %username, priv_lvl = priv_lvl))]
    pub async fn authenticate_enable(
        &mut self,
        username: &str,
        password: &str,
        priv_lvl: u8,
    ) -> Result<AuthenResult> {
        if priv_lvl > 15 {
            bail!("privilege level must be 0-15");
        }

        let session = self.new_session();

        let body = build_authen_start(
            ACTION_ENABLE,
            priv_lvl,
            AUTHEN_TYPE_PAP,
            SERVICE_ENABLE,
            username.as_bytes(),
            b"",
            b"",
            password.as_bytes(),
        );

        send_authen_packet(&mut self.writer, &session, &body).await?;
        let reply = recv_authen_reply(&mut self.reader).await?;

        debug!(status = reply.status, "received enable authentication reply");

        Ok(parse_authen_result(&reply))
    }
}

/// Build an authentication START packet body.
fn build_authen_start(
    action: u8,
    priv_lvl: u8,
    authen_type: u8,
    service: u8,
    user: &[u8],
    port: &[u8],
    rem_addr: &[u8],
    data: &[u8],
) -> Vec<u8> {
    let mut buf = BytesMut::new();

    buf.put_u8(action);
    buf.put_u8(priv_lvl);
    buf.put_u8(authen_type);
    buf.put_u8(service);
    buf.put_u8(user.len() as u8);
    buf.put_u8(port.len() as u8);
    buf.put_u8(rem_addr.len() as u8);
    buf.put_u8(data.len() as u8);
    buf.extend_from_slice(user);
    buf.extend_from_slice(port);
    buf.extend_from_slice(rem_addr);
    buf.extend_from_slice(data);

    buf.to_vec()
}

/// Build an authentication CONTINUE packet body.
fn build_authen_continue(user_msg: &[u8], data: &[u8], flags: u8) -> Vec<u8> {
    let mut buf = BytesMut::new();

    buf.put_u16(user_msg.len() as u16);
    buf.put_u16(data.len() as u16);
    buf.put_u8(flags);
    buf.extend_from_slice(user_msg);
    buf.extend_from_slice(data);

    buf.to_vec()
}

/// Send an authentication START packet.
async fn send_authen_packet<W>(writer: &mut W, session: &Session, body: &[u8]) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    let mut header = [0u8; 12];
    header[0] = VERSION;
    header[1] = TYPE_AUTHEN;
    header[2] = session.seq_no;
    header[3] = 0; // flags - no obfuscation needed with TLS
    header[4..8].copy_from_slice(&session.session_id.to_be_bytes());
    header[8..12].copy_from_slice(&(body.len() as u32).to_be_bytes());

    writer.write_all(&header).await.context("writing header")?;
    writer.write_all(body).await.context("writing body")?;
    writer.flush().await.context("flushing")?;

    Ok(())
}

/// Send an authentication CONTINUE packet.
async fn send_authen_continue<W>(writer: &mut W, session: &Session, body: &[u8]) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    send_authen_packet(writer, session, body).await
}

/// Authentication reply from server.
struct AuthenReply {
    status: u8,
    flags: u8,
    server_msg: String,
    #[allow(dead_code)]
    data: Vec<u8>,
}

/// Receive an authentication reply.
async fn recv_authen_reply<R>(reader: &mut R) -> Result<AuthenReply>
where
    R: AsyncReadExt + Unpin,
{
    // Read header
    let mut header = [0u8; 12];
    reader
        .read_exact(&mut header)
        .await
        .context("reading reply header")?;

    let length = u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize;

    // Read body (no decryption needed - TLS handles security)
    let mut body = vec![0u8; length];
    reader
        .read_exact(&mut body)
        .await
        .context("reading reply body")?;

    if body.len() < 6 {
        bail!("authentication reply too short");
    }

    let status = body[0];
    let flags = body[1];
    let server_msg_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    let data_len = u16::from_be_bytes([body[4], body[5]]) as usize;

    if body.len() < 6 + server_msg_len + data_len {
        bail!("authentication reply truncated");
    }

    let server_msg = String::from_utf8_lossy(&body[6..6 + server_msg_len]).to_string();
    let data = body[6 + server_msg_len..6 + server_msg_len + data_len].to_vec();

    Ok(AuthenReply {
        status,
        flags,
        server_msg,
        data,
    })
}

/// Parse authentication reply into result enum.
fn parse_authen_result(reply: &AuthenReply) -> AuthenResult {
    const AUTHEN_FLAG_NOECHO: u8 = 0x01;

    match reply.status {
        AUTHEN_STATUS_PASS => AuthenResult::Pass {
            server_msg: reply.server_msg.clone(),
        },
        AUTHEN_STATUS_FAIL => AuthenResult::Fail {
            server_msg: reply.server_msg.clone(),
        },
        AUTHEN_STATUS_ERROR => AuthenResult::Error {
            server_msg: reply.server_msg.clone(),
        },
        AUTHEN_STATUS_GETDATA => AuthenResult::GetData {
            prompt: reply.server_msg.clone(),
            echo: reply.flags & AUTHEN_FLAG_NOECHO == 0,
        },
        AUTHEN_STATUS_GETUSER => AuthenResult::GetUser {
            prompt: reply.server_msg.clone(),
        },
        AUTHEN_STATUS_GETPASS => AuthenResult::GetPass {
            prompt: reply.server_msg.clone(),
            echo: reply.flags & AUTHEN_FLAG_NOECHO == 0,
        },
        _ => AuthenResult::Error {
            server_msg: format!("unknown status: 0x{:02x}", reply.status),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_authen_start_pap() {
        let body = build_authen_start(
            ACTION_LOGIN,
            0,
            AUTHEN_TYPE_PAP,
            SERVICE_LOGIN,
            b"alice",
            b"tty0",
            b"192.168.1.1",
            b"password",
        );

        assert_eq!(body[0], ACTION_LOGIN);
        assert_eq!(body[1], 0); // priv_lvl
        assert_eq!(body[2], AUTHEN_TYPE_PAP);
        assert_eq!(body[3], SERVICE_LOGIN);
        assert_eq!(body[4], 5); // user len
        assert_eq!(body[5], 4); // port len
        assert_eq!(body[6], 11); // rem_addr len
        assert_eq!(body[7], 8); // data len
    }

    #[test]
    fn build_authen_start_ascii_no_user() {
        let body = build_authen_start(
            ACTION_LOGIN,
            0,
            AUTHEN_TYPE_ASCII,
            SERVICE_LOGIN,
            b"",
            b"",
            b"",
            b"",
        );

        assert_eq!(body[4], 0); // user len = 0
        assert_eq!(body[7], 0); // data len = 0
    }

    #[test]
    fn build_authen_continue_with_password() {
        let body = build_authen_continue(b"mypassword", b"", 0);

        let user_msg_len = u16::from_be_bytes([body[0], body[1]]);
        assert_eq!(user_msg_len, 10);

        let data_len = u16::from_be_bytes([body[2], body[3]]);
        assert_eq!(data_len, 0);

        assert_eq!(body[4], 0); // flags
    }

    #[test]
    fn parse_authen_result_pass() {
        let reply = AuthenReply {
            status: AUTHEN_STATUS_PASS,
            flags: 0,
            server_msg: "Welcome!".to_string(),
            data: vec![],
        };

        match parse_authen_result(&reply) {
            AuthenResult::Pass { server_msg } => assert_eq!(server_msg, "Welcome!"),
            _ => panic!("expected Pass"),
        }
    }

    #[test]
    fn parse_authen_result_fail() {
        let reply = AuthenReply {
            status: AUTHEN_STATUS_FAIL,
            flags: 0,
            server_msg: "Invalid credentials".to_string(),
            data: vec![],
        };

        match parse_authen_result(&reply) {
            AuthenResult::Fail { server_msg } => assert_eq!(server_msg, "Invalid credentials"),
            _ => panic!("expected Fail"),
        }
    }

    #[test]
    fn parse_authen_result_getpass_noecho() {
        let reply = AuthenReply {
            status: AUTHEN_STATUS_GETPASS,
            flags: 0x01, // NOECHO
            server_msg: "Password: ".to_string(),
            data: vec![],
        };

        match parse_authen_result(&reply) {
            AuthenResult::GetPass { prompt, echo } => {
                assert_eq!(prompt, "Password: ");
                assert!(!echo);
            }
            _ => panic!("expected GetPass"),
        }
    }

    #[test]
    fn parse_authen_result_getuser() {
        let reply = AuthenReply {
            status: AUTHEN_STATUS_GETUSER,
            flags: 0,
            server_msg: "Username: ".to_string(),
            data: vec![],
        };

        match parse_authen_result(&reply) {
            AuthenResult::GetUser { prompt } => assert_eq!(prompt, "Username: "),
            _ => panic!("expected GetUser"),
        }
    }
}
