// SPDX-License-Identifier: Apache-2.0
//! TACACS+ accounting operations for TLS client.
//!
//! This module provides accounting methods for recording user activities,
//! including session start/stop, command execution, and resource usage.
//!
//! # Accounting Record Types
//!
//! - **START**: Marks the beginning of a session or command
//! - **STOP**: Marks the end with resource usage statistics
//! - **WATCHDOG**: Periodic update during long-running sessions
//!
//! # Example
//!
//! ```ignore
//! // Record session start
//! let task_id = "12345";
//! client.accounting_start("alice", "shell", task_id).await?;
//!
//! // ... user activity ...
//!
//! // Record session stop with statistics
//! client.accounting_stop("alice", "shell", task_id, 3600, 0, 1024, 2048).await?;
//! ```
//!
//! # NIST SP 800-53 Security Controls
//!
//! This module implements the following security controls:
//!
//! - **AU-2 (Audit Events)**: Defines auditable events including session
//!   start/stop, command execution, and resource usage.
//!
//! - **AU-3 (Content of Audit Records)**: Records include username, service,
//!   task ID, timestamps, and resource statistics (bytes in/out).
//!
//! - **AU-12 (Audit Generation)**: Generates audit records at session start,
//!   periodic intervals (watchdog), and session end with statistics.
//!
//! - **AU-14 (Session Audit)**: Provides session-level accounting with
//!   elapsed time, status, and data transfer metrics.

use crate::client::{Session, TacacsClient};
use anyhow::{Context, Result};
use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, instrument};
use usg_tacacs_proto::{
    ACCT_FLAG_START, ACCT_FLAG_STOP, ACCT_FLAG_WATCHDOG, ACCT_STATUS_ERROR, ACCT_STATUS_SUCCESS,
    TYPE_ACCT, VERSION,
};

/// Authentication method used for accounting requests.
pub const AUTHEN_METHOD_TACACSPLUS: u8 = 0x06;

/// Result of an accounting request.
#[derive(Debug, Clone)]
pub enum AcctResult {
    /// Accounting record accepted successfully.
    Success {
        /// Optional server message.
        server_msg: String,
    },
    /// Server error processing accounting record.
    Error {
        /// Error message from server.
        server_msg: String,
    },
}

impl TacacsClient {
    /// Send a START accounting record.
    ///
    /// Records the beginning of a user session or activity. The task_id
    /// should be unique and used in subsequent WATCHDOG/STOP records.
    ///
    /// # Arguments
    ///
    /// * `username` - The authenticated username
    /// * `service` - The service being accessed (e.g., "shell", "ppp")
    /// * `task_id` - Unique identifier for this activity
    ///
    /// # NIST Controls
    /// - **AU-2 (Audit Events)**: Session start logging
    /// - **AU-12 (Audit Generation)**: Generate audit record
    #[instrument(skip(self), fields(username = %username, service = %service, task_id = %task_id))]
    pub async fn accounting_start(
        &mut self,
        username: &str,
        service: &str,
        task_id: &str,
    ) -> Result<AcctResult> {
        let session = self.new_session();

        let args = vec![
            format!("service={}", service),
            format!("task_id={}", task_id),
        ];

        let body = build_acct_request(
            ACCT_FLAG_START,
            AUTHEN_METHOD_TACACSPLUS,
            0, // priv_lvl
            usg_tacacs_proto::AUTHEN_TYPE_PAP,
            1, // authen_service
            username.as_bytes(),
            b"", // port
            b"", // rem_addr
            &args,
        );

        send_acct_packet(&mut self.writer, &session, &body).await?;
        let reply = recv_acct_reply(&mut self.reader).await?;

        debug!(status = reply.status, "received accounting start reply");

        Ok(parse_acct_result(&reply))
    }

    /// Send a STOP accounting record.
    ///
    /// Records the end of a user session or activity with resource usage
    /// statistics. Should match a previous START record with the same task_id.
    ///
    /// # Arguments
    ///
    /// * `username` - The authenticated username
    /// * `service` - The service that was accessed
    /// * `task_id` - Unique identifier matching the START record
    /// * `elapsed_time` - Duration in seconds
    /// * `status` - Exit status (0 for success)
    /// * `bytes_in` - Bytes received
    /// * `bytes_out` - Bytes transmitted
    ///
    /// # NIST Controls
    /// - **AU-2 (Audit Events)**: Session end logging
    /// - **AU-12 (Audit Generation)**: Generate audit record with statistics
    #[instrument(skip(self), fields(username = %username, task_id = %task_id, elapsed = elapsed_time))]
    pub async fn accounting_stop(
        &mut self,
        username: &str,
        service: &str,
        task_id: &str,
        elapsed_time: u32,
        status: u8,
        bytes_in: u64,
        bytes_out: u64,
    ) -> Result<AcctResult> {
        let session = self.new_session();

        let args = vec![
            format!("service={}", service),
            format!("task_id={}", task_id),
            format!("elapsed_time={}", elapsed_time),
            format!("status={}", status),
            format!("bytes_in={}", bytes_in),
            format!("bytes_out={}", bytes_out),
        ];

        let body = build_acct_request(
            ACCT_FLAG_STOP,
            AUTHEN_METHOD_TACACSPLUS,
            0,
            usg_tacacs_proto::AUTHEN_TYPE_PAP,
            1,
            username.as_bytes(),
            b"",
            b"",
            &args,
        );

        send_acct_packet(&mut self.writer, &session, &body).await?;
        let reply = recv_acct_reply(&mut self.reader).await?;

        debug!(status = reply.status, "received accounting stop reply");

        Ok(parse_acct_result(&reply))
    }

    /// Send a WATCHDOG accounting record.
    ///
    /// Provides periodic updates during long-running sessions. Used to
    /// maintain session state and provide intermediate statistics.
    ///
    /// # Arguments
    ///
    /// * `username` - The authenticated username
    /// * `service` - The service being accessed
    /// * `task_id` - Unique identifier matching the START record
    /// * `elapsed_time` - Duration since session start
    ///
    /// # NIST Controls
    /// - **AU-12 (Audit Generation)**: Periodic audit updates
    #[instrument(skip(self), fields(username = %username, task_id = %task_id, elapsed = elapsed_time))]
    pub async fn accounting_watchdog(
        &mut self,
        username: &str,
        service: &str,
        task_id: &str,
        elapsed_time: u32,
    ) -> Result<AcctResult> {
        let session = self.new_session();

        let args = vec![
            format!("service={}", service),
            format!("task_id={}", task_id),
            format!("elapsed_time={}", elapsed_time),
        ];

        let body = build_acct_request(
            ACCT_FLAG_WATCHDOG,
            AUTHEN_METHOD_TACACSPLUS,
            0,
            usg_tacacs_proto::AUTHEN_TYPE_PAP,
            1,
            username.as_bytes(),
            b"",
            b"",
            &args,
        );

        send_acct_packet(&mut self.writer, &session, &body).await?;
        let reply = recv_acct_reply(&mut self.reader).await?;

        debug!(status = reply.status, "received accounting watchdog reply");

        Ok(parse_acct_result(&reply))
    }

    /// Send a command accounting record.
    ///
    /// Records execution of a specific command. Used for command-level
    /// audit trails.
    ///
    /// # Arguments
    ///
    /// * `username` - The authenticated username
    /// * `task_id` - Unique identifier for this command execution
    /// * `cmd` - The command executed
    /// * `cmd_args` - Command arguments
    /// * `is_start` - True for command start, false for command completion
    ///
    /// # NIST Controls
    /// - **AU-2 (Audit Events)**: Command execution logging
    /// - **AU-12 (Audit Generation)**: Generate command audit record
    #[instrument(skip(self, cmd_args), fields(username = %username, cmd = %cmd, is_start = is_start))]
    pub async fn accounting_command(
        &mut self,
        username: &str,
        task_id: &str,
        cmd: &str,
        cmd_args: &[&str],
        is_start: bool,
    ) -> Result<AcctResult> {
        let session = self.new_session();

        let flag = if is_start {
            ACCT_FLAG_START
        } else {
            ACCT_FLAG_STOP
        };

        let mut args = vec![
            format!("service=shell"),
            format!("task_id={}", task_id),
            format!("cmd={}", cmd),
        ];

        for arg in cmd_args {
            args.push(format!("cmd-arg={}", arg));
        }

        if !is_start {
            args.push("elapsed_time=0".to_string());
            args.push("status=0".to_string());
            args.push("bytes_in=0".to_string());
            args.push("bytes_out=0".to_string());
        }

        let body = build_acct_request(
            flag,
            AUTHEN_METHOD_TACACSPLUS,
            0,
            usg_tacacs_proto::AUTHEN_TYPE_PAP,
            1,
            username.as_bytes(),
            b"",
            b"",
            &args,
        );

        send_acct_packet(&mut self.writer, &session, &body).await?;
        let reply = recv_acct_reply(&mut self.reader).await?;

        debug!(status = reply.status, "received command accounting reply");

        Ok(parse_acct_result(&reply))
    }

    /// Send a custom accounting record.
    ///
    /// Allows full control over the accounting request for advanced use cases.
    ///
    /// # Arguments
    ///
    /// * `username` - The authenticated username
    /// * `flags` - Accounting flags (ACCT_FLAG_START, ACCT_FLAG_STOP, or ACCT_FLAG_WATCHDOG)
    /// * `priv_lvl` - Privilege level (0-15)
    /// * `args` - List of attribute strings
    #[instrument(skip(self, args), fields(username = %username, flags = flags, priv_lvl = priv_lvl))]
    pub async fn accounting_custom(
        &mut self,
        username: &str,
        flags: u8,
        priv_lvl: u8,
        args: &[String],
    ) -> Result<AcctResult> {
        let session = self.new_session();

        let body = build_acct_request(
            flags,
            AUTHEN_METHOD_TACACSPLUS,
            priv_lvl,
            usg_tacacs_proto::AUTHEN_TYPE_PAP,
            1,
            username.as_bytes(),
            b"",
            b"",
            args,
        );

        send_acct_packet(&mut self.writer, &session, &body).await?;
        let reply = recv_acct_reply(&mut self.reader).await?;

        debug!(status = reply.status, "received custom accounting reply");

        Ok(parse_acct_result(&reply))
    }
}

/// Build an accounting request packet body.
fn build_acct_request(
    flags: u8,
    authen_method: u8,
    priv_lvl: u8,
    authen_type: u8,
    authen_service: u8,
    user: &[u8],
    port: &[u8],
    rem_addr: &[u8],
    args: &[String],
) -> Vec<u8> {
    let mut buf = BytesMut::new();

    buf.put_u8(flags);
    buf.put_u8(authen_method);
    buf.put_u8(priv_lvl);
    buf.put_u8(authen_type);
    buf.put_u8(authen_service);
    buf.put_u8(user.len() as u8);
    buf.put_u8(port.len() as u8);
    buf.put_u8(rem_addr.len() as u8);
    buf.put_u8(args.len() as u8);

    // Argument lengths
    for arg in args {
        buf.put_u8(arg.len() as u8);
    }

    buf.extend_from_slice(user);
    buf.extend_from_slice(port);
    buf.extend_from_slice(rem_addr);

    // Arguments
    for arg in args {
        buf.extend_from_slice(arg.as_bytes());
    }

    buf.to_vec()
}

/// Send an accounting packet.
async fn send_acct_packet<W>(writer: &mut W, session: &Session, body: &[u8]) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    let mut header = [0u8; 12];
    header[0] = VERSION;
    header[1] = TYPE_ACCT;
    header[2] = session.seq_no;
    header[3] = 0; // flags
    header[4..8].copy_from_slice(&session.session_id.to_be_bytes());
    header[8..12].copy_from_slice(&(body.len() as u32).to_be_bytes());

    writer.write_all(&header).await.context("writing header")?;
    writer.write_all(body).await.context("writing body")?;
    writer.flush().await.context("flushing")?;

    Ok(())
}

/// Accounting reply from server.
struct AcctReply {
    status: u8,
    server_msg: String,
    #[allow(dead_code)]
    data: String,
}

/// Receive an accounting reply.
async fn recv_acct_reply<R>(reader: &mut R) -> Result<AcctReply>
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

    // Read body
    let mut body = vec![0u8; length];
    reader
        .read_exact(&mut body)
        .await
        .context("reading reply body")?;

    if body.len() < 5 {
        anyhow::bail!("accounting reply too short");
    }

    let status = body[0];
    let server_msg_len = u16::from_be_bytes([body[1], body[2]]) as usize;
    let data_len = u16::from_be_bytes([body[3], body[4]]) as usize;

    let server_msg = if server_msg_len > 0 && body.len() >= 5 + server_msg_len {
        String::from_utf8_lossy(&body[5..5 + server_msg_len]).to_string()
    } else {
        String::new()
    };

    let data = if data_len > 0 && body.len() >= 5 + server_msg_len + data_len {
        String::from_utf8_lossy(&body[5 + server_msg_len..5 + server_msg_len + data_len])
            .to_string()
    } else {
        String::new()
    };

    Ok(AcctReply {
        status,
        server_msg,
        data,
    })
}

/// Parse accounting reply into result enum.
fn parse_acct_result(reply: &AcctReply) -> AcctResult {
    match reply.status {
        ACCT_STATUS_SUCCESS => AcctResult::Success {
            server_msg: reply.server_msg.clone(),
        },
        ACCT_STATUS_ERROR => AcctResult::Error {
            server_msg: reply.server_msg.clone(),
        },
        _ => AcctResult::Error {
            server_msg: format!("unknown status: 0x{:02x}", reply.status),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_acct_request_start() {
        let args = vec!["service=shell".to_string(), "task_id=12345".to_string()];

        let body = build_acct_request(
            ACCT_FLAG_START,
            AUTHEN_METHOD_TACACSPLUS,
            0,
            usg_tacacs_proto::AUTHEN_TYPE_PAP,
            1,
            b"alice",
            b"",
            b"",
            &args,
        );

        assert_eq!(body[0], ACCT_FLAG_START);
        assert_eq!(body[1], AUTHEN_METHOD_TACACSPLUS);
        assert_eq!(body[2], 0); // priv_lvl
        assert_eq!(body[5], 5); // user len
        assert_eq!(body[8], 2); // arg count
    }

    #[test]
    fn build_acct_request_stop() {
        let args = vec![
            "service=shell".to_string(),
            "task_id=12345".to_string(),
            "elapsed_time=3600".to_string(),
            "status=0".to_string(),
            "bytes_in=1024".to_string(),
            "bytes_out=2048".to_string(),
        ];

        let body = build_acct_request(
            ACCT_FLAG_STOP,
            AUTHEN_METHOD_TACACSPLUS,
            0,
            usg_tacacs_proto::AUTHEN_TYPE_PAP,
            1,
            b"alice",
            b"tty0",
            b"192.168.1.1",
            &args,
        );

        assert_eq!(body[0], ACCT_FLAG_STOP);
        assert_eq!(body[5], 5); // user len
        assert_eq!(body[6], 4); // port len
        assert_eq!(body[7], 11); // rem_addr len
        assert_eq!(body[8], 6); // arg count
    }

    #[test]
    fn build_acct_request_watchdog() {
        let args = vec![
            "service=shell".to_string(),
            "task_id=12345".to_string(),
            "elapsed_time=1800".to_string(),
        ];

        let body = build_acct_request(
            ACCT_FLAG_WATCHDOG,
            AUTHEN_METHOD_TACACSPLUS,
            0,
            usg_tacacs_proto::AUTHEN_TYPE_PAP,
            1,
            b"alice",
            b"",
            b"",
            &args,
        );

        assert_eq!(body[0], ACCT_FLAG_WATCHDOG);
        assert_eq!(body[8], 3); // arg count
    }

    #[test]
    fn parse_acct_result_success() {
        let reply = AcctReply {
            status: ACCT_STATUS_SUCCESS,
            server_msg: "Recorded".to_string(),
            data: "".to_string(),
        };

        match parse_acct_result(&reply) {
            AcctResult::Success { server_msg } => {
                assert_eq!(server_msg, "Recorded");
            }
            _ => panic!("expected Success"),
        }
    }

    #[test]
    fn parse_acct_result_error() {
        let reply = AcctReply {
            status: ACCT_STATUS_ERROR,
            server_msg: "Database error".to_string(),
            data: "".to_string(),
        };

        match parse_acct_result(&reply) {
            AcctResult::Error { server_msg } => {
                assert_eq!(server_msg, "Database error");
            }
            _ => panic!("expected Error"),
        }
    }

    #[test]
    fn parse_acct_result_unknown_status() {
        let reply = AcctReply {
            status: 0xFF,
            server_msg: "".to_string(),
            data: "".to_string(),
        };

        match parse_acct_result(&reply) {
            AcctResult::Error { server_msg } => {
                assert!(server_msg.contains("unknown"));
            }
            _ => panic!("expected Error for unknown status"),
        }
    }
}
