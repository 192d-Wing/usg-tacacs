// SPDX-License-Identifier: Apache-2.0
//! TACACS+ authorization operations for TLS client.
//!
//! This module provides authorization methods for checking user permissions
//! to execute commands or access services.
//!
//! # Example
//!
//! ```ignore
//! // Check if user can execute a command
//! let result = client.authorize_command("alice", "show", &["version"]).await?;
//!
//! match result {
//!     AuthorResult::PassAdd { args, .. } => println!("Authorized with args: {:?}", args),
//!     AuthorResult::Fail { .. } => println!("Not authorized"),
//!     _ => {}
//! }
//! ```

use crate::client::{Session, TacacsClient};
use anyhow::{Context, Result};
use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, instrument};
use usg_tacacs_proto::{AUTHOR_STATUS_ERROR, AUTHOR_STATUS_FAIL, AUTHOR_STATUS_PASS_ADD, AUTHOR_STATUS_PASS_REPL, TYPE_AUTHOR, VERSION};

/// Authentication method used for the authorization request.
pub const AUTHEN_METHOD_TACACSPLUS: u8 = 0x06;

/// Result of an authorization request.
#[derive(Debug, Clone)]
pub enum AuthorResult {
    /// Authorization passed, server adds attributes to request.
    PassAdd {
        /// Server message.
        server_msg: String,
        /// Additional data from server.
        data: String,
        /// Arguments to add to the request.
        args: Vec<String>,
    },
    /// Authorization passed, server replaces request attributes.
    PassReplace {
        /// Server message.
        server_msg: String,
        /// Additional data from server.
        data: String,
        /// Arguments that replace the original request.
        args: Vec<String>,
    },
    /// Authorization denied.
    Fail {
        /// Server message explaining denial.
        server_msg: String,
        /// Additional data from server.
        data: String,
    },
    /// Server error occurred.
    Error {
        /// Error message from server.
        server_msg: String,
        /// Additional data from server.
        data: String,
    },
}

impl TacacsClient {
    /// Authorize a shell command execution.
    ///
    /// Checks if the user is allowed to execute the specified command with
    /// the given arguments.
    ///
    /// # Arguments
    ///
    /// * `username` - The authenticated username
    /// * `cmd` - The command to authorize (e.g., "show", "configure")
    /// * `cmd_args` - Command arguments (e.g., ["version"], ["terminal"])
    ///
    /// # NIST Controls
    /// - **AC-3 (Access Enforcement)**: Command authorization check
    /// - **AC-6 (Least Privilege)**: Enforce minimum necessary access
    #[instrument(skip(self), fields(username = %username, cmd = %cmd))]
    pub async fn authorize_command(
        &mut self,
        username: &str,
        cmd: &str,
        cmd_args: &[&str],
    ) -> Result<AuthorResult> {
        let session = self.new_session();

        // Build arguments list
        let mut args = vec![
            format!("service=shell"),
            format!("cmd={}", cmd),
        ];
        for arg in cmd_args {
            args.push(format!("cmd-arg={}", arg));
        }

        let body = build_author_request(
            AUTHEN_METHOD_TACACSPLUS,
            0, // priv_lvl
            usg_tacacs_proto::AUTHEN_TYPE_PAP,
            1, // authen_service (login)
            username.as_bytes(),
            b"", // port
            b"", // rem_addr
            &args,
        );

        send_author_packet(&mut self.writer, &session, &body).await?;
        let reply = recv_author_reply(&mut self.reader).await?;

        debug!(status = reply.status, "received authorization reply");

        Ok(parse_author_result(&reply))
    }

    /// Authorize access to a service.
    ///
    /// Checks if the user is allowed to access a specific service with
    /// the given attributes.
    ///
    /// # Arguments
    ///
    /// * `username` - The authenticated username
    /// * `service` - The service name (e.g., "shell", "ppp", "login")
    /// * `protocol` - Optional protocol (e.g., "ip", "exec")
    /// * `attrs` - Additional service-specific attributes
    ///
    /// # NIST Controls
    /// - **AC-3 (Access Enforcement)**: Service authorization check
    #[instrument(skip(self, attrs), fields(username = %username, service = %service))]
    pub async fn authorize_service(
        &mut self,
        username: &str,
        service: &str,
        protocol: Option<&str>,
        attrs: &[(&str, &str)],
    ) -> Result<AuthorResult> {
        let session = self.new_session();

        let mut args = vec![format!("service={}", service)];

        if let Some(proto) = protocol {
            args.push(format!("protocol={}", proto));
        }

        for (key, value) in attrs {
            args.push(format!("{}={}", key, value));
        }

        let body = build_author_request(
            AUTHEN_METHOD_TACACSPLUS,
            0,
            usg_tacacs_proto::AUTHEN_TYPE_PAP,
            1,
            username.as_bytes(),
            b"",
            b"",
            &args,
        );

        send_author_packet(&mut self.writer, &session, &body).await?;
        let reply = recv_author_reply(&mut self.reader).await?;

        debug!(status = reply.status, "received service authorization reply");

        Ok(parse_author_result(&reply))
    }

    /// Authorize with a custom set of attributes.
    ///
    /// This is the lowest-level authorization method, allowing full control
    /// over the authorization request attributes.
    ///
    /// # Arguments
    ///
    /// * `username` - The authenticated username
    /// * `priv_lvl` - Privilege level (0-15)
    /// * `args` - List of attribute strings (e.g., "service=shell", "cmd=show")
    #[instrument(skip(self, args), fields(username = %username, priv_lvl = priv_lvl))]
    pub async fn authorize_custom(
        &mut self,
        username: &str,
        priv_lvl: u8,
        args: &[String],
    ) -> Result<AuthorResult> {
        let session = self.new_session();

        let body = build_author_request(
            AUTHEN_METHOD_TACACSPLUS,
            priv_lvl,
            usg_tacacs_proto::AUTHEN_TYPE_PAP,
            1,
            username.as_bytes(),
            b"",
            b"",
            args,
        );

        send_author_packet(&mut self.writer, &session, &body).await?;
        let reply = recv_author_reply(&mut self.reader).await?;

        debug!(status = reply.status, "received custom authorization reply");

        Ok(parse_author_result(&reply))
    }
}

/// Build an authorization request packet body.
fn build_author_request(
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

/// Send an authorization packet.
async fn send_author_packet<W>(writer: &mut W, session: &Session, body: &[u8]) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    let mut header = [0u8; 12];
    header[0] = VERSION;
    header[1] = TYPE_AUTHOR;
    header[2] = session.seq_no;
    header[3] = 0; // flags
    header[4..8].copy_from_slice(&session.session_id.to_be_bytes());
    header[8..12].copy_from_slice(&(body.len() as u32).to_be_bytes());

    writer.write_all(&header).await.context("writing header")?;
    writer.write_all(body).await.context("writing body")?;
    writer.flush().await.context("flushing")?;

    Ok(())
}

/// Authorization reply from server.
struct AuthorReply {
    status: u8,
    server_msg: String,
    data: String,
    args: Vec<String>,
}

/// Receive an authorization reply.
async fn recv_author_reply<R>(reader: &mut R) -> Result<AuthorReply>
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

    if body.len() < 6 {
        anyhow::bail!("authorization reply too short");
    }

    let status = body[0];
    let arg_cnt = body[1] as usize;
    let server_msg_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    let data_len = u16::from_be_bytes([body[4], body[5]]) as usize;

    let mut cursor = 6;

    // Read argument lengths
    let arg_lens: Vec<u8> = body[cursor..cursor + arg_cnt].to_vec();
    cursor += arg_cnt;

    // Read server_msg
    let server_msg = String::from_utf8_lossy(&body[cursor..cursor + server_msg_len]).to_string();
    cursor += server_msg_len;

    // Read data
    let data = String::from_utf8_lossy(&body[cursor..cursor + data_len]).to_string();
    cursor += data_len;

    // Read arguments
    let mut args = Vec::with_capacity(arg_cnt);
    for len in arg_lens {
        let arg = String::from_utf8_lossy(&body[cursor..cursor + len as usize]).to_string();
        cursor += len as usize;
        args.push(arg);
    }

    Ok(AuthorReply {
        status,
        server_msg,
        data,
        args,
    })
}

/// Parse authorization reply into result enum.
fn parse_author_result(reply: &AuthorReply) -> AuthorResult {
    match reply.status {
        AUTHOR_STATUS_PASS_ADD => AuthorResult::PassAdd {
            server_msg: reply.server_msg.clone(),
            data: reply.data.clone(),
            args: reply.args.clone(),
        },
        AUTHOR_STATUS_PASS_REPL => AuthorResult::PassReplace {
            server_msg: reply.server_msg.clone(),
            data: reply.data.clone(),
            args: reply.args.clone(),
        },
        AUTHOR_STATUS_FAIL => AuthorResult::Fail {
            server_msg: reply.server_msg.clone(),
            data: reply.data.clone(),
        },
        AUTHOR_STATUS_ERROR => AuthorResult::Error {
            server_msg: reply.server_msg.clone(),
            data: reply.data.clone(),
        },
        _ => AuthorResult::Error {
            server_msg: format!("unknown status: 0x{:02x}", reply.status),
            data: String::new(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_author_request_shell_cmd() {
        let args = vec![
            "service=shell".to_string(),
            "cmd=show".to_string(),
            "cmd-arg=version".to_string(),
        ];

        let body = build_author_request(
            AUTHEN_METHOD_TACACSPLUS,
            0,
            usg_tacacs_proto::AUTHEN_TYPE_PAP,
            1,
            b"alice",
            b"",
            b"",
            &args,
        );

        assert_eq!(body[0], AUTHEN_METHOD_TACACSPLUS);
        assert_eq!(body[1], 0); // priv_lvl
        assert_eq!(body[4], 5); // user len
        assert_eq!(body[7], 3); // arg count
    }

    #[test]
    fn build_author_request_no_args() {
        let body = build_author_request(
            AUTHEN_METHOD_TACACSPLUS,
            15,
            usg_tacacs_proto::AUTHEN_TYPE_PAP,
            1,
            b"admin",
            b"tty0",
            b"192.168.1.1",
            &[],
        );

        assert_eq!(body[1], 15); // priv_lvl
        assert_eq!(body[4], 5); // user len
        assert_eq!(body[5], 4); // port len
        assert_eq!(body[6], 11); // rem_addr len
        assert_eq!(body[7], 0); // arg count
    }

    #[test]
    fn parse_author_result_pass_add() {
        let reply = AuthorReply {
            status: AUTHOR_STATUS_PASS_ADD,
            server_msg: "OK".to_string(),
            data: "".to_string(),
            args: vec!["priv-lvl=15".to_string()],
        };

        match parse_author_result(&reply) {
            AuthorResult::PassAdd { args, .. } => {
                assert_eq!(args.len(), 1);
                assert_eq!(args[0], "priv-lvl=15");
            }
            _ => panic!("expected PassAdd"),
        }
    }

    #[test]
    fn parse_author_result_pass_replace() {
        let reply = AuthorReply {
            status: AUTHOR_STATUS_PASS_REPL,
            server_msg: "Modified".to_string(),
            data: "".to_string(),
            args: vec!["cmd=show".to_string(), "cmd-arg=running-config".to_string()],
        };

        match parse_author_result(&reply) {
            AuthorResult::PassReplace { args, server_msg, .. } => {
                assert_eq!(server_msg, "Modified");
                assert_eq!(args.len(), 2);
            }
            _ => panic!("expected PassReplace"),
        }
    }

    #[test]
    fn parse_author_result_fail() {
        let reply = AuthorReply {
            status: AUTHOR_STATUS_FAIL,
            server_msg: "Command not permitted".to_string(),
            data: "".to_string(),
            args: vec![],
        };

        match parse_author_result(&reply) {
            AuthorResult::Fail { server_msg, .. } => {
                assert_eq!(server_msg, "Command not permitted");
            }
            _ => panic!("expected Fail"),
        }
    }

    #[test]
    fn parse_author_result_error() {
        let reply = AuthorReply {
            status: AUTHOR_STATUS_ERROR,
            server_msg: "Internal error".to_string(),
            data: "".to_string(),
            args: vec![],
        };

        match parse_author_result(&reply) {
            AuthorResult::Error { server_msg, .. } => {
                assert_eq!(server_msg, "Internal error");
            }
            _ => panic!("expected Error"),
        }
    }
}
