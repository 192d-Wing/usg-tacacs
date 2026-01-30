// SPDX-License-Identifier: Apache-2.0
//! TACACS+ authorization packet structures plus parsing/encoding helpers.

use crate::header::Header;
use crate::util::validate_attributes;
use crate::util::{parse_attributes, read_string};
use crate::{
    AUTHOR_STATUS_ERROR, AUTHOR_STATUS_FAIL, AUTHOR_STATUS_PASS_ADD, AUTHOR_STATUS_PASS_REPL,
};
use anyhow::{Result, anyhow, ensure};
use bytes::{BufMut, BytesMut};

#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    pub header: Header,
    pub authen_method: u8,
    pub priv_lvl: u8,
    pub authen_type: u8,
    pub authen_service: u8,
    pub user: String,
    pub port: String,
    pub rem_addr: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AuthorizationResponse {
    pub status: u8,
    pub server_msg: String,
    pub data: String,
    pub args: Vec<String>,
}

impl AuthorizationRequest {
    /// Set or replace the service attribute (enforced to appear first).
    pub fn with_service(mut self, service: impl AsRef<str>) -> Self {
        self.args
            .retain(|a| !a.to_lowercase().starts_with("service="));
        self.args.insert(0, format!("service={}", service.as_ref()));
        self
    }

    /// Set or replace the protocol attribute (kept after service when present).
    pub fn with_protocol(mut self, protocol: impl AsRef<str>) -> Self {
        self.args
            .retain(|a| !a.to_lowercase().starts_with("protocol="));
        let service_pos = self
            .args
            .iter()
            .position(|a| a.to_lowercase().starts_with("service="));
        let insert_pos = service_pos.map(|p| p + 1).unwrap_or(self.args.len());
        self.args
            .insert(insert_pos, format!("protocol={}", protocol.as_ref()));
        self
    }

    /// Set or replace the cmd attribute.
    pub fn with_cmd(mut self, cmd: impl AsRef<str>) -> Self {
        self.args.retain(|a| !a.to_lowercase().starts_with("cmd="));
        self.args.push(format!("cmd={}", cmd.as_ref()));
        self
    }

    /// Add a cmd-arg attribute (multiple allowed).
    pub fn add_cmd_arg(mut self, arg: impl AsRef<str>) -> Self {
        self.args.push(format!("cmd-arg={}", arg.as_ref()));
        self
    }

    /// Convenience for shell start requests: sets service and protocol.
    pub fn as_shell(mut self, protocol: impl AsRef<str>) -> Self {
        self = self.with_service("shell");
        self = self.with_protocol(protocol);
        self
    }

    pub fn builder(session_id: u32) -> AuthorizationRequest {
        AuthorizationRequest {
            header: Header {
                version: crate::VERSION,
                seq_no: 1,
                session_id,
                length: 0,
                packet_type: crate::TYPE_AUTHOR,
                flags: 0,
            },
            authen_method: 1,
            priv_lvl: 1,
            authen_type: 1,
            authen_service: 1,
            user: String::new(),
            port: String::new(),
            rem_addr: String::new(),
            args: Vec::new(),
        }
    }

    pub fn with_authen(mut self, method: u8, authen_type: u8, service: u8, priv_lvl: u8) -> Self {
        self.authen_method = method;
        self.authen_type = authen_type;
        self.authen_service = service;
        self.priv_lvl = priv_lvl;
        self
    }

    pub fn with_user(mut self, user: String) -> Self {
        self.user = user;
        self
    }

    pub fn with_port(mut self, port: String) -> Self {
        self.port = port;
        self
    }

    pub fn with_rem_addr(mut self, rem_addr: String) -> Self {
        self.rem_addr = rem_addr;
        self
    }

    pub fn add_arg(mut self, arg: String) -> Self {
        self.args.push(arg);
        self
    }

    pub fn validate(self) -> anyhow::Result<Self> {
        crate::validate_author_request(&self)?;
        Ok(self)
    }

    pub fn command_string(&self) -> Option<String> {
        let mut base = None;
        let mut arguments = Vec::new();

        for arg in &self.args {
            if let Some(cmd) = arg.strip_prefix("cmd=") {
                base = Some(cmd.to_string());
            } else if let Some(cmd_arg) = arg.strip_prefix("cmd-arg=") {
                arguments.push(cmd_arg.to_string());
            }
        }

        if base.is_none() && !self.args.is_empty() {
            base = Some(self.args.join(" "));
        }

        base.map(|mut cmd| {
            if !arguments.is_empty() {
                if !cmd.is_empty() {
                    cmd.push(' ');
                }
                cmd.push_str(&arguments.join(" "));
            }
            cmd
        })
    }

    pub fn is_shell_start(&self) -> bool {
        self.args
            .iter()
            .any(|arg| arg.eq_ignore_ascii_case("service=shell"))
            && self
                .args
                .iter()
                .all(|arg| arg.starts_with("service=") || arg.starts_with("protocol="))
    }

    pub fn attributes(&self) -> Vec<crate::util::Attribute> {
        parse_attributes(&self.args)
    }

    pub fn has_cmd_attrs(&self) -> bool {
        self.args
            .iter()
            .any(|a| a.starts_with("cmd=") || a.starts_with("cmd-arg="))
    }

    pub fn has_service_attr(&self) -> bool {
        self.args.iter().any(|a| a.starts_with("service="))
    }
}

fn validate_author_basic_fields(body: &[u8]) -> Result<(u8, u8, u8, u8)> {
    ensure!(body.len() >= 8, "authorization body too short");
    let authen_method = body[0];
    let priv_lvl = body[1];
    let authen_type = body[2];
    let authen_service = body[3];
    ensure!(
        (1..=8).contains(&authen_method),
        "authorization authen_method invalid"
    );
    ensure!(authen_type <= 0x04, "authorization authen_type invalid");
    ensure!(
        authen_service <= 0x07,
        "authorization authen_service invalid"
    );
    ensure!(priv_lvl <= 0x0f, "authorization priv_lvl invalid");
    Ok((authen_method, priv_lvl, authen_type, authen_service))
}

fn parse_author_variable_fields(
    body: &[u8],
) -> Result<(String, String, String, usize, usize)> {
    let user_len = body[4] as usize;
    let port_len = body[5] as usize;
    let rem_addr_len = body[6] as usize;
    let arg_cnt = body[7] as usize;
    let mut cursor = 8;
    let (user, next) = read_string(body, cursor, user_len, "user")?;
    cursor = next;
    let (port, next) = read_string(body, cursor, port_len, "port")?;
    cursor = next;
    let (rem_addr, next) = read_string(body, cursor, rem_addr_len, "rem_addr")?;
    cursor = next;
    Ok((user, port, rem_addr, cursor, arg_cnt))
}

fn parse_author_args(body: &[u8], cursor: usize, arg_cnt: usize) -> Result<Vec<String>> {
    let arg_lens = body
        .get(cursor..cursor + arg_cnt)
        .ok_or_else(|| anyhow!("authorization args length truncated"))?;
    let mut cursor = cursor + arg_cnt;
    let total_args_len: usize = arg_lens.iter().map(|l| *l as usize).sum();
    ensure!(
        cursor + total_args_len <= body.len(),
        "authorization args exceed body length"
    );
    let mut args = Vec::with_capacity(arg_cnt);
    for (idx, len) in arg_lens.iter().enumerate() {
        ensure!(*len > 0, "authorization arg length invalid");
        let (arg, next_cursor) = read_string(body, cursor, *len as usize, &format!("arg[{idx}]"))?;
        cursor = next_cursor;
        args.push(arg);
    }
    validate_attributes(
        &args,
        &[
            "cmd", "cmd-arg", "service", "protocol", "acl", "addr", "priv-lvl",
        ],
    )?;
    Ok(args)
}

pub fn parse_author_body(header: Header, body: &[u8]) -> Result<AuthorizationRequest> {
    let (authen_method, priv_lvl, authen_type, authen_service) =
        validate_author_basic_fields(body)?;
    let (user, port, rem_addr, cursor, arg_cnt) = parse_author_variable_fields(body)?;
    let args = parse_author_args(body, cursor, arg_cnt)?;
    Ok(AuthorizationRequest {
        header,
        authen_method,
        priv_lvl,
        authen_type,
        authen_service,
        user,
        port,
        rem_addr,
        args,
    })
}

pub fn encode_author_response(response: &AuthorizationResponse) -> Result<Vec<u8>> {
    ensure!(
        response.status == AUTHOR_STATUS_PASS_REPL
            || response.status == AUTHOR_STATUS_PASS_ADD
            || response.status == AUTHOR_STATUS_FAIL
            || response.status == AUTHOR_STATUS_ERROR,
        "authorization response status invalid"
    );
    ensure!(
        response.args.len() <= u8::MAX as usize,
        "too many authorization response args"
    );
    ensure!(
        response.server_msg.len() <= u16::MAX as usize,
        "authorization server_msg too long"
    );
    ensure!(
        response.data.len() <= u16::MAX as usize,
        "authorization data too long"
    );
    let mut buf = BytesMut::new();
    buf.put_u8(response.status);
    buf.put_u8(response.args.len() as u8);
    buf.put_u16(response.server_msg.len() as u16);
    buf.put_u16(response.data.len() as u16);
    for arg in &response.args {
        buf.put_u8(arg.len() as u8);
    }
    buf.extend_from_slice(response.server_msg.as_bytes());
    buf.extend_from_slice(response.data.as_bytes());
    for arg in &response.args {
        buf.extend_from_slice(arg.as_bytes());
    }
    Ok(buf.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header() -> Header {
        Header {
            version: crate::VERSION,
            packet_type: crate::TYPE_AUTHOR,
            seq_no: 1,
            flags: 0,
            session_id: 0x12345678,
            length: 0,
        }
    }

    // ==================== AuthorizationRequest Builder Tests ====================

    #[test]
    fn author_request_builder_creates_valid_defaults() {
        let req = AuthorizationRequest::builder(0xDEADBEEF);

        assert_eq!(req.header.session_id, 0xDEADBEEF);
        assert_eq!(req.header.seq_no, 1);
        assert_eq!(req.header.packet_type, crate::TYPE_AUTHOR);
        assert_eq!(req.authen_method, 1);
        assert_eq!(req.priv_lvl, 1);
        assert_eq!(req.authen_type, 1);
        assert_eq!(req.authen_service, 1);
        assert!(req.user.is_empty());
        assert!(req.args.is_empty());
    }

    #[test]
    fn author_request_with_user() {
        let req = AuthorizationRequest::builder(123).with_user("alice".to_string());

        assert_eq!(req.user, "alice");
    }

    #[test]
    fn author_request_with_port() {
        let req = AuthorizationRequest::builder(123).with_port("tty0".to_string());

        assert_eq!(req.port, "tty0");
    }

    #[test]
    fn author_request_with_rem_addr() {
        let req = AuthorizationRequest::builder(123).with_rem_addr("10.0.0.1".to_string());

        assert_eq!(req.rem_addr, "10.0.0.1");
    }

    #[test]
    fn author_request_with_authen() {
        let req = AuthorizationRequest::builder(123).with_authen(5, 2, 3, 15);

        assert_eq!(req.authen_method, 5);
        assert_eq!(req.authen_type, 2);
        assert_eq!(req.authen_service, 3);
        assert_eq!(req.priv_lvl, 15);
    }

    #[test]
    fn author_request_add_arg() {
        let req = AuthorizationRequest::builder(123)
            .add_arg("service=shell".to_string())
            .add_arg("cmd=show".to_string());

        assert_eq!(req.args.len(), 2);
        assert_eq!(req.args[0], "service=shell");
        assert_eq!(req.args[1], "cmd=show");
    }

    // ==================== Service/Protocol/Cmd Builder Tests ====================

    #[test]
    fn author_request_with_service_replaces_existing() {
        let req = AuthorizationRequest::builder(123)
            .add_arg("service=ppp".to_string())
            .with_service("shell");

        assert_eq!(req.args.len(), 1);
        assert_eq!(req.args[0], "service=shell");
    }

    #[test]
    fn author_request_with_service_inserts_first() {
        let req = AuthorizationRequest::builder(123)
            .add_arg("cmd=show".to_string())
            .with_service("shell");

        assert_eq!(req.args[0], "service=shell");
        assert_eq!(req.args[1], "cmd=show");
    }

    #[test]
    fn author_request_with_protocol_after_service() {
        let req = AuthorizationRequest::builder(123)
            .with_service("shell")
            .with_protocol("exec");

        assert_eq!(req.args[0], "service=shell");
        assert_eq!(req.args[1], "protocol=exec");
    }

    #[test]
    fn author_request_with_protocol_replaces_existing() {
        let req = AuthorizationRequest::builder(123)
            .with_service("shell")
            .with_protocol("exec")
            .with_protocol("ssh");

        assert_eq!(req.args.len(), 2);
        assert_eq!(req.args[1], "protocol=ssh");
    }

    #[test]
    fn author_request_with_cmd() {
        let req = AuthorizationRequest::builder(123)
            .with_service("login")
            .with_cmd("show running-config");

        assert!(req.args.iter().any(|a| a == "cmd=show running-config"));
    }

    #[test]
    fn author_request_add_cmd_arg() {
        let req = AuthorizationRequest::builder(123)
            .with_service("login")
            .with_cmd("show")
            .add_cmd_arg("running-config")
            .add_cmd_arg("full");

        assert!(req.args.iter().any(|a| a == "cmd-arg=running-config"));
        assert!(req.args.iter().any(|a| a == "cmd-arg=full"));
    }

    #[test]
    fn author_request_as_shell() {
        let req = AuthorizationRequest::builder(123).as_shell("exec");

        assert_eq!(req.args[0], "service=shell");
        assert_eq!(req.args[1], "protocol=exec");
    }

    // ==================== Query Methods Tests ====================

    #[test]
    fn author_request_command_string_with_cmd_and_args() {
        let req = AuthorizationRequest::builder(123)
            .with_service("login")
            .with_cmd("show")
            .add_cmd_arg("running-config")
            .add_cmd_arg("full");

        let cmd = req.command_string().unwrap();
        assert_eq!(cmd, "show running-config full");
    }

    #[test]
    fn author_request_command_string_cmd_only() {
        let req = AuthorizationRequest::builder(123)
            .with_service("login")
            .with_cmd("reboot");

        let cmd = req.command_string().unwrap();
        assert_eq!(cmd, "reboot");
    }

    #[test]
    fn author_request_command_string_fallback_to_args() {
        let req = AuthorizationRequest::builder(123)
            .add_arg("service=login".to_string())
            .add_arg("protocol=ip".to_string());

        let cmd = req.command_string().unwrap();
        assert_eq!(cmd, "service=login protocol=ip");
    }

    #[test]
    fn author_request_is_shell_start_true() {
        let req = AuthorizationRequest::builder(123)
            .with_service("shell")
            .with_protocol("exec");

        assert!(req.is_shell_start());
    }

    #[test]
    fn author_request_is_shell_start_false_with_cmd() {
        let req = AuthorizationRequest::builder(123)
            .with_service("shell")
            .with_protocol("exec")
            .with_cmd("show");

        assert!(!req.is_shell_start());
    }

    #[test]
    fn author_request_is_shell_start_false_non_shell() {
        let req = AuthorizationRequest::builder(123)
            .with_service("login")
            .with_protocol("ip");

        assert!(!req.is_shell_start());
    }

    #[test]
    fn author_request_has_cmd_attrs() {
        let req = AuthorizationRequest::builder(123).with_cmd("show");

        assert!(req.has_cmd_attrs());
    }

    #[test]
    fn author_request_has_service_attr() {
        let req = AuthorizationRequest::builder(123).with_service("shell");

        assert!(req.has_service_attr());
    }

    #[test]
    fn author_request_attributes_parsing() {
        let req = AuthorizationRequest::builder(123)
            .with_service("shell")
            .with_protocol("exec")
            .add_arg("priv-lvl=15".to_string());

        let attrs = req.attributes();
        assert_eq!(attrs.len(), 3);
        assert_eq!(attrs[0].name, "service");
        assert_eq!(attrs[0].value, Some("shell".to_string()));
        assert_eq!(attrs[1].name, "protocol");
        assert_eq!(attrs[2].name, "priv-lvl");
        assert_eq!(attrs[2].value, Some("15".to_string()));
    }

    // ==================== parse_author_body Tests ====================

    #[test]
    fn parse_author_body_valid() {
        let header = make_header();
        let mut body = vec![
            0x01, // authen_method
            0x01, // priv_lvl
            0x01, // authen_type
            0x01, // authen_service
            0x05, // user_len = 5
            0x04, // port_len = 4
            0x09, // rem_addr_len = 9
            0x02, // arg_cnt = 2
        ];
        body.extend_from_slice(b"alice"); // user
        body.extend_from_slice(b"tty0"); // port
        body.extend_from_slice(b"127.0.0.1"); // rem_addr
        body.push(13); // arg[0] len = "service=shell"
        body.push(13); // arg[1] len = "protocol=exec"
        body.extend_from_slice(b"service=shell");
        body.extend_from_slice(b"protocol=exec");

        let req = parse_author_body(header, &body).unwrap();

        assert_eq!(req.authen_method, 1);
        assert_eq!(req.user, "alice");
        assert_eq!(req.port, "tty0");
        assert_eq!(req.rem_addr, "127.0.0.1");
        assert_eq!(req.args.len(), 2);
        assert_eq!(req.args[0], "service=shell");
        assert_eq!(req.args[1], "protocol=exec");
    }

    #[test]
    fn parse_author_body_rejects_short_body() {
        let header = make_header();
        let body = vec![0x01, 0x01, 0x01]; // only 3 bytes, needs 8

        let result = parse_author_body(header, &body);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn parse_author_body_rejects_invalid_authen_method() {
        let header = make_header();
        let body = vec![
            0x00, // authen_method = 0 (invalid, must be 1-8)
            0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];

        let result = parse_author_body(header, &body);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("authen_method"));
    }

    #[test]
    fn parse_author_body_rejects_invalid_authen_type() {
        let header = make_header();
        let body = vec![
            0x01, // authen_method
            0x01, // priv_lvl
            0x05, // authen_type = 5 (invalid, max is 4)
            0x01, 0x00, 0x00, 0x00, 0x00,
        ];

        let result = parse_author_body(header, &body);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("authen_type"));
    }

    #[test]
    fn parse_author_body_rejects_invalid_priv_lvl() {
        let header = make_header();
        let body = vec![
            0x01, // authen_method
            0x10, // priv_lvl = 16 (invalid, max is 15)
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];

        let result = parse_author_body(header, &body);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("priv_lvl"));
    }

    #[test]
    fn parse_author_body_rejects_empty_arg() {
        let header = make_header();
        let mut body = vec![
            0x01, 0x01, 0x01, 0x01, // authen fields
            0x00, 0x00, 0x00, // user/port/rem_addr lens = 0
            0x01, // arg_cnt = 1
        ];
        body.push(0); // arg[0] len = 0 (invalid)

        let result = parse_author_body(header, &body);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("arg length"));
    }

    // ==================== encode_author_response Tests ====================

    #[test]
    fn encode_author_response_pass_add() {
        let response = AuthorizationResponse {
            status: AUTHOR_STATUS_PASS_ADD,
            server_msg: "Authorized".to_string(),
            data: String::new(),
            args: vec!["priv-lvl=15".to_string()],
        };

        let encoded = encode_author_response(&response).unwrap();

        assert_eq!(encoded[0], AUTHOR_STATUS_PASS_ADD);
        assert_eq!(encoded[1], 1); // arg count
    }

    #[test]
    fn encode_author_response_pass_repl() {
        let response = AuthorizationResponse {
            status: AUTHOR_STATUS_PASS_REPL,
            server_msg: String::new(),
            data: String::new(),
            args: vec!["priv-lvl=1".to_string()],
        };

        let result = encode_author_response(&response);
        assert!(result.is_ok());
    }

    #[test]
    fn encode_author_response_fail() {
        let response = AuthorizationResponse {
            status: AUTHOR_STATUS_FAIL,
            server_msg: "Access denied".to_string(),
            data: String::new(),
            args: vec![],
        };

        let result = encode_author_response(&response);
        assert!(result.is_ok());
    }

    #[test]
    fn encode_author_response_error() {
        let response = AuthorizationResponse {
            status: AUTHOR_STATUS_ERROR,
            server_msg: "Internal error".to_string(),
            data: "debug info".to_string(),
            args: vec![],
        };

        let result = encode_author_response(&response);
        assert!(result.is_ok());
    }

    #[test]
    fn encode_author_response_rejects_invalid_status() {
        let response = AuthorizationResponse {
            status: 0xFF,
            server_msg: String::new(),
            data: String::new(),
            args: vec![],
        };

        let result = encode_author_response(&response);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("status"));
    }

    #[test]
    fn encode_author_response_with_multiple_args() {
        let response = AuthorizationResponse {
            status: AUTHOR_STATUS_PASS_ADD,
            server_msg: "OK".to_string(),
            data: String::new(),
            args: vec![
                "priv-lvl=15".to_string(),
                "acl=admin".to_string(),
                "addr=10.0.0.0/8".to_string(),
            ],
        };

        let encoded = encode_author_response(&response).unwrap();

        assert_eq!(encoded[1], 3); // 3 args
    }

    // ==================== Validation Edge Cases ====================

    #[test]
    fn author_request_case_insensitive_service() {
        let req = AuthorizationRequest::builder(123)
            .add_arg("SERVICE=shell".to_string())
            .with_service("login"); // Should replace SERVICE=shell

        assert_eq!(req.args.len(), 1);
        assert_eq!(req.args[0], "service=login");
    }

    #[test]
    fn author_request_case_insensitive_protocol() {
        let req = AuthorizationRequest::builder(123)
            .with_service("shell")
            .add_arg("PROTOCOL=exec".to_string())
            .with_protocol("ssh"); // Should replace PROTOCOL=exec

        assert!(req.args.iter().any(|a| a == "protocol=ssh"));
        assert!(!req.args.iter().any(|a| a == "PROTOCOL=exec"));
    }
}
