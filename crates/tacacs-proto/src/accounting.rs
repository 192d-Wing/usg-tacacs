// SPDX-License-Identifier: Apache-2.0
//! TACACS+ accounting packet structures plus parsing/encoding helpers.

use crate::header::Header;
use crate::util::{parse_attributes, read_string, validate_attributes};
use crate::{
    ACCT_FLAG_START, ACCT_FLAG_STOP, ACCT_FLAG_WATCHDOG, ACCT_STATUS_ERROR, ACCT_STATUS_FOLLOW,
    ACCT_STATUS_SUCCESS,
};
use anyhow::{Result, anyhow, ensure};

#[derive(Debug, Clone)]
pub struct AccountingRequest {
    pub header: Header,
    pub flags: u8,
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
pub struct AccountingResponse {
    pub status: u8,
    pub server_msg: String,
    pub data: String,
    pub args: Vec<String>,
}

fn validate_acct_basic_fields(body: &[u8]) -> Result<(u8, u8, u8, u8, u8)> {
    ensure!(body.len() >= 9, "accounting body too short");
    let flags = body[0];
    let authen_method = body[1];
    let priv_lvl = body[2];
    let authen_type = body[3];
    let authen_service = body[4];
    ensure!(
        (1..=8).contains(&authen_method),
        "accounting authen_method invalid"
    );
    ensure!(authen_type <= 0x04, "accounting authen_type invalid");
    ensure!(authen_service <= 0x07, "accounting authen_service invalid");
    ensure!(priv_lvl <= 0x0f, "accounting priv_lvl invalid");
    Ok((flags, authen_method, priv_lvl, authen_type, authen_service))
}

fn validate_acct_flags(flags: u8) -> Result<()> {
    let valid_mask: u8 = ACCT_FLAG_START | ACCT_FLAG_STOP | ACCT_FLAG_WATCHDOG;
    let flag_bits: u8 = flags & valid_mask;
    ensure!(
        flag_bits.count_ones() == 1 && flags & !valid_mask == 0,
        "accounting flags invalid"
    );
    Ok(())
}

fn parse_acct_variable_fields(
    body: &[u8],
) -> Result<(String, String, String, usize, usize)> {
    let user_len = body[5] as usize;
    let port_len = body[6] as usize;
    let rem_addr_len = body[7] as usize;
    let arg_cnt = body[8] as usize;
    // Per RFC 8907 Section 7.1: arg lengths are at [9..9+arg_cnt],
    // then user, port, rem_addr, then arg data.
    let mut cursor: usize = 9 + arg_cnt;
    let (user, next) = read_string(body, cursor, user_len, "user")?;
    cursor = next;
    let (port, next) = read_string(body, cursor, port_len, "port")?;
    cursor = next;
    let (rem_addr, next) = read_string(body, cursor, rem_addr_len, "rem_addr")?;
    cursor = next;
    Ok((user, port, rem_addr, cursor, arg_cnt))
}

fn parse_acct_args(body: &[u8], cursor: usize, arg_cnt: usize) -> Result<Vec<String>> {
    let arg_lens: &[u8] = body
        .get(9..9 + arg_cnt)
        .ok_or_else(|| anyhow!("accounting args length truncated"))?;
    let mut cursor = cursor;
    let total_args_len: usize = arg_lens.iter().map(|l| *l as usize).sum();
    ensure!(
        cursor + total_args_len <= body.len(),
        "accounting args exceed body length"
    );
    let mut args: Vec<String> = Vec::with_capacity(arg_cnt);
    for len in arg_lens.iter() {
        ensure!(*len > 0, "accounting arg length invalid");
        let (arg, next_cursor) = read_string(body, cursor, *len as usize, "arg")?;
        cursor = next_cursor;
        args.push(arg);
    }
    validate_attributes(
        &args,
        &[
            "cmd",
            "cmd-arg",
            "service",
            "protocol",
            "acl",
            "addr",
            "priv-lvl",
            "task_id",
            "elapsed_time",
            "status",
            "start_time",
            "elapsed_seconds",
            "bytes_in",
            "bytes_out",
        ],
    )?;
    Ok(args)
}

pub fn parse_accounting_body(header: Header, body: &[u8]) -> Result<AccountingRequest> {
    let (flags, authen_method, priv_lvl, authen_type, authen_service) =
        validate_acct_basic_fields(body)?;
    validate_acct_flags(flags)?;
    let (user, port, rem_addr, cursor, arg_cnt) = parse_acct_variable_fields(body)?;
    let args = parse_acct_args(body, cursor, arg_cnt)?;
    Ok(AccountingRequest {
        header,
        flags,
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

impl AccountingRequest {
    pub fn attributes(&self) -> Vec<crate::util::Attribute> {
        parse_attributes(&self.args)
    }

    pub fn with_service(mut self, service: impl AsRef<str>) -> Self {
        self.args
            .retain(|a| !a.to_lowercase().starts_with("service="));
        self.args.insert(0, format!("service={}", service.as_ref()));
        self
    }

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

    pub fn with_cmd(mut self, cmd: impl AsRef<str>) -> Self {
        self.args.retain(|a| !a.to_lowercase().starts_with("cmd="));
        self.args.push(format!("cmd={}", cmd.as_ref()));
        self
    }

    pub fn add_cmd_arg(mut self, arg: impl AsRef<str>) -> Self {
        self.args.push(format!("cmd-arg={}", arg.as_ref()));
        self
    }

    pub fn with_task_id(mut self, task: impl AsRef<str>) -> Self {
        self.args
            .retain(|a| !a.to_lowercase().starts_with("task_id="));
        self.args.push(format!("task_id={}", task.as_ref()));
        self
    }

    pub fn with_status(mut self, status: impl AsRef<str>) -> Self {
        self.args
            .retain(|a| !a.to_lowercase().starts_with("status="));
        self.args.push(format!("status={}", status.as_ref()));
        self
    }

    pub fn with_bytes(mut self, bytes_in: impl AsRef<str>, bytes_out: impl AsRef<str>) -> Self {
        self.args
            .retain(|a| !a.to_lowercase().starts_with("bytes_in="));
        self.args
            .retain(|a| !a.to_lowercase().starts_with("bytes_out="));
        self.args.push(format!("bytes_in={}", bytes_in.as_ref()));
        self.args.push(format!("bytes_out={}", bytes_out.as_ref()));
        self
    }

    pub fn builder(session_id: u32, flags: u8) -> AccountingRequest {
        AccountingRequest {
            header: Header {
                version: crate::VERSION,
                seq_no: 1,
                session_id,
                length: 0,
                packet_type: crate::TYPE_ACCT,
                flags: 0,
            },
            flags,
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
        crate::validate_accounting_request(&self)?;
        Ok(self)
    }
}

pub fn encode_accounting_response(response: &AccountingResponse) -> Result<Vec<u8>> {
    ensure!(
        response.status == ACCT_STATUS_SUCCESS
            || response.status == ACCT_STATUS_ERROR
            || response.status == ACCT_STATUS_FOLLOW,
        "accounting response status invalid"
    );
    ensure!(
        response.args.len() <= u8::MAX as usize,
        "too many accounting response args"
    );
    ensure!(
        response.server_msg.len() <= u16::MAX as usize,
        "accounting server_msg too long"
    );
    ensure!(
        response.data.len() <= u16::MAX as usize,
        "accounting data too long"
    );
    // RFC 8907 Section 7.2: server_msg_len(2) + data_len(2) + status(1)
    let total_arg_data_len: usize = response.args.iter().map(|a| a.len()).sum();
    let total_len =
        6 + response.args.len() + response.server_msg.len() + response.data.len() + total_arg_data_len;
    let mut buf = Vec::with_capacity(total_len);
    buf.extend_from_slice(&(response.server_msg.len() as u16).to_be_bytes());
    buf.extend_from_slice(&(response.data.len() as u16).to_be_bytes());
    buf.push(response.status);
    buf.push(response.args.len() as u8);
    for arg in &response.args {
        buf.push(arg.len() as u8);
    }
    buf.extend_from_slice(response.server_msg.as_bytes());
    buf.extend_from_slice(response.data.as_bytes());
    for arg in &response.args {
        buf.extend_from_slice(arg.as_bytes());
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header() -> Header {
        Header {
            version: crate::VERSION,
            packet_type: crate::TYPE_ACCT,
            seq_no: 1,
            flags: 0,
            session_id: 0x12345678,
            length: 0,
        }
    }

    // ==================== AccountingRequest Builder Tests ====================

    #[test]
    fn accounting_request_builder_creates_valid_defaults() {
        let req = AccountingRequest::builder(0xDEADBEEF, ACCT_FLAG_START);

        assert_eq!(req.header.session_id, 0xDEADBEEF);
        assert_eq!(req.header.seq_no, 1);
        assert_eq!(req.header.packet_type, crate::TYPE_ACCT);
        assert_eq!(req.flags, ACCT_FLAG_START);
        assert_eq!(req.authen_method, 1);
        assert_eq!(req.priv_lvl, 1);
        assert!(req.user.is_empty());
        assert!(req.args.is_empty());
    }

    #[test]
    fn accounting_request_with_user() {
        let req = AccountingRequest::builder(123, ACCT_FLAG_START).with_user("alice".to_string());

        assert_eq!(req.user, "alice");
    }

    #[test]
    fn accounting_request_with_port() {
        let req = AccountingRequest::builder(123, ACCT_FLAG_START).with_port("tty0".to_string());

        assert_eq!(req.port, "tty0");
    }

    #[test]
    fn accounting_request_with_rem_addr() {
        let req =
            AccountingRequest::builder(123, ACCT_FLAG_START).with_rem_addr("10.0.0.1".to_string());

        assert_eq!(req.rem_addr, "10.0.0.1");
    }

    #[test]
    fn accounting_request_with_authen() {
        let req = AccountingRequest::builder(123, ACCT_FLAG_START).with_authen(5, 2, 3, 15);

        assert_eq!(req.authen_method, 5);
        assert_eq!(req.authen_type, 2);
        assert_eq!(req.authen_service, 3);
        assert_eq!(req.priv_lvl, 15);
    }

    #[test]
    fn accounting_request_add_arg() {
        let req = AccountingRequest::builder(123, ACCT_FLAG_START)
            .add_arg("service=shell".to_string())
            .add_arg("task_id=123".to_string());

        assert_eq!(req.args.len(), 2);
        assert_eq!(req.args[0], "service=shell");
        assert_eq!(req.args[1], "task_id=123");
    }

    // ==================== Service/Protocol/Cmd Builder Tests ====================

    #[test]
    fn accounting_request_with_service() {
        let req = AccountingRequest::builder(123, ACCT_FLAG_START).with_service("shell");

        assert_eq!(req.args[0], "service=shell");
    }

    #[test]
    fn accounting_request_with_service_replaces_existing() {
        let req = AccountingRequest::builder(123, ACCT_FLAG_START)
            .add_arg("service=ppp".to_string())
            .with_service("shell");

        assert_eq!(req.args.len(), 1);
        assert_eq!(req.args[0], "service=shell");
    }

    #[test]
    fn accounting_request_with_protocol() {
        let req = AccountingRequest::builder(123, ACCT_FLAG_START)
            .with_service("shell")
            .with_protocol("exec");

        assert_eq!(req.args[0], "service=shell");
        assert_eq!(req.args[1], "protocol=exec");
    }

    #[test]
    fn accounting_request_with_cmd() {
        let req = AccountingRequest::builder(123, ACCT_FLAG_START)
            .with_service("login")
            .with_cmd("show running-config");

        assert!(req.args.iter().any(|a| a == "cmd=show running-config"));
    }

    #[test]
    fn accounting_request_add_cmd_arg() {
        let req = AccountingRequest::builder(123, ACCT_FLAG_START)
            .with_service("login")
            .with_cmd("show")
            .add_cmd_arg("running-config");

        assert!(req.args.iter().any(|a| a == "cmd-arg=running-config"));
    }

    #[test]
    fn accounting_request_with_task_id() {
        let req = AccountingRequest::builder(123, ACCT_FLAG_START).with_task_id("42");

        assert!(req.args.iter().any(|a| a == "task_id=42"));
    }

    #[test]
    fn accounting_request_with_status() {
        let req = AccountingRequest::builder(123, ACCT_FLAG_STOP).with_status("0");

        assert!(req.args.iter().any(|a| a == "status=0"));
    }

    #[test]
    fn accounting_request_with_bytes() {
        let req = AccountingRequest::builder(123, ACCT_FLAG_STOP).with_bytes("1024", "2048");

        assert!(req.args.iter().any(|a| a == "bytes_in=1024"));
        assert!(req.args.iter().any(|a| a == "bytes_out=2048"));
    }

    #[test]
    fn accounting_request_attributes_parsing() {
        let req = AccountingRequest::builder(123, ACCT_FLAG_START)
            .with_service("shell")
            .with_task_id("42")
            .add_arg("elapsed_time=100".to_string());

        let attrs = req.attributes();
        assert_eq!(attrs.len(), 3);
        assert_eq!(attrs[0].name, "service");
        assert_eq!(attrs[0].value, Some("shell".to_string()));
        assert_eq!(attrs[1].name, "task_id");
        assert_eq!(attrs[1].value, Some("42".to_string()));
    }

    // ==================== parse_accounting_body Tests ====================

    #[test]
    fn parse_accounting_body_start_valid() {
        let header = make_header();
        let mut body = vec![
            ACCT_FLAG_START, // flags
            0x01,            // authen_method
            0x01,            // priv_lvl
            0x01,            // authen_type
            0x01,            // authen_service
            0x05,            // user_len = 5
            0x04,            // port_len = 4
            0x09,            // rem_addr_len = 9
            0x02,            // arg_cnt = 2
        ];
        body.push(13); // arg[0] len = "service=shell"
        body.push(10); // arg[1] len = "task_id=42"
        body.extend_from_slice(b"alice"); // user
        body.extend_from_slice(b"tty0"); // port
        body.extend_from_slice(b"127.0.0.1"); // rem_addr
        body.extend_from_slice(b"service=shell");
        body.extend_from_slice(b"task_id=42");

        let req = parse_accounting_body(header, &body).unwrap();

        assert_eq!(req.flags, ACCT_FLAG_START);
        assert_eq!(req.authen_method, 1);
        assert_eq!(req.user, "alice");
        assert_eq!(req.port, "tty0");
        assert_eq!(req.rem_addr, "127.0.0.1");
        assert_eq!(req.args.len(), 2);
        assert_eq!(req.args[0], "service=shell");
        assert_eq!(req.args[1], "task_id=42");
    }

    #[test]
    fn parse_accounting_body_stop_valid() {
        let header = make_header();
        let mut body = vec![
            ACCT_FLAG_STOP, // flags
            0x01,           // authen_method
            0x01,           // priv_lvl
            0x01,           // authen_type
            0x01,           // authen_service
            0x05,           // user_len = 5
            0x00,           // port_len = 0
            0x00,           // rem_addr_len = 0
            0x01,           // arg_cnt = 1
        ];
        body.push(13); // arg[0] len
        body.extend_from_slice(b"alice"); // user
        body.extend_from_slice(b"service=shell");

        let req = parse_accounting_body(header, &body).unwrap();

        assert_eq!(req.flags, ACCT_FLAG_STOP);
    }

    #[test]
    fn parse_accounting_body_watchdog_valid() {
        let header = make_header();
        let mut body = vec![
            ACCT_FLAG_WATCHDOG, // flags
            0x01,               // authen_method
            0x01,               // priv_lvl
            0x01,               // authen_type
            0x01,               // authen_service
            0x05,               // user_len = 5
            0x00,               // port_len = 0
            0x00,               // rem_addr_len = 0
            0x01,               // arg_cnt = 1
        ];
        body.push(13); // arg[0] len
        body.extend_from_slice(b"alice"); // user
        body.extend_from_slice(b"service=shell");

        let req = parse_accounting_body(header, &body).unwrap();

        assert_eq!(req.flags, ACCT_FLAG_WATCHDOG);
    }

    #[test]
    fn parse_accounting_body_rejects_short_body() {
        let header = make_header();
        let body = vec![0x02, 0x01, 0x01]; // only 3 bytes, needs 9

        let result = parse_accounting_body(header, &body);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn parse_accounting_body_rejects_invalid_flags() {
        let header = make_header();
        let body = vec![
            0x00, // flags = 0 (invalid, must have exactly one of START/STOP/WATCHDOG)
            0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];

        let result = parse_accounting_body(header, &body);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("flags"));
    }

    #[test]
    fn parse_accounting_body_rejects_multiple_flags() {
        let header = make_header();
        let body = vec![
            ACCT_FLAG_START | ACCT_FLAG_STOP, // both START and STOP (invalid)
            0x01,
            0x01,
            0x01,
            0x01,
            0x00,
            0x00,
            0x00,
            0x00,
        ];

        let result = parse_accounting_body(header, &body);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("flags"));
    }

    #[test]
    fn parse_accounting_body_rejects_invalid_authen_method() {
        let header = make_header();
        let body = vec![
            ACCT_FLAG_START,
            0x00, // authen_method = 0 (invalid, must be 1-8)
            0x01,
            0x01,
            0x01,
            0x00,
            0x00,
            0x00,
            0x00,
        ];

        let result = parse_accounting_body(header, &body);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("authen_method"));
    }

    #[test]
    fn parse_accounting_body_rejects_invalid_authen_type() {
        let header = make_header();
        let body = vec![
            ACCT_FLAG_START,
            0x01, // authen_method
            0x01, // priv_lvl
            0x05, // authen_type = 5 (invalid, max is 4)
            0x01,
            0x00,
            0x00,
            0x00,
            0x00,
        ];

        let result = parse_accounting_body(header, &body);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("authen_type"));
    }

    #[test]
    fn parse_accounting_body_rejects_invalid_priv_lvl() {
        let header = make_header();
        let body = vec![
            ACCT_FLAG_START,
            0x01, // authen_method
            0x10, // priv_lvl = 16 (invalid, max is 15)
            0x01,
            0x01,
            0x00,
            0x00,
            0x00,
            0x00,
        ];

        let result = parse_accounting_body(header, &body);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("priv_lvl"));
    }

    #[test]
    fn parse_accounting_body_rejects_empty_arg() {
        let header = make_header();
        let mut body = vec![
            ACCT_FLAG_START,
            0x01,
            0x01,
            0x01,
            0x01, // authen fields
            0x00,
            0x00,
            0x00, // user/port/rem_addr lens = 0
            0x01, // arg_cnt = 1
        ];
        body.push(0); // arg[0] len = 0 (invalid)

        let result = parse_accounting_body(header, &body);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("arg length"));
    }

    // ==================== encode_accounting_response Tests ====================

    #[test]
    fn encode_accounting_response_success() {
        let response = AccountingResponse {
            status: ACCT_STATUS_SUCCESS,
            server_msg: "Recorded".to_string(),
            data: String::new(),
            args: vec![],
        };

        let encoded = encode_accounting_response(&response).unwrap();

        // RFC 8907: server_msg_len(2) + data_len(2) + status(1)
        assert_eq!(encoded[4], ACCT_STATUS_SUCCESS);
    }

    #[test]
    fn encode_accounting_response_error() {
        let response = AccountingResponse {
            status: ACCT_STATUS_ERROR,
            server_msg: "Database error".to_string(),
            data: "debug info".to_string(),
            args: vec![],
        };

        let result = encode_accounting_response(&response);
        assert!(result.is_ok());
    }

    #[test]
    fn encode_accounting_response_follow() {
        let response = AccountingResponse {
            status: ACCT_STATUS_FOLLOW,
            server_msg: String::new(),
            data: String::new(),
            args: vec![],
        };

        let result = encode_accounting_response(&response);
        assert!(result.is_ok());
    }

    #[test]
    fn encode_accounting_response_rejects_invalid_status() {
        let response = AccountingResponse {
            status: 0xFF,
            server_msg: String::new(),
            data: String::new(),
            args: vec![],
        };

        let result = encode_accounting_response(&response);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("status"));
    }

    #[test]
    fn encode_accounting_response_with_args() {
        let response = AccountingResponse {
            status: ACCT_STATUS_SUCCESS,
            server_msg: String::new(),
            data: String::new(),
            args: vec!["result=ok".to_string()],
        };

        let encoded = encode_accounting_response(&response).unwrap();

        // status(1) + server_msg_len(2) + data_len(2) + arg_cnt(1) + arg_lens(1) + args(9)
        assert_eq!(encoded[5], 1); // arg count
    }

    // ==================== Flag Combination Tests ====================

    #[test]
    fn accounting_flags_start_only() {
        let header = make_header();
        let mut body = vec![
            ACCT_FLAG_START, // only START
            0x01,
            0x01,
            0x01,
            0x01,
            0x00,
            0x00,
            0x00,
            0x01,
        ];
        body.push(13);
        body.extend_from_slice(b"service=shell");

        let result = parse_accounting_body(header, &body);
        assert!(result.is_ok());
    }

    #[test]
    fn accounting_flags_stop_only() {
        let header = make_header();
        let mut body = vec![
            ACCT_FLAG_STOP, // only STOP
            0x01,
            0x01,
            0x01,
            0x01,
            0x00,
            0x00,
            0x00,
            0x01,
        ];
        body.push(13);
        body.extend_from_slice(b"service=shell");

        let result = parse_accounting_body(header, &body);
        assert!(result.is_ok());
    }

    #[test]
    fn accounting_flags_watchdog_only() {
        let header = make_header();
        let mut body = vec![
            ACCT_FLAG_WATCHDOG, // only WATCHDOG
            0x01,
            0x01,
            0x01,
            0x01,
            0x00,
            0x00,
            0x00,
            0x01,
        ];
        body.push(13);
        body.extend_from_slice(b"service=shell");

        let result = parse_accounting_body(header, &body);
        assert!(result.is_ok());
    }

    #[test]
    fn accounting_rejects_extraneous_flags() {
        let header = make_header();
        let body = vec![
            ACCT_FLAG_START | 0x80, // START + unknown high bit
            0x01,
            0x01,
            0x01,
            0x01,
            0x00,
            0x00,
            0x00,
            0x00,
        ];

        let result = parse_accounting_body(header, &body);
        assert!(result.is_err());
    }
}
