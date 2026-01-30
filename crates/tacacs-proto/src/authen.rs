// SPDX-License-Identifier: Apache-2.0
//! TACACS+ authentication packet structures plus parsing/encoding helpers.

use crate::header::Header;
use crate::util::read_bytes;
use crate::{
    AUTHEN_FLAG_NOECHO, AUTHEN_STATUS_ERROR, AUTHEN_STATUS_FAIL, AUTHEN_STATUS_FOLLOW,
    AUTHEN_STATUS_GETDATA, AUTHEN_STATUS_GETPASS, AUTHEN_STATUS_GETUSER, AUTHEN_STATUS_PASS,
    AUTHEN_STATUS_RESTART, AUTHEN_TYPE_ARAP, AUTHEN_TYPE_ASCII, AUTHEN_TYPE_CHAP, AUTHEN_TYPE_PAP,
};
use anyhow::{Result, ensure};
use bytes::{BufMut, BytesMut};
use std::borrow::Cow;

#[derive(Debug, Clone)]
pub struct AuthenStart {
    pub header: Header,
    pub action: u8,
    pub priv_lvl: u8,
    pub authen_type: u8,
    pub service: u8,
    pub user_raw: Vec<u8>,
    pub user: String,
    pub port_raw: Vec<u8>,
    pub port: String,
    pub rem_addr_raw: Vec<u8>,
    pub rem_addr: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct AuthenContinue {
    pub header: Header,
    pub user_msg: Vec<u8>,
    pub data: Vec<u8>,
    pub flags: u8,
}

#[derive(Debug, Clone)]
pub struct AuthenReply {
    pub status: u8,
    pub flags: u8,
    pub server_msg: String,
    pub server_msg_raw: Vec<u8>,
    pub data: Vec<u8>,
}

impl AuthenReply {
    /// Returns the server_msg as raw bytes, preferring the raw buffer when present.
    pub fn server_msg_bytes(&self) -> Cow<'_, [u8]> {
        if !self.server_msg_raw.is_empty() {
            Cow::Borrowed(self.server_msg_raw.as_slice())
        } else {
            Cow::Owned(self.server_msg.as_bytes().to_vec())
        }
    }
}

#[derive(Debug, Clone)]
pub enum AuthenPacket {
    Start(AuthenStart),
    Continue(AuthenContinue),
}

impl AuthenStart {
    pub fn builder(
        session_id: u32,
        action: u8,
        priv_lvl: u8,
        authen_type: u8,
        service: u8,
    ) -> AuthenStart {
        AuthenStart {
            header: Header {
                version: crate::VERSION,
                seq_no: 1,
                session_id,
                length: 0,
                packet_type: crate::TYPE_AUTHEN,
                flags: 0,
            },
            action,
            priv_lvl,
            authen_type,
            service,
            user_raw: Vec::new(),
            user: String::new(),
            port_raw: Vec::new(),
            port: String::new(),
            rem_addr_raw: Vec::new(),
            rem_addr: String::new(),
            data: Vec::new(),
        }
    }

    pub fn with_user(mut self, user_raw: Vec<u8>, user: String) -> Self {
        self.user_raw = user_raw;
        self.user = user;
        self
    }

    pub fn with_port(mut self, port_raw: Vec<u8>, port: String) -> Self {
        self.port_raw = port_raw;
        self.port = port;
        self
    }

    pub fn with_rem_addr(mut self, rem_addr_raw: Vec<u8>, rem_addr: String) -> Self {
        self.rem_addr_raw = rem_addr_raw;
        self.rem_addr = rem_addr;
        self
    }

    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }

    pub fn validate(self) -> anyhow::Result<Self> {
        crate::validate_authen_start(&self)?;
        Ok(self)
    }
}

impl AuthenContinue {
    pub fn builder(session_id: u32) -> AuthenContinue {
        AuthenContinue {
            header: Header {
                version: crate::VERSION,
                seq_no: 2,
                session_id,
                length: 0,
                packet_type: crate::TYPE_AUTHEN,
                flags: 0,
            },
            user_msg: Vec::new(),
            data: Vec::new(),
            flags: 0,
        }
    }

    pub fn with_seq(mut self, seq_no: u8) -> Self {
        self.header.seq_no = seq_no;
        self
    }

    pub fn with_user_msg(mut self, msg: Vec<u8>) -> Self {
        self.user_msg = msg;
        self
    }

    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }

    pub fn with_flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }

    pub fn validate(self) -> anyhow::Result<Self> {
        crate::validate_authen_continue(&self)?;
        Ok(self)
    }
}

#[derive(Debug, Clone)]
pub enum AuthenData {
    Pap { password: String },
    Chap { chap_id: u8, response: Vec<u8> },
    Raw(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct AuthSessionState {
    pub last_seq: u8,
    pub expect_client: bool,
    pub authen_type: Option<u8>,
    pub challenge: Option<Vec<u8>>,
    pub username: Option<String>,
    pub username_raw: Option<Vec<u8>>,
    pub port_raw: Option<Vec<u8>>,
    pub port: Option<String>,
    pub rem_addr_raw: Option<Vec<u8>>,
    pub rem_addr: Option<String>,
    pub chap_id: Option<u8>,
    pub ascii_need_user: bool,
    pub ascii_need_pass: bool,
    pub ascii_attempts: u8,
    pub ascii_user_attempts: u8,
    pub ascii_pass_attempts: u8,
    pub service: Option<u8>,
    pub action: Option<u8>,
}

impl AuthSessionState {
    /// Create a new AuthSessionState from an AuthenStart packet.
    ///
    /// This is the preferred way to create an AuthSessionState from a start packet.
    pub fn from_start(start: &AuthenStart) -> Result<Self> {
        ensure!(start.header.seq_no % 2 == 1, "auth start must use odd seq");
        Ok(Self {
            last_seq: start.header.seq_no,
            expect_client: false,
            authen_type: Some(start.authen_type),
            challenge: None,
            username: Some(start.user.clone()),
            username_raw: Some(start.user_raw.clone()),
            port_raw: Some(start.port_raw.clone()),
            port: if start.port_raw.is_empty() || start.port.is_empty() {
                None
            } else {
                Some(start.port.clone())
            },
            rem_addr_raw: Some(start.rem_addr_raw.clone()),
            rem_addr: if start.rem_addr_raw.is_empty() || start.rem_addr.is_empty() {
                None
            } else {
                Some(start.rem_addr.clone())
            },
            chap_id: None,
            ascii_need_user: false,
            ascii_need_pass: false,
            ascii_attempts: 0,
            ascii_user_attempts: 0,
            ascii_pass_attempts: 0,
            service: Some(start.service),
            action: Some(start.action),
        })
    }

    /// Deprecated: Use `from_start()` instead.
    #[deprecated(since = "0.76.0", note = "Use `from_start()` instead")]
    #[allow(clippy::too_many_arguments)]
    pub fn new_from_start(
        header: &Header,
        authen_type: u8,
        username: String,
        username_raw: Vec<u8>,
        port: String,
        port_raw: Vec<u8>,
        rem_addr: String,
        rem_addr_raw: Vec<u8>,
        service: u8,
        action: u8,
    ) -> Result<Self> {
        ensure!(header.seq_no % 2 == 1, "auth start must use odd seq");
        Ok(Self {
            last_seq: header.seq_no,
            expect_client: false,
            authen_type: Some(authen_type),
            challenge: None,
            username: Some(username),
            username_raw: Some(username_raw),
            port_raw: Some(port_raw.clone()),
            port: if port_raw.is_empty() || port.is_empty() {
                None
            } else {
                Some(port)
            },
            rem_addr_raw: Some(rem_addr_raw.clone()),
            rem_addr: if rem_addr_raw.is_empty() || rem_addr.is_empty() {
                None
            } else {
                Some(rem_addr)
            },
            chap_id: None,
            ascii_need_user: false,
            ascii_need_pass: false,
            ascii_attempts: 0,
            ascii_user_attempts: 0,
            ascii_pass_attempts: 0,
            service: Some(service),
            action: Some(action),
        })
    }

    pub fn validate_client(&mut self, header: &Header) -> Result<()> {
        ensure!(self.expect_client, "unexpected client packet order");
        ensure!(header.seq_no % 2 == 1, "client packets must be odd seq");
        ensure!(
            header.seq_no == self.last_seq.wrapping_add(1),
            "client seq out of order"
        );
        self.last_seq = header.seq_no;
        self.expect_client = false;
        Ok(())
    }

    pub fn prepare_server_reply(&mut self, header: &Header) -> Result<()> {
        ensure!(!self.expect_client, "unexpected server turn");
        ensure!(
            header.seq_no == self.last_seq.wrapping_add(1),
            "server reply seq mismatch"
        );
        ensure!(
            header.seq_no.is_multiple_of(2),
            "server replies must be even seq"
        );
        self.last_seq = header.seq_no;
        self.expect_client = true;
        Ok(())
    }
}

impl AuthenStart {
    pub fn parsed_data(&self) -> AuthenData {
        match self.authen_type {
            AUTHEN_TYPE_PAP => match String::from_utf8(self.data.clone()) {
                Ok(password) => AuthenData::Pap { password },
                Err(_) => AuthenData::Raw(self.data.clone()),
            },
            AUTHEN_TYPE_CHAP if self.data.len() >= 2 => AuthenData::Chap {
                chap_id: self.data[0],
                response: self.data[1..].to_vec(),
            },
            _ => AuthenData::Raw(self.data.clone()),
        }
    }
}

fn validate_authen_header(header: &Header, body: &[u8]) -> Result<()> {
    ensure!(body.len() >= 4, "authentication body too short");
    ensure!(
        header.seq_no % 2 == 1,
        "authentication client packets must use odd seq"
    );
    ensure!(
        body[0] == 0x01 || body[0] == 0x02,
        "invalid authen action (only login/enable allowed)"
    );
    ensure!(body[1] <= 0x0f, "invalid priv_lvl");
    ensure!(
        body[2] == AUTHEN_TYPE_ASCII
            || body[2] == AUTHEN_TYPE_PAP
            || body[2] == AUTHEN_TYPE_CHAP
            || body[2] == AUTHEN_TYPE_ARAP,
        "invalid authen_type"
    );
    Ok(())
}

fn parse_authen_start_packet(header: Header, body: &[u8]) -> Result<AuthenPacket> {
    let user_len = body[4] as usize;
    let port_len = body[5] as usize;
    let rem_addr_len = body[6] as usize;
    let data_len = body[7] as usize;
    let expected = 8 + user_len + port_len + rem_addr_len + data_len;
    ensure!(expected <= body.len(), "authentication start exceeds body");
    let mut cursor = 8;
    let (user_bytes, next) = read_bytes(body, cursor, user_len, "user")?;
    let user_raw = user_bytes.clone();
    let user = String::from_utf8(user_bytes).unwrap_or_default();
    cursor = next;
    let (port_bytes, next) = read_bytes(body, cursor, port_len, "port")?;
    let port_raw = port_bytes.clone();
    let port = String::from_utf8(port_bytes).unwrap_or_default();
    cursor = next;
    let (rem_addr_bytes, next) = read_bytes(body, cursor, rem_addr_len, "rem_addr")?;
    let rem_addr_raw = rem_addr_bytes.clone();
    let rem_addr = String::from_utf8(rem_addr_bytes).unwrap_or_default();
    cursor = next;
    let (data, _) = read_bytes(body, cursor, data_len, "data")?;
    Ok(AuthenPacket::Start(AuthenStart {
        header,
        action: body[0],
        priv_lvl: body[1],
        authen_type: body[2],
        service: body[3],
        user_raw,
        user,
        port_raw,
        port,
        rem_addr_raw,
        rem_addr,
        data,
    }))
}

fn parse_authen_continue_packet(header: Header, body: &[u8]) -> Result<AuthenPacket> {
    ensure!(body.len() >= 5, "authentication continue body too short");
    let user_msg_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    let data_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    let flags = body[4];
    let next = 5 + user_msg_len + data_len;
    ensure!(next <= body.len(), "authentication continue exceeds body");
    let (user_msg, next) = read_bytes(body, 5, user_msg_len, "user_msg")?;
    let (data, _) = read_bytes(body, next, data_len, "data")?;
    Ok(AuthenPacket::Continue(AuthenContinue {
        header,
        user_msg,
        data,
        flags,
    }))
}

pub fn parse_authen_body(header: Header, body: &[u8]) -> Result<AuthenPacket> {
    validate_authen_header(&header, body)?;
    if body.len() >= 8 {
        let user_len = body[4] as usize;
        let port_len = body[5] as usize;
        let rem_addr_len = body[6] as usize;
        let data_len = body[7] as usize;
        let expected = 8 + user_len + port_len + rem_addr_len + data_len;
        if expected <= body.len() {
            return parse_authen_start_packet(header, body);
        }
    }
    parse_authen_continue_packet(header, body)
}

pub fn encode_authen_reply(reply: &AuthenReply) -> Result<Vec<u8>> {
    let mut buf = BytesMut::new();
    buf.put_u8(reply.status);
    buf.put_u8(reply.flags);
    let msg_bytes = if reply.server_msg_raw.is_empty() {
        reply.server_msg.as_bytes()
    } else {
        reply.server_msg_raw.as_slice()
    };
    buf.put_u16(msg_bytes.len() as u16);
    buf.put_u16(reply.data.len() as u16);
    buf.extend_from_slice(msg_bytes);
    buf.extend_from_slice(&reply.data);
    Ok(buf.to_vec())
}

pub fn parse_authen_reply(_header: Header, body: &[u8]) -> Result<AuthenReply> {
    ensure!(body.len() >= 6, "authentication reply body too short");
    let status = body[0];
    let flags = body[1];
    ensure!(
        matches!(
            status,
            AUTHEN_STATUS_PASS
                | AUTHEN_STATUS_FAIL
                | AUTHEN_STATUS_GETDATA
                | AUTHEN_STATUS_GETUSER
                | AUTHEN_STATUS_GETPASS
                | AUTHEN_STATUS_RESTART
                | AUTHEN_STATUS_ERROR
                | AUTHEN_STATUS_FOLLOW
        ),
        "invalid authen status"
    );
    ensure!(
        flags & !(AUTHEN_FLAG_NOECHO) == 0,
        "invalid authen reply flags"
    );
    let msg_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    let data_len = u16::from_be_bytes([body[4], body[5]]) as usize;
    let expected = 6 + msg_len + data_len;
    ensure!(
        expected <= body.len(),
        "authentication reply exceeds body length"
    );
    let server_msg_bytes = body[6..6 + msg_len].to_vec();
    let server_msg = String::from_utf8(server_msg_bytes.clone())
        .unwrap_or_else(|_| format!("(non-utf8 {} bytes)", server_msg_bytes.len()));
    let data = body[6 + msg_len..expected].to_vec();

    Ok(AuthenReply {
        status,
        flags,
        server_msg,
        server_msg_raw: server_msg_bytes,
        data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header(seq_no: u8) -> Header {
        Header {
            version: crate::VERSION,
            packet_type: crate::TYPE_AUTHEN,
            seq_no,
            flags: 0,
            session_id: 0x12345678,
            length: 0,
        }
    }

    // ==================== AuthenStart Builder Tests ====================

    #[test]
    fn authen_start_builder_creates_valid_header() {
        let start = AuthenStart::builder(0xDEADBEEF, 0x01, 15, AUTHEN_TYPE_ASCII, 1);

        assert_eq!(start.header.session_id, 0xDEADBEEF);
        assert_eq!(start.header.seq_no, 1);
        assert_eq!(start.header.packet_type, crate::TYPE_AUTHEN);
        assert_eq!(start.action, 0x01);
        assert_eq!(start.priv_lvl, 15);
        assert_eq!(start.authen_type, AUTHEN_TYPE_ASCII);
        assert_eq!(start.service, 1);
    }

    #[test]
    fn authen_start_with_user() {
        let start = AuthenStart::builder(123, 1, 1, AUTHEN_TYPE_ASCII, 1)
            .with_user(b"alice".to_vec(), "alice".to_string());

        assert_eq!(start.user, "alice");
        assert_eq!(start.user_raw, b"alice".to_vec());
    }

    #[test]
    fn authen_start_with_port() {
        let start = AuthenStart::builder(123, 1, 1, AUTHEN_TYPE_ASCII, 1)
            .with_port(b"tty0".to_vec(), "tty0".to_string());

        assert_eq!(start.port, "tty0");
        assert_eq!(start.port_raw, b"tty0".to_vec());
    }

    #[test]
    fn authen_start_with_rem_addr() {
        let start = AuthenStart::builder(123, 1, 1, AUTHEN_TYPE_ASCII, 1)
            .with_rem_addr(b"192.168.1.1".to_vec(), "192.168.1.1".to_string());

        assert_eq!(start.rem_addr, "192.168.1.1");
        assert_eq!(start.rem_addr_raw, b"192.168.1.1".to_vec());
    }

    #[test]
    fn authen_start_with_data() {
        let start =
            AuthenStart::builder(123, 1, 1, AUTHEN_TYPE_PAP, 1).with_data(b"password123".to_vec());

        assert_eq!(start.data, b"password123".to_vec());
    }

    // ==================== AuthenContinue Builder Tests ====================

    #[test]
    fn authen_continue_builder_creates_valid_header() {
        let cont = AuthenContinue::builder(0xCAFEBABE);

        assert_eq!(cont.header.session_id, 0xCAFEBABE);
        assert_eq!(cont.header.seq_no, 2);
        assert_eq!(cont.header.packet_type, crate::TYPE_AUTHEN);
        assert!(cont.user_msg.is_empty());
        assert!(cont.data.is_empty());
        assert_eq!(cont.flags, 0);
    }

    #[test]
    fn authen_continue_with_seq() {
        let cont = AuthenContinue::builder(123).with_seq(5);

        assert_eq!(cont.header.seq_no, 5);
    }

    #[test]
    fn authen_continue_with_user_msg() {
        let cont = AuthenContinue::builder(123).with_user_msg(b"my_password".to_vec());

        assert_eq!(cont.user_msg, b"my_password".to_vec());
    }

    #[test]
    fn authen_continue_with_data() {
        let cont = AuthenContinue::builder(123).with_data(b"extra_data".to_vec());

        assert_eq!(cont.data, b"extra_data".to_vec());
    }

    #[test]
    fn authen_continue_with_flags() {
        let cont = AuthenContinue::builder(123).with_flags(AUTHEN_FLAG_NOECHO);

        assert_eq!(cont.flags, AUTHEN_FLAG_NOECHO);
    }

    // ==================== AuthenReply Tests ====================

    #[test]
    fn authen_reply_server_msg_bytes_uses_raw_when_present() {
        let reply = AuthenReply {
            status: AUTHEN_STATUS_PASS,
            flags: 0,
            server_msg: "fallback".to_string(),
            server_msg_raw: b"raw_message".to_vec(),
            data: vec![],
        };

        assert_eq!(reply.server_msg_bytes().as_ref(), b"raw_message");
    }

    #[test]
    fn authen_reply_server_msg_bytes_uses_string_when_raw_empty() {
        let reply = AuthenReply {
            status: AUTHEN_STATUS_PASS,
            flags: 0,
            server_msg: "message".to_string(),
            server_msg_raw: vec![],
            data: vec![],
        };

        assert_eq!(reply.server_msg_bytes().as_ref(), b"message");
    }

    // ==================== AuthenData Parsing Tests ====================

    #[test]
    fn parsed_data_pap_valid_utf8() {
        let start =
            AuthenStart::builder(123, 1, 1, AUTHEN_TYPE_PAP, 1).with_data(b"mypassword".to_vec());

        match start.parsed_data() {
            AuthenData::Pap { password } => assert_eq!(password, "mypassword"),
            _ => panic!("expected PAP data"),
        }
    }

    #[test]
    fn parsed_data_pap_invalid_utf8_becomes_raw() {
        let start =
            AuthenStart::builder(123, 1, 1, AUTHEN_TYPE_PAP, 1).with_data(vec![0xFF, 0xFE, 0x00]);

        match start.parsed_data() {
            AuthenData::Raw(data) => assert_eq!(data, vec![0xFF, 0xFE, 0x00]),
            _ => panic!("expected Raw data for invalid UTF-8"),
        }
    }

    #[test]
    fn parsed_data_chap_extracts_id_and_response() {
        let start = AuthenStart::builder(123, 1, 1, AUTHEN_TYPE_CHAP, 1)
            .with_data(vec![0x42, 0x01, 0x02, 0x03]);

        match start.parsed_data() {
            AuthenData::Chap { chap_id, response } => {
                assert_eq!(chap_id, 0x42);
                assert_eq!(response, vec![0x01, 0x02, 0x03]);
            }
            _ => panic!("expected CHAP data"),
        }
    }

    #[test]
    fn parsed_data_chap_short_becomes_raw() {
        let start = AuthenStart::builder(123, 1, 1, AUTHEN_TYPE_CHAP, 1).with_data(vec![0x42]); // Only 1 byte, needs at least 2

        match start.parsed_data() {
            AuthenData::Raw(data) => assert_eq!(data, vec![0x42]),
            _ => panic!("expected Raw data for short CHAP"),
        }
    }

    #[test]
    fn parsed_data_ascii_returns_raw() {
        let start =
            AuthenStart::builder(123, 1, 1, AUTHEN_TYPE_ASCII, 1).with_data(b"some data".to_vec());

        match start.parsed_data() {
            AuthenData::Raw(data) => assert_eq!(data, b"some data".to_vec()),
            _ => panic!("expected Raw data for ASCII"),
        }
    }

    // ==================== AuthSessionState Tests ====================

    #[test]
    fn auth_session_state_new_from_start_valid() {
        let header = make_header(1); // odd seq

        let start = AuthenStart {
            header,
            action: 1,
            priv_lvl: 15,
            authen_type: AUTHEN_TYPE_ASCII,
            service: 1,
            user_raw: b"alice".to_vec(),
            user: "alice".to_string(),
            port_raw: b"tty0".to_vec(),
            port: "tty0".to_string(),
            rem_addr_raw: b"10.0.0.1".to_vec(),
            rem_addr: "10.0.0.1".to_string(),
            data: vec![],
        };

        let state = AuthSessionState::from_start(&start).unwrap();

        assert_eq!(state.last_seq, 1);
        assert!(!state.expect_client);
        assert_eq!(state.authen_type, Some(AUTHEN_TYPE_ASCII));
        assert_eq!(state.username, Some("alice".to_string()));
        assert_eq!(state.port, Some("tty0".to_string()));
        assert_eq!(state.rem_addr, Some("10.0.0.1".to_string()));
    }

    #[test]
    fn auth_session_state_new_from_start_rejects_even_seq() {
        let header = make_header(2); // even seq - invalid for start

        let start = AuthenStart {
            header,
            action: 1,
            priv_lvl: 15,
            authen_type: AUTHEN_TYPE_ASCII,
            service: 1,
            user_raw: b"alice".to_vec(),
            user: "alice".to_string(),
            port_raw: vec![],
            port: String::new(),
            rem_addr_raw: vec![],
            rem_addr: String::new(),
            data: vec![],
        };

        let result = AuthSessionState::from_start(&start);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("odd"));
    }

    #[test]
    fn auth_session_state_empty_port_becomes_none() {
        let header = make_header(1);

        let start = AuthenStart {
            header,
            action: 1,
            priv_lvl: 15,
            authen_type: AUTHEN_TYPE_ASCII,
            service: 1,
            user_raw: b"alice".to_vec(),
            user: "alice".to_string(),
            port_raw: vec![],
            port: String::new(),
            rem_addr_raw: vec![],
            rem_addr: String::new(),
            data: vec![],
        };

        let state = AuthSessionState::from_start(&start).unwrap();

        assert!(state.port.is_none());
        assert!(state.rem_addr.is_none());
    }

    #[test]
    fn auth_session_state_validate_client_valid() {
        let header = make_header(1);

        let start = AuthenStart {
            header,
            action: 1,
            priv_lvl: 15,
            authen_type: AUTHEN_TYPE_ASCII,
            service: 1,
            user_raw: b"alice".to_vec(),
            user: "alice".to_string(),
            port_raw: vec![],
            port: String::new(),
            rem_addr_raw: vec![],
            rem_addr: String::new(),
            data: vec![],
        };

        let mut state = AuthSessionState::from_start(&start).unwrap();

        // Simulate server reply was sent
        state.expect_client = true;
        state.last_seq = 2;

        let client_header = make_header(3); // odd, last_seq + 1
        let result = state.validate_client(&client_header);

        assert!(result.is_ok());
        assert_eq!(state.last_seq, 3);
        assert!(!state.expect_client);
    }

    #[test]
    fn auth_session_state_validate_client_rejects_even_seq() {
        let header = make_header(1);

        let start = AuthenStart {
            header,
            action: 1,
            priv_lvl: 15,
            authen_type: AUTHEN_TYPE_ASCII,
            service: 1,
            user_raw: b"alice".to_vec(),
            user: "alice".to_string(),
            port_raw: vec![],
            port: String::new(),
            rem_addr_raw: vec![],
            rem_addr: String::new(),
            data: vec![],
        };

        let mut state = AuthSessionState::from_start(&start).unwrap();

        state.expect_client = true;
        state.last_seq = 2;

        let client_header = make_header(4); // even seq - invalid
        let result = state.validate_client(&client_header);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("odd"));
    }

    #[test]
    fn auth_session_state_prepare_server_reply_valid() {
        let header = make_header(1);

        let start = AuthenStart {
            header,
            action: 1,
            priv_lvl: 15,
            authen_type: AUTHEN_TYPE_ASCII,
            service: 1,
            user_raw: b"alice".to_vec(),
            user: "alice".to_string(),
            port_raw: vec![],
            port: String::new(),
            rem_addr_raw: vec![],
            rem_addr: String::new(),
            data: vec![],
        };

        let mut state = AuthSessionState::from_start(&start).unwrap();

        let reply_header = make_header(2); // even, last_seq + 1
        let result = state.prepare_server_reply(&reply_header);

        assert!(result.is_ok());
        assert_eq!(state.last_seq, 2);
        assert!(state.expect_client);
    }

    // ==================== parse_authen_body Tests ====================

    #[test]
    fn parse_authen_body_start_valid() {
        let header = make_header(1);
        // Build a valid authentication START body
        let mut body = vec![
            0x01, // action = login
            0x01, // priv_lvl = 1
            0x01, // authen_type = ASCII
            0x01, // service = 1
            0x05, // user_len = 5
            0x04, // port_len = 4
            0x09, // rem_addr_len = 9
            0x00, // data_len = 0
        ];
        body.extend_from_slice(b"alice"); // user
        body.extend_from_slice(b"tty0"); // port
        body.extend_from_slice(b"127.0.0.1"); // rem_addr

        let packet = parse_authen_body(header, &body).unwrap();

        match packet {
            AuthenPacket::Start(start) => {
                assert_eq!(start.action, 0x01);
                assert_eq!(start.priv_lvl, 0x01);
                assert_eq!(start.authen_type, AUTHEN_TYPE_ASCII);
                assert_eq!(start.user, "alice");
                assert_eq!(start.port, "tty0");
                assert_eq!(start.rem_addr, "127.0.0.1");
            }
            _ => panic!("expected Start packet"),
        }
    }

    #[test]
    fn parse_authen_body_rejects_even_seq() {
        let header = make_header(2); // even - invalid
        let body = vec![0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00];

        let result = parse_authen_body(header, &body);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("odd"));
    }

    #[test]
    fn parse_authen_body_rejects_invalid_action() {
        let header = make_header(1);
        let body = vec![
            0x00, // action = 0 (invalid, must be 1 or 2)
            0x01, 0x01, 0x01,
        ];

        let result = parse_authen_body(header, &body);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("action"));
    }

    #[test]
    fn parse_authen_body_rejects_invalid_priv_lvl() {
        let header = make_header(1);
        let body = vec![
            0x01, // action
            0x10, // priv_lvl = 16 (invalid, max is 15)
            0x01, 0x01,
        ];

        let result = parse_authen_body(header, &body);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("priv_lvl"));
    }

    #[test]
    fn parse_authen_body_rejects_invalid_authen_type() {
        let header = make_header(1);
        let body = vec![
            0x01, // action
            0x01, // priv_lvl
            0x00, // authen_type = 0 (invalid)
            0x01,
        ];

        let result = parse_authen_body(header, &body);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("authen_type"));
    }

    // ==================== encode_authen_reply Tests ====================

    #[test]
    fn encode_authen_reply_roundtrip() {
        let reply = AuthenReply {
            status: AUTHEN_STATUS_PASS,
            flags: 0,
            server_msg: "Welcome!".to_string(),
            server_msg_raw: vec![],
            data: vec![0x01, 0x02],
        };

        let encoded = encode_authen_reply(&reply).unwrap();
        let header = make_header(2);
        let parsed = parse_authen_reply(header, &encoded).unwrap();

        assert_eq!(parsed.status, AUTHEN_STATUS_PASS);
        assert_eq!(parsed.flags, 0);
        assert_eq!(parsed.server_msg, "Welcome!");
        assert_eq!(parsed.data, vec![0x01, 0x02]);
    }

    #[test]
    fn encode_authen_reply_uses_raw_when_present() {
        let reply = AuthenReply {
            status: AUTHEN_STATUS_GETPASS,
            flags: AUTHEN_FLAG_NOECHO,
            server_msg: "ignored".to_string(),
            server_msg_raw: b"Password: ".to_vec(),
            data: vec![],
        };

        let encoded = encode_authen_reply(&reply).unwrap();
        let header = make_header(2);
        let parsed = parse_authen_reply(header, &encoded).unwrap();

        assert_eq!(parsed.server_msg, "Password: ");
        assert_eq!(parsed.flags, AUTHEN_FLAG_NOECHO);
    }

    // ==================== parse_authen_reply Tests ====================

    #[test]
    fn parse_authen_reply_rejects_invalid_status() {
        let header = make_header(2);
        let body = vec![
            0xFF, // invalid status
            0x00, // flags
            0x00, 0x00, // server_msg_len
            0x00, 0x00, // data_len
        ];

        let result = parse_authen_reply(header, &body);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("status"));
    }

    #[test]
    fn parse_authen_reply_rejects_invalid_flags() {
        let header = make_header(2);
        let body = vec![
            AUTHEN_STATUS_PASS,
            0xFF, // invalid flags
            0x00,
            0x00,
            0x00,
            0x00,
        ];

        let result = parse_authen_reply(header, &body);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("flags"));
    }

    #[test]
    fn parse_authen_reply_rejects_truncated_body() {
        let header = make_header(2);
        let body = vec![
            AUTHEN_STATUS_PASS,
            0x00,
            0x00,
            0x10, // claims 16 byte message
            0x00,
            0x00, // but body ends here
        ];

        let result = parse_authen_reply(header, &body);

        assert!(result.is_err());
    }

    #[test]
    fn parse_authen_reply_handles_non_utf8_gracefully() {
        let header = make_header(2);
        let mut body = vec![
            AUTHEN_STATUS_PASS,
            0x00,
            0x00,
            0x03, // 3 byte message
            0x00,
            0x00,
        ];
        body.extend_from_slice(&[0xFF, 0xFE, 0xFD]); // invalid UTF-8

        let parsed = parse_authen_reply(header, &body).unwrap();

        // Should contain fallback message
        assert!(parsed.server_msg.contains("non-utf8"));
        assert_eq!(parsed.server_msg_raw, vec![0xFF, 0xFE, 0xFD]);
    }

    #[test]
    fn parse_authen_reply_all_valid_statuses() {
        let header = make_header(2);
        let statuses = [
            AUTHEN_STATUS_PASS,
            AUTHEN_STATUS_FAIL,
            AUTHEN_STATUS_GETDATA,
            AUTHEN_STATUS_GETUSER,
            AUTHEN_STATUS_GETPASS,
            AUTHEN_STATUS_RESTART,
            AUTHEN_STATUS_ERROR,
            AUTHEN_STATUS_FOLLOW,
        ];

        for status in statuses {
            let body = vec![status, 0x00, 0x00, 0x00, 0x00, 0x00];
            let result = parse_authen_reply(header.clone(), &body);
            assert!(result.is_ok(), "status 0x{:02x} should be valid", status);
        }
    }
}
