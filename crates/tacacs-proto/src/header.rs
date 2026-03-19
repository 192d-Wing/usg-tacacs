// SPDX-License-Identifier: Apache-2.0
//! TACACS+ packet header parsing and serialization for async streams.

// NIST 800-53 Rev5: SC-8 Transmission Confidentiality and Integrity
use anyhow::{Context, Result, ensure};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone)]
pub struct Header {
    pub version: u8,
    pub packet_type: u8,
    pub seq_no: u8,
    pub flags: u8,
    pub session_id: u32,
    pub length: u32,
}

impl Header {
    /// Build a response header by incrementing seq_no. Returns an error if
    /// the resulting sequence number would wrap past 255 (RFC 8907 violation).
    pub fn response(&self, length: u32) -> Result<Header> {
        ensure!(
            self.seq_no < 254,
            "TACACS+ seq_no {} would overflow on response (max request seq_no is 253)",
            self.seq_no
        );
        Ok(Header {
            version: self.version,
            packet_type: self.packet_type,
            seq_no: self.seq_no.wrapping_add(1),
            flags: self.flags, // mirrors request flags; caller can override if needed
            session_id: self.session_id,
            length,
        })
    }
}

pub async fn read_header<R>(reader: &mut R) -> Result<Header>
where
    R: AsyncRead + Unpin,
{
    let mut buf = [0u8; 12];
    reader
        .read_exact(&mut buf)
        .await
        .with_context(|| "reading TACACS+ header")?;

    let version = buf[0];
    let packet_type = buf[1];
    let seq_no = buf[2];
    let flags = buf[3];
    let session_id = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let length = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);

    Ok(Header {
        version,
        packet_type,
        seq_no,
        flags,
        session_id,
        length,
    })
}

pub async fn write_header<W>(writer: &mut W, header: &Header) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; 12];
    buf[0] = header.version;
    buf[1] = header.packet_type;
    buf[2] = header.seq_no;
    buf[3] = header.flags;
    buf[4..8].copy_from_slice(&header.session_id.to_be_bytes());
    buf[8..12].copy_from_slice(&header.length.to_be_bytes());
    writer
        .write_all(&buf)
        .await
        .with_context(|| "writing TACACS+ header")
}

pub fn validate_request_header(
    header: &Header,
    expected_packet_type: Option<u8>,
    allowed_flags: u8,
    require_odd_seq: bool,
    expected_major: u8,
) -> Result<()> {
    ensure!(header.seq_no >= 1, "TACACS+ seq_no must be >= 1");
    if let Some(packet_type) = expected_packet_type {
        ensure!(
            header.packet_type == packet_type,
            "unexpected TACACS+ type {}, expected {}",
            header.packet_type,
            packet_type
        );
    }
    ensure!(
        header.version >> 4 == expected_major,
        "unsupported TACACS+ major version {:x}",
        header.version >> 4
    );
    ensure!(
        header.flags & !allowed_flags == 0,
        "unsupported TACACS+ flags set {:02x}",
        header.flags & !allowed_flags
    );
    if require_odd_seq {
        ensure!(
            header.seq_no % 2 == 1,
            "client TACACS+ packets must use odd seq numbers"
        );
    }
    Ok(())
}

pub fn validate_response_header(
    header: &Header,
    expected_packet_type: Option<u8>,
    allowed_flags: u8,
    require_even_seq: bool,
    expected_major: u8,
) -> Result<()> {
    ensure!(header.seq_no >= 1, "TACACS+ seq_no must be >= 1");
    if let Some(packet_type) = expected_packet_type {
        ensure!(
            header.packet_type == packet_type,
            "unexpected TACACS+ type {}, expected {}",
            header.packet_type,
            packet_type
        );
    }
    ensure!(
        header.version >> 4 == expected_major,
        "unsupported TACACS+ major version {:x}",
        header.version >> 4
    );
    ensure!(
        header.flags & !allowed_flags == 0,
        "unsupported TACACS+ flags set {:02x}",
        header.flags & !allowed_flags
    );
    if require_even_seq {
        ensure!(
            header.seq_no.is_multiple_of(2),
            "server TACACS+ packets must use even seq numbers"
        );
    }
    Ok(())
}

pub fn is_known_service(service: &str) -> bool {
    matches!(
        service.to_ascii_lowercase().as_str(),
        "shell" | "login" | "enable" | "ppp" | "arap" | "tty-daemon" | "connection" | "none"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn make_header(
        version: u8,
        packet_type: u8,
        seq_no: u8,
        flags: u8,
        session_id: u32,
        length: u32,
    ) -> Header {
        Header {
            version,
            packet_type,
            seq_no,
            flags,
            session_id,
            length,
        }
    }

    // ==================== Header::response Tests ====================

    #[test]
    fn header_response_increments_seq_no() {
        let request = make_header(0xC0, 0x01, 1, 0, 12345, 100);
        let response = request.response(50).unwrap();

        assert_eq!(response.seq_no, 2);
        assert_eq!(response.length, 50);
        assert_eq!(response.session_id, request.session_id);
        assert_eq!(response.version, request.version);
        assert_eq!(response.packet_type, request.packet_type);
        assert_eq!(response.flags, request.flags);
    }

    #[test]
    fn header_response_rejects_seq_overflow() {
        let request = make_header(0xC0, 0x01, 254, 0, 12345, 100);
        let result = request.response(50);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("overflow"));
    }

    #[test]
    fn header_response_rejects_seq_255() {
        let request = make_header(0xC0, 0x01, 255, 0, 12345, 100);
        let result = request.response(50);

        assert!(result.is_err());
    }

    #[test]
    fn header_response_allows_seq_253() {
        let request = make_header(0xC0, 0x01, 253, 0, 12345, 100);
        let response = request.response(50).unwrap();

        assert_eq!(response.seq_no, 254);
    }

    // ==================== read_header / write_header Tests ====================

    #[tokio::test]
    async fn header_roundtrip() {
        let original = make_header(0xC0, 0x02, 3, 0x04, 0xDEADBEEF, 256);

        // Write to buffer
        let mut buf = Vec::new();
        write_header(&mut buf, &original).await.unwrap();

        assert_eq!(buf.len(), 12);

        // Read back
        let mut cursor = Cursor::new(buf);
        let parsed = read_header(&mut cursor).await.unwrap();

        assert_eq!(parsed.version, original.version);
        assert_eq!(parsed.packet_type, original.packet_type);
        assert_eq!(parsed.seq_no, original.seq_no);
        assert_eq!(parsed.flags, original.flags);
        assert_eq!(parsed.session_id, original.session_id);
        assert_eq!(parsed.length, original.length);
    }

    #[tokio::test]
    async fn header_read_exact_bytes() {
        // Manually construct a valid 12-byte header
        let bytes: [u8; 12] = [
            0xC1, // version (major 12, minor 1)
            0x01, // packet_type (authen)
            0x05, // seq_no
            0x04, // flags (single-connect)
            0x12, 0x34, 0x56, 0x78, // session_id (big-endian)
            0x00, 0x00, 0x01, 0x00, // length = 256 (big-endian)
        ];

        let mut cursor = Cursor::new(bytes);
        let header = read_header(&mut cursor).await.unwrap();

        assert_eq!(header.version, 0xC1);
        assert_eq!(header.packet_type, 0x01);
        assert_eq!(header.seq_no, 0x05);
        assert_eq!(header.flags, 0x04);
        assert_eq!(header.session_id, 0x12345678);
        assert_eq!(header.length, 256);
    }

    #[tokio::test]
    async fn header_read_truncated_fails() {
        // Only 8 bytes, but header requires 12
        let bytes: [u8; 8] = [0xC0, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01];
        let mut cursor = Cursor::new(bytes);

        let result = read_header(&mut cursor).await;
        assert!(result.is_err());
    }

    // ==================== validate_request_header Tests ====================

    #[test]
    fn validate_request_header_valid() {
        let header = make_header(0xC0, 0x01, 1, 0x00, 12345, 100);

        let result = validate_request_header(&header, Some(0x01), 0x05, true, 0x0C);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_request_header_wrong_type() {
        let header = make_header(0xC0, 0x02, 1, 0x00, 12345, 100);

        let result = validate_request_header(&header, Some(0x01), 0x05, true, 0x0C);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unexpected"));
    }

    #[test]
    fn validate_request_header_wrong_major_version() {
        let header = make_header(0xB0, 0x01, 1, 0x00, 12345, 100); // Major version 0x0B

        let result = validate_request_header(&header, Some(0x01), 0x05, true, 0x0C);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("version"));
    }

    #[test]
    fn validate_request_header_disallowed_flags() {
        let header = make_header(0xC0, 0x01, 1, 0xFF, 12345, 100); // All flags set

        // Only allow flags 0x05
        let result = validate_request_header(&header, Some(0x01), 0x05, true, 0x0C);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("flags"));
    }

    #[test]
    fn validate_request_header_even_seq_when_odd_required() {
        let header = make_header(0xC0, 0x01, 2, 0x00, 12345, 100); // Even seq_no

        let result = validate_request_header(&header, Some(0x01), 0x05, true, 0x0C);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("odd"));
    }

    #[test]
    fn validate_request_header_even_seq_allowed_when_not_required() {
        let header = make_header(0xC0, 0x01, 2, 0x00, 12345, 100);

        // require_odd_seq = false
        let result = validate_request_header(&header, Some(0x01), 0x05, false, 0x0C);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_request_header_none_packet_type_accepts_any() {
        let header = make_header(0xC0, 0x99, 1, 0x00, 12345, 100);

        let result = validate_request_header(&header, None, 0xFF, true, 0x0C);
        assert!(result.is_ok());
    }

    // ==================== validate_response_header Tests ====================

    #[test]
    fn validate_response_header_valid() {
        let header = make_header(0xC0, 0x01, 2, 0x00, 12345, 100);

        let result = validate_response_header(&header, Some(0x01), 0x05, true, 0x0C);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_response_header_odd_seq_when_even_required() {
        let header = make_header(0xC0, 0x01, 3, 0x00, 12345, 100); // Odd seq_no

        let result = validate_response_header(&header, Some(0x01), 0x05, true, 0x0C);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("even"));
    }

    // ==================== is_known_service Tests ====================

    #[test]
    fn is_known_service_valid_services() {
        assert!(is_known_service("shell"));
        assert!(is_known_service("SHELL")); // Case insensitive
        assert!(is_known_service("Shell"));
        assert!(is_known_service("login"));
        assert!(is_known_service("enable"));
        assert!(is_known_service("ppp"));
        assert!(is_known_service("arap"));
        assert!(is_known_service("tty-daemon"));
        assert!(is_known_service("connection"));
        assert!(is_known_service("none"));
    }

    #[test]
    fn is_known_service_unknown_services() {
        assert!(!is_known_service("unknown"));
        assert!(!is_known_service(""));
        assert!(!is_known_service("ftp"));
        assert!(!is_known_service("ssh"));
    }
}
