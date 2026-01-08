#![no_main]

//! Fuzz target for TACACS+ header parsing.
//!
//! This target fuzzes the header parsing logic to find crashes, panics,
//! or memory safety issues when parsing malformed headers.

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // Test header parsing with arbitrary bytes
    // Header is exactly 12 bytes, but we test with any input length
    let mut cursor = Cursor::new(data);

    // Use a runtime to run the async header parsing
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    let _ = rt.block_on(async {
        usg_tacacs_proto::header::read_header(&mut cursor).await
    });

    // If we got a valid header, also test validation functions
    if data.len() >= 12 {
        let header = usg_tacacs_proto::Header {
            version: data[0],
            packet_type: data[1],
            seq_no: data[2],
            flags: data[3],
            session_id: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            length: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
        };

        // Test request header validation with various parameters
        let _ = usg_tacacs_proto::header::validate_request_header(
            &header,
            Some(data[1]),
            0xFF,
            true,
            0x0C,
        );

        let _ = usg_tacacs_proto::header::validate_request_header(
            &header,
            None,
            data[3],
            false,
            data[0] >> 4,
        );

        // Test response header validation
        let _ = usg_tacacs_proto::header::validate_response_header(
            &header,
            Some(data[1]),
            0xFF,
            true,
            0x0C,
        );

        // Test response creation
        let _response = header.response(42);
    }
});
