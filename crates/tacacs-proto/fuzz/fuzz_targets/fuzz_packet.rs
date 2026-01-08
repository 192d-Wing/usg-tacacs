#![no_main]

//! Fuzz target for complete TACACS+ packet parsing.
//!
//! This target fuzzes all packet types: authentication, authorization,
//! accounting, and capability packets. It exercises header parsing,
//! body crypto, and body structure parsing.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

/// Valid TACACS+ packet type constants
const TYPE_AUTHEN: u8 = 0x01;
const TYPE_AUTHOR: u8 = 0x02;
const TYPE_ACCT: u8 = 0x03;
const TYPE_CAPABILITY: u8 = 0x04;

#[derive(Arbitrary, Debug)]
struct FuzzPacket {
    /// Use structured packet type for better coverage
    packet_type: u8,
    /// Version byte (major in high nibble, minor in low)
    version: u8,
    /// Sequence number
    seq_no: u8,
    /// Flags
    flags: u8,
    /// Session ID
    session_id: u32,
    /// Packet body (will be encrypted/obfuscated)
    body: Vec<u8>,
}

fuzz_target!(|input: FuzzPacket| {
    // Limit body size to prevent OOM
    if input.body.len() > 65535 {
        return;
    }

    // Construct header bytes
    let mut header = [0u8; 12];
    header[0] = input.version;
    header[1] = input.packet_type;
    header[2] = input.seq_no;
    header[3] = input.flags;
    header[4..8].copy_from_slice(&input.session_id.to_be_bytes());
    header[8..12].copy_from_slice(&(input.body.len() as u32).to_be_bytes());

    // Build full packet
    let mut packet = Vec::with_capacity(12 + input.body.len());
    packet.extend_from_slice(&header);
    packet.extend_from_slice(&input.body);

    let secret = b"testsecret123";

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    // Test read_packet (dispatches to appropriate parser based on type)
    let mut cursor = Cursor::new(packet.clone());
    let _ = rt.block_on(async {
        usg_tacacs_proto::read_packet(&mut cursor, Some(secret)).await
    });

    // Test type-specific readers
    match input.packet_type {
        TYPE_AUTHEN => {
            // Test authentication reply parsing
            cursor = Cursor::new(packet.clone());
            let _ = rt.block_on(async {
                usg_tacacs_proto::read_authen_reply(&mut cursor, Some(secret)).await
            });
        }
        TYPE_AUTHOR => {
            // Test authorization request parsing
            cursor = Cursor::new(packet.clone());
            let _ = rt.block_on(async {
                usg_tacacs_proto::read_author_request(&mut cursor, Some(secret)).await
            });

            // Test authorization response parsing
            cursor = Cursor::new(packet.clone());
            let _ = rt.block_on(async {
                usg_tacacs_proto::read_author_response(&mut cursor, Some(secret)).await
            });
        }
        TYPE_ACCT => {
            // Test accounting response parsing
            cursor = Cursor::new(packet.clone());
            let _ = rt.block_on(async {
                usg_tacacs_proto::read_accounting_response(&mut cursor, Some(secret)).await
            });
        }
        _ => {
            // Other types handled by read_packet
        }
    }

    // Also test with valid TACACS+ version (0xC0 = major 12, minor 0)
    let mut valid_version_packet = packet.clone();
    valid_version_packet[0] = 0xC0;
    // Ensure not using UNENCRYPTED flag (would be rejected)
    valid_version_packet[3] &= !0x01;
    // Use odd seq_no for client requests
    if valid_version_packet[2] % 2 == 0 {
        valid_version_packet[2] = valid_version_packet[2].wrapping_add(1);
    }

    cursor = Cursor::new(valid_version_packet);
    let _ = rt.block_on(async {
        usg_tacacs_proto::read_packet(&mut cursor, Some(secret)).await
    });
});
