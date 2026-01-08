#![no_main]

//! Fuzz target for TACACS+ body obfuscation through packet I/O.
//!
//! This target tests the crypto layer by constructing full TACACS+ packets
//! and parsing them through the public API, which internally applies the
//! MD5-based body obfuscation.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

#[derive(Arbitrary, Debug)]
struct PacketInput {
    header_bytes: [u8; 12],
    body: Vec<u8>,
    secret: Vec<u8>,
}

fuzz_target!(|input: PacketInput| {
    // Limit body size to prevent OOM (max TACACS+ packet is 65535 bytes)
    if input.body.len() > 65535 {
        return;
    }

    // Construct a complete packet: 12-byte header + body
    let mut packet = Vec::with_capacity(12 + input.body.len());
    packet.extend_from_slice(&input.header_bytes);
    packet.extend_from_slice(&input.body);

    // Patch the length field in the header to match body length
    let body_len = input.body.len() as u32;
    packet[8..12].copy_from_slice(&body_len.to_be_bytes());

    let mut cursor = Cursor::new(packet.clone());

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    // Test with None secret
    let _ = rt.block_on(async {
        usg_tacacs_proto::read_packet(&mut cursor, None).await
    });

    // Test with short secret
    cursor = Cursor::new(packet.clone());
    let _ = rt.block_on(async {
        usg_tacacs_proto::read_packet(&mut cursor, Some(b"short")).await
    });

    // Test with valid secret
    if input.secret.len() >= 8 {
        cursor = Cursor::new(packet.clone());
        let _ = rt.block_on(async {
            usg_tacacs_proto::read_packet(&mut cursor, Some(&input.secret)).await
        });
    }

    // Test with fixed valid secret
    cursor = Cursor::new(packet);
    let _ = rt.block_on(async {
        usg_tacacs_proto::read_packet(&mut cursor, Some(b"testsecret123")).await
    });
});
