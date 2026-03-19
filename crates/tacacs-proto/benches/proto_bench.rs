// SPDX-License-Identifier: Apache-2.0
//! Benchmarks for TACACS+ protocol hot paths.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use std::io::Cursor;

// ---------- helpers ----------

fn make_header(pkt_type: u8, seq: u8, session_id: u32, length: u32) -> [u8; 12] {
    let mut buf = [0u8; 12];
    buf[0] = 0xC1; // version (PAP minor=1)
    buf[1] = pkt_type;
    buf[2] = seq;
    buf[3] = 0; // flags (encrypted)
    buf[4..8].copy_from_slice(&session_id.to_be_bytes());
    buf[8..12].copy_from_slice(&length.to_be_bytes());
    buf
}

fn build_pap_authen_start(user: &str, password: &str) -> Vec<u8> {
    let mut body = vec![
        0x01, // action = login
        0x0f, // priv_lvl = 15
        0x02, // authen_type = PAP
        0x01, // service = login
        user.len() as u8,
        4,    // port_len
        9,    // rem_addr_len
        password.len() as u8,
    ];
    body.extend_from_slice(user.as_bytes());
    body.extend_from_slice(b"tty0");
    body.extend_from_slice(b"127.0.0.1");
    body.extend_from_slice(password.as_bytes());
    body
}

fn build_author_request(user: &str, args: &[&str]) -> Vec<u8> {
    let mut body = vec![
        0x06, // authen_method = TACACSPLUS
        0x0f, // priv_lvl = 15
        0x01, // authen_type = ASCII
        0x01, // authen_service = login
        user.len() as u8,
        4,    // port_len
        9,    // rem_addr_len
        args.len() as u8,
    ];
    for a in args {
        body.push(a.len() as u8);
    }
    body.extend_from_slice(user.as_bytes());
    body.extend_from_slice(b"tty0");
    body.extend_from_slice(b"127.0.0.1");
    for a in args {
        body.extend_from_slice(a.as_bytes());
    }
    body
}

fn build_acct_start(user: &str, args: &[&str]) -> Vec<u8> {
    let mut body = vec![
        0x02, // flags = START
        0x06, // authen_method = TACACSPLUS
        0x0f, // priv_lvl = 15
        0x01, // authen_type = ASCII
        0x01, // authen_service = login
        user.len() as u8,
        4,    // port_len
        9,    // rem_addr_len
        args.len() as u8,
    ];
    for a in args {
        body.push(a.len() as u8);
    }
    body.extend_from_slice(user.as_bytes());
    body.extend_from_slice(b"tty0");
    body.extend_from_slice(b"127.0.0.1");
    for a in args {
        body.extend_from_slice(a.as_bytes());
    }
    body
}

const SECRET: &[u8] = b"benchmark-secret-key";
const SESSION_ID: u32 = 0xDEADBEEF;

// ---------- crypto benchmarks ----------

fn bench_crypto(c: &mut Criterion) {
    let header = usg_tacacs_proto::Header {
        version: 0xC1,
        packet_type: 0x01,
        seq_no: 1,
        flags: 0,
        session_id: SESSION_ID,
        length: 0,
    };

    let mut group = c.benchmark_group("crypto");

    for size in [32, 128, 512, 2048] {
        let mut body = vec![0xAA; size];
        group.bench_function(format!("apply_body_crypto_{size}B"), |b| {
            b.iter(|| {
                let mut data = body.clone();
                usg_tacacs_proto::crypto::apply_body_crypto(
                    black_box(&header),
                    black_box(&mut data),
                    Some(SECRET),
                )
                .unwrap();
            });
        });
    }
    group.finish();
}

// ---------- parse benchmarks ----------

fn bench_parse_authen(c: &mut Criterion) {
    let plaintext_body = build_pap_authen_start("alice", "password123");
    let header = usg_tacacs_proto::Header {
        version: 0xC1,
        packet_type: 0x01,
        seq_no: 1,
        flags: 0,
        session_id: SESSION_ID,
        length: plaintext_body.len() as u32,
    };

    c.bench_function("parse_authen_start_pap", |b| {
        b.iter(|| {
            usg_tacacs_proto::authen::parse_authen_body(
                black_box(header.clone()),
                black_box(&plaintext_body),
            )
            .unwrap();
        });
    });
}

fn bench_parse_author(c: &mut Criterion) {
    let args = ["service=shell", "cmd=show", "cmd-arg=version"];
    let plaintext_body = build_author_request("alice", &args);
    let header = usg_tacacs_proto::Header {
        version: 0xC0,
        packet_type: 0x02,
        seq_no: 1,
        flags: 0,
        session_id: SESSION_ID,
        length: plaintext_body.len() as u32,
    };

    c.bench_function("parse_author_request", |b| {
        b.iter(|| {
            usg_tacacs_proto::author::parse_author_body(
                black_box(header.clone()),
                black_box(&plaintext_body),
            )
            .unwrap();
        });
    });
}

fn bench_parse_accounting(c: &mut Criterion) {
    let args = ["service=shell", "task_id=42", "cmd=show version"];
    let plaintext_body = build_acct_start("alice", &args);
    let header = usg_tacacs_proto::Header {
        version: 0xC0,
        packet_type: 0x03,
        seq_no: 1,
        flags: 0,
        session_id: SESSION_ID,
        length: plaintext_body.len() as u32,
    };

    c.bench_function("parse_accounting_start", |b| {
        b.iter(|| {
            usg_tacacs_proto::accounting::parse_accounting_body(
                black_box(header.clone()),
                black_box(&plaintext_body),
            )
            .unwrap();
        });
    });
}

// ---------- encode benchmarks ----------

fn bench_encode_authen_reply(c: &mut Criterion) {
    let reply = usg_tacacs_proto::AuthenReply {
        status: 0x01,
        flags: 0,
        server_msg: String::new(),
        server_msg_raw: Vec::new(),
        data: Vec::new(),
    };

    c.bench_function("encode_authen_reply", |b| {
        b.iter(|| {
            usg_tacacs_proto::authen::encode_authen_reply(black_box(&reply)).unwrap();
        });
    });
}

fn bench_encode_author_response(c: &mut Criterion) {
    let response = usg_tacacs_proto::AuthorizationResponse {
        status: 0x01,
        args: vec!["priv-lvl=15".to_string()],
        server_msg: String::new(),
        data: String::new(),
    };

    c.bench_function("encode_author_response", |b| {
        b.iter(|| {
            usg_tacacs_proto::author::encode_author_response(black_box(&response)).unwrap();
        });
    });
}

// ---------- full round-trip: decrypt + parse + encode + encrypt ----------

fn bench_full_authen_roundtrip(c: &mut Criterion) {
    let mut body = build_pap_authen_start("alice", "password123");
    let header = usg_tacacs_proto::Header {
        version: 0xC1,
        packet_type: 0x01,
        seq_no: 1,
        flags: 0,
        session_id: SESSION_ID,
        length: body.len() as u32,
    };
    // Encrypt the body
    usg_tacacs_proto::crypto::apply_body_crypto(&header, &mut body, Some(SECRET)).unwrap();
    let encrypted_body = body;

    let reply = usg_tacacs_proto::AuthenReply {
        status: 0x01,
        flags: 0,
        server_msg: String::new(),
        server_msg_raw: Vec::new(),
        data: Vec::new(),
    };

    c.bench_function("full_authen_roundtrip", |b| {
        b.iter(|| {
            // Decrypt
            let mut body = encrypted_body.clone();
            usg_tacacs_proto::crypto::apply_body_crypto(&header, &mut body, Some(SECRET)).unwrap();
            // Parse
            let _parsed = usg_tacacs_proto::authen::parse_authen_body(
                header.clone(),
                &body,
            ).unwrap();
            // Encode reply
            let mut reply_body = usg_tacacs_proto::authen::encode_authen_reply(&reply).unwrap();
            // Encrypt reply
            let resp_header = header.response(reply_body.len() as u32).unwrap();
            usg_tacacs_proto::crypto::apply_body_crypto(
                &resp_header,
                &mut reply_body,
                Some(SECRET),
            )
            .unwrap();
            black_box(reply_body);
        });
    });
}

criterion_group!(
    benches,
    bench_crypto,
    bench_parse_authen,
    bench_parse_author,
    bench_parse_accounting,
    bench_encode_authen_reply,
    bench_encode_author_response,
    bench_full_authen_roundtrip,
);
criterion_main!(benches);
