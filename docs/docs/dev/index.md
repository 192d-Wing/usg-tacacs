---
icon: lucide/code-2
---

# Developer Guide

This guide covers the architecture, development setup, and contribution guidelines for `usg-tacacs`.

## Architecture Overview

### Crate Structure

```
tacacs-rs/
├── crates/
│   ├── tacacs-proto/          # Protocol implementation (RFC 8907)
│   │   ├── src/
│   │   │   ├── lib.rs         # Packet parsing, validation
│   │   │   ├── header.rs      # TACACS+ header handling
│   │   │   ├── authen.rs      # Authentication packets
│   │   │   ├── author.rs      # Authorization packets
│   │   │   ├── accounting.rs  # Accounting packets
│   │   │   ├── crypto.rs      # MD5 obfuscation
│   │   │   ├── capability.rs  # Capability/keepalive packets
│   │   │   └── util.rs        # Shared utilities
│   │   └── Cargo.toml
│   │
│   ├── tacacs-policy/         # Policy engine
│   │   ├── src/
│   │   │   └── lib.rs         # Rule matching, normalization
│   │   └── Cargo.toml
│   │
│   ├── tacacs-server/         # Main server binary
│   │   ├── src/
│   │   │   ├── main.rs        # Entry point, CLI parsing
│   │   │   ├── server.rs      # Connection handling, packet routing
│   │   │   ├── config.rs      # Configuration loading
│   │   │   ├── tls.rs         # TLS/mTLS setup
│   │   │   ├── auth.rs        # Authentication logic, LDAP
│   │   │   ├── ascii.rs       # ASCII authentication flow
│   │   │   ├── session.rs     # Session state, single-connect
│   │   │   └── policy.rs      # Policy integration
│   │   └── Cargo.toml
│   │
│   └── tacacs-policy-ingest/  # Policy ingestion service
│       ├── src/
│       │   └── main.rs        # REST API, bundle handling
│       ├── sql/
│       │   └── schema.sql     # Database schema
│       └── Cargo.toml
│
├── policy/                     # Example policies and schemas
├── container/                  # Docker deployment
└── docs/                       # Documentation (Zensical)
```

### Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                         tacacs-server                            │
│                                                                  │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐  │
│  │   TLS    │───►│  Packet  │───►│ Session  │───►│  Policy  │  │
│  │ Listener │    │  Parser  │    │  State   │    │  Engine  │  │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘  │
│       │               │               │               │         │
│       │         tacacs-proto    session.rs     tacacs-policy    │
│       │                                                          │
│  ┌──────────┐                   ┌──────────┐                    │
│  │   Auth   │◄─────────────────►│   LDAP   │                    │
│  │  Logic   │                   │  Client  │                    │
│  └──────────┘                   └──────────┘                    │
│       │                                                          │
│       └───────────────────► Response ──────────────────────►    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Development Setup

### Prerequisites

- Rust stable (1.75+): `rustup toolchain install stable`
- OpenSSL development headers (for TLS)
- Optional: Docker for container testing
- Optional: PostgreSQL for policy-ingest

### Build

```sh
# Clone the repository
git clone https://github.com/192d-Wing/usg-tacacs.git
cd usg-tacacs

# Build all crates
cargo build --locked

# Run tests
cargo test --locked

# Build release
cargo build --locked --release
```

### Code Quality

```sh
# Format code
cargo fmt

# Lint with Clippy
cargo clippy -- -D warnings

# Check for security vulnerabilities
cargo audit

# Check dependencies
cargo deny check
```

### Running Locally

```sh
# Start server with example config
cargo run -p tacacs-server -- \
  --listen-tls 127.0.0.1:300 \
  --tls-cert ./test-certs/server.pem \
  --tls-key ./test-certs/server-key.pem \
  --client-ca ./test-certs/client-ca.pem \
  --policy ./policy/policy.example.json \
  --secret "dev-secret"
```

## Key Components

### tacacs-proto

The protocol implementation crate handles:

- **Packet parsing**: Reading/writing TACACS+ packets
- **Header validation**: Version, type, flags, sequence numbers
- **Body handling**: Authentication, authorization, accounting
- **Obfuscation**: MD5-based body encryption (RFC 8907 Section 4.5)

Key types:

```rust
// Packet types
pub enum Packet {
    Authentication(AuthenPacket),
    Authorization(AuthorizationRequest),
    Accounting(AccountingRequest),
    Capability(CapabilityPacket),
}

// Read a packet from a stream
pub async fn read_packet<R>(reader: &mut R, secret: Option<&[u8]>) -> Result<Option<Packet>>

// Write responses
pub async fn write_authen_reply<W>(writer: &mut W, header: &Header, reply: &AuthenReply, secret: Option<&[u8]>) -> Result<()>
```

### tacacs-policy

The policy engine provides:

- **Rule matching**: Priority-based, last-match-wins
- **Command normalization**: Whitespace, case handling
- **User/group matching**: Case-insensitive, match-any
- **Regex patterns**: Auto-anchored command matching

```rust
pub struct PolicyEngine {
    rules: Vec<Rule>,
}

impl PolicyEngine {
    pub fn evaluate(&self, user: &str, groups: &[String], command: &str) -> Decision
}
```

### tacacs-server

The main server binary handles:

- **Connection management**: TLS/legacy listeners
- **Session state**: Authentication flows, single-connect
- **LDAP integration**: Service-account bind, group lookup
- **Audit logging**: Structured tracing events

### Session Management

```rust
// Single-connect state per connection
pub struct SingleConnectState {
    pub user: Option<String>,
    pub active: bool,
    pub locked: bool,
    pub session: Option<u32>,
}

// RFC 8907 task_id tracking for accounting
pub struct TaskIdTracker {
    active: HashSet<u32>,
}
```

## Testing

### Unit Tests

```sh
cargo test
```

### Integration Testing

Test with a real TACACS+ client:

```sh
# Start server
cargo run -p tacacs-server -- --listen-legacy 127.0.0.1:4949 ...

# Use tacacs+ client (e.g., tac_plus_ng, tactest)
tactest -h 127.0.0.1 -p 4949 -u admin -w password
```

### Packet Capture Analysis

Use Wireshark with TACACS+ dissector:

1. Capture on port 49 or 300
2. If using obfuscation, Wireshark needs the shared secret
3. Analyze packet sequences and flags

## Adding Features

### New Authentication Method

1. Add constants to `tacacs-proto/src/lib.rs`
2. Implement parsing in `authen.rs`
3. Add handling in `tacacs-server/src/auth.rs`
4. Add tests

### New Policy Attribute

1. Update `policy/policy.schema.json`
2. Modify `tacacs-policy/src/lib.rs` for matching
3. Update documentation
4. Add tests

### New Configuration Option

1. Add to `tacacs-server/src/config.rs` (Args struct)
2. Update `config.schema.json`
3. Handle in server initialization
4. Document in configuration reference

## Code Style

### Rust Conventions

- Use `rustfmt` defaults
- Follow Clippy recommendations
- Prefer `anyhow::Result` for errors
- Use `tracing` for logging

### Commit Messages

Follow Conventional Commits:

```
feat(auth): add argon2 password hashing
fix(proto): handle sequence number wraparound
docs(policy): clarify last-match-wins behavior
refactor(server): extract session state to module
```

### Documentation

- Keep doc comments updated
- Document public API with `///`
- Include examples where helpful

## Pull Request Process

1. **Create a branch** from `master`
2. **Make changes** with tests
3. **Run quality checks**:
   ```sh
   cargo fmt
   cargo clippy -- -D warnings
   cargo test
   ```
4. **Update documentation** if needed
5. **Submit PR** with clear description
6. **Address review feedback**
7. **Merge** after approval

## Release Process

1. Update version in `Cargo.toml` files
2. Update CHANGELOG
3. Create git tag: `git tag v0.x.y`
4. Build release artifacts
5. Generate SBOM
6. Sign artifacts
7. Publish release

## Debugging Tips

### Enable Debug Logging

```sh
RUST_LOG=debug cargo run -p tacacs-server -- ...
```

### Trace Specific Components

```sh
RUST_LOG=usg_tacacs_server::auth=trace cargo run ...
```

### Profile Performance

```sh
cargo build --release
perf record ./target/release/usg-tacacs-server ...
perf report
```

## Resources

- [RFC 8907 - TACACS+ Protocol](https://datatracker.ietf.org/doc/rfc8907/)
- [RFC 9887 - TACACS+ over TLS 1.3](https://datatracker.ietf.org/doc/rfc9887/)
- [Rust Book](https://doc.rust-lang.org/book/)
- [Tokio Tutorial](https://tokio.rs/tokio/tutorial)
- [Rustls Documentation](https://docs.rs/rustls/)
