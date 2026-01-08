# TACACS+ Protocol Fuzzing

This directory contains fuzzing infrastructure for the `tacacs-proto` crate using [cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz.html) and libFuzzer.

## Overview

Fuzzing is used to discover bugs, crashes, and security vulnerabilities by testing the protocol parser with randomized and mutated inputs. The fuzzer has already discovered and helped fix a bounds check bug (CWE-125).

## Fuzz Targets

### 1. `fuzz_header`
Fuzzes TACACS+ header parsing and validation logic.

**Coverage:**
- 12-byte header parsing
- Version validation
- Packet type validation
- Flags validation
- Sequence number validation (odd/even)

### 2. `fuzz_body_crypto`
Fuzzes MD5-based body obfuscation through the public packet I/O API.

**Coverage:**
- Encryption/decryption roundtrip verification
- Secret validation (minimum 8 bytes)
- UNENCRYPTED flag handling
- Empty body handling
- Multi-block body handling (>16 bytes)

### 3. `fuzz_packet`
Fuzzes complete TACACS+ packet parsing for all packet types.

**Coverage:**
- Authentication packets (PAP, CHAP, ASCII)
- Authorization requests/responses
- Accounting requests/responses
- Capability negotiation packets
- Header + body integration
- Type-specific parsers

## Prerequisites

```bash
# Install Rust nightly toolchain
rustup install nightly

# Install cargo-fuzz
cargo install cargo-fuzz
```

## Usage

```bash
cd /path/to/usg-tacacs/crates/tacacs-proto

# List available fuzz targets
cargo +nightly fuzz list

# Run a specific target (runs indefinitely until crash or Ctrl+C)
cargo +nightly fuzz run fuzz_header
cargo +nightly fuzz run fuzz_body_crypto
cargo +nightly fuzz run fuzz_packet

# Run with time limit (in seconds)
cargo +nightly fuzz run fuzz_packet -- -max_total_time=60

# Run with custom options
cargo +nightly fuzz run fuzz_packet -- -max_len=4096 -timeout=10

# Reproduce a crash
cargo +nightly fuzz run fuzz_packet fuzz/artifacts/fuzz_packet/crash-<hash>

# Minimize a crashing input
cargo +nightly fuzz tmin fuzz_packet fuzz/artifacts/fuzz_packet/crash-<hash>
```

## Seed Corpus

The `corpus/` directory contains seed inputs with valid TACACS+ packets to improve coverage:

- **fuzz_header/**: Valid 12-byte headers (authentication, authorization, accounting, capability)
- **fuzz_body_crypto/**: Complete packets with headers and bodies
- **fuzz_packet/**: Complete packets for all packet types (PAP, CHAP, ASCII, authorization, accounting)

The fuzzer uses these seeds as starting points and mutates them to explore edge cases.

## Results

### Bugs Found

#### 1. Bounds Check Bug (CWE-125) - FIXED
- **File:** `src/lib.rs:352`
- **Issue:** Authorization response parsing checked `body.len() >= 5` but accessed `body[5]`
- **Fix:** Changed check to `body.len() >= 6`
- **Impact:** Prevented potential DoS via crafted 5-byte authorization response

### Performance

Typical fuzzing performance on Apple Silicon (M-series):
- **fuzz_header**: ~75,000 exec/sec
- **fuzz_body_crypto**: ~36,000 exec/sec
- **fuzz_packet**: ~39,000 exec/sec

## Continuous Fuzzing

For long-running fuzzing campaigns:

```bash
# Run overnight (8 hours)
cargo +nightly fuzz run fuzz_packet -- -max_total_time=28800

# Run with dictionary (libFuzzer learns patterns)
cargo +nightly fuzz run fuzz_packet -- -dict=fuzz.dict

# Run with multiple jobs (parallel fuzzing)
cargo +nightly fuzz run fuzz_packet -- -jobs=4 -workers=4
```

## Coverage Analysis

To see code coverage:

```bash
# Generate coverage report
cargo +nightly fuzz coverage fuzz_packet

# View coverage with llvm-cov
llvm-cov show target/coverage/fuzz_packet \
    --instr-profile=fuzz/coverage/fuzz_packet/coverage.profdata \
    --format=html > coverage.html
```

## Integration with CI

Fuzzing can be integrated into CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Install cargo-fuzz
  run: cargo install cargo-fuzz

- name: Run fuzz tests (smoke test)
  run: |
    cd crates/tacacs-proto
    cargo +nightly fuzz run fuzz_header -- -max_total_time=60
    cargo +nightly fuzz run fuzz_body_crypto -- -max_total_time=60
    cargo +nightly fuzz run fuzz_packet -- -max_total_time=60
```

## Security Considerations

- Fuzzing is performed on the **protocol parser only**, not the authentication/authorization logic
- Fuzzing uses the `legacy-md5` feature to test RFC 8907 MD5-based body obfuscation
- All fuzzing is done locally; no sensitive data is transmitted
- Crash artifacts are stored in `artifacts/` (not committed to git)

## References

- [Rust Fuzz Book](https://rust-fuzz.github.io/book/)
- [libFuzzer Documentation](https://llvm.org/docs/LibFuzzer.html)
- [RFC 8907: TACACS+ Protocol](https://www.rfc-editor.org/rfc/rfc8907.html)
- [CWE-125: Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html)

## Troubleshooting

### "error: no such command: `fuzz`"
Install cargo-fuzz: `cargo install cargo-fuzz`

### "error: current package believes it's in a workspace when it's not"
This is expected. The fuzz directory has an empty `[workspace]` table to opt out of the parent workspace.

### Slow fuzzing performance
- Ensure you're using `--release` builds (cargo-fuzz does this by default)
- Use nightly Rust for best performance
- Consider running with `-jobs=N` for parallel fuzzing
