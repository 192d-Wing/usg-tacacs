# NIST Security Controls Mapping for usg-tacacs

**Document Version:** 1.0
**Date:** 2026-01-07
**Software Version:** 0.76.0
**Applicable Framework:** NIST SP 800-53 Rev. 5

---

## Executive Summary

This document maps the security controls implemented in **usg-tacacs** (a production-grade TACACS+ server written in Rust) to the NIST SP 800-53 security control framework. The usg-tacacs implementation provides comprehensive security controls for network device authentication, authorization, and accounting (AAA) services.

---

## Table of Contents

1. [Access Control (AC)](#1-access-control-ac)
2. [Audit and Accountability (AU)](#2-audit-and-accountability-au)
3. [Configuration Management (CM)](#3-configuration-management-cm)
4. [Identification and Authentication (IA)](#4-identification-and-authentication-ia)
5. [System and Communications Protection (SC)](#5-system-and-communications-protection-sc)
6. [System and Information Integrity (SI)](#6-system-and-information-integrity-si)
7. [Control Summary Matrix](#7-control-summary-matrix)

---

## 1. Access Control (AC)

### AC-2: Account Management

| Aspect | Implementation |
|--------|----------------|
| **Control** | The organization manages information system accounts |
| **Implementation** | LDAP integration with group membership validation; policy-based user/group matching |
| **Code Location** | `crates/tacacs-server/src/auth.rs` (LDAP authentication), `crates/tacacs-policy/` (policy engine) |
| **Configuration** | `--ldap-url`, `--ldap-required-groups`, policy file user/group definitions |

**Evidence:**
- LDAP group membership enforcement via `ldap_fetch_groups_blocking()`
- Policy rules support user and group matching
- Case-insensitive group comparison for consistency

---

### AC-3: Access Enforcement

| Aspect | Implementation |
|--------|----------------|
| **Control** | The system enforces approved authorizations for logical access |
| **Implementation** | Policy engine with ordered rules, regex command matching, allow/deny effects |
| **Code Location** | `crates/tacacs-server/src/policy.rs`, `crates/tacacs-policy/src/` |
| **Configuration** | Policy JSON file with `--policy` flag |

**Evidence:**
- Authorization decisions logged with rule ID and reason
- Command normalization (whitespace, case) before matching
- Auto-anchored regex patterns for precise matching
- Last-match-wins semantics with priority ordering

---

### AC-4: Information Flow Enforcement

| Aspect | Implementation |
|--------|----------------|
| **Control** | The system enforces approved authorizations for controlling information flow |
| **Implementation** | Per-command authorization, service/protocol filtering, message allowlists/denylists |
| **Code Location** | `crates/tacacs-server/src/policy.rs` |
| **Configuration** | Policy rules with `action`, `service`, `protocol`, `server_msg` filters |

**Evidence:**
- Commands authorized individually before execution
- Service-level filtering (shell, PPP, etc.)
- Raw message filtering per user configuration

---

### AC-6: Least Privilege

| Aspect | Implementation |
|--------|----------------|
| **Control** | The organization employs the principle of least privilege |
| **Implementation** | Role-based access control (RBAC) for Management API; per-NAD secrets; non-root execution |
| **Code Location** | `crates/tacacs-server/src/api/rbac.rs`, systemd unit files |
| **Configuration** | RBAC roles (admin, operator, viewer), systemd security directives |

**Evidence:**
- Permission model: `read:*`, `write:*`, `read:status`, etc.
- User-to-role mapping via TLS client certificate CN/SAN
- Process runs without root privileges
- Capability bounding set dropped via systemd

---

### AC-7: Unsuccessful Logon Attempts

| Aspect | Implementation |
|--------|----------------|
| **Control** | The system enforces a limit of consecutive invalid logon attempts |
| **Implementation** | Multi-layered brute-force protection with exponential backoff and lockout |
| **Code Location** | `crates/tacacs-server/src/ascii.rs`, `crates/tacacs-server/src/config.rs` |
| **Configuration** | `--ascii-attempt-limit`, `--ascii-backoff-base-ms`, `--ascii-backoff-cap-ms`, `--ascii-lockout-threshold` |

**Evidence:**
- Global attempt limit per session (default: 5)
- Username prompt attempts (default: 3)
- Password prompt attempts (default: 5)
- Exponential backoff formula: `base * 2^(attempt-1)`
- Random jitter (0-5000ms) to prevent timing attacks
- Hard lockout after configurable threshold

---

### AC-10: Concurrent Session Control

| Aspect | Implementation |
|--------|----------------|
| **Control** | The system limits the number of concurrent sessions |
| **Implementation** | Per-IP connection limiting with atomic counters |
| **Code Location** | `crates/tacacs-server/src/server.rs` (ConnLimiter) |
| **Configuration** | `--max-connections-per-ip` (default: 50) |

**Evidence:**
- Connection guard automatically releases on drop
- Atomic counter prevents race conditions
- Excess connections rejected with logging

---

### AC-11: Session Lock / AC-12: Session Termination

| Aspect | Implementation |
|--------|----------------|
| **Control** | The system initiates session termination after inactivity |
| **Implementation** | Idle timeout and keepalive timeouts |
| **Code Location** | `crates/tacacs-server/src/server.rs` |
| **Configuration** | `--single-connect-idle-timeout-secs` (default: 300), `--keepalive-activity-timeout-secs` (default: 120) |

**Evidence:**
- Sessions terminated after idle period
- Keepalive packets supported for long-lived connections
- Graceful connection draining during shutdown

---

## 2. Audit and Accountability (AU)

### AU-2: Audit Events

| Aspect | Implementation |
|--------|----------------|
| **Control** | The system generates audit events for defined auditable events |
| **Implementation** | Comprehensive event logging via tracing crate |
| **Code Location** | Throughout codebase, `crates/tacacs-server/src/telemetry.rs` |
| **Audited Events** | Authentication attempts, authorization decisions, accounting records, connection events |

**Events Logged:**
- Authentication: method, result, username, peer IP
- Authorization: command, decision (allow/deny), rule ID, groups
- Accounting: start/stop/watchdog, task ID, session ID
- Connection: accept/reject, TLS handshake, certificate validation
- Policy: reload attempts, validation results

---

### AU-3: Content of Audit Records

| Aspect | Implementation |
|--------|----------------|
| **Control** | Audit records contain required information |
| **Implementation** | Structured logging with consistent fields |
| **Code Location** | All event logging sites |
| **Fields** | Timestamp (UTC RFC 3339), peer IP, username, session ID, outcome, rule ID |

**Record Contents:**
- **What:** Event type (auth, authz, acct, connection)
- **When:** UTC timestamp in RFC 3339 format
- **Where:** Peer IP address, server instance
- **Who:** Username (UTF-8 and binary support)
- **Outcome:** Success/failure, rule ID, decision reason
- **Context:** Session ID, sequence number, groups

---

### AU-4: Audit Storage Capacity

| Aspect | Implementation |
|--------|----------------|
| **Control** | The organization allocates audit storage capacity |
| **Implementation** | External log aggregation via OpenTelemetry OTLP export |
| **Code Location** | `crates/tacacs-server/src/telemetry.rs` |
| **Configuration** | `--otlp-endpoint` |

**Evidence:**
- Logs exported to external OTLP collectors
- No local storage limits (streaming export)
- Compatible with enterprise SIEM systems

---

### AU-6: Audit Review, Analysis, and Reporting

| Aspect | Implementation |
|--------|----------------|
| **Control** | The organization reviews and analyzes audit records |
| **Implementation** | Prometheus metrics for operational visibility; structured JSON logging |
| **Code Location** | `crates/tacacs-server/src/metrics.rs`, `crates/tacacs-server/src/http.rs` |
| **Configuration** | `--enable-prometheus-metrics`, `--log-format json` |

**Metrics Available:**
- `tacacs_connections_total` (by outcome)
- `tacacs_authentications_total` (by method, result)
- `tacacs_authorizations_total` (by result)
- `tacacs_accounting_total` (by type, status)
- Duration histograms for performance analysis

---

### AU-8: Time Stamps

| Aspect | Implementation |
|--------|----------------|
| **Control** | The system uses internal clocks to generate timestamps |
| **Implementation** | UTC timestamps in RFC 3339 format |
| **Code Location** | `crates/tacacs-server/src/telemetry.rs` |
| **Format** | ISO 8601 / RFC 3339 with timezone |

---

### AU-9: Protection of Audit Information

| Aspect | Implementation |
|--------|----------------|
| **Control** | The system protects audit information from unauthorized access |
| **Implementation** | Sensitive data excluded from logs; TLS for OTLP export |
| **Code Location** | Throughout logging code |

**Protected Information (NOT logged):**
- Passwords and authentication secrets
- Certificate private keys
- Shared secrets
- LDAP bind credentials

---

### AU-12: Audit Generation

| Aspect | Implementation |
|--------|----------------|
| **Control** | The system generates audit records for auditable events |
| **Implementation** | Tracing crate integrated throughout codebase |
| **Code Location** | All security-relevant functions |

**Generation Points:**
- Connection acceptance/rejection
- TLS handshake completion
- Authentication method execution
- Authorization policy evaluation
- Accounting record processing
- Session state transitions

---

## 3. Configuration Management (CM)

### CM-2: Baseline Configuration

| Aspect | Implementation |
|--------|----------------|
| **Control** | The organization maintains baseline configurations |
| **Implementation** | JSON schema validation for configuration and policy files |
| **Code Location** | `config.schema.json`, `policy/policy.schema.json` |
| **Configuration** | `--check-policy` for validation-only mode |

**Evidence:**
- Machine-readable configuration schemas
- Two-phase validation (schema + semantic)
- Version-controlled configuration files

---

### CM-3: Configuration Change Control

| Aspect | Implementation |
|--------|----------------|
| **Control** | The organization analyzes changes prior to implementation |
| **Implementation** | Policy validation before reload; atomic policy updates |
| **Code Location** | `crates/tacacs-server/src/policy.rs` |
| **Configuration** | Policy reload via signal (SIGHUP) |

**Evidence:**
- `--check-policy` validates without applying
- Policy reload metrics track success/failure
- Invalid policies rejected with detailed errors

---

### CM-5: Access Restrictions for Change

| Aspect | Implementation |
|--------|----------------|
| **Control** | The organization defines and enforces access restrictions for change |
| **Implementation** | Management API RBAC; file system permissions |
| **Code Location** | `crates/tacacs-server/src/api/rbac.rs` |
| **Configuration** | Role-based permissions for API access |

**Evidence:**
- Configuration files require appropriate permissions
- API changes require authenticated mTLS connection
- RBAC enforces write permissions for changes

---

### CM-6: Configuration Settings

| Aspect | Implementation |
|--------|----------------|
| **Control** | The organization establishes mandatory configuration settings |
| **Implementation** | Secure defaults; required parameter validation |
| **Code Location** | `crates/tacacs-server/src/config.rs` |

**Secure Defaults:**
- TLS 1.3 mandatory (no fallback)
- mTLS required for all connections
- Static credentials disabled by default
- Minimum secret length enforced (8 bytes)
- Reasonable timeout defaults

---

## 4. Identification and Authentication (IA)

### IA-2: Identification and Authentication (Organizational Users)

| Aspect | Implementation |
|--------|----------------|
| **Control** | The system uniquely identifies and authenticates users |
| **Implementation** | Multiple authentication methods: PAP, CHAP, ASCII, LDAPS |
| **Code Location** | `crates/tacacs-server/src/auth.rs`, `crates/tacacs-server/src/ascii.rs` |
| **Configuration** | `--ldap-url`, `--allow-static-credentials`, credential files |

**Methods:**
- **PAP:** Password Authentication Protocol (static or LDAPS)
- **CHAP:** Challenge-Handshake Authentication Protocol
- **ASCII:** Interactive authentication with brute-force protection
- **LDAPS:** Secure LDAP (StartTLS rejected for security)

---

### IA-3: Device Identification and Authentication

| Aspect | Implementation |
|--------|----------------|
| **Control** | The system uniquely identifies and authenticates devices |
| **Implementation** | Mutual TLS with certificate validation; certificate allowlists |
| **Code Location** | `crates/tacacs-server/src/tls.rs`, `crates/tacacs-server/src/server.rs` |
| **Configuration** | `--cn-allowlist`, `--san-allowlist`, `--client-ca` |

**Evidence:**
- mTLS required for all connections
- Certificate Common Name (CN) allowlist
- Subject Alternative Name (SAN) allowlist (DNS, IP, URI)
- WebPkiClientVerifier for chain validation

---

### IA-4: Identifier Management

| Aspect | Implementation |
|--------|----------------|
| **Control** | The organization manages information system identifiers |
| **Implementation** | Certificate-based identity; LDAP user management |
| **Code Location** | `crates/tacacs-server/src/server.rs` |

**Evidence:**
- Device identity from TLS client certificate
- User identity from LDAP directory
- Session ID tracking per connection

---

### IA-5: Authenticator Management

| Aspect | Implementation |
|--------|----------------|
| **Control** | The organization manages information system authenticators |
| **Implementation** | Argon2id password hashing; secret validation; certificate management |
| **Code Location** | `crates/tacacs-server/src/auth.rs`, `crates/tacacs-secrets/` |
| **Configuration** | Argon2 parameters, secret minimum length |

**Evidence:**
- **Argon2id:** Memory-hard hashing (m=65536, t=3, p=4)
- **Secret Validation:** Minimum 8 bytes, must differ from TLS PSK
- **Certificate Rotation:** Integration with OpenBao/Vault for PKI
- **No Plaintext Storage:** Argon2 hashes stored, not passwords

---

### IA-6: Authenticator Feedback

| Aspect | Implementation |
|--------|----------------|
| **Control** | The system obscures feedback of authentication information |
| **Implementation** | Generic error messages; no credential leakage in logs |
| **Code Location** | `crates/tacacs-server/src/auth.rs`, `crates/tacacs-server/src/ascii.rs` |

**Evidence:**
- Authentication failures do not reveal credential validity
- Passwords never logged
- Timing-safe comparison where possible

---

### IA-8: Identification and Authentication (Non-Organizational Users)

| Aspect | Implementation |
|--------|----------------|
| **Control** | The system identifies and authenticates non-organizational users |
| **Implementation** | Same authentication mechanisms apply to all connecting devices |
| **Code Location** | Same as IA-2 |

---

## 5. System and Communications Protection (SC)

### SC-4: Information in Shared Resources

| Aspect | Implementation |
|--------|----------------|
| **Control** | The system prevents unauthorized information transfer via shared resources |
| **Implementation** | Memory-safe Rust language; isolated session state |
| **Code Location** | Throughout codebase |

**Evidence:**
- Rust prevents buffer overflows and use-after-free
- Session state isolated per connection
- No shared mutable state between sessions

---

### SC-7: Boundary Protection

| Aspect | Implementation |
|--------|----------------|
| **Control** | The system monitors and controls communications at external boundaries |
| **Implementation** | Connection limits; IP-based rate limiting; network isolation |
| **Code Location** | `crates/tacacs-server/src/server.rs` |
| **Configuration** | `--max-connections-per-ip`, systemd `RestrictAddressFamilies` |

**Evidence:**
- Per-IP connection limiting
- Only AF_INET and AF_INET6 allowed via systemd
- Private network deployment recommended

---

### SC-8: Transmission Confidentiality and Integrity

| Aspect | Implementation |
|--------|----------------|
| **Control** | The system protects the confidentiality and integrity of transmitted information |
| **Implementation** | TLS 1.3 mandatory; TACACS+ obfuscation layer |
| **Code Location** | `crates/tacacs-server/src/tls.rs`, `crates/tacacs-proto/src/crypto.rs` |
| **Configuration** | TLS certificates, shared secrets |

**Evidence:**
- **TLS 1.3:** Modern cipher suites, forward secrecy
- **No Fallback:** TLS 1.2 and earlier disabled
- **Defense-in-Depth:** Obfuscation applied over TLS
- **Rustls:** Memory-safe TLS implementation

---

### SC-12: Cryptographic Key Establishment and Management

| Aspect | Implementation |
|--------|----------------|
| **Control** | The organization establishes and manages cryptographic keys |
| **Implementation** | TLS certificate management; shared secret configuration; Vault/OpenBao integration |
| **Code Location** | `crates/tacacs-secrets/src/`, `crates/tacacs-server/src/tls.rs` |
| **Configuration** | `--server-cert`, `--server-key`, `--secret`, per-NAD secrets |

**Evidence:**
- PKI certificates for TLS
- Per-NAD secrets for legacy obfuscation
- Dynamic secret rotation via Vault/OpenBao
- Secrets validation (length, uniqueness)

---

### SC-13: Cryptographic Protection

| Aspect | Implementation |
|--------|----------------|
| **Control** | The system implements required cryptographic protections |
| **Implementation** | TLS 1.3, Argon2id, MD5 obfuscation (legacy) |
| **Code Location** | Multiple crates |

**Algorithms:**
| Purpose | Algorithm | Location |
|---------|-----------|----------|
| Transport | TLS 1.3 | `tls.rs` |
| Password Hash | Argon2id | `auth.rs` |
| Body Obfuscation | MD5-XOR | `crypto.rs` |

---

### SC-17: Public Key Infrastructure Certificates

| Aspect | Implementation |
|--------|----------------|
| **Control** | The organization issues certificates under an appropriate policy |
| **Implementation** | X.509 certificate validation; certificate allowlists |
| **Code Location** | `crates/tacacs-server/src/server.rs`, `crates/tacacs-server/src/tls.rs` |
| **Configuration** | `--client-ca`, `--extra-trust-roots`, `--cn-allowlist`, `--san-allowlist` |

**Evidence:**
- WebPkiClientVerifier for certificate chain validation
- CN and SAN allowlists for identity enforcement
- Support for multiple trust roots

---

### SC-23: Session Authenticity

| Aspect | Implementation |
|--------|----------------|
| **Control** | The system protects the authenticity of communications sessions |
| **Implementation** | mTLS authentication; session ID validation; sequence number tracking |
| **Code Location** | `crates/tacacs-server/src/session.rs`, `crates/tacacs-server/src/server.rs` |

**Evidence:**
- Mutual TLS authenticates both endpoints
- Session ID validated per RFC 8907
- Sequence numbers prevent replay attacks

---

## 6. System and Information Integrity (SI)

### SI-2: Flaw Remediation

| Aspect | Implementation |
|--------|----------------|
| **Control** | The organization identifies, reports, and corrects flaws |
| **Implementation** | Rust memory safety; dependency management; security testing |
| **Code Location** | `Cargo.lock`, CI/CD configuration |

**Evidence:**
- Rust eliminates memory corruption vulnerabilities
- Cargo.lock for reproducible builds
- Cargo audit recommendations documented

---

### SI-3: Malicious Code Protection

| Aspect | Implementation |
|--------|----------------|
| **Control** | The system implements malicious code protection |
| **Implementation** | Input validation; command normalization; parameterized queries |
| **Code Location** | `crates/tacacs-server/src/ascii.rs`, `crates/tacacs-server/src/auth.rs` |

**Evidence:**
- Command input normalized before policy evaluation
- LDAP filters use parameterized construction (no injection)
- JSON schema validation prevents malformed input

---

### SI-4: Information System Monitoring

| Aspect | Implementation |
|--------|----------------|
| **Control** | The organization monitors the information system |
| **Implementation** | Prometheus metrics; health checks; distributed tracing |
| **Code Location** | `crates/tacacs-server/src/metrics.rs`, `crates/tacacs-server/src/http.rs` |
| **Configuration** | `--enable-prometheus-metrics`, `--otlp-endpoint` |

**Endpoints:**
| Endpoint | Purpose |
|----------|---------|
| `/health` | Liveness probe |
| `/ready` | Readiness probe |
| `/live` | Alive check |
| `/metrics` | Prometheus metrics |

---

### SI-7: Software, Firmware, and Information Integrity

| Aspect | Implementation |
|--------|----------------|
| **Control** | The organization employs integrity verification tools |
| **Implementation** | Locked builds; policy validation |
| **Code Location** | `Cargo.lock`, policy validation code |

**Evidence:**
- `cargo build --locked` for reproducible builds
- Policy schema validation before application
- Configuration validation at startup

---

### SI-10: Information Input Validation

| Aspect | Implementation |
|--------|----------------|
| **Control** | The system checks the validity of information inputs |
| **Implementation** | Schema validation; input sanitization; regex validation |
| **Code Location** | Throughout codebase |

**Validations:**
- JSON schema validation for configuration
- Regex pattern compilation and validation
- Certificate identity validation
- Command string normalization
- Minimum secret length enforcement

---

## 7. Control Summary Matrix

| Control ID | Control Name | Status | Implementation Strength |
|------------|--------------|--------|------------------------|
| **Access Control (AC)** ||||
| AC-2 | Account Management | Implemented | Strong (LDAP + Policy) |
| AC-3 | Access Enforcement | Implemented | Strong (Policy Engine) |
| AC-4 | Information Flow Enforcement | Implemented | Strong |
| AC-6 | Least Privilege | Implemented | Strong (RBAC + systemd) |
| AC-7 | Unsuccessful Logon Attempts | Implemented | Strong (Multi-layered) |
| AC-10 | Concurrent Session Control | Implemented | Strong |
| AC-11/12 | Session Lock/Termination | Implemented | Strong |
| **Audit (AU)** ||||
| AU-2 | Audit Events | Implemented | Comprehensive |
| AU-3 | Content of Audit Records | Implemented | Comprehensive |
| AU-4 | Audit Storage Capacity | Implemented | Strong (OTLP export) |
| AU-6 | Audit Review/Analysis | Implemented | Strong (Metrics + JSON) |
| AU-8 | Time Stamps | Implemented | Strong (UTC/RFC 3339) |
| AU-9 | Protection of Audit Info | Implemented | Strong |
| AU-12 | Audit Generation | Implemented | Comprehensive |
| **Configuration Management (CM)** ||||
| CM-2 | Baseline Configuration | Implemented | Strong (Schema) |
| CM-3 | Configuration Change Control | Implemented | Strong |
| CM-5 | Access Restrictions for Change | Implemented | Strong (RBAC) |
| CM-6 | Configuration Settings | Implemented | Strong (Secure Defaults) |
| **Identification & Authentication (IA)** ||||
| IA-2 | User Authentication | Implemented | Strong (Multi-method) |
| IA-3 | Device Authentication | Implemented | Strong (mTLS) |
| IA-4 | Identifier Management | Implemented | Strong |
| IA-5 | Authenticator Management | Implemented | Strong (Argon2) |
| IA-6 | Authenticator Feedback | Implemented | Strong |
| IA-8 | Non-Org User Authentication | Implemented | Strong |
| **System & Communications Protection (SC)** ||||
| SC-4 | Shared Resource Protection | Implemented | Strong (Rust) |
| SC-7 | Boundary Protection | Implemented | Strong |
| SC-8 | Transmission Protection | Implemented | Strong (TLS 1.3) |
| SC-12 | Cryptographic Key Management | Implemented | Strong |
| SC-13 | Cryptographic Protection | Implemented | Strong |
| SC-17 | PKI Certificates | Implemented | Strong |
| SC-23 | Session Authenticity | Implemented | Strong (mTLS) |
| **System & Information Integrity (SI)** ||||
| SI-2 | Flaw Remediation | Implemented | Strong (Rust) |
| SI-3 | Malicious Code Protection | Implemented | Strong |
| SI-4 | System Monitoring | Implemented | Strong |
| SI-7 | Software Integrity | Implemented | Strong |
| SI-10 | Input Validation | Implemented | Strong |

---

## Appendix A: Key File Locations

| Security Function | Primary File(s) |
|-------------------|-----------------|
| Authentication | `crates/tacacs-server/src/auth.rs` |
| ASCII Auth (Brute-force) | `crates/tacacs-server/src/ascii.rs` |
| TLS Configuration | `crates/tacacs-server/src/tls.rs` |
| Policy Engine | `crates/tacacs-server/src/policy.rs`, `crates/tacacs-policy/` |
| RBAC | `crates/tacacs-server/src/api/rbac.rs` |
| Metrics | `crates/tacacs-server/src/metrics.rs` |
| Telemetry | `crates/tacacs-server/src/telemetry.rs` |
| Session Management | `crates/tacacs-server/src/session.rs` |
| Connection Handling | `crates/tacacs-server/src/server.rs` |
| Cryptography | `crates/tacacs-proto/src/crypto.rs` |
| Secrets Management | `crates/tacacs-secrets/src/` |
| Configuration | `crates/tacacs-server/src/config.rs` |

---

## Appendix B: Configuration Parameters for Compliance

### Critical Security Parameters

```bash
# TLS Configuration (SC-8, SC-13, IA-3)
--server-cert /path/to/cert.pem
--server-key /path/to/key.pem
--client-ca /path/to/ca.pem
--cn-allowlist "device1.example.com,device2.example.com"
--san-allowlist "DNS:*.example.com,IP:10.0.0.0/8"

# Authentication (IA-2, IA-5)
--ldap-url ldaps://ldap.example.com:636
--ldap-service-account-bind-dn "cn=service,dc=example,dc=com"
--ldap-required-groups "network-admins,security-team"

# Brute-Force Protection (AC-7)
--ascii-attempt-limit 5
--ascii-backoff-base-ms 1000
--ascii-backoff-cap-ms 30000
--ascii-lockout-threshold 10

# Connection Limits (AC-10, SC-7)
--max-connections-per-ip 50
--single-connect-idle-timeout-secs 300

# Auditing (AU-2, AU-12)
--otlp-endpoint http://collector:4317
--log-format json
--enable-prometheus-metrics

# Policy (AC-3, CM-2)
--policy /etc/tacacs/policy.json
```

---

## Appendix C: Systemd Security Directives

For maximum NIST compliance, deploy with these systemd hardening options:

```ini
[Service]
# Privilege Restrictions (AC-6)
User=tacacs
Group=tacacs
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=

# Filesystem Protection (SC-4)
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadOnlyPaths=/etc/tacacs

# Kernel Protection (SI-7)
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
LockPersonality=yes

# Network Isolation (SC-7)
RestrictAddressFamilies=AF_INET AF_INET6

# Resource Limits (AC-10)
LimitNOFILE=4096
LimitNPROC=256

# Additional Hardening
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
```

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-07 | Generated | Initial NIST mapping |

---

*This document was generated based on analysis of usg-tacacs version 0.76.0.*
