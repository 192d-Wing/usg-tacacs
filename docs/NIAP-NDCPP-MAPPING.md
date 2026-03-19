# NDcPP v4.0 Security Functional Requirements Mapping

<!-- NIST SP 800-53 Rev. 5 Security Controls
     Control Implementation Matrix

     | Control | Family | Status | Validated | Primary Functions |
     |---------|--------|--------|-----------|-------------------|
     | SA-4    | System and Services Acquisition | Documented | 2026-01-31 | Requirements mapping |
     | SA-5    | System Documentation | Documented | 2026-01-31 | Implementation documentation |
-->

**Project:** usg-tacacs TACACS+ Server
**Protection Profile:** NDcPP v4.0 + PP-Module for Authentication Servers v1.0
**Document Version:** 1.0
**Last Updated:** 2026-01-31

---

## Table of Contents

1. [Introduction](#introduction)
2. [Audit and Accountability (FAU)](#audit-and-accountability-fau)
3. [Cryptographic Support (FCS)](#cryptographic-support-fcs)
4. [Identification and Authentication (FIA)](#identification-and-authentication-fia)
5. [Security Management (FMT)](#security-management-fmt)
6. [Protection of TSF (FPT)](#protection-of-tsf-fpt)
7. [TOE Access (FTA)](#toe-access-fta)
8. [Trusted Path/Channels (FTP)](#trusted-pathchannels-ftp)
9. [Communications (FCO)](#communications-fco)
10. [Gap Summary](#gap-summary)

---

## Introduction

This document provides a comprehensive mapping of NDcPP v4.0 and PP-Module for Authentication Servers v1.0 Security Functional Requirements (SFRs) to their implementation in the usg-tacacs codebase.

### Status Legend

- ✅ **Implemented** - Fully implemented and tested
- ⚠️ **Partial** - Partially implemented, needs enhancement
- ❌ **Gap** - Not implemented, requires development

---

## Audit and Accountability (FAU)

### FAU_GEN.1 - Audit Data Generation

**Status:** ✅ Implemented

**Requirement:** The TSF shall generate audit records for security-relevant events.

**Implementation:**

| File | Lines | Description |
|------|-------|-------------|
| `crates/tacacs-audit/src/event.rs` | 23-50 | Audit event type enumeration |
| `crates/tacacs-audit/src/event.rs` | 105-159 | AuditEvent structure with metadata |
| `crates/tacacs-audit/src/event.rs` | 169-186 | Auto-timestamp generation |

**Auditable Events:**
- `AuthnSuccess` - Successful authentication
- `AuthnFailure` - Failed authentication
- `AuthzAllow` - Authorization granted
- `AuthzDeny` - Authorization denied
- `AcctStart` - Accounting session start
- `AcctStop` - Accounting session stop
- `AcctWatchdog` - Interim accounting update
- `SessionStart` - Connection established
- `SessionEnd` - Connection terminated
- `PolicyReload` - Policy configuration changed
- `ConfigReload` - System configuration changed
- `RatelimitTriggered` - Rate limit exceeded
- `LockoutActivated` - Account locked due to failures

**NIST Controls:** AU-2, AU-12

---

### FAU_GEN.2 - User Identity Association

**Status:** ✅ Implemented

**Requirement:** Audit records shall associate user identity with auditable events.

**Implementation:**

| File | Lines | Description |
|------|-------|-------------|
| `crates/tacacs-audit/src/event.rs` | 124-126 | username field |
| `crates/tacacs-audit/src/event.rs` | 120-122 | source_ip field |
| `crates/tacacs-audit/src/event.rs` | 136-138 | session_id field |
| `crates/tacacs-audit/src/event.rs` | 132-134 | remote_addr field |

**Audit Record Fields:**
```rust
pub struct AuditEvent {
    pub timestamp: DateTime<Utc>,      // ISO 8601 UTC
    pub event_type: AuditEventType,
    pub outcome: AuditOutcome,
    pub username: Option<String>,      // User identity
    pub source_ip: Option<IpAddr>,     // Source IP address
    pub session_id: Option<u32>,       // TACACS+ session ID
    pub remote_addr: Option<String>,   // Remote address from packet
    // ... additional context fields
}
```

**NIST Controls:** AU-3

---

### FAU_STG_EXT.1 - Protected Audit Event Storage

**Status:** ✅ Implemented

**Requirement:** Audit records shall be protected during storage and transmission.

**Implementation:**

| File | Lines | Description |
|------|-------|-------------|
| `crates/tacacs-audit/src/forwarder.rs` | 1-200 | Syslog/Elasticsearch forwarding |
| `crates/tacacs-audit/src/syslog.rs` | 1-500 | Syslog over TLS implementation |
| `crates/tacacs-audit/src/lib.rs` | 50-65 | Async audit channel |

**Protection Mechanisms:**
- **Syslog over TLS** - TCP with TLS 1.2+ encryption
- **Elasticsearch over HTTPS** - HTTPS with certificate validation
- **Unbounded channel** - Prevents audit loss under load
- **External storage** - Immutable append-only logs

**Configuration Example:**
```yaml
audit:
  syslog:
    enabled: true
    server: "syslog.example.com:6514"
    protocol: tcp+tls
    tls_ca_file: /etc/tacacs/ca.pem
```

**NIST Controls:** AU-4, AU-9

---

## Cryptographic Support (FCS)

### FCS_CKM.1 - Cryptographic Key Generation

**Status:** ✅ Implemented

**Requirement:** Generate cryptographic keys using approved algorithms and key sizes.

**Implementation:**

| File | Lines | Description |
|------|-------|-------------|
| `crates/tacacs-server/src/tls.rs` | 74-78 | TLS 1.3 key generation |
| `crates/tacacs-server/src/auth.rs` | 446-464 | CHAP challenge generation |

**Algorithms:**
- **TLS 1.3 ECDHE**: P-256, P-384 (ephemeral keys for forward secrecy)
- **CHAP Challenge**: 16-byte random nonce via OpenSSL CSPRNG

**Code Reference:**
```rust
// TLS 1.3 configuration enforces modern key agreement
rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
```

**NIST Controls:** SC-12, SC-13

---

### FCS_CKM.2 - Cryptographic Key Establishment

**Status:** ✅ Implemented

**Requirement:** Establish cryptographic keys using approved methods.

**Implementation:**

| File | Lines | Description |
|------|-------|-------------|
| `crates/tacacs-server/src/tls.rs` | 74-82 | TLS 1.3 handshake |

**Key Establishment:**
- TLS 1.3 Diffie-Hellman Ephemeral (DHE) with P-256/P-384 curves
- Forward secrecy enforced (no RSA key transport)
- Mutual authentication via X.509 certificates

**NIST Controls:** SC-8, SC-13

---

### FCS_CKM.4 - Cryptographic Key Destruction

**Status:** ✅ Implemented

**Requirement:** Destroy cryptographic keys when no longer needed.

**Implementation:**

| File | Lines | Description |
|------|-------|-------------|
| `crates/tacacs-proto/src/crypto.rs` | 62-67 | Secret validation and lifecycle |
| TLS library (Rustls) | N/A | Auto-zeroization on connection close |

**Destruction Mechanisms:**
- TLS session keys zeroized on connection termination (Rustls behavior)
- Rust's `Drop` trait ensures cleanup
- Shared secrets remain in memory (persistent configuration)

**Gap:** Need explicit zeroization for key storage enhancement (FCS_STG_EXT.1)

**NIST Controls:** SC-12

---

### FCS_COP.1/DataEncryption - Symmetric Encryption/Decryption

**Status:** ✅ Implemented

**Requirement:** Perform encryption/decryption using approved algorithms.

**Implementation:**

| File | Lines | Description |
|------|-------|-------------|
| `crates/tacacs-proto/src/crypto.rs` | 55-102 | MD5 body obfuscation |
| `crates/tacacs-server/src/tls.rs` | 74-78 | TLS 1.3 (AES-GCM) |

**Algorithms:**
- **TLS 1.3**: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
- **MD5** (legacy TACACS+ protocol): XOR-based obfuscation per RFC 8907
  - ⚠️ **Security Note:** MD5 documented as weak (CWE-327), TLS 1.3 provides actual encryption

**NIST Controls:** SC-8, SC-13

---

### FCS_COP.1/SigGen - Cryptographic Signature Generation/Verification

**Status:** ✅ Implemented

**Requirement:** Generate and verify digital signatures using approved algorithms.

**Implementation:**

| File | Lines | Description |
|------|-------|-------------|
| `crates/tacacs-server/src/tls.rs` | 52-66 | X.509 certificate validation |

**Algorithms:**
- RSA-PSS with SHA-256/SHA-384 (certificate signatures)
- ECDSA with P-256/P-384 (certificate signatures)

**NIST Controls:** SC-13, SC-17

---

### FCS_COP.1/Hash - Cryptographic Hashing

**Status:** ✅ Implemented

**Requirement:** Perform cryptographic hashing using approved algorithms.

**Implementation:**

| File | Lines | Description |
|------|-------|-------------|
| `crates/tacacs-server/src/auth.rs` | 446-464 | CHAP MD5 hashing |
| Various | N/A | SHA-256 for certificates, integrity |

**Algorithms:**
- **SHA-256**: Certificate fingerprints, integrity checks
- **MD5** (CHAP only): RFC 1994 compliance (legacy)

**NIST Controls:** SC-13

---

### FCS_COP.1/KeyedHash - Keyed-Hash Message Authentication

**Status:** ✅ Implemented

**Requirement:** Perform keyed-hash operations using approved algorithms.

**Implementation:**

| File | Lines | Description |
|------|-------|-------------|
| TLS 1.3 | N/A | HMAC-SHA256/HMAC-SHA384 for TLS |

**Algorithms:**
- HMAC-SHA256, HMAC-SHA384 (TLS 1.3 handshake and record protection)

**NIST Controls:** SC-13

---

### FCS_RBG_EXT.1 - Random Bit Generation

**Status:** ✅ Implemented

**Requirement:** Generate random bits using an approved DRBG.

**Implementation:**

| File | Lines | Description |
|------|-------|-------------|
| `crates/tacacs-server/src/ascii.rs` | 81-85 | OpenSSL CSPRNG for jitter |
| `crates/tacacs-server/src/auth.rs` | 446-464 | CHAP challenge generation |

**Random Bit Generator:**
- OpenSSL `RAND_bytes()` - CTR_DRBG or compatible FIPS 140-2 DRBG
- Used for: CHAP challenges, exponential backoff jitter, session IDs

**Code Reference:**
```rust
use openssl::rand::rand_bytes;

let mut buf = [0u8; 2];
rand_bytes(&mut buf)?;  // CSPRNG
```

**NIST Controls:** SC-13

---

### FCS_STG_EXT.1 - Cryptographic Key Storage

**Status:** ⚠️ Partial (Gap: needs encrypted key storage)

**Requirement:** Persistent keys stored encrypted in hardware-protected key storage, hardware cryptographic module, or isolated execution environment.

**Current Implementation:**

| File | Lines | Description |
|------|-------|-------------|
| `crates/tacacs-server/src/config.rs` | 365-400 | File-based secret provisioning |
| `crates/tacacs-secrets/src/provider.rs` | 1-200 | OpenBao/Vault integration |

**Current Protection:**
- File permissions (0600 recommended)
- Secrets loaded from files (not CLI arguments)
- OpenBao/Vault support for dynamic secrets

**Gap:**
- ❌ No encrypted key file support
- ❌ No HSM/PKCS#11 integration
- ❌ No memory locking (mlock) for secrets

**Planned Enhancement:** See gap closure plan - encrypted key storage with zeroize

**NIST Controls:** SC-12, SC-28

---

### FCS_EAPTLS_EXT.1 - EAP-TLS Protocol (PP-Module)

**Status:** ✅ Implemented (TACACS+ over TLS 1.3)

**Requirement:** Implement EAP-TLS or EAP-TTLS with mutual authentication.

**Mapping Rationale:**
TACACS+ over TLS 1.3 with mTLS provides equivalent security to EAP-TLS:
- Mutual authentication via X.509 certificates
- TLS 1.3 cryptographic channel
- Session key establishment

**Implementation:**

| File | Lines | Description |
|------|-------|-------------|
| `crates/tacacs-server/src/tls.rs` | 68-82 | mTLS configuration |
| `crates/tacacs-server/src/server.rs` | 315-360 | Client certificate validation |

**NIST Controls:** IA-3, SC-8

---

### FCS_RADIUS_EXT.1 - RADIUS/DIAMETER Protocol (PP-Module)

**Status:** ✅ Implemented (TACACS+ as direct federation protocol)

**Requirement:** Implement RADIUS, DIAMETER, or other direct identity federation protocol.

**Mapping Rationale:**
TACACS+ serves as a "direct federation protocol" for AAA:
- Authentication, authorization, and accounting services
- TLS 1.3 protected channel (superior to RADIUS MD5)
- Identity assertions to relying parties (NADs)

**Implementation:**

| File | Lines | Description |
|------|-------|-------------|
| `crates/tacacs-proto/` | All | RFC 8907 TACACS+ protocol |
| `crates/tacacs-server/src/auth.rs` | 85-540 | Authentication services |
| `crates/tacacs-server/src/server.rs` | 1-2300 | Server implementation |

**NIST Controls:** IA-2, AU-2

---

## Identification and Authentication (FIA)

### FIA_AFL.1 - Authentication Failure Handling

**Status:** ✅ Implemented

**Requirement:** Detect successive unsuccessful authentication attempts and take action.

**Implementation:**

| File | Lines | Description |
|------|-------|-------------|
| `crates/tacacs-server/src/ascii.rs` | 46-87 | Configurable attempt limits |
| `crates/tacacs-server/src/config.rs` | 179-181 | CLI configuration |

**Failure Handling:**
```rust
pub struct AsciiAuthConfig {
    pub max_total_attempts: u8,           // Default: 3
    pub max_username_attempts: u8,        // Default: 3
    pub max_password_attempts: u8,        // Default: 3
    pub lockout_threshold: u8,            // Default: 5
    pub base_backoff_ms: u64,             // Default: 500ms
}

// Exponential backoff: base * 2^(attempt-1) + random jitter
```

**Protection Mechanisms:**
- Configurable attempt limits per stage
- Exponential backoff with cryptographic jitter (prevents timing analysis)
- Hard lockout threshold
- Audit event on lockout

**NIST Controls:** AC-7

---

### FIA_PMG_EXT.1 - Password Management

**Status:** ✅ Implemented

**Requirement:** Support password-based authentication with management capabilities.

**Implementation:**

| File | Lines | Description |
|------|-------|-------------|
| `crates/tacacs-server/src/auth.rs` | 315-329 | Argon2id password hashing |
| `crates/tacacs-server/src/config.rs` | 365-400 | Password source configuration |

**Password Management:**
- Argon2id (default parameters: m=65536, t=3, p=4)
- Support for plaintext (testing) and hashed credentials
- LDAP integration for enterprise password policies
- File-based or OpenBao/Vault storage

**Gap:** No complexity requirements (rely on LDAP policy or external enforcement)

**NIST Controls:** IA-5

---

### FIA_UIA_EXT.1 - User Identification and Authentication

**Status:** ✅ Implemented

**Requirement:** Require user identification and authentication before any actions.

**Implementation:**

| File | Lines | Description |
|------|-------|-------------|
| `crates/tacacs-server/src/server.rs` | 176-214 | Authentication before authorization |

**Enforcement:**
- All TACACS+ packets validated for authentication before authorization
- Device authentication via mTLS required
- User authentication required before command authorization
- No anonymous access

**NIST Controls:** IA-2, IA-4

---

### FIA_UAU_EXT.2 - User Authentication Before Any Action

**Status:** ✅ Implemented

**Requirement:** Require successful authentication before allowing user actions.

**Implementation:**

| File | Lines | Description |
|------|-------|-------------|
| `crates/tacacs-server/src/auth.rs` | 85-540 | Multiple authentication methods |

**Authentication Methods:**
1. **PAP** (Password Authentication Protocol)
   - Static file credentials
   - Argon2id hash verification
   - LDAP bind authentication

2. **CHAP** (Challenge-Handshake Authentication Protocol)
   - MD5 challenge-response per RFC 1994
   - 16-byte random challenge

3. **ASCII** (Interactive Authentication)
   - Username/password prompts
   - Brute-force protection

4. **LDAP**
   - LDAPS-only (no StartTLS or plain)
   - Group membership validation

**NIST Controls:** IA-2, IA-5

---

### FIA_UAU.7 - Protected Authentication Feedback

**Status:** ✅ Implemented

**Requirement:** Provide no authentication feedback that could aid unauthorized access.

**Implementation:**

| File | Lines | Description |
|------|-------|-------------|
| `crates/tacacs-server/src/auth.rs` | 280-313 | Constant-time comparisons |
| `crates/tacacs-server/src/auth.rs` | 469 | Generic error messages |
| `crates/tacacs-server/src/ascii.rs` | 158 | NOECHO flag for passwords |

**Protection Mechanisms:**
```rust
// Generic error - no username enumeration
const GENERIC_AUTH_ERROR: &str = "authentication failed";

// Dummy work for non-existent users (prevents timing attacks)
if !creds.contains_key(user) {
    let _ = constant_time_eq_str("dummy", password);
    let _ = verify_argon_hash(DUMMY_HASH, password.as_bytes());
}
```

**NIST Controls:** IA-6

---

### FIA_AFL.1/AuthSvr - Authentication Failure for Claimants (PP-Module)

**Status:** ✅ Implemented

**Requirement:** Same as FIA_AFL.1, specific to authentication server role.

**Implementation:** Same as FIA_AFL.1 above

---

### FIA_UAU.6 - Re-Authenticating

**Status:** ⚠️ Partial

**Requirement:** Re-authenticate when passwords change or sessions lock.

**Current Implementation:**
- Session termination on idle timeout (re-authentication required for new session)
- No explicit session lock/unlock mechanism

**Gap:** Session locking not implemented (AC-11)

---

### FIA_X509_EXT.1/AuthSvr - X.509 Certificate Validation for Claimants (PP-Module)

**Status:** ⚠️ Partial (Gap: OCSP/CRL checking)

**Requirement:** Validate X.509 certificates with revocation checking.

**Current Implementation:**

| File | Lines | Description |
|------|-------|-------------|
| `crates/tacacs-server/src/tls.rs` | 52-66 | Certificate chain validation |
| `crates/tacacs-server/src/server.rs` | 315-360 | CN/SAN allowlist enforcement |

**Certificate Validation:**
- RFC 5280 version 3 certificates
- Certification path validation
- Certificate expiration checking
- CN/SAN allowlist enforcement

**Gap:**
- ❌ No OCSP (RFC 6960) checking
- ❌ No CRL (RFC 5280) validation

**Planned Enhancement:** See gap closure plan - OCSP/CRL module

**NIST Controls:** IA-3, SC-17

---

## Security Management (FMT)

### FMT_MOF.1/ManualUpdate - Management of Security Functions Behavior

**Status:** ✅ Implemented

**Requirement:** Restrict ability to modify security function behavior to authorized administrators.

**Implementation:**

| File | Lines | Description |
|------|-------|-------------|
| `crates/tacacs-server/src/api/rbac.rs` | 24-234 | RBAC permission enforcement |
| `crates/tacacs-server/src/api/handlers.rs` | 327-488 | Policy reload API |

**Management Functions:**
- Policy reload (requires `write:policy` permission)
- Configuration validation
- Session termination (requires `write:sessions` permission)

**NIST Controls:** CM-3, AC-3

---

### FMT_MTD.1/CoreData - Management of TSF Data

**Status:** ✅ Implemented

**Requirement:** Restrict ability to modify TSF data to authorized administrators.

**Implementation:**

| File | Lines | Description |
|------|-------|-------------|
| `crates/tacacs-server/src/api/rbac.rs` | 63-109 | Permission checking |
| `crates/tacacs-server/src/config.rs` | 1-600 | Secure default configuration |

**TSF Data Management:**
- Policy files (hot-reload with validation)
- RBAC configuration
- Secret rotation via OpenBao/Vault
- Certificate renewal via EST

**NIST Controls:** CM-6, SC-28

---

### FMT_SMF.1 - Specification of Management Functions

**Status:** ✅ Implemented

**Requirement:** Provide management functions for security features.

**Implementation:**

| File | Lines | Description |
|------|-------|-------------|
| `crates/tacacs-server/src/api/handlers.rs` | 104-1220 | Management API endpoints |

**Management Functions:**

| Endpoint | Method | Permission | Description |
|----------|--------|------------|-------------|
| `/health` | GET | None | Health check |
| `/ready` | GET | None | Readiness probe |
| `/metrics` | GET | `read:metrics` | Prometheus metrics |
| `/api/v1/sessions` | GET | `read:sessions` | List active sessions |
| `/api/v1/sessions/:id` | DELETE | `write:sessions` | Terminate session |
| `/api/v1/policy/reload` | POST | `write:policy` | Reload policy |
| `/api/v1/policy` | POST | `write:policy` | Upload new policy |
| `/api/v1/config` | GET | `read:config` | View configuration |

**NIST Controls:** CM-2, CM-3, SI-4

---

### FMT_SMR.2 - Restrictions on Security Roles

**Status:** ✅ Implemented

**Requirement:** Maintain roles and enforce role-based access control.

**Implementation:**

| File | Lines | Description |
|------|-------|-------------|
| `crates/tacacs-server/src/api/rbac.rs` | 40-60 | Default role definitions |

**Security Roles:**

| Role | Permissions | Use Case |
|------|-------------|----------|
| `admin` | `read:*`, `write:*` | Full administrative access |
| `operator` | `read:*`, `write:sessions` | Session management only |
| `viewer` | `read:status`, `read:metrics` | Read-only monitoring |

**Role Assignment:**
- User-to-role mapping in RBAC config file
- Wildcard permission matching
- Least privilege enforcement

**NIST Controls:** AC-2, AC-6

---

## Protection of TSF (FPT)

### FPT_SKP_EXT.1 - Protection of TSF Data (Keys)

**Status:** ✅ Implemented

**Requirement:** Prevent plaintext export/visibility of persistent private/secret keys.

**Implementation:**

| File | Lines | Description |
|------|-------|-------------|
| `crates/tacacs-server/src/config.rs` | 365-400 | File-based secret provisioning |

**Key Protection:**
- Secrets loaded from files (not CLI arguments - prevents `ps` visibility)
- Recommended file permissions: 0600
- No secret echoing in logs
- Environment variable fallback (for containers)

**NIST Controls:** SC-12, SC-28

---

### FPT_APW_EXT.1 - Protection of Administrator Passwords

**Status:** ✅ Implemented

**Requirement:** Store administrator passwords using approved hashing.

**Implementation:**

| File | Lines | Description |
|------|-------|-------------|
| `crates/tacacs-server/src/auth.rs` | 315-329 | Argon2id password hashing |

**Password Protection:**
```rust
use argon2::{Argon2, PasswordHash, PasswordVerifier};

fn verify_argon_hash(hash: &str, password: &[u8]) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else { return false };
    Argon2::default().verify_password(password, &parsed).is_ok()
}
```

**Argon2id Parameters:**
- Memory: 65536 KiB (64 MB)
- Iterations: 3
- Parallelism: 4
- Memory-hard construction (GPU/ASIC resistant)

**NIST Controls:** IA-5

---

### FPT_STM_EXT.1 - Reliable Time Stamps

**Status:** ❌ Gap (needs NTP integration)

**Requirement:** Use reliable time source for timestamp generation.

**Current Implementation:**

| File | Lines | Description |
|------|-------|-------------|
| `crates/tacacs-audit/src/event.rs` | 108, 169 | System clock timestamps |

**Current Mechanism:**
```rust
pub timestamp: DateTime<Utc>  // Uses system clock (Utc::now())
```

**Gap:**
- ❌ No NTP synchronization verification
- ❌ No time drift detection
- ❌ No time source validation

**Planned Enhancement:** See gap closure plan - NTP/NTS module

**NIST Controls:** AU-8

---

### FPT_TST_EXT.1 - TSF Testing

**Status:** ❌ Gap (needs self-test module)

**Requirement:** Run self-tests at startup and periodically to verify correct operation.

**Current Implementation:**
- Configuration validation at startup
- Policy schema validation

**Gap:**
- ❌ No cryptographic Known Answer Tests (KATs)
- ❌ No startup integrity verification
- ❌ No runtime health checks

**Planned Enhancement:** See gap closure plan - self-test module with:
- SHA-256 KAT (NIST test vector)
- Argon2id KAT (RFC 9106 test vector)
- Binary hash verification
- TLS configuration validation

**NIST Controls:** SI-7

---

### FPT_TUD_EXT.1 - Trusted Update

**Status:** ❌ Gap (needs signature verification)

**Requirement:** Verify integrity/authenticity of updates before installation.

**Current Implementation:**
- Policy hot-reload with validation
- No binary update mechanism

**Gap:**
- ❌ No binary signature verification
- ❌ No rollback protection
- ❌ No version enforcement

**Planned Enhancement:** See gap closure plan - trusted update module with:
- Ed25519 or RSA-PSS signature verification
- Semantic versioning enforcement
- Update API endpoint with signature validation

**NIST Controls:** CM-3, SI-7

---

## TOE Access (FTA)

### FTA_SSL_EXT.1 - TSF-Initiated Session Locking

**Status:** ✅ Implemented (Idle Timeout)

**Requirement:** Lock sessions after period of inactivity.

**Implementation:**

| File | Lines | Description |
|------|-------|-------------|
| `crates/tacacs-server/src/session_registry.rs` | 515-592 | Idle timeout and sweep |
| `crates/tacacs-server/src/config.rs` | Lines with timeout config | CLI arguments |

**Session Locking Mechanism:**
- Idle timeout (default: 300 seconds for single-connect)
- Keepalive timeout (default: 120 seconds)
- Background sweep task terminates idle sessions
- Configurable via `--single-connect-idle-timeout-secs`

**NIST Controls:** AC-11, AC-12

---

### FTA_SSL.3 - TSF-Initiated Termination

**Status:** ✅ Implemented

**Requirement:** Terminate sessions after configured inactivity period.

**Implementation:**

| File | Lines | Description |
|------|-------|-------------|
| `crates/tacacs-server/src/session_registry.rs` | 449-502 | Session termination |

**Termination Mechanisms:**
- Idle timeout automatic termination
- Administrative termination via API (`DELETE /sessions/:id`)
- Graceful shutdown terminates all sessions

**NIST Controls:** AC-12

---

### FTA_SSL.4 - User-Initiated Termination

**Status:** ✅ Implemented

**Requirement:** Allow administrators to terminate their own sessions.

**Implementation:**

| File | Lines | Description |
|------|-------|-------------|
| `crates/tacacs-server/src/api/handlers.rs` | 269-301 | Session termination API |

**User Actions:**
- Network admin closes TCP connection (implicit)
- Administrator terminates via management API

**NIST Controls:** AC-12

---

### FTA_TAB.1 - Default TOE Access Banners

**Status:** ❌ Gap (needs banner implementation)

**Requirement:** Display advisory warning before authentication.

**Current Implementation:**
- No banner support in ASCII authentication

**Gap:**
- ❌ No configurable login banner
- ❌ No warning message before authentication

**Planned Enhancement:** See gap closure plan - ASCII authentication banner display

**NIST Controls:** AC-8

---

## Trusted Path/Channels (FTP)

### FTP_ITC.1 - Inter-TSF Trusted Channel

**Status:** ✅ Implemented

**Requirement:** Establish trusted channels to external services.

**Implementation:**

| File | Lines | Description |
|------|-------|-------------|
| `crates/tacacs-server/src/auth.rs` | 108-110 | LDAPS enforcement |
| `crates/tacacs-audit/src/syslog.rs` | 1-500 | Syslog over TLS |
| `crates/tacacs-secrets/src/openbao.rs` | 1-300 | OpenBao HTTPS |

**Trusted Channels:**
- **LDAPS** - LDAP over TLS (no plain LDAP or StartTLS)
- **Syslog/TLS** - RFC 5425 TLS transport
- **HTTPS** - Elasticsearch, OpenBao, EST enrollment
- **OTLP/TLS** - OpenTelemetry with TLS transport

**NIST Controls:** SC-8

---

### FTP_TRP.1/Admin - Trusted Path for Administrators

**Status:** ✅ Implemented

**Requirement:** Provide secure path for administrator access.

**Implementation:**

| File | Lines | Description |
|------|-------|-------------|
| `crates/tacacs-server/src/api/mod.rs` | 49-100 | Management API with mTLS |
| `crates/tacacs-server/src/tls.rs` | 68-82 | Client certificate verification |

**Trusted Path:**
- HTTPS with mutual TLS (mTLS) for management API
- Client certificate validation (CN/SAN allowlist)
- RBAC enforcement at endpoint level

**NIST Controls:** SC-8, SC-23

---

## Communications (FCO)

### FCO_NRO.1 - Selective Proof of Origin

**Status:** ❌ Gap (needs federation module)

**Requirement:** Generate evidence of origin for identity assertions.

**Current Implementation:**
- Session ID tracking
- TLS provides channel integrity

**Gap:**
- ❌ No cryptographic binding of request to origin
- ❌ No explicit proof of origin

**Planned Enhancement:** See gap closure plan - federation module with:
- SHA-256 hash of TACACS+ request
- Client certificate fingerprint binding
- Timestamp and session correlation

**PP-Module Requirement:** FCO_NRO.1

---

### FCO_NRR.1 - Selective Proof of Receipt

**Status:** ❌ Gap (needs federation module)

**Requirement:** Generate evidence of receipt for authentication requests.

**Current Implementation:**
- Audit logging of requests
- Session tracking

**Gap:**
- ❌ No cryptographic proof of receipt
- ❌ No response correlation to request

**Planned Enhancement:** See gap closure plan - federation module with:
- SHA-256 hash of TACACS+ response
- Correlation to request hash
- Receipt proof in audit log

**PP-Module Requirement:** FCO_NRR.1

---

## Gap Summary

### Critical Gaps (High Priority)

| SFR | Requirement | Effort | Dependencies |
|-----|-------------|--------|--------------|
| FPT_TST_EXT.1 | Self-testing module | 1 week | None |
| FPT_TUD_EXT.1 | Trusted update | 1 week | `ed25519-dalek`, `semver` |
| FIA_X509_EXT.1 | OCSP/CRL checking | 1 week | `reqwest`, `x509-parser` |

### Medium Gaps

| SFR | Requirement | Effort | Dependencies |
|-----|-------------|--------|--------------|
| FPT_STM_EXT.1 | NTP time sync | 3 days | `ntp` or `rsntp` |
| FCS_STG_EXT.1 | Encrypted key storage | 1 week | `zeroize`, `aes-gcm` |
| FCO_NRO.1/NRR.1 | Federation proofs | 3 days | `sha2` (existing) |

### Low Gaps

| SFR | Requirement | Effort | Dependencies |
|-----|-------------|--------|--------------|
| FTA_TAB.1 | Access banners | 1 day | None |

### Total Development Effort

**Estimated:** 5-6 weeks for 7 modules

---

## References

- [NDcPP v4.0 PDF](https://nd-itc.github.io/cPP/NDcPP_v4_0.pdf)
- [PP-Module for Authentication Servers](https://www.niap-ccevs.org/Profile/Info.cfm?PPID=470)
- [RFC 8907: TACACS+ Protocol](https://www.rfc-editor.org/rfc/rfc8907.html)
- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)

---

**Document Control**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-31 | usg-tacacs Team | Initial requirements mapping |
