# Security Policy

## Supported Versions

We actively maintain and provide security updates for the following versions:

| Version | Supported          | Status             |
| ------- | ------------------ | ------------------ |
| 0.77.x  | :white_check_mark: | Current (Security) |
| 0.76.x  | :white_check_mark: | Previous           |
| < 0.76  | :x:                | End of Life        |

**Note**: Version 0.77.0 is a **security release** addressing 13 vulnerabilities and 3 RUSTSEC advisories.

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in usg-tacacs, please report it responsibly.

### How to Report

**Please DO NOT open public GitHub issues for security vulnerabilities.**

Instead, report security issues via:

1. **Email**: Send details to the maintainers (check repository for contact info)
2. **Private GitHub Security Advisory**: Use GitHub's "Report a vulnerability" feature in the Security tab
3. **GPG Encrypted Email**: For highly sensitive issues, request our GPG public key first

### What to Include

Please include the following information in your report:

- **Description**: Clear description of the vulnerability
- **Impact**: What could an attacker accomplish?
- **Affected versions**: Which versions are vulnerable?
- **Proof of Concept**: Steps to reproduce (if possible)
- **Suggested fix**: If you have one (optional)
- **Your contact information**: For follow-up questions

### Response Timeline

- **Initial Response**: Within 48 hours of receipt
- **Triage & Assessment**: Within 7 days
- **Fix Development**: Varies by severity (1-30 days)
- **Security Advisory**: Published with fix release
- **Public Disclosure**: After patch is available (coordinated disclosure)

### Severity Levels

We follow CVSS 3.1 scoring for severity assessment:

| Severity | CVSS Score | Response Time |
|----------|------------|---------------|
| CRITICAL | 9.0-10.0   | 1-3 days      |
| HIGH     | 7.0-8.9    | 7-14 days     |
| MEDIUM   | 4.0-6.9    | 14-30 days    |
| LOW      | 0.1-3.9    | 30-90 days    |

## Security Advisories

### 0.77.0 Security Release (2026-01-12)

**Summary**: Comprehensive security hardening addressing 13 vulnerabilities and 3 RUSTSEC advisories.

**RUSTSEC Advisories Resolved**:
- [RUSTSEC-2025-0134](https://rustsec.org/advisories/RUSTSEC-2025-0134): `rustls-pemfile` unmaintained → migrated to `rustls-pki-types`
- [RUSTSEC-2025-0012](https://rustsec.org/advisories/RUSTSEC-2025-0012): `backoff` unmaintained → migrated to `backon`
- [RUSTSEC-2024-0384](https://rustsec.org/advisories/RUSTSEC-2024-0384): `instant` unmaintained (transitive dependency)

**Critical Vulnerabilities Fixed**:
1. **Retry Logic Off-by-One Error** (CRITICAL)
   - **CVE**: Pending
   - **Impact**: Infinite loop risk, one extra retry attempt
   - **Fix**: Corrected loop counter initialization and increment timing
   - **Commit**: 1e9b2ee

2. **TOCTOU Race in Token Refresh** (CRITICAL)
   - **CVE**: Pending
   - **Impact**: Thundering herd, multiple simultaneous authentication attempts
   - **Fix**: Double-checked locking with write lock protection
   - **Commit**: 1e9b2ee

**High Severity Vulnerabilities Fixed**:
None

**Medium Severity Vulnerabilities Fixed**:
3. **Fragile Retry Error Detection** (MEDIUM)
   - **Impact**: Incorrect retry behavior on transient failures
   - **Fix**: Structured error type checking with `downcast_ref::<reqwest::Error>()`
   - **Commit**: 1e9b2ee

4. **Empty TLS Certificate Files Accepted** (MEDIUM)
   - **Impact**: Server could start with invalid TLS configuration
   - **Fix**: Explicit validation rejecting empty certificate files
   - **Commit**: 1e9b2ee

5. **CHAP ID Validation Bypass** (MEDIUM)
   - **Impact**: Authentication bypass if CHAP ID not set
   - **Fix**: Mandatory CHAP ID validation, returns ERROR if missing
   - **Commit**: 6a11a22

6. **Unsafe `register_connection()` Method** (MEDIUM)
   - **Impact**: Session limit bypass through deprecated method
   - **Fix**: Deprecated method, forced migration to `try_register_connection()`
   - **Commit**: 6a11a22

7. **Information Disclosure in OpenBao Errors** (MEDIUM)
   - **Impact**: Internal paths/architecture revealed in error messages
   - **Fix**: Error sanitization, detailed logging only internally
   - **Commit**: 6a11a22

8. **Production `.unwrap()` Calls** (MEDIUM)
   - **Impact**: Service crashes on unexpected None values
   - **Fix**: Replaced with proper error handling using `.context()`
   - **Commit**: cd61482

9. **Clock-Sensitive `elapsed()` in Session Registry** (MEDIUM)
   - **Impact**: Panic on system clock changes (NTP adjustments)
   - **Fix**: Replaced with `duration_since()` for robustness
   - **Commit**: cd61482

10. **Clock-Sensitive `elapsed()` in Metrics** (MEDIUM)
    - **Impact**: Panic on system clock changes during metrics collection
    - **Fix**: Replaced with `saturating_duration_since()`
    - **Commit**: aa345e6

**Low Severity Issues Fixed**:
11. **Certificate IP Parsing Bounds Check** (LOW)
    - **Impact**: Potential panic on invalid certificate SAN lengths
    - **Fix**: Safe `try_from()` conversion with error handling
    - **Commit**: 6a11a22

12. **Session Sweep Integer Overflow** (LOW)
    - **Impact**: Counter overflow on extremely long uptime
    - **Fix**: Saturating arithmetic with `saturating_add()`
    - **Commit**: 6a11a22

13. **Test-Only Panic Macro** (LOW)
    - **Impact**: None (test code only)
    - **Status**: Acceptable - intentional test failure indicator

**Upgrade Recommendation**: **IMMEDIATE** - All users should upgrade to 0.77.0 as soon as possible.

**Breaking Changes**: None - fully backward compatible.

## Security Architecture

### Defense in Depth

usg-tacacs implements multiple layers of security:

1. **TLS 1.3 with mTLS** - Mandatory mutual authentication on TCP/300
2. **Client Certificate Allowlists** - CN and SAN-based access control
3. **LDAP Injection Prevention** - RFC 4515 compliant escaping
4. **Timing Attack Protection** - Constant-time password comparisons
5. **Username Enumeration Protection** - Dummy Argon2 verification for non-existent users
6. **Rate Limiting** - Per-IP connection limits and authentication backoff
7. **Session Management** - Atomic limit enforcement with race condition protection
8. **Saturating Arithmetic** - Overflow protection throughout
9. **Memory Safety** - Zero `unsafe` blocks in production code

### NIST SP 800-53 Controls

See [SECURITY_CONTROLS.md](SECURITY_CONTROLS.md) for comprehensive NIST control mappings including:

- **AC-10**: Concurrent Session Control
- **AC-12**: Session Termination
- **IA-5**: Authenticator Management (Argon2id)
- **IA-6**: Authenticator Feedback (timing attack protection)
- **SC-8**: Transmission Confidentiality (TLS 1.3, LDAPS-only)
- **SC-13**: Cryptographic Protection (constant-time comparisons)
- **SI-10**: Information Input Validation (LDAP escaping, RFC validation)
- **SI-11**: Error Handling (saturating arithmetic, safe unwrapping)
- **SI-16**: Memory Protection (zero unsafe code)

### Security Hardening

**Required for Production**:
- Enable TLS 1.3 on TCP/300 (`--listen-tls`)
- Use `--forbid-unencrypted` flag (default: true)
- Configure client certificate allowlists (CN or SAN)
- Use strong TACACS+ shared secrets (min 8 chars) for legacy support
- Enable session limits (`--max-connections-per-ip`)

**Recommended**:
- Use LDAPS for authentication (not plain LDAP)
- Enable Argon2id password hashing
- Deploy behind HAProxy with rate limiting
- Monitor metrics for authentication failures
- Enable audit logging with UTC timestamps
- Use EST (RFC 7030) for automated certificate rotation

**Avoid**:
- Legacy TACACS+ on TCP/49 without TLS (use for backward compatibility only)
- Plain LDAP authentication (use LDAPS)
- Reusing TACACS+ shared secrets
- Empty or weak shared secrets
- Disabling `--forbid-unencrypted`

## Security Testing

### Continuous Security

- **Dependency Scanning**: `cargo audit` in CI/CD
- **Static Analysis**: `cargo clippy` with strict lints
- **Fuzzing**: Protocol parsing fuzzing (planned)
- **Penetration Testing**: Annual third-party security audits (recommended)

### Known Limitations

1. **MD5 Usage for TACACS+ Obfuscation**
   - **Status**: Acceptable - RFC 8907 requirement
   - **Mitigation**: TLS 1.3 mandatory, MD5 only for XOR pad generation
   - **Context**: Not used for password hashing or authentication

2. **LDAP Group Enumeration**
   - **Status**: By design - required for authorization
   - **Mitigation**: LDAPS-only, service account with minimal permissions

3. **Transitive Dependencies**
   - **Status**: Monitoring via `cargo audit`
   - **Action**: Update dependencies regularly

## Secure Configuration Examples

### Minimal TLS-Only Configuration

```bash
usg-tacacs-server \
  --listen-tls 0.0.0.0:300 \
  --tls-cert /etc/tacacs/server.crt \
  --tls-key /etc/tacacs/server.key \
  --client-ca /etc/tacacs/client-ca.crt \
  --tls-allowed-client-san "device01.example.com" \
  --tls-allowed-client-san "device02.example.com" \
  --forbid-unencrypted \
  --max-connections-per-ip 10 \
  --policy /etc/tacacs/policy.json
```

### LDAPS Authentication

```bash
usg-tacacs-server \
  --listen-tls 0.0.0.0:300 \
  --tls-cert /etc/tacacs/server.crt \
  --tls-key /etc/tacacs/server.key \
  --client-ca /etc/tacacs/client-ca.crt \
  --ldaps-url ldaps://ldap.example.com:636 \
  --ldap-bind-dn "cn=tacacs-svc,ou=services,dc=example,dc=com" \
  --ldap-bind-password-file /etc/tacacs/ldap-password \
  --ldap-search-base "ou=users,dc=example,dc=com" \
  --ldap-required-group "cn=network-admins,ou=groups,dc=example,dc=com" \
  --policy /etc/tacacs/policy.json
```

### EST Certificate Provisioning

```bash
usg-tacacs-server \
  --listen-tls 0.0.0.0:300 \
  --client-ca /etc/tacacs/client-ca.crt \
  --est-enabled \
  --est-server-url https://est.example.com/.well-known/est \
  --est-username bootstrap \
  --est-password-file /etc/tacacs/est-password \
  --est-common-name tacacs-01.internal \
  --est-renewal-threshold 70 \
  --policy /etc/tacacs/policy.json
```

## Disclosure Policy

We follow **coordinated disclosure**:

1. **Private Report**: Security researcher reports issue privately
2. **Acknowledgment**: We acknowledge receipt within 48 hours
3. **Fix Development**: We develop and test a fix
4. **Coordinated Release**: We coordinate release timing with reporter
5. **Public Advisory**: We publish advisory with fix release
6. **CVE Assignment**: We request CVE IDs for qualifying vulnerabilities
7. **Credit**: We credit reporters in SECURITY.md and release notes

**Embargo Period**: Typically 90 days from initial report, negotiable based on severity and complexity.

## Security Hall of Fame

We recognize and thank security researchers who responsibly disclose vulnerabilities:

- *Your name could be here!*

## Contact

- **Security Email**: (See repository for current contact)
- **GitHub Security Advisories**: Use "Report a vulnerability" button
- **Response Time**: Within 48 hours

## Additional Resources

- [SECURITY_CONTROLS.md](SECURITY_CONTROLS.md) - NIST SP 800-53 control mappings
- [SECURITY_RECOMMENDATIONS.md](SECURITY_RECOMMENDATIONS.md) - Deployment best practices
- [docs/tls.md](docs/docs/tls.md) - TLS configuration guide
- [docs/est-provisioning.md](docs/docs/est-provisioning.md) - EST certificate provisioning

---

**Last Updated**: 2026-01-12 (Version 0.77.0 Security Release)
