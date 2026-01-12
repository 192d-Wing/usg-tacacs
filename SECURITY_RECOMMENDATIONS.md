# Security Hardening Recommendations

**Project:** usg-tacacs TACACS+ Server
**Date:** 2026-01-11

## Quick Implementation Guide

This document provides actionable security enhancements prioritized by impact and implementation complexity.

---

## Priority 1: Critical Security Enhancements

### 1.1 Add Certificate Revocation Checking (CRL/OCSP)

**Impact:** HIGH | **Complexity:** MEDIUM | **NIST:** IA-3, SC-17

**Current Gap:** No revocation checking for client certificates

**Implementation:**

```rust
// In tls.rs or new revocation.rs module
use x509_parser::revocation_list::RevocationList;

pub async fn check_certificate_revocation(
    cert: &X509,
    crl_url: Option<&str>,
) -> Result<(), RevocationError> {
    // Fetch and validate CRL
    // Check certificate serial against revocation list
    // Add OCSP stapling support
}
```

**Benefits:**

- Immediately invalidate compromised certificates
- Comply with PKI best practices
- Prevent unauthorized access from stolen credentials

---

### 1.2 Implement Structured Audit Logging

**Impact:** HIGH | **Complexity:** LOW | **NIST:** AU-2, AU-3, AU-12

**Current Gap:** Logs are text-based, difficult to parse programmatically

**Implementation:**

```rust
// Add structured logging with serde
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::Layer;

pub fn init_structured_logging(format: LogFormat) {
    match format {
        LogFormat::Json => {
            tracing_subscriber::fmt()
                .json()
                .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
                .init();
        }
        // ... existing formats
    }
}

// Add structured event types
#[derive(Debug, Serialize)]
pub struct AuthenticationEvent {
    pub timestamp: SystemTime,
    pub event_type: &'static str,
    pub username: String,
    pub source_ip: IpAddr,
    pub success: bool,
    pub method: &'static str,
}
```

**Benefits:**

- Enable SIEM integration
- Facilitate compliance audits
- Improve incident response capabilities

---

### 1.3 Add Global Account Lockout Tracking

**Impact:** HIGH | **Complexity:** MEDIUM | **NIST:** AC-7

**Current Gap:** Per-session tracking only, persistent attackers can retry

**Implementation:**

```rust
// New module: lockout.rs
use std::collections::HashMap;
use std::time::{SystemTime, Duration};
use tokio::sync::RwLock;

pub struct AccountLockout {
    failures: RwLock<HashMap<String, FailureTracker>>,
    lockout_threshold: u32,
    lockout_duration: Duration,
}

struct FailureTracker {
    count: u32,
    first_failure: SystemTime,
    locked_until: Option<SystemTime>,
}

impl AccountLockout {
    pub async fn record_failure(&self, username: &str) -> LockoutStatus {
        // Track failures across sessions
        // Implement time-based decay
        // Return locked/unlocked status
    }

    pub async fn is_locked(&self, username: &str) -> bool {
        // Check if account is currently locked
    }
}
```

**Benefits:**

- Prevent distributed brute-force attacks
- Protect against credential stuffing
- Complement existing per-session limits

---

## Priority 2: Important Enhancements

### 2.1 Add Configuration Validation Tool

**Impact:** MEDIUM | **Complexity:** LOW | **NIST:** CM-2, CM-6

**Current Gap:** No pre-deployment validation

**Implementation:**

```rust
// In config.rs or new validate.rs
pub fn validate_configuration(args: &Args) -> Result<ValidationReport> {
    let mut report = ValidationReport::new();

    // Check TLS certificate validity
    if let Some(cert_path) = &args.tls_cert {
        report.add(validate_certificate(cert_path)?);
    }

    // Check secret file permissions
    if let Some(secret_path) = &args.secret_file {
        report.add(validate_file_permissions(secret_path, 0o600)?);
    }

    // Validate RBAC configuration
    if let Some(rbac_path) = &args.api_rbac_config {
        report.add(validate_rbac_config(rbac_path)?);
    }

    // Check policy file syntax
    report.add(validate_policy(&args.policy)?);

    Ok(report)
}
```

**Benefits:**

- Catch misconfigurations before deployment
- Reduce production incidents
- Provide clear guidance on fixes

---

### 2.2 Add Certificate Expiration Monitoring

**Impact:** MEDIUM | **Complexity:** LOW | **NIST:** SC-17

**Current Gap:** No proactive expiration alerting

**Implementation:**

```rust
// In tls.rs
pub struct CertificateMonitor {
    cert_path: PathBuf,
    warning_days: u64,
}

impl CertificateMonitor {
    pub async fn check_expiration(&self) -> Result<ExpirationStatus> {
        let cert = load_certificate(&self.cert_path)?;
        let not_after = cert.not_after();
        let days_until_expiry = calculate_days_until(not_after);

        if days_until_expiry <= self.warning_days {
            warn!(
                days_remaining = days_until_expiry,
                "Certificate expiring soon"
            );
            return Ok(ExpirationStatus::Warning(days_until_expiry));
        }

        Ok(ExpirationStatus::Valid)
    }

    pub async fn run_monitoring_task(&self, interval: Duration) {
        loop {
            sleep(interval).await;
            if let Err(e) = self.check_expiration().await {
                error!(error = %e, "Certificate check failed");
            }
        }
    }
}
```

**Benefits:**

- Prevent outages from expired certificates
- Enable proactive renewal
- Improve operational awareness

---

### 2.3 Add IP-Based Access Control

**Impact:** MEDIUM | **Complexity:** LOW | **NIST:** SC-7

**Current Gap:** No IP allowlist/blocklist capability

**Implementation:**

```rust
// New module: ip_filter.rs
use std::net::IpAddr;
use ipnet::IpNet;

pub struct IpFilter {
    allowlist: Vec<IpNet>,
    blocklist: Vec<IpNet>,
    mode: FilterMode,
}

pub enum FilterMode {
    AllowlistOnly,  // Default deny, allow specific IPs
    BlocklistOnly,  // Default allow, block specific IPs
    Combined,       // Check blocklist first, then allowlist
}

impl IpFilter {
    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        match self.mode {
            FilterMode::AllowlistOnly => {
                self.allowlist.iter().any(|net| net.contains(&ip))
            }
            FilterMode::BlocklistOnly => {
                !self.blocklist.iter().any(|net| net.contains(&ip))
            }
            FilterMode::Combined => {
                !self.blocklist.iter().any(|net| net.contains(&ip))
                    && self.allowlist.iter().any(|net| net.contains(&ip))
            }
        }
    }
}
```

**Benefits:**

- Block known malicious IPs
- Restrict access to trusted networks
- Layer defense in depth

---

## Priority 3: Nice-to-Have Features

### 3.1 Add Prometheus Alerting Rules

**Impact:** LOW | **Complexity:** LOW | **NIST:** SI-4

**Implementation:**

Create `alerts.yml`:

```yaml
groups:
  - name: tacacs_security
    interval: 30s
    rules:
      - alert: HighAuthenticationFailureRate
        expr: rate(authn_failure_total[5m]) > 0.1
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High authentication failure rate detected"

      - alert: SessionLimitApproached
        expr: sessions_active / max_total_sessions > 0.9
        for: 5m
        labels:
          severity: warning

      - alert: SuspiciousBruteForce
        expr: sum(rate(authn_failure_total[1m])) by (source_ip) > 1
        for: 1m
        labels:
          severity: critical
```

---

### 3.2 Add Password Complexity Requirements

**Impact:** LOW | **Complexity:** LOW | **NIST:** IA-5

**Implementation:**

```rust
// In auth.rs or new password_policy.rs
pub struct PasswordPolicy {
    min_length: usize,
    require_uppercase: bool,
    require_lowercase: bool,
    require_digits: bool,
    require_special: bool,
}

impl PasswordPolicy {
    pub fn validate(&self, password: &str) -> Result<(), PasswordError> {
        if password.len() < self.min_length {
            return Err(PasswordError::TooShort);
        }

        if self.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
            return Err(PasswordError::MissingUppercase);
        }

        // ... additional checks

        Ok(())
    }
}
```

---

### 3.3 Add Session Token Rotation

**Impact:** LOW | **Complexity:** MEDIUM | **NIST:** SC-23

**Implementation:**

```rust
// In session_registry.rs
impl SessionRegistry {
    pub async fn rotate_session_id(
        &self,
        connection_id: u64,
    ) -> Result<u32, SessionError> {
        let mut sessions = self.sessions.write().await;

        if let Some(record) = sessions.get_mut(&connection_id) {
            let new_session_id = generate_session_id();
            let old_session_id = record.session_id;
            record.session_id = Some(new_session_id);

            info!(
                connection_id = connection_id,
                old_session = ?old_session_id,
                new_session = new_session_id,
                "session ID rotated"
            );

            Ok(new_session_id)
        } else {
            Err(SessionError::NotFound)
        }
    }
}
```

---

## Implementation Roadmap

### Phase 1: Critical Security (2-3 weeks)

- [ ] Structured audit logging (1 week)
- [ ] Global account lockout (1 week)
- [ ] Configuration validation tool (3 days)

### Phase 2: Operational Security (2-3 weeks)

- [ ] Certificate expiration monitoring (3 days)
- [ ] Certificate revocation checking (1 week)
- [ ] IP-based access control (3 days)

### Phase 3: Advanced Features (1-2 weeks)

- [ ] Prometheus alerting rules (2 days)
- [ ] Password complexity requirements (2 days)
- [ ] Session token rotation (3 days)

---

## Testing Requirements

For each enhancement, implement:

1. **Unit tests** - Test core logic in isolation
2. **Integration tests** - Test end-to-end behavior
3. **Security tests** - Verify security properties
4. **Performance tests** - Ensure no significant overhead

Example test structure:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_lockout_threshold() {
        // Verify lockout after N failures
    }

    #[tokio::test]
    async fn test_lockout_expiration() {
        // Verify lockout expires after duration
    }

    #[test]
    fn test_lockout_prevents_authentication() {
        // Verify locked accounts cannot authenticate
    }
}
```

---

## Monitoring and Metrics

Add metrics for new features:

```rust
// In metrics.rs
pub struct SecurityMetrics {
    // Account lockout
    pub accounts_locked: IntGauge,
    pub lockout_events_total: IntCounter,

    // Certificate monitoring
    pub cert_days_until_expiry: IntGauge,
    pub cert_validation_errors_total: IntCounter,

    // IP filtering
    pub ip_filter_blocks_total: IntCounterVec, // by reason
    pub ip_filter_allows_total: IntCounter,
}
```

---

## Documentation Requirements

For each feature, document:

1. **Configuration** - How to enable and configure
2. **Operation** - How it works in production
3. **Troubleshooting** - Common issues and solutions
4. **Security implications** - What it protects against

---

## Backwards Compatibility

Ensure all enhancements:

- Default to current behavior when not configured
- Provide migration guides for breaking changes
- Maintain API compatibility where possible
- Document any deprecated features with timelines

---

## Success Criteria

Each enhancement should:

- ✅ Pass all security tests
- ✅ Have >80% test coverage
- ✅ Include comprehensive documentation
- ✅ Add <5% performance overhead
- ✅ Integrate with existing metrics/logging
- ✅ Follow existing code patterns
