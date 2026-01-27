# NIST SP 800-53 Rev. 5 Header Template

**Version:** 1.0
**Date:** 2026-01-26
**Purpose:** Formal security control marking headers for source files

---

## Overview

This template provides a standardized format for documenting NIST SP 800-53 Rev. 5 security controls in Rust source files. The format combines:

1. **Human-readable documentation** (markdown tables)
2. **Machine-readable metadata** (JSON)
3. **Traceable references** (links to master mapping document)

---

## Template Structure

### Module-Level Header (File Top)

Add to the module docstring (after `//! <Module description>`):

```rust
// SPDX-License-Identifier: Apache-2.0

//! <Module description>
//!
//! # NIST SP 800-53 Rev. 5 Security Controls
//!
//! **Control Implementation Matrix**
//!
//! This module implements controls documented in
//! [NIST-CONTROLS-MAPPING.md](../../../docs/NIST-CONTROLS-MAPPING.md).
//!
//! | Control | Family | Status | Validated | Primary Functions |
//! |---------|--------|--------|-----------|-------------------|
//! | AC-3 | Access Control | Implemented | 2026-01-07 | [`enforce_access`] |
//! | AU-12 | Audit/Accountability | Implemented | 2026-01-07 | All functions |
//!
//! <details>
//! <summary><b>Validation Metadata (JSON)</b></summary>
//!
//! ```json
//! {
//!   "nist_framework": "NIST SP 800-53 Rev. 5",
//!   "software_version": "0.77.1",
//!   "last_validation": "2026-01-26",
//!   "control_families": ["AC", "AU"],
//!   "total_controls": 2,
//!   "file_path": "crates/tacacs-server/src/policy.rs"
//! }
//! ```
//!
//! </details>
//!
//! ## Control Details
//!
//! ### AC-3: Access Enforcement
//! - **Implementation:** Policy engine evaluates authorization rules with ordered precedence
//! - **Evidence:** Decision logging, regex pattern matching, last-match-wins semantics
//! - **Reference:** [AC-3 in Mapping](../../../docs/NIST-CONTROLS-MAPPING.md#ac-3-access-enforcement)
//!
//! ### AU-12: Audit Generation
//! - **Implementation:** All authorization decisions and errors logged via tracing
//! - **Evidence:** Structured audit events with peer, user, session_id, reason, detail
//! - **Reference:** [AU-12 in Mapping](../../../docs/NIST-CONTROLS-MAPPING.md#au-12-audit-generation)
```

### Function-Level Header (Existing Pattern - Enhanced)

Add to function docstrings:

```rust
/// Enforces authorization policy for command execution.
///
/// # NIST SP 800-53 Controls
///
/// | Control | Implementation | Validated |
/// |---------|----------------|-----------|
/// | AC-3 | Rule evaluation with precedence | 2026-01-07 |
/// | AU-12 | Decision logging via tracing | 2026-01-07 |
```

### Inline Markers (Existing Pattern - Preserved)

Keep existing inline markers:

```rust
// [NIST:AC-3] Normalize command before evaluation
let normalized_cmd = normalize_command(command);
```

---

## Control Families

| Code | Family Name |
|------|-------------|
| AC | Access Control |
| AU | Audit and Accountability |
| CM | Configuration Management |
| IA | Identification and Authentication |
| SC | System and Communications Protection |
| SI | System and Information Integrity |

---

## Status Values

| Status | Meaning |
|--------|---------|
| Implemented | Control fully implemented and tested |
| Partial | Control partially implemented |
| Planned | Control design complete, implementation pending |

---

## Validation Date Format

Use ISO 8601 date format: `YYYY-MM-DD`

Example: `2026-01-26`

---

## JSON Metadata Fields

### Required Fields

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `nist_framework` | string | Framework name and revision | `"NIST SP 800-53 Rev. 5"` |
| `software_version` | string | Software version validated against | `"0.77.1"` |
| `last_validation` | string | ISO 8601 date of last validation | `"2026-01-26"` |
| `control_families` | array | List of control family codes | `["AC", "AU"]` |
| `total_controls` | number | Count of controls in file | `2` |
| `file_path` | string | Relative path from repo root | `"crates/tacacs-server/src/policy.rs"` |

### Optional Fields

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `validation_method` | string | How controls were validated | `"Manual code review"` |
| `reviewer` | string | Who performed validation | `"Security team"` |
| `notes` | string | Additional context | `"Focused on authorization flow"` |

---

## Example: Simple File (1-2 Controls)

```rust
// SPDX-License-Identifier: Apache-2.0

//! Connection rate limiter for DoS protection.
//!
//! # NIST SP 800-53 Rev. 5 Security Controls
//!
//! **Control Implementation Matrix**
//!
//! This module implements controls documented in
//! [NIST-CONTROLS-MAPPING.md](../../../docs/NIST-CONTROLS-MAPPING.md).
//!
//! | Control | Family | Status | Validated | Primary Functions |
//! |---------|--------|--------|-----------|-------------------|
//! | AC-10 | Access Control | Implemented | 2026-01-26 | [`try_acquire`] |
//! | SC-7 | Sys/Comm Protection | Implemented | 2026-01-26 | [`try_acquire`] |
//!
//! <details>
//! <summary><b>Validation Metadata (JSON)</b></summary>
//!
//! ```json
//! {
//!   "nist_framework": "NIST SP 800-53 Rev. 5",
//!   "software_version": "0.77.1",
//!   "last_validation": "2026-01-26",
//!   "control_families": ["AC", "SC"],
//!   "total_controls": 2,
//!   "file_path": "crates/tacacs-server/src/limiter.rs"
//! }
//! ```
//!
//! </details>
//!
//! ## Control Details
//!
//! ### AC-10: Concurrent Session Control
//! - **Implementation:** Per-IP connection counting with configurable limit
//! - **Evidence:** HashMap tracking with atomic operations
//! - **Reference:** [AC-10 in Mapping](../../../docs/NIST-CONTROLS-MAPPING.md#ac-10-concurrent-session-control)
//!
//! ### SC-7: Boundary Protection
//! - **Implementation:** Connection exhaustion attack prevention
//! - **Evidence:** Rejects connections exceeding per-IP threshold
//! - **Reference:** [SC-7 in Mapping](../../../docs/NIST-CONTROLS-MAPPING.md#sc-7-boundary-protection)
```

---

## Example: Complex File (5+ Controls)

```rust
// SPDX-License-Identifier: Apache-2.0

//! TACACS+ authentication handler with multiple authentication methods.
//!
//! # NIST SP 800-53 Rev. 5 Security Controls
//!
//! **Control Implementation Matrix**
//!
//! This module implements controls documented in
//! [NIST-CONTROLS-MAPPING.md](../../../docs/NIST-CONTROLS-MAPPING.md).
//!
//! | Control | Family | Status | Validated | Primary Functions |
//! |---------|--------|--------|-----------|-------------------|
//! | IA-2 | Ident/Authentication | Implemented | 2026-01-26 | [`verify_pap`], [`handle_chap_continue`] |
//! | IA-5 | Authenticator Mgmt | Implemented | 2026-01-26 | [`verify_password_sources`] |
//! | IA-6 | Authenticator Feedback | Implemented | 2026-01-26 | All authentication functions |
//! | AC-7 | Unsuccessful Logon | Implemented | 2026-01-26 | [`calc_ascii_backoff_capped`] |
//! | AU-12 | Audit Generation | Implemented | 2026-01-26 | All functions |
//!
//! <details>
//! <summary><b>Validation Metadata (JSON)</b></summary>
//!
//! ```json
//! {
//!   "nist_framework": "NIST SP 800-53 Rev. 5",
//!   "software_version": "0.77.1",
//!   "last_validation": "2026-01-26",
//!   "control_families": ["IA", "AC", "AU"],
//!   "total_controls": 5,
//!   "file_path": "crates/tacacs-server/src/auth.rs"
//! }
//! ```
//!
//! </details>
//!
//! ## Control Details
//!
//! ### IA-2: Identification and Authentication (Organizational Users)
//! - **Implementation:** PAP (plaintext), CHAP (challenge-response), ASCII (interactive) authentication
//! - **Evidence:** Password verification against static credentials and LDAP
//! - **Reference:** [IA-2 in Mapping](../../../docs/NIST-CONTROLS-MAPPING.md#ia-2-identification-and-authentication-organizational-users)
//!
//! ### IA-5: Authenticator Management
//! - **Implementation:** Argon2id password hashing with timing-attack protection
//! - **Evidence:** Constant-time comparison, password strength via hash parameters
//! - **Reference:** [IA-5 in Mapping](../../../docs/NIST-CONTROLS-MAPPING.md#ia-5-authenticator-management)
//!
//! ### IA-6: Authenticator Feedback
//! - **Implementation:** Generic error messages prevent username enumeration
//! - **Evidence:** "authentication failed" for all error paths (CWE-209)
//! - **Reference:** [IA-6 in Mapping](../../../docs/NIST-CONTROLS-MAPPING.md#ia-6-authenticator-feedback)
//!
//! ### AC-7: Unsuccessful Logon Attempts
//! - **Implementation:** Exponential backoff with capped delay after failed attempts
//! - **Evidence:** Per-session attempt tracking, sleep delays
//! - **Reference:** [AC-7 in Mapping](../../../docs/NIST-CONTROLS-MAPPING.md#ac-7-unsuccessful-logon-attempts)
//!
//! ### AU-12: Audit Generation
//! - **Implementation:** All authentication events logged with user, method, result
//! - **Evidence:** Structured audit_event calls with reason and detail
//! - **Reference:** [AU-12 in Mapping](../../../docs/NIST-CONTROLS-MAPPING.md#au-12-audit-generation)
```

---

## Markdown Link Format

### Internal Repository Links

```rust
[NIST-CONTROLS-MAPPING.md](../../../docs/NIST-CONTROLS-MAPPING.md)
```

**Path calculation:**
- From `crates/tacacs-server/src/file.rs` → `../../../docs/`
- From `crates/tacacs-policy/src/file.rs` → `../../../docs/`
- From `src/file.rs` (workspace root) → `docs/`

### Control-Specific Anchors

```rust
[AC-3 in Mapping](../../../docs/NIST-CONTROLS-MAPPING.md#ac-3-access-enforcement)
```

**Anchor format:** `#<lowercase-control-id>-<kebab-case-title>`

Examples:
- `#ac-3-access-enforcement`
- `#ia-2-identification-and-authentication-organizational-users`
- `#au-12-audit-generation`

---

## Maintenance Guidelines

### When to Update Validation Date

Update `last_validation` when:
1. Code implementing the control is modified
2. New controls are added to the file
3. Periodic re-validation is performed (quarterly recommended)

### When to Update Control List

Update the control matrix when:
1. New functionality implements additional controls
2. Control implementation is refactored to different files
3. Controls are deprecated or removed

### Version Tracking

Update `software_version` in JSON metadata when:
1. A new release includes control implementation changes
2. During release preparation (e.g., 0.77.1 → 0.78.0)

---

## Automation Support

### JSON Extraction Pattern

Scripts can extract metadata using regex:

```regex
```json\n(.*?)\n```
```

Then parse as JSON for validation.

### Control Extraction Pattern

Scripts can extract control list using:

```regex
\| ([A-Z]{2}-[0-9]+) \| (.*?) \| (Implemented|Partial|Planned) \| ([0-9]{4}-[0-9]{2}-[0-9]{2}) \| (.*?) \|
```

Captures:
1. Control ID (e.g., `AC-3`)
2. Family name
3. Status
4. Validation date
5. Primary functions

---

## Benefits

### For Developers
- Clear documentation of security requirements
- Easy to locate control implementations
- Linked to master control mapping

### For Auditors
- Machine-readable validation metadata
- Traceability to control framework
- Timestamped validation records

### For Compliance
- Formal control marking per NIST guidelines
- Consistent documentation format
- Version-tracked control implementation

---

## References

- **NIST SP 800-53 Rev. 5:** https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
- **Master Controls Mapping:** `/docs/NIST-CONTROLS-MAPPING.md`
- **NASA Power of 10 Rule #11:** Formal control markings for critical software

---

**Template Version:** 1.0
**Last Updated:** 2026-01-26
**Maintainer:** usg-tacacs project team
