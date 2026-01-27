# NIST Control Usage Analysis

**Generated:** /Users/johnewillmanv/projects/usg-tacacs
**Files analyzed:** 62

## Summary

- **Total unique controls:** 37
- **Files with controls:** 35
- **Files with module headers:** 31
- **Files needing headers:** 4

## Top Files by Control Count

| File | Controls | Has Header | Refs | Lines |
|------|----------|------------|------|-------|
| crates/tacacs-server/src/server.rs | 16 | ✅ | 78 | 2859 |
| crates/tacacs-openssh/src/lib.rs | 12 | ✅ | 23 | 267 |
| crates/tacacs-client-tls/src/lib.rs | 9 | ✅ | 9 | 123 |
| crates/tacacs-server/src/auth.rs | 9 | ✅ | 30 | 1430 |
| crates/tacacs-server/src/api/mod.rs | 8 | ✅ | 13 | 151 |
| crates/tacacs-server/src/config.rs | 8 | ✅ | 16 | 2034 |
| crates/tacacs-server/src/session_registry.rs | 8 | ✅ | 32 | 957 |
| crates/tacacs-openssh/src/bin/authkeys.rs | 7 | ✅ | 16 | 298 |
| crates/tacacs-server/src/api/handlers.rs | 7 | ✅ | 24 | 1199 |
| crates/tacacs-server/src/main.rs | 7 | ❌ | 10 | 622 |
| crates/tacacs-audit/src/lib.rs | 6 | ✅ | 9 | 62 |
| crates/tacacs-server/src/tls.rs | 6 | ✅ | 18 | 461 |
| crates/tacacs-client-tls/src/authen.rs | 5 | ✅ | 10 | 581 |
| crates/tacacs-client-tls/src/tls.rs | 5 | ✅ | 12 | 274 |
| crates/tacacs-openssh/src/bin/pam_helper.rs | 5 | ✅ | 5 | 197 |

## Files Needing Formal Headers (Priority Order)

| Priority | File | Controls | Control IDs |
|----------|------|----------|-------------|
| 1 | crates/tacacs-server/src/main.rs | 7 | AC-10, AC-12, AC-3, CM-3, IA-5, ... (+2 more) |
| 2 | crates/tacacs-server/src/api/models.rs | 4 | AC-10, AU-12, AU-3, CM-3 |
| 3 | crates/tacacs-secrets/src/config.rs | 3 | CM-3, IA-5, SC-17 |
| 4 | crates/tacacs-client-tls/src/client.rs | 2 | SC-23, SC-8 |

## Control Family Distribution

| Family | Count |
|--------|-------|
| AC | 9 |
| AU | 8 |
| CM | 4 |
| IA | 6 |
| SC | 7 |
| SI | 3 |
