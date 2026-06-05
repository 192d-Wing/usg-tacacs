# USG TACACS+ Roadmap

## Device Flow Testing & Hardening

Post-implementation validation for the RFC 8628 device authorization grant
feature gate (`--icam-device-flow`) and related single-connect fixes.

### Immediate / High Risk

- [x] **#1 Policy schema** — added `shell_start_groups` to all three copies of
  `policy.schema.json`; `--check-policy` validates clean against the live policy.
  Cluster configmap updated.

- [x] **#3 Single-connect accounting** — removed cross-transaction session-id
  comparison from `validate_acct_single_connect` (same RFC 8907 fix as authz).

- [x] **#2 ROPC regression** — PAP auth reaches ICAM ROPC unaffected; device
  flow is ASCII-only and did not intercept the PAP path.

### Device Flow Behavior

- [x] **#4 Max polls exhaustion** — FAIL delivered on press 49 (`max_polls=48`
  enforced), message: "device authorization timed out".

- [x] **#5 Device code expiry** — ICAM returns `invalid_grant` / "Device code
  not valid" for invalid/expired codes; `interpret_poll_response` maps this to
  `Denied → FAIL` with a clean message.

- [x] **#6 Concurrent sessions** — two simultaneous ASCII logins from the same
  NAD each received independent device_codes (PFBM-ZATF ≠ GUPZ-DPOV); sessions
  are completely isolated at both the server and ICAM level.

### Authorization Correctness

- [x] **#7 Group-based priv-lvl** — `operator` (member of `netops`) receives
  `priv-lvl=15` in shell-start authz reply via `shell_start_groups` lookup.

- [x] **#8 Command authz with groups** — `show version` → PASS_REPL (allow-show),
  `configure terminal` → FAIL (deny-config); group context flows correctly
  through single-connect into command authz decisions.

### Regression

- [x] **#9 E2E suite** — all 12 usg-tacacs scenarios pass including concurrent_burst
  (20/20). Root cause of prior OOM: dummy Argon2 (m=524288 = 512 MB) fired on
  every PAP request even when no argon users existed; fixed to skip dummy when
  `creds.argon.is_empty()`.
