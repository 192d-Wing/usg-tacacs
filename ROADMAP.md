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

- [ ] **#2 ROPC regression** — PAP auth must still reach ICAM via ROPC unchanged
  when `--icam-device-flow` is enabled (device flow is ASCII-only). Run a PAP
  auth against the cluster and confirm PASS + correct groups.

### Device Flow Behavior

- [ ] **#4 Max polls exhaustion** — press ENTER 48 times without completing
  browser auth; expect a clean FAIL at poll 49, not a hang or panic.

- [ ] **#5 Device code expiry** — let the ICAM 600 s device code window expire
  without browser auth; verify ICAM returns `expired_token` and the user
  receives a clean FAIL message.

- [ ] **#6 Concurrent sessions** — two simultaneous ASCII logins from the same
  NAD must each receive an independent device_code and verification URL.

### Authorization Correctness

- [ ] **#7 Group-based priv-lvl** — confirm a `netops` user receives `priv-lvl=15`
  in the shell authz reply and that Cisco auto-exec fires. Confirm a user with
  no matching group gets default attributes only.

- [ ] **#8 Command authz with groups** — verify `deny-config` and
  `allow-all-admins` policy rules still evaluate correctly now that
  `effective_groups` is always populated on single-connect sessions.

### Regression

- [ ] **#9 E2E suite** — run `tests/e2e/compose.yaml` (PAP / CHAP / authz /
  accounting) against the full server binary; all scenarios must pass.
