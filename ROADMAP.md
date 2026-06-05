# USG TACACS+ Roadmap

## Authorization Depth

- [x] **Time-based rules** — `schedule` field on policy rules with `days` and `hours`
  sub-fields.  Days accept 3-letter names, full names, and `weekdays`/`weekends`
  shorthands.  Hours use `HH:MM-HH:MM` UTC; midnight-wrapping ranges (e.g.
  `"22:00-06:00"`) are supported.  Schedule is compiled at policy-load time
  (bitmask + minute offsets) and checked in the authz hot path with no allocations.
  9 unit tests; schema updated (all 3 copies).

- [x] **NAD-group policy** — `nad_groups` top-level policy map and `nad_groups` field on
  rules.  Groups are defined by CIDR ranges (IPv4/IPv6, including /0 and /32); the server
  resolves the requesting NAD's source IP against all groups at authz time and passes the
  result to `authorize_with_nad()`.  Rules with `nad_groups` only fire when the NAD is in
  a matching group.  No new crate dependencies; CIDR matching is pure `std::net` bit
  arithmetic.  7 unit tests; schema updated (all 3 copies).

- [x] **Dynamic `enable` via device flow** — `ACTION_ENABLE` requests route through the
  RFC 8628 device flow (CAC re-authentication in browser) when `--icam-device-flow` is on,
  then gate on the new policy `enable_groups` map (priv-lvl → permitted ICAM/LDAP groups).
  Privilege is hierarchical: a group cleared for level 15 may also enable to lower levels.
  Empty `enable_groups` preserves legacy behavior (any authenticated user may enable).
  AuthSessionState now carries `priv_lvl`; `can_enable()` performs the check.

## Observability

- [x] **Policy dry-run** — `POST /api/policy/dry-run` on the BFF accepts a candidate
  policy JSON, fetches recent authz events from Loki, re-evaluates each command against
  the new rules (compiled regex), and returns a list of changed decisions with summary
  counts.  Groups field on rules is respected.

- [x] **Live session dashboard** — `GET /sessions` on the TACACS+ health HTTP port
  returns a JSON snapshot of all active connections (peer, user, session_id, idle_secs,
  request count).  BFF proxies it as `GET /api/sessions` via `TACACS_HTTP_URL`.
  New Sessions page in the UI polls every 5 s with idle-time colour coding.

- [x] **Command frequency alerting** — Alert rule #5 in the BFF alerts handler queries
  Loki for `authz_policy_allow` events, groups by user, and fires a warning when any
  user exceeds 100 commands in 15 minutes.

## Protocol / Infrastructure

- [ ] **TACACS+ proxy mode** — Forward auth/authz/accounting for specific NAD IP ranges
  to a legacy TACACS+ server (Cisco ACS/ISE).  Enables side-by-side migration: new
  devices use this server; legacy devices proxy through to the old one.

- [ ] **RADIUS bridge** — Thin RADIUS→TACACS+ shim for devices that only speak RADIUS
  (wireless controllers, older access gear).  Allows ICAM/device-flow auth across the
  full estate.  Larger scope; depends on a RADIUS library.

## Security Hardening

- [x] **Per-username rate limiting** — `UsernameRateLimiter` tracks failure counts per
  username across all source IPs with a sliding window.  CLI flags:
  `--username-lockout-window-secs` (300), `--username-lockout-limit` (10),
  `--username-lockout-secs` (900).  Lockout recorded in `finalize_authentication`
  at every terminal auth event; success clears the counter.

- [x] **Audit log HMAC signing** — `--audit-hmac-key` / `--audit-hmac-key-file`
  (hex-encoded, min 32 bytes).  When set, every structured audit event includes an
  `hmac` field containing HMAC-SHA256 over the pipe-delimited canonical fields.
  Key stored in process-global `OnceLock`; no call-site changes required.
