# USG TACACS+ Roadmap

## Authorization Depth

- [ ] **Time-based rules** — Add a `schedule` field to policy rules (e.g. `days`, `hours`)
  so change-control windows can be enforced at the policy layer.  Example: `deny reload`
  on weekends, `allow configure` only 08:00–18:00 Monday–Friday.  The rule schema and
  evaluator need a `schedule` block; the server clock is the only dependency.

- [ ] **NAD-group policy** — Tag network devices by role (core, access, firewall) via peer
  IP range or mTLS cert CN, then match policy rules against the tag.  Lets you write
  `deny configure` for access-layer devices while allowing it for core routers, all in
  one policy file.

- [ ] **Dynamic `enable` via device flow** — When a user requests privilege escalation
  (`ACTION_ENABLE`), trigger a second device flow / ICAM just-in-time approval instead of
  a static enable secret.  The TACACS+ enable action is already handled; the change is in
  the ASCII auth state machine and the policy approval step.

## Observability

- [ ] **Policy dry-run** — BFF endpoint that accepts a candidate policy JSON and replays
  the last N audit events from Loki against it, returning a diff of which decisions would
  change.  Lets operators validate policy changes before deploying, without touching
  production.

- [ ] **Live session dashboard** — WebSocket stream of active single-connect sessions in
  the UI.  The session registry already tracks them; surfacing it as a live view lets
  operators see who is logged into which device in real time.

- [ ] **Command frequency alerting** — Extend the existing alert engine with unusual
  command-volume detection.  If a user runs more than a configurable threshold of commands
  in a rolling window, fire a warning alert.  Loki data is already available; this is an
  additional alert rule in the BFF alerts handler.

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
