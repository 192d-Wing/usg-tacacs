---
icon: lucide/shield
---

# usg-tacacs documentation

## Overview

`usg-tacacs` is a Rust TACACS+ server that targets RFC 8907 semantics and defaults to TLS 1.3 with mutual authentication. Legacy TACACS+ on TCP/49 is optional and obfuscation is enforced when a shared secret is configured. Authorization is policy-driven (JSON), and authentication can use static credentials or LDAPS with optional group requirements. Single-connection and capability/keepalive packets are supported. See the [Policy guide](./policy.md) for detailed rule behavior.

### Core capabilities

- TLS 1.3 + mTLS on TCP/300; optional legacy TACACS+ on TCP/49 with shared secret.
- Client certificate allowlists (CN or SAN) and optional extra trust roots.
- **EST (RFC 7030) zero-touch certificate provisioning** with automated enrollment and renewal.
- Per-command authorization via JSON policy (priorities, last-match-wins), with user and group matching.
- Authentication sources: static user/password map or LDAPS (service-account bind, match-any required groups, configurable group attribute).
- Accounting/authz semantic checks aligned with RFC 8907; explicit rejection of deprecated FOLLOW/ARAP paths.
- Single-connection flag handling and vendor capability/keepalive packet support.
- Telemetry/audit logging with UTC timestamps, peer/session identifiers, and outcome codes.

## Quick start

1. **Install Rust:** `rustup toolchain install stable` (if needed).
2. **Generate TLS material:** create `server.pem`, `server-key.pem`, and a client CA (`client-ca.pem`) for mTLS. Optionally add extra trust roots with `tls_trust_root`.
3. **Prepare policy:** start from `policy/policy.example.json`; adjust rules, `users`, and `groups` as needed. Validate with:

   ```sh
   cargo run -p tacacs-server -- --check-policy ./policy/policy.example.json --schema ./policy/policy.schema.json
   ```

4. **Run the server (TLS only):**

   ```sh
   cargo run -p tacacs-server -- \
     --listen-tls 0.0.0.0:300 \
     --tls-cert ./certs/server.pem \
     --tls-key ./certs/server-key.pem \
     --client-ca ./certs/client-ca.pem \
     --policy ./policy/policy.example.json \
     --secret "use-a-strong-shared-secret"
   ```

   Add `--listen-legacy 0.0.0.0:49` if you must serve legacy TACACS+ (obfuscation is required when a secret is set).
5. **Enable LDAPS (optional):**

   ```sh
   --ldaps-url ldaps://ldap.example.com \
   --ldap-bind-dn "cn=svc,ou=svc,dc=example,dc=com" \
   --ldap-bind-password "svc-secret" \
   --ldap-search-base "dc=example,dc=com" \
   --ldap-required-group "cn=netops,ou=groups,dc=example,dc=com" \
   --ldap-group-attr memberOf \
   --ldap-username-attr uid
   ```

   Only LDAPS is permitted; StartTLS is rejected. Group checks are match-any and case-insensitive.

## Configuration reference (flags / config.json)

You can pass options via CLI flags or JSON (`config.example.json` / `config.schema.json`).

### TLS and transport

- `listen_tls` (host:port, required) — TLS listener for TACACS+.
- `listen_legacy` (host:port | null) — legacy TACACS+ listener.
- `tls_cert` / `tls_key` / `client_ca` — server keypair and client CA for mTLS.
- `tls_trust_root` (array) — extra trust roots for client validation.
- `tls_allowed_client_cn` / `tls_allowed_client_san` (arrays) — allowlist client cert identities.
- `tls_psk` (optional) — PSK for TLS if using pre-shared keys.
- `secret` (string | null) — TACACS+ shared secret; required for legacy obfuscation; min length 8.
- `forbid_unencrypted` (bool, default true) — drop requests with `TAC_PLUS_UNENCRYPTED_FLAG`.
- `single_connect_idle_secs` / `single_connect_keepalive_secs` — timeouts for single-connection sessions.
- `max_connections_per_ip` — simple connection limiter.

For **automated certificate provisioning**, see [EST Certificate Provisioning](./est-provisioning.md).

### Authentication

- `user_password` — array of `user:password` strings for static credentials.
- ASCII/PAP attempt tuning: `ascii_attempt_limit`, `ascii_user_attempt_limit`, `ascii_pass_attempt_limit`, `ascii_backoff_ms`, `ascii_backoff_max_ms`, `ascii_lockout_limit`.
- LDAPS:
  - `ldaps_url` (must start with `ldaps://`)
  - `ldap_bind_dn`, `ldap_bind_password`, `ldap_search_base`
  - `ldap_username_attr` (default `uid`)
  - `ldap_group_attr` (default `memberOf`)
  - `ldap_required_group` (array, match-any)
  - `ldap_timeout_ms`, `ldap_ca_file` (optional trust anchor for LDAPS)

### Authorization policy

Policies live in `policy/policy.example.json` and are validated against `policy/policy.schema.json`.

Rule fields:

- `id`: string identifier for audit.
- `priority`: higher wins; ties resolved by last-match-wins order.
- `pattern`: regex for command (auto-anchored and normalized).
- `effect`: `"allow"` or `"deny"`.
- `users`: array of usernames (case-insensitive).
- `groups`: array of group names/DNs (match-any, case-insensitive).

Default shell `PASS_ADD` attributes are injected when none are provided; non-shell decisions return policy-specified attributes only.

### Accounting and authorization semantics

- Authz rejects deprecated FOLLOW and invalid protocol/service combinations per RFC 8907; error responses include reason codes.
- Accounting rejects deprecated FOLLOW status; audits include flags/status/attr counts.
- Single-connection and capability packets are parsed and acknowledged; keepalive timers are configurable.

### Telemetry and auditing

- Logging uses `tracing` with UTC timestamps; include peer addresses, session IDs, and outcomes.
- Audit events are emitted for authn/authz/acct passes/fails/denies, with policy rule IDs and reasons where applicable.
- Forward logs to a centralized collector (TLS/syslog) and configure rotation/retention externally.

## Hardening checklist

- Run as a dedicated non-root user; drop ambient capabilities; set RLIMITs for fds/mem/procs.
- Optionally chroot/jail the process and place certs/policy inside the jail.
- Keep `Cargo.lock` committed; build with `cargo build --locked`; consider `cargo vendor` for offline reproducibility.
- Use strong TACACS+ shared secrets on legacy listeners; prefer TLS-only deployments.
- Restrict TLS clients with CN/SAN allowlists and extra trust roots when needed.

## Troubleshooting

- **Policy rejected:** run `--check-policy` with the schema to catch validation errors.
- **Client mTLS fails:** verify client CA, CN/SAN allowlists, and any extra trust roots.
- **LDAP auth fails:** confirm LDAPS URL, service bind credentials, search base, username/group attributes, and required group values.
- **Legacy TACACS+ fails:** ensure `secret` is set and `forbid_unencrypted` remains true for production.
