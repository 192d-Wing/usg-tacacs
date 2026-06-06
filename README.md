# usg-tacacs

[![CI](https://github.com/192d-Wing/usg-tacacs/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/192d-Wing/usg-tacacs/actions/workflows/ci.yml)
[![NIST Compliance](https://img.shields.io/badge/NIST%20SP%20800--53-Rev.%205%20Compliant-brightgreen)](./docs/nist-control-analysis.md)
[![NASA Power of 10](https://img.shields.io/badge/NASA%20Power%20of%2010-Compliant-blue)](#nasa-power-of-10-compliance)

A hardened, RFC 9887 TACACS+-over-TLS server written in Rust, built for DoD/IL environments: enterprise identity (LDAPS, ICAM/OIDC, CAC/PIV device flow), signed tamper-evident audit, zero-touch certificate provisioning, and Kubernetes-native deployment.

## NASA Power of 10 Compliance

This project adheres to NASA Power of 10 safety-critical coding rules:

- ✅ **Rule #4:** All functions ≤60 lines (handle_connection: 52 lines, 96.2% reduction from 1,357)
- ✅ **Rule #5 & #7:** Safe error handling with zero `.unwrap()` in critical runtime paths
- ✅ **Rule #11:** Formal NIST SP 800-53 Rev. 5 control markings (100% coverage)

**Automated Validation:** CI enforces compliance on every commit (function-length, runtime-`unwrap`, and NIST-header checks live in `.github/workflows/ci.yml`). See [NIST Control Analysis](./docs/nist-control-analysis.md) for detailed coverage.

---

## Features

- **RFC 9887 TACACS+ over TLS 1.3** (mTLS only) on TCP/300, with optional legacy TACACS+ (TCP/49) for transitional deployments
- **Authentication backends** (PAP / CHAP / ASCII login):
  - Local static credentials (Argon2id hashes), disabled by default
  - **LDAP** over LDAPS only, service-account bind + match-any required groups
  - **ICAM / OIDC** via Resource Owner Password Credentials (ROPC); groups extracted from the JWT drive policy
  - **ICAM device flow (RFC 8628)** — browser-based CAC/PIV authentication, with the verification URL presented at the NAD terminal
- **Group-aware authorization** — JSON policy with priorities, last-match-wins, per-command regex ACLs (auto-anchored), `groups` + `users` matching, and `--check-policy` validate-only mode against a JSON Schema
- **Redis-backed group cache** — login→authz group memberships persisted so group policy works across standalone authz transactions and server replicas
- **Tamper-evident audit** — every audit event (incl. `authn_terminal`) is HMAC-SHA256 signed over a canonical field set; a single emitter guarantees no event bypasses signing
- **Brute-force / spray defenses** — per-username and per-source-IP rate limiting with lockout, and lockout state masked from clients (same generic failure as bad credentials) to prevent state confirmation
- **EST (RFC 7030) zero-touch certificate provisioning** with automated enrollment and renewal; optional **OpenBao** (Vault) integration for secrets and PKI
- **Operations** — SIGHUP hot reload, capability/keepalive (single-connect) support, hardened RFC 8907 semantics (authz protocol/service checks, explicit FOLLOW rejection), Management API with RBAC for session visibility/termination/reload, Prometheus metrics, and OpenTelemetry/OTLP tracing
- **Process hardening guidance** — run as non-root, drop ambient caps, set RLIMITs, optional chroot/jail (see below)

## Workspace crates

| Crate | Purpose |
| ----- | ------- |
| `tacacs-proto` | TACACS+ protocol codec (headers, authn/authz/acct bodies, legacy shared-secret crypto) |
| `tacacs-policy` | Authorization policy engine: rule matching, group enforcement, regex command ACLs |
| `tacacs-secrets` | Secrets abstraction: file-based, OpenBao/Vault, PKI, EST zero-touch provisioning |
| `tacacs-server` | Main server: authn/authz/acct, rate limiting, audit, TLS, ICAM, device flow, group cache |
| `tacacs-policy-ingest` | Policy ingest HTTP service: REST upload/validation, schema checks, mTLS |
| `tacacs-client-tls` | TLS-only TACACS+ client library (RFC 9887, TLS 1.3, no MD5 obfuscation) |
| `tacacs-openssh` | OpenSSH integration helpers |
| `tacacs-audit` | Audit forwarding (syslog-over-TLS, Elasticsearch) and HMAC integrity signing |

## Validate policy

```shell
cargo run -p tacacs-server -- \
  --check-policy ./policy/policy.example.json \
  --schema ./policy/policy.schema.json
```

## Run TLS server

```shell
cargo run -p tacacs-server -- \
  --listen-tls 0.0.0.0:300 \
  --tls-cert ./certs/server.pem \
  --tls-key ./certs/server-key.pem \
  --client-ca ./certs/client-ca.pem \
  --policy ./policy/policy.example.json
```

## ICAM / OIDC authentication (ROPC)

Delegate authentication to ICAM via the OIDC Resource Owner Password Credentials grant. Groups are read from the JWT and feed policy matching:

```shell
cargo run -p tacacs-server -- \
  --listen-tls 0.0.0.0:300 \
  --tls-cert ./certs/server.pem --tls-key ./certs/server-key.pem \
  --client-ca ./certs/client-ca.pem \
  --policy ./policy/policy.example.json \
  --icam-token-endpoint https://icam.example.mil/realms/dod/protocol/openid-connect/token \
  --icam-client-id tacacs \
  --icam-client-secret-file /run/secrets/icam-client-secret \
  --icam-groups-claim groups \
  --icam-ca-file ./certs/icam-ca.pem
```

Add `--icam-device-flow` (RFC 8628) to present a browser verification URL at the NAD terminal for CAC/PIV login instead of collecting a password inline. See [docs/ICAM-OIDC-CONFIGURATION.md](./docs/ICAM-OIDC-CONFIGURATION.md) and [docs/docs/authentication.md](./docs/docs/authentication.md).

## Redis group cache

When using ICAM, cache the groups resolved at login so standalone authorization transactions (which carry no JWT) and other server replicas can apply group policy:

```shell
cargo run -p tacacs-server -- \
  ... \
  --group-cache-url rediss://redis:6379 \
  --group-cache-password-file /run/secrets/redis-password \
  --group-cache-ttl-secs 900
```

The cache is best-effort: Redis errors are logged but never block authentication or authorization.

## LDAP authentication (LDAPS only)

```shell
cargo run -p tacacs-server -- \
  --listen-tls 0.0.0.0:300 \
  --tls-cert ./certs/server.pem --tls-key ./certs/server-key.pem \
  --client-ca ./certs/client-ca.pem \
  --policy ./policy/policy.example.json \
  --ldaps-url ldaps://ldap.example.com \
  --ldap-bind-dn "cn=svc,ou=svc,dc=example,dc=com" \
  --ldap-bind-password "secret" \
  --ldap-search-base "dc=example,dc=com" \
  --ldap-required-group "cn=netops,ou=groups,dc=example,dc=com" \
  --ldap-required-group "cn=secops,ou=groups,dc=example,dc=com" \
  --ldap-group-attr memberOf \
  --ldap-username-attr uid
```

Notes:

- Only LDAPS is permitted; StartTLS is rejected.
- Group checks are match-any; group names are compared case-insensitively.
- Policy rules can also declare `groups` to require group membership for authorization decisions.

## EST zero-touch certificate provisioning

Automatically enroll and renew certificates using RFC 7030 EST:

```shell
cargo run -p tacacs-server -- \
  --est-enabled \
  --est-server-url https://est.example.com/.well-known/est \
  --est-username bootstrap-user \
  --est-password secret123 \
  --est-common-name tacacs-01.internal \
  --listen-tls 0.0.0.0:300 \
  --client-ca ./certs/client-ca.pem \
  --policy ./policy/policy.example.json
```

The server starts degraded, auto-enrolls certificates, then becomes ready. See [docs/docs/est-provisioning.md](./docs/docs/est-provisioning.md) for complete configuration and deployment guides.

## Audit integrity (HMAC signing)

Sign every audit event so log tampering is detectable. Use a key file in production:

```shell
cargo run -p tacacs-server -- \
  ... \
  --audit-hmac-key-file /run/secrets/audit-hmac-key
```

All events flow through a single emitter and are signed over a canonical
`event|peer|user|session|status|reason|data|identity_source` field set (NIST AU-9, SC-13).

## Brute-force and spray defenses

- **Per-username lockout** (`--username-lockout-*`) throttles failures for one identity across rotating source IPs.
- **Per-source-IP lockout** (`--ip-lockout-*`, default 50 failures / 5 min → 15 min) throttles one NAD spraying many usernames; set `--ip-lockout-limit 0` to disable.
- **State masking** — locked-out and rate-limited sessions return the same generic failure as bad credentials; the real reason is recorded only in the (signed) audit trail.

## Deployment (Kubernetes)

`deploy/k3s/` contains modular manifests for K3s + Cilium: the TACACS+ deployment/services, a hardened Iron Bank Redis for the group cache, NetworkPolicy, Cilium BGP/LB for an anycast VIP, the management UI with oauth2-proxy, and Prometheus/Loki/Alloy observability. Bring Redis up before the server. See [k3s deployment notes](./deploy/k3s/) and the operations docs below.

## Process hardening (recommended)

Run the daemon under a dedicated non-root user, with strict sandboxing/limits. Example systemd unit excerpt:

```shell
[Service]
User=tacacs
Group=tacacs
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_INET AF_INET6
LimitNOFILE=4096
LimitNPROC=256
MemoryAccounting=yes
TasksAccounting=yes
ProtectControlGroups=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
LockPersonality=yes
```

If you require chroot/jail, place certs/policy inside the jail and adjust paths accordingly.

## Supply-chain hygiene

- Build reproducibly with locked deps: `cargo build --locked`; keep `Cargo.lock` under version control.
- Vendor third-party crates for offline/attestable builds: `cargo vendor --locked vendor/` and point `CARGO_HOME`/`CARGO_REGISTRIES_CRATES_IO_PROTOCOL=file`.
- Generate an SBOM for releases (e.g., `syft packages dir:. -o spdx-json > sbom.json`); a checked-in `sbom.spdx.json` is provided.
- Sign release artifacts/hashes (e.g., `sha256sum target/release/usg-tacacs-* | gpg --clearsign`).
- CI runs `cargo audit`, `cargo deny check`, and gitleaks secret scanning to catch vulnerable/banlisted crates and hardcoded secrets.

## Logging / auditing guidance

- UTC timestamps enabled by default via the tracing subscriber; audit events include peer/user/session/outcome fields for correlation, and are HMAC-signed (see above).
- Forward logs to a central collector with integrity (e.g., TLS/syslog with signing) and set up rotation/retention at the service-manager level (systemd journald or logrotate).
- Consider shipping signed hash manifests of log files for tamper detection if storing locally.

## Configuration files

- `config.example.json` / `config.schema.json` cover server flags including TLS trust roots (`tls_trust_root`), CN/SAN allowlists (`tls_allowed_client_cn`/`tls_allowed_client_san`), max connections per IP, ASCII backoff/lockout, single-connect idle/keepalive timers, and the LDAP/ICAM/group-cache options above.
- `policy.example.json` / `policy.schema.json` describe authorization rules; rules support `groups` (match-any, combined with `users` and regex command match). Default shell PASS-ADD attrs are added when none are supplied.

## Documentation

- Authentication: [docs/docs/authentication.md](./docs/docs/authentication.md) · ICAM/OIDC: [docs/ICAM-OIDC-CONFIGURATION.md](./docs/ICAM-OIDC-CONFIGURATION.md)
- Configuration: [docs/docs/config.md](./docs/docs/config.md) · Policy: [docs/docs/policy.md](./docs/docs/policy.md), [docs/docs/policy-ingest.md](./docs/docs/policy-ingest.md)
- TLS & EST: [docs/docs/tls.md](./docs/docs/tls.md), [docs/docs/est-provisioning.md](./docs/docs/est-provisioning.md)
- Operations & Management API: [docs/docs/operations.md](./docs/docs/operations.md), [docs/docs/admin/management-api.md](./docs/docs/admin/management-api.md)
- Security & compliance: [docs/SECURITY.md](./docs/SECURITY.md), [docs/HARDENING_GUIDE.md](./docs/HARDENING_GUIDE.md), [docs/NIST-CONTROLS-MAPPING.md](./docs/NIST-CONTROLS-MAPPING.md), [docs/NASA-POWER-OF-10-COMPLIANCE.md](./docs/NASA-POWER-OF-10-COMPLIANCE.md)
- Container usage: [docs/docs/container.md](./docs/docs/container.md)
