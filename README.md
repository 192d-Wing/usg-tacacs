# usg-tacacs

[![GitLab Pipeline](https://gitlab.com/192d-wing/usg-tacacs/badges/master/pipeline.svg)](https://gitlab.com/192d-wing/usg-tacacs/-/pipelines)
[![NIST Compliance](https://img.shields.io/badge/NIST%20SP%20800--53-Rev.%205%20Compliant-brightgreen)](./docs/nist-control-analysis.md)
[![NASA Power of 10](https://img.shields.io/badge/NASA%20Power%20of%2010-Compliant-blue)](#nasa-power-of-10-compliance)

## NASA Power of 10 Compliance

This project adheres to NASA Power of 10 safety-critical coding rules:

- ✅ **Rule #4:** All functions ≤60 lines (handle_connection: 52 lines, 96.2% reduction from 1,357)
- ✅ **Rule #5 & #7:** Safe error handling with zero `.unwrap()` in critical runtime paths
- ✅ **Rule #11:** Formal NIST SP 800-53 Rev. 5 control markings (100% coverage, 35/35 files)

**Automated Validation:** CI/CD pipelines enforce compliance on every commit. See [NIST Control Analysis](./docs/nist-control-analysis.md) for detailed coverage.

---

Rust TACACS+ server with:

- RFC 9887 TACACS+ over TLS 1.3 (mTLS only) on TCP/300
- Optional legacy TACACS+ (TCP/49)
- **EST (RFC 7030) zero-touch certificate provisioning** with automated enrollment and renewal
- Per-command authorization
- JSON policy with priorities + last-match-wins
- JSON Schema validation + validate-only mode
- SIGHUP hot reload
- Command normalization + regex auto-anchoring
- Capability/keepalive packet support (vendor-specific, single-connect/keepalive bits, request/ack)
- Hardened RFC 8907 semantics: authz protocol/service checks, explicit FOLLOW rejection, richer audit telemetry
- LDAP authentication (LDAPS only) with service-account bind + match-any required groups, with group-aware policy matching
- Client-certificate allowlists (CN/SAN), optional extra trust roots, and per-peer connection limits
- Management API with RBAC for session visibility, session termination, policy reload, and runtime monitoring
- Process hardening guidance: run as non-root, optionally chroot/jail, set RLIMITs, and drop ambient caps (see below)

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
- Generate an SBOM for releases (e.g., `syft packages dir:. -o spdx-json > sbom.json` or `cargo audit-sbom`).
- Sign release artifacts/hashes (e.g., `sha256sum target/release/usg-tacacs-* | gpg --clearsign`).
- Optional: run `cargo audit` / `cargo deny check` in CI to catch vulnerable/banlisted crates.

## Logging/auditing guidance

- UTC timestamps enabled by default via tracing subscriber; include peer/user/session/outcome fields in audit logs for correlation.
- Forward logs to a central collector with integrity (e.g., TLS/syslog with signing) and set up rotation/retention at the service manager level (systemd journald or logrotate).
- Consider shipping signed hash manifests of log files for tamper detection if storing locally.

## Validate policy

cargo run -p tacacs-server -- \
  --check-policy ./policy/policy.example.json \
  --schema ./policy/policy.schema.json

## Run TLS server

cargo run -p tacacs-server -- \
  --listen-tls 0.0.0.0:300 \
  --tls-cert ./certs/server.pem \
  --tls-key ./certs/server-key.pem \
  --client-ca ./certs/client-ca.pem \
  --policy ./policy/policy.example.json

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

Server starts degraded, auto-enrolls certificates, then becomes ready. See [docs/docs/est-provisioning.md](./docs/docs/est-provisioning.md) for complete configuration and deployment guides.

## LDAP authentication (LDAPS only)

Enable LDAPS with a service account and optional required groups (match-any):

```shell
cargo run -p tacacs-server -- \
  --listen-tls 0.0.0.0:300 \
  --tls-cert ./certs/server.pem \
  --tls-key ./certs/server-key.pem \
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

## Configuration files

- `config.example.json` / `config.schema.json` cover server flags including TLS trust roots (`tls_trust_root`), CN/SAN allowlists (`tls_allowed_client_cn`/`tls_allowed_client_san`), max connections per IP, ASCII backoff/lockout, single-connect idle/keepalive timers, and LDAP options above.
- `policy.example.json` / `policy.schema.json` describe authorization rules; rules now support `groups` (match-any, combined with `users` and regex command match). Default shell PASS-ADD attrs are added when none are supplied.
