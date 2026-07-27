---
icon: lucide/code-xml
---

# Developer guide

USG TACACS is a Rust workspace. Security boundaries are explicit: protocol
parsing, typed configuration, policy, secrets, management/JIT APIs,
reconciliation, and audit are separate crates or modules.

## Workspace

| Crate | Responsibility |
| --- | --- |
| `tacacs-proto` | RFC 8907 packet codec and legacy body obfuscation |
| `tacacs-policy` | Command authorization evaluation |
| `tacacs-config` | Strict `TacacsServer` YAML and checker |
| `tacacs-secrets` | Secret/certificate providers and EST |
| `tacacs-server` | Runtime roles, AAA, APIs, reconciliation, JIT |
| `tacacs-policy-ingest` | Legacy bundle-ingest compatibility service |
| `tacacs-client-tls` | RFC 9887 client library |
| `tacacs-openssh` | OpenSSH helpers |
| `tacacs-audit` | Audit signing and forwarding |

## Configuration rule

New production settings belong in typed YAML and require:

1. strict Rust types with `deny_unknown_fields`;
2. semantic validation and negative tests;
3. Helm rendering where applicable;
4. sanitized effective-config/schema output;
5. documentation and migration behavior; and
6. no secret value in serialized configuration.

Compatibility CLI/environment settings should not expand without an explicit
migration plan.

## API rule

Management API changes require synchronized handler, RBAC permission, OpenAPI
3.1.1, Swagger tag, audit event, idempotency/concurrency behavior, and tests.
Identity comes only from validated mTLS state.

## Security review prompts

- Can malformed or ambiguous input select another NAD/user?
- Does failure remain closed for JIT-managed devices?
- Can a secret enter logs, errors, metrics, or API responses?
- Is state replica-independent and transactionally durable?
- Are audit records complete and cryptographically chained?
- Does retry remain idempotent?
- Can YAML/API ownership conflict?
- Are loops, allocations, sessions, and payloads bounded?

Start with [Development setup](../dev_setup.md) and
[Protocol implementation](protocol.md).
