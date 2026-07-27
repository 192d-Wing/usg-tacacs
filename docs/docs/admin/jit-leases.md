---
icon: lucide/key-round
---

# JIT password leases

USG TACACS authenticates JIT-managed NADs against short-lived leases issued by
JITPW. PostgreSQL is authoritative for lease metadata and keyed password
verifiers. Passwords are never returned by the API or written to audit.

## Security invariants

- Canonical usernames are lowercase EIDs.
- A lease is bound to exactly one NAD and expires within 15 minutes.
- Revocation takes effect immediately.
- Managed NADs use only JIT authentication and fail closed.
- TLS NAD identity comes from its client certificate.
- Legacy NAD identity requires an exact source mapping and unique secret.
- JITPW and TACACS communicate over the mTLS management listener.
- The issuer receives only `write:jit-leases`.

## Typed configuration

Configure the store and keys in each rendered role:

```yaml
jit:
  storeUrl: postgresql://tacacs_jit@postgres.example.mil:5432/tacacs?sslmode=verify-full
  storePasswordFile: /run/secrets/postgres/password
  storeCaFile: /run/tls/postgres/ca.crt
  verifierKeyFile: /run/secrets/jit/verifier-key
  maximumTtlSeconds: 900
```

Configure management RBAC in the same document:

```yaml
management:
  rbac:
    roles:
      jitpw-issuer:
        permissions: [write:jit-leases]
      jitpw-auditor:
        permissions: [read:jit-leases]
    subjects:
      - certificateIdentity: dns:jitpw-api.jitpw-system.svc
        role: jitpw-issuer
      - certificateIdentity: dns:jitpw-audit.jitpw-system.svc
        role: jitpw-auditor
```

Mount all referenced files read-only. The PostgreSQL URL contains no password.
Do not configure JIT with environment variables when authoritative YAML is
active.

## Database

Apply release migrations with a dedicated migration identity. The runtime role
must not own the schema or receive migration privileges. Use validated
PostgreSQL TLS, point-in-time recovery, encrypted backups, and audited restore
access.

A restored database is usable only with the exact verifier key that created
its unexpired leases. If continuity cannot be proven, revoke all restored
active leases before admitting traffic.

## API

The JIT lease contract is OpenAPI 3.1.1 and its protected Swagger UI is served
on the management origin. Operations are:

| Method | Path | Permission |
| --- | --- | --- |
| `POST` | `/api/v1/jit-leases` | `write:jit-leases` |
| `GET` | `/api/v1/jit-leases/{lease_id}` | `read:jit-leases` |
| `DELETE` | `/api/v1/jit-leases/{lease_id}` | `write:jit-leases` |

Creation requires `Idempotency-Key` and `X-Correlation-ID`. Proxies, service
meshes, APM, and request loggers must not capture create bodies.

## Rotation

The verifier key is shared across replicas. Drain or revoke outstanding leases
before coordinated replacement, then restart all roles under one controlled
change. Rotate PostgreSQL credentials independently and verify store health.

## Validation

- A lease succeeds only for its exact EID and NAD.
- The credential fails on a different NAD.
- Expired and revoked leases fail.
- Managed NADs cannot fall back.
- The issuer cannot read leases unless separately authorized.
- Audit contains lease/correlation metadata but no credential or verifier.
- Store failure produces a closed authentication result and alert.
