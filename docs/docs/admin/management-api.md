---
icon: lucide/settings
---

# Management API

The USG TACACS Management API administers TACACS runtime state. It is separate
from the JITPW user API. The management workload serves the OpenAPI 3.1.1
contract and Swagger UI on the same TLS 1.3 mTLS origin.

## Security

Production startup requires a server certificate, private key, client CA, TLS
1.3, and typed RBAC:

```yaml
management:
  listener:
    address: 0.0.0.0:8443
    certificateFile: /run/tls/api/server.crt
    privateKeyFile: /run/tls/api/server.key
    clientCaFile: /run/tls/api/client-ca.crt
    minimumVersion: "1.3"
  rbac:
    roles:
      nad-automation:
        permissions: [read:nads, write:nads]
      forensic-reader:
        permissions: [read:audit]
    subjects:
      - certificateIdentity: uri:spiffe://example.mil/tacacs/nad-automation
        role: nad-automation
```

Supported identity selectors are `cn:`, `dns:`, `email:`, and `uri:`. Exactly
one configured selector must match the validated certificate. Runtime requests
cannot assert identity through a header.

Use TCP passthrough if a load balancer is required. Restrict the Service with
NetworkPolicy in addition to mTLS and RBAC.

## Documentation endpoints

Swagger groups operations with OpenAPI tags for status, sessions,
configuration, policy, certificates, NADs, forensic audit, and JIT leases.
Access to documentation follows management mTLS/RBAC; it is not a public
endpoint.

The repository contracts are:

- `docs/api/mgmt/openapi.yaml`
- `docs/api/jit-lease.openapi.yaml`

## Configuration inspection

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/mgmt/v1/config/validate` | Dry-run typed YAML validation |
| `GET` | `/api/mgmt/v1/config/schema` | Typed configuration schema |
| `GET` | `/api/mgmt/v1/config/effective` | Effective declarative config and hash |

Validation does not resolve secret contents. Effective configuration may show
file references but never returns file contents.

## NAD lifecycle

| Method | Path | Control |
| --- | --- | --- |
| `GET` | `/api/mgmt/v1/nads` | Paginated API-owned NADs |
| `GET` | `/api/mgmt/v1/nads/inventory` | YAML and API inventory |
| `GET` | `/api/mgmt/v1/nads/reconciliation` | Applied/failure state |
| `GET` | `/api/mgmt/v1/nads/{nadId}` | One API-owned NAD |
| `POST` | `/api/mgmt/v1/nads` | `Idempotency-Key` |
| `PATCH` | `/api/mgmt/v1/nads/{nadId}` | Current `If-Match` ETag |
| `DELETE` | `/api/mgmt/v1/nads/{nadId}` | Current `If-Match` ETag |

Mutations require a UUID `X-Correlation-ID`. Legacy NAD requests contain an
opaque `secretRef`, never the secret value.

YAML-owned inventory items are immutable through the API. Accepted API state
becomes active only after reconciliation resolves secrets and detects no
ownership, name, source-address, or certificate-identity conflict.

Collection endpoints are bounded. Follow `nextOffset`; never assume the first
page is complete.

## Forensic NAD audit

`GET /api/mgmt/v1/audit/nads` exports bounded chronological events with actor,
correlation ID, before/after state, chain hashes, and HMAC signature.
`GET /api/mgmt/v1/audit/nads/verify` verifies bounded pages. Continue until
`complete` is true.

Treat `valid: false` as an integrity incident. Preserve PostgreSQL, raw audit,
Pod metadata, configuration hash, and service logs before remediation. Never
rewrite historical events to repair a chain.

## Asynchronous operations

Reload operations return `202 Accepted` with an operation ID. Poll the
operation resource until `succeeded` or `failed`. A failed reload retains the
previous active policy. With PostgreSQL management storage, operations survive
replica changes and Pod restarts.

## Safe client behavior

- Validate the API server certificate and use an authorized client certificate.
- Generate a UUIDv7 correlation ID when the client standard permits it.
- Reuse an idempotency key for retries of the same logical create.
- Honor ETags and surface concurrency conflicts.
- Do not log request bodies containing credentials.
- Verify reconciliation after NAD mutation.
- Preserve problem details and correlation IDs without exposing secrets.

See the repository
[Management API architecture](https://github.com/192d-Wing/usg-tacacs/blob/main/docs/api/mgmt/architecture.md)
and
[NAD lifecycle](../operator/nad-lifecycle.md).
