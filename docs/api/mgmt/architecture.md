# TACACS Management API Architecture

## Purpose

The TACACS management API is the administrative control plane for a USG TACACS
server. It is owned and served by `usg-tacacs`; it is not the JITPW API and it
does not issue or reveal device passwords.

The APIs have independent namespaces and contracts:

| API | Namespace | Consumer | Responsibility |
| --- | --- | --- | --- |
| TACACS management | `/api/mgmt/v1` | administrators and automation | status, sessions, policy, redacted configuration, and metrics |
| TACACS JIT lease | `/api/jit/v1` | JITPW backend | create, inspect, and revoke keyed-verifier leases |
| JITPW | separate service and listener | `jit-ssh` and JITPW operators | PIV authentication, ABAC decisions, lease orchestration, and auditing |

The original `/api/v1/jit-leases` routes remain compatibility aliases during
migration. New integrations must use `/api/jit/v1/leases`.

## Security boundary

The management listener requires TLS client authentication. The validated
certificate identity is inserted into the request by the TLS acceptor; HTTP
headers cannot select an identity in production. RBAC then maps that certificate
identity to a role and checks the permission required by each operation.

The management API must:

- negotiate TLS 1.3 only in the production baseline;
- require a client certificate issued by an explicitly configured management CA;
- deny identities and roles that are not present in the declarative RBAC configuration;
- return only redacted configuration data;
- audit administrative reads and mutations with a correlation identifier;
- apply request-size and rate limits to mutation endpoints.

Secrets are referenced by file path in configuration and mounted into the
container at runtime. They are never returned by the API or embedded in the
OpenAPI document.

## Contract and Swagger UI

The version-controlled OpenAPI 3.1.1 contract is
[`openapi.yaml`](openapi.yaml). A running server exposes:

- Swagger UI: `/api/docs/mgmt`
- OpenAPI YAML: `/api/docs/mgmt/openapi.yaml`

Both endpoints are protected by mTLS and the `read:config` RBAC permission.
The contract deliberately excludes JIT lease operations.

## Configuration lifecycle

The desired configuration model is a single, typed YAML server configuration.
Static baseline data such as listeners, trusted roots, authorization rules,
RBAC roles, and secret-file references is declarative and validated before the
server starts.

Dynamic NAD records created through future management API operations are stored
transactionally in PostgreSQL, with an immutable audit record. The management
API does not rewrite a mounted ConfigMap or local YAML file. Git-managed YAML is
the baseline; PostgreSQL contains runtime resources. A deterministic precedence
and reconciliation policy must reject conflicting NAD identities.

### NAD ownership and reconciliation

YAML NADs have `yaml` ownership and remain Git-managed. PostgreSQL NADs have
`api` ownership. The management API lists both sources but mutation operations
apply only to `api` resources. Attempts to update or delete YAML-owned NADs
return `409 Conflict`.

An active NAD name and source address must be globally unique across both
sources. Before committing a database mutation, the service checks the current
YAML snapshot and PostgreSQL partial unique indexes protect API resources from
concurrent conflicts.

API resources use a positive `resourceVersion`. Updates and soft deletes require
`If-Match` with the current ETag so concurrent administrators cannot silently
overwrite one another. Creates require an idempotency key; only its keyed token
and request fingerprint are retained.

The database stores an opaque `secretRef`, never a TACACS shared secret.
Resolution is performed by the approved secret provider. A NAD cannot become
active until that reference resolves successfully.

Every successful mutation appends a hash-chained, HMAC-authenticated audit
event containing the certificate actor, UUIDv7 correlation identifier, before
and after state, and resource version. Database triggers reject updates and
deletes against the audit table.

## Deployment

The management listener may share the server process with TACACS data-plane
listeners, but it uses a distinct port, route namespace, certificate trust
policy, and Kubernetes NetworkPolicy. It must not be exposed through the public
JITPW ingress.
