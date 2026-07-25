---
icon: lucide/settings
---

# Management API

The Management API provides REST endpoints for runtime administration of the TACACS+ server, including session management, policy reload, and monitoring.

## Typed configuration inspection

The API uses the same strict `TacacsServer` Rust types as the startup config
checker:

```text
POST /api/mgmt/v1/config/validate
GET  /api/mgmt/v1/config/schema
GET  /api/mgmt/v1/config/effective
```

Validation is a dry run: it neither reads referenced secret files nor applies
the submitted YAML. The effective endpoint returns the YAML-owned configuration
as JSON with a stable SHA-256 hash. Authorized administrators can see secret
references, but secret file contents are never included.

Policy reload returns `202 Accepted` with an `operationId`. Poll
`GET /api/mgmt/v1/operations/{operationId}` until its status is `succeeded` or
`failed`. A failed reload preserves the previous active policy. Static listener,
RBAC, NAD baseline, and secret-mount changes require a rolling restart.

Apply migration `0004_management_operations.sql` before running multiple
management API replicas. With PostgreSQL management storage enabled, operation
IDs are replica-independent and survive pod restarts. Completed operations are
retained for 24 hours and the service permits at most 1,024 concurrent running
operations.

## Overview

The API is disabled by default and must be explicitly enabled with
`--api-enabled`. Production deployments require direct TLS 1.3 mutual
authentication.

### Security Controls

The Management API implements the following NIST SP 800-53 security controls:

| Control | Implementation |
|---------|----------------|
| **AC-3** (Access Enforcement) | RBAC authentication required for all endpoints |
| **AC-10** (Concurrent Session Control) | Session visibility via `/sessions` endpoint |
| **AC-12** (Session Termination) | Administrative session termination via API |
| **CM-3** (Configuration Change Control) | Policy reload with audit logging |
| **SC-8** (Transmission Confidentiality) | TLS 1.3 with mTLS (when configured) |
| **AU-2/AU-12** (Audit Events) | All API access attempts are logged |

## Production Deployment

Production deployments must use the server's TLS 1.3 mutual-authentication
listener. A proxy may use TCP passthrough, but an HTTP proxy cannot supply the
client identity through a header.

## Enabling the API

### Command Line

```sh
usg-tacacs-server \
  --api-enabled \
  --api-listen 127.0.0.1:8443 \
  --api-tls-cert /etc/usg-tacacs/tls/api-server.pem \
  --api-tls-key /etc/usg-tacacs/tls/api-server-key.pem \
  --api-client-ca /etc/usg-tacacs/tls/api-client-ca.pem \
  --api-rbac-config /etc/usg-tacacs/rbac.json \
  # ... other options
```

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `--api-enabled` | Enable the Management API | `false` |
| `--api-listen` | Address and port to listen on | Required when enabled |
| `--api-tls-cert` | API server TLS certificate | None (plaintext if not set) |
| `--api-tls-key` | API server TLS private key | None |
| `--api-client-ca` | Client CA for mTLS authentication | None |
| `--api-rbac-config` | Path to RBAC configuration file | Uses defaults |

## Authentication

### TLS Client Certificate (Production)

Authentication is performed from typed identities in the validated client
certificate:

```sh
curl --cert client.pem --key client-key.pem \
  https://localhost:8443/api/mgmt/v1/status
```

Supported selectors are `cn:`, `dns:`, `email:`, and `uri:`. DNS and email
values are canonicalized to lowercase. Exactly one configured selector must
match the certificate; ambiguous certificates fail closed even if both
identities map to the same role.

`X-User-CN` exists only in compiled test code. Runtime requests cannot select
their identity with an HTTP header.

> **Warning**: Plaintext mode should only be used for development/testing.

## RBAC Configuration

Create an RBAC configuration file to define users and roles:

```json
{
  "users": {
    "cn:admin.example.com": "admin",
    "dns:operator.example.com": "operator",
    "uri:spiffe://example.com/tacacs/monitor": "viewer"
  },
  "roles": {
    "admin": ["read:*", "write:*"],
    "operator": ["read:*", "write:sessions"],
    "viewer": ["read:status", "read:metrics"]
  }
}
```

Untyped legacy identities such as `CN=admin.example.com` are rejected at
startup. Convert them to typed selectors before upgrading.

### Default Roles

If no RBAC config is provided, the following default roles are used:

| Role | Permissions |
|------|-------------|
| `admin` | All read and write permissions |
| `operator` | All read permissions, `write:sessions` |
| `viewer` | `read:status`, `read:metrics` |

NAD automation should receive only `read:nads` and/or `write:nads` unless it
also operates other server resources. The wildcard permissions used by the
default `admin` role include both.

### NAD Management

API-owned NAD desired state is managed through:

| Method | Path | Permission | Concurrency requirement |
| --- | --- | --- | --- |
| `GET` | `/api/mgmt/v1/nads` | `read:nads` | none |
| `GET` | `/api/mgmt/v1/nads/inventory` | `read:nads` | none |
| `GET` | `/api/mgmt/v1/nads/reconciliation` | `read:nads` | none |
| `GET` | `/api/mgmt/v1/nads/{nadId}` | `read:nads` | none |
| `POST` | `/api/mgmt/v1/nads` | `write:nads` | `Idempotency-Key` |
| `PATCH` | `/api/mgmt/v1/nads/{nadId}` | `write:nads` | current `If-Match` ETag |
| `DELETE` | `/api/mgmt/v1/nads/{nadId}` | `write:nads` | current `If-Match` ETag |

All mutations also require `X-Correlation-ID` containing a UUID. Legacy NAD
requests contain only an opaque `secretRef`; provision the actual shared secret
through the deployment's approved secret provider. Neither the secret value nor
an idempotency key is stored in plaintext.

Use `/nads/inventory` when an operator needs the complete view. Its entries
identify `yaml` or `api` ownership and include a `mutable` flag. YAML-owned
entries must be changed through the declarative configuration delivery
workflow, not through NAD mutation endpoints.

The API-owned `/nads` collection accepts `namePrefix`, `limit`, and `offset`.
The default page size is 100 and the maximum is 200. Follow `nextOffset` until
it is `null`; do not assume a single request contains every API-owned NAD.

Use `/nads/reconciliation` for monitoring and automation. It reports aggregate
counts for the current snapshot and returns at most 200 statuses per request.
The `state`, `limit`, and `offset` query parameters support bounded queries such
as `?state=conflict&limit=100`.

### Forensic NAD Audit

`GET /api/mgmt/v1/audit/nads` requires `read:audit` and exports at most 200
chronologically ordered events. Filters are available for `nadId`,
`correlationId`, and `action`; use `nextOffset` to continue. Each event contains
the certificate actor, before/after resource state, previous and current
SHA-256 chain hashes, and the HMAC-SHA-256 signature. The endpoint never returns
the HMAC key or resolved TACACS shared secrets.

Use `GET /api/mgmt/v1/audit/nads/verify` to verify the evidence in bounded
pages. The default verification page is 1,000 events and the maximum is 5,000.
Continue with `offset + checkedEvents` until `complete` is true. Any
`valid: false` response includes the first failing event and a stable failure
code; treat it as an integrity incident and preserve the database and service
logs before remediation.

Apply database migration `0003_nad_audit_hash_v2.sql` before deploying the
corresponding server build. Historical events remain `hashVersion: 1`; new
events use `hashVersion: 2`, which also authenticates the event ID, normalized
timestamp, actor, and other forensic metadata. Do not rewrite v1 rows during
the upgrade.

An accepted NAD record becomes active only after runtime reconciliation
validates secret resolution and conflicts against the YAML-owned baseline.
Successful mutations trigger immediate reconciliation; each replica also
refreshes periodically to observe peer updates and mounted-secret rotation.
New TACACS connections use the latest atomically published snapshot.

## API Endpoints

### GET /api/mgmt/v1/status

Returns server status and statistics.

**Permission**: `read:status`

**Response**:
```json
{
  "status": "running",
  "version": "0.76.0",
  "uptime_seconds": 3600,
  "stats": {
    "total_connections": 1250,
    "active_connections": 42,
    "total_authn_requests": 5000,
    "total_authz_requests": 12000,
    "total_acct_requests": 8000,
    "authn_success_rate": 0.98,
    "authz_success_rate": 0.95
  }
}
```

### GET /api/mgmt/v1/sessions

Lists all active TACACS+ sessions.

**Permission**: `read:sessions`

**Response**:
```json
{
  "sessions": [
    {
      "id": 1,
      "peer_addr": "192.168.1.100:54321",
      "username": "admin",
      "start_time": 1704067200,
      "idle_seconds": 30,
      "request_count": 5
    }
  ],
  "total": 1
}
```

### DELETE /api/mgmt/v1/sessions/:id

Terminates an active session by ID.

**Permission**: `write:sessions`

**Parameters**:
- `id` - The session connection ID from the sessions list

**Response** (success):
```json
{
  "success": true,
  "message": "Session 1 termination requested"
}
```

**Response** (not found):
```json
{
  "success": false,
  "message": "Session 999 not found"
}
```

**Note**: Session termination is asynchronous. The session will close on its next activity check.

### GET /api/mgmt/v1/policy

Returns current policy information.

**Permission**: `read:policy`

**Response**:
```json
{
  "rule_count": 25,
  "last_loaded": "2025-01-01T00:00:00Z",
  "source": "/etc/usg-tacacs/policy.json"
}
```

### POST /api/mgmt/v1/policy/reload

Triggers a policy hot reload from disk.

**Permission**: `write:policy`

**Response** (success):
```json
{
  "success": true,
  "message": "Policy reload triggered"
}
```

This endpoint queues a policy reload request. The reload is processed asynchronously by the same mechanism that handles SIGHUP.

### GET /api/mgmt/v1/config

Returns the running configuration (sanitized, no secrets).

**Permission**: `read:config`

**Response**:
```json
{
  "listen_addrs": ["0.0.0.0:300", "0.0.0.0:49"],
  "tls_enabled": true,
  "ldap_enabled": true,
  "policy_source": "/etc/usg-tacacs/policy.json",
  "metrics_enabled": true,
  "api_enabled": true
}
```

### GET /api/mgmt/v1/metrics

Returns Prometheus-format metrics.

**Permission**: `read:metrics`

**Response** (text/plain):
```
# HELP tacacs_sessions_active Number of active sessions
# TYPE tacacs_sessions_active gauge
tacacs_sessions_active 42

# HELP tacacs_authn_requests_total Total authentication requests
# TYPE tacacs_authn_requests_total counter
tacacs_authn_requests_total{method="pap",result="pass"} 1234
tacacs_authn_requests_total{method="pap",result="fail"} 56
...
```

## Error Responses

### 403 Forbidden

Returned when:
- No authentication provided
- User not found in RBAC configuration
- User lacks required permission

```json
{
  "error": "access denied",
  "required_permission": "write:sessions"
}
```

### 404 Not Found

Returned when a resource (e.g., session) is not found.

### 500 Internal Server Error

Returned when an internal error occurs (e.g., policy reload channel closed).

## Usage Examples

### List Active Sessions

```sh
curl -s https://localhost:8443/api/mgmt/v1/sessions \
  --cert admin.pem --key admin-key.pem | jq
```

### Terminate a Session

```sh
curl -X DELETE https://localhost:8443/api/mgmt/v1/sessions/42 \
  --cert admin.pem --key admin-key.pem
```

### Trigger Policy Reload

```sh
curl -X POST https://localhost:8443/api/mgmt/v1/policy/reload \
  --cert admin.pem --key admin-key.pem
```

### Monitor with Prometheus

Add to your Prometheus configuration:

```yaml
scrape_configs:
  - job_name: 'tacacs'
    scheme: https
    tls_config:
      cert_file: /path/to/client.pem
      key_file: /path/to/client-key.pem
      ca_file: /path/to/ca.pem
    static_configs:
      - targets: ['tacacs-server:8443']
    metrics_path: /api/mgmt/v1/metrics
```

## Metrics Reference

| Metric | Type | Description |
|--------|------|-------------|
| `tacacs_sessions_active` | Gauge | Current number of active sessions |
| `tacacs_connections_total` | Counter | Total connections by type (tls/legacy) |
| `tacacs_authn_requests_total` | Counter | Auth requests by method and result |
| `tacacs_authz_requests_total` | Counter | Authz requests by result |
| `tacacs_acct_records_total` | Counter | Accounting records by type |
| `tacacs_policy_rules_count` | Gauge | Number of policy rules loaded |
| `tacacs_policy_reload_total` | Counter | Policy reloads by result |

## Security Recommendations

1. **Always use TLS with mTLS** in production
2. **Bind to localhost** or internal network only
3. **Use a firewall** to restrict access to the API port
4. **Rotate client certificates** regularly
5. **Monitor access logs** for unauthorized attempts
6. **Use the principle of least privilege** when assigning roles
