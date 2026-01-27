---
icon: lucide/settings
---

# Management API

The Management API provides REST endpoints for runtime administration of the TACACS+ server, including session management, policy reload, and monitoring.

## Overview

The API is disabled by default and must be explicitly enabled with `--api-enabled`. For production use, TLS with mutual authentication (mTLS) is strongly recommended.

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

!!! tip "Reverse Proxy Recommended"
    For production deployments, use a reverse proxy (Nginx or HAProxy) with mTLS instead of direct TLS mode. This provides better security, flexibility, and follows industry best practices.

    See the **[Reverse Proxy with mTLS Guide](reverse-proxy-mtls.md)** for complete setup instructions.

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

When API TLS is configured, authentication is performed via client certificate CN:

```sh
curl --cert client.pem --key client-key.pem \
  https://localhost:8443/api/v1/status
```

The CN from the client certificate is extracted and mapped to a role via the RBAC configuration.

### X-User-CN Header (Development Only)

When TLS is not configured (plaintext mode), the `X-User-CN` header can be used:

```sh
curl -H "X-User-CN: CN=admin.example.com" \
  http://localhost:8443/api/v1/status
```

> **Warning**: Plaintext mode should only be used for development/testing.

## RBAC Configuration

Create an RBAC configuration file to define users and roles:

```json
{
  "users": {
    "CN=admin.example.com": "admin",
    "CN=operator.example.com": "operator",
    "CN=monitor.example.com": "viewer"
  },
  "roles": {
    "admin": {
      "permissions": [
        "read:status", "read:metrics", "read:sessions", "read:policy", "read:config",
        "write:sessions", "write:policy"
      ]
    },
    "operator": {
      "permissions": [
        "read:status", "read:metrics", "read:sessions", "read:policy", "read:config",
        "write:sessions"
      ]
    },
    "viewer": {
      "permissions": [
        "read:status", "read:metrics"
      ]
    }
  }
}
```

### Default Roles

If no RBAC config is provided, the following default roles are used:

| Role | Permissions |
|------|-------------|
| `admin` | All read and write permissions |
| `operator` | All read permissions, `write:sessions` |
| `viewer` | `read:status`, `read:metrics` |

## API Endpoints

### GET /api/v1/status

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

### GET /api/v1/sessions

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

### DELETE /api/v1/sessions/:id

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

### GET /api/v1/policy

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

### POST /api/v1/policy/reload

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

### GET /api/v1/config

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

### GET /api/v1/metrics

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
curl -s https://localhost:8443/api/v1/sessions \
  --cert admin.pem --key admin-key.pem | jq
```

### Terminate a Session

```sh
curl -X DELETE https://localhost:8443/api/v1/sessions/42 \
  --cert admin.pem --key admin-key.pem
```

### Trigger Policy Reload

```sh
curl -X POST https://localhost:8443/api/v1/policy/reload \
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
    metrics_path: /api/v1/metrics
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
