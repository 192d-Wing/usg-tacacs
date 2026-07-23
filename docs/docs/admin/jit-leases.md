---
icon: lucide/key-round
---

# JIT password leases

USG TACACS can authenticate managed network devices against short-lived JITPW
password leases. The lease API is part of the mTLS management listener;
PostgreSQL is the authoritative lease store shared with the authentication path.

The feature is disabled unless `JIT_LEASE_STORE_URL` is set. When enabled, the
server fails startup unless all required secrets, managed NAD identities, API
mTLS, and signed audit logging are configured.

## Security model

- JITPW sends a password verifier and non-secret authorization metadata. The
  cleartext password is never returned by the API or included in audit events.
- TACACS derives the NAD identity from a validated client certificate for
  TACACS-over-TLS or from an explicit source-IP mapping plus a unique per-NAD
  shared secret for legacy TACACS+.
- A NAD listed in `JIT_MANAGED_NADS` uses only the JIT lease authenticator.
  LDAP, ICAM, and static-credential fallback are prohibited for that NAD.
- EIDs are canonical lowercase values, for example
  `john.e.willman3.mil`. Non-canonical input is rejected.
- Leases are NAD-bound, expire no later than 15 minutes after issuance, and can
  be revoked immediately.
- Lease administration requires a validated management API client certificate
  and an explicit RBAC permission.

## Prerequisites

1. Prefer TACACS-over-TLS and issue each capable NAD a unique certificate
   identity. For a legacy NAD, configure a unique TACACS shared secret, an exact
   source-IP-to-NAD mapping, anti-spoofing controls, and a protected management
   network or IPsec transport.
2. Configure the management API for TLS 1.3 and require client certificates.
3. Provision a dedicated PostgreSQL database reachable with certificate-
   validated TLS. Apply migrations with a deployment role and give the TACACS
   runtime role only the required data access.
4. Provision three independent secrets through mounted files:

   - PostgreSQL password
   - JIT lease verifier key
   - audit HMAC key

5. Route signed JSON audit output to immutable centralized storage and alert on
   gaps, signature failures, store errors, and repeated authentication rejects.

## Server configuration

Set the following environment variables on every TACACS replica:

| Variable | Required | Purpose |
|---|---:|---|
| `JIT_LEASE_STORE_URL` | yes | PostgreSQL URL without a password |
| `JIT_LEASE_STORE_PASSWORD_FILE` | yes | Mounted file containing the PostgreSQL password |
| `JIT_LEASE_STORE_CA_FILE` | yes | CA bundle used to validate the PostgreSQL server identity |
| `JIT_LEASE_VERIFIER_KEY_FILE` | yes | Mounted binary verifier key shared with the authorized JITPW issuer |
| `JIT_MANAGED_NADS` | yes | Comma-separated canonical NAD identities that require JIT exclusively |
| `JIT_LEGACY_NADS` | no | Comma-separated `IP=NAD_IDENTITY` mappings for managed legacy NADs |
| `AUDIT_HMAC_KEY_FILE` | yes | Hex-encoded key of at least 32 bytes for audit-record signatures |

Example Kubernetes environment and secret mounts:

```yaml
env:
  - name: JIT_LEASE_STORE_URL
    value: postgresql://tacacs_jit@jit-postgres.jitpw.svc:5432/tacacs?sslmode=verify-full
  - name: JIT_LEASE_STORE_PASSWORD_FILE
    value: /run/secrets/jit/postgres-password
  - name: JIT_LEASE_STORE_CA_FILE
    value: /run/tls/postgres-ca.crt
  - name: JIT_LEASE_VERIFIER_KEY_FILE
    value: /run/secrets/jit/verifier-key
  - name: JIT_MANAGED_NADS
    value: router-a.example.mil,router-b.example.mil
  - name: JIT_LEGACY_NADS
    value: 192.0.2.10=router-b.example.mil
  - name: AUDIT_HMAC_KEY_FILE
    value: /run/secrets/audit/hmac-key
```

Mount secret volumes read-only, restrict them to the TACACS service identity,
and never place secret values directly in environment variables, command-line
arguments, ConfigMaps, manifests, or logs.

### Database migration

Apply `crates/tacacs-server/migrations/0001_jit_leases.sql` with a dedicated
migration identity before starting a JIT-enabled TACACS replica. Do not grant
schema creation or alteration privileges to the runtime identity. Validate the
schema and take a recoverable database snapshot before deployment.

The initial migration is forward-only. To roll back the application, stop lease
issuance, revoke or drain active leases, deploy the previous TACACS release, and
retain the `jitpw` schema for forensic and recovery purposes. Schema removal is
a separately approved data-destruction operation, not an application rollback.

## Management API and RBAC

Enable the existing management listener with mTLS:

```text
--api-enabled
--api-listen 0.0.0.0:8443
--api-tls-cert /run/tls/server.crt
--api-tls-key /run/tls/server.key
--api-client-ca /run/tls/client-ca.crt
--api-rbac-config /etc/usg-tacacs/rbac.json
```

Use a dedicated JITPW client certificate and grant only the permissions its
component needs. The RBAC file format maps role names directly to permission
arrays:

```json
{
  "roles": {
    "jitpw-issuer": ["write:jit-leases"],
    "jitpw-auditor": ["read:jit-leases"]
  },
  "users": {
    "jitpw-api.example.mil": "jitpw-issuer",
    "jitpw-audit.example.mil": "jitpw-auditor"
  }
}
```

The certificate Common Name must exactly match the key under `users`. Keep
read and write identities separate where operationally possible. Never assign
the default `admin` role to the lease issuer.

## API operations

The authoritative OpenAPI 3.1.1 contract is available at
`/api/docs/jit/openapi.yaml`. Interactive Swagger UI is available at
`/api/docs/jit/`. Both routes require mTLS and `read:jit-leases`.

Lease operations are:

| Method | Path | Permission | Result |
|---|---|---|---|
| `POST` | `/api/v1/jit-leases` | `write:jit-leases` | Create a lease or replay an idempotent request |
| `GET` | `/api/v1/jit-leases/{lease_id}` | `read:jit-leases` | Return non-secret lease metadata |
| `DELETE` | `/api/v1/jit-leases/{lease_id}` | `write:jit-leases` | Revoke a lease idempotently |

Creation requests require `Idempotency-Key` and `X-Correlation-ID`. Preserve
the correlation ID across JITPW, TACACS, PostgreSQL telemetry, and centralized audit
records. Do not capture request bodies at proxies, service meshes, or APM agents
because the create body contains credential material.

## Audit and monitoring

Treat the signed structured audit stream as a required dependency. Collect at
least these JIT events:

- lease creation, read, revocation, expiration, and rejection;
- successful and rejected lease authentication;
- lease-store unavailability;
- management API authorization denials;
- configuration and secret-rotation events from the deployment platform.

Retain the actor certificate identity, canonical EID, NAD identity, lease ID,
correlation ID, outcome, reason code, source address, server instance, and event
time. Never retain passwords, verifiers, PostgreSQL credentials, verifier keys, or
audit-signing keys. Verify HMAC signatures before ingestion and preserve raw
records in write-once storage under the organization's retention policy.

## Rotation and recovery

Coordinate verifier-key rotation between JITPW and TACACS. Because a single
verifier key is active, drain or revoke outstanding leases before replacing the
key and restart all TACACS replicas as one controlled change. Rotate the
PostgreSQL credential independently, then verify store health before restoring
traffic.

If PostgreSQL becomes unavailable, managed NAD authentication fails closed. Do not
temporarily remove a NAD from `JIT_MANAGED_NADS` to restore access. Use the
documented emergency-access process, record the incident, and preserve all
related audit evidence.

## Validation checklist

- A valid lease authenticates only its exact lowercase EID and bound NAD.
- The same credential fails on an unbound NAD.
- Expired and revoked leases fail immediately.
- A managed NAD cannot fall back to LDAP, ICAM, or static credentials.
- An issuer certificate cannot read leases unless separately authorized.
- Swagger and the OpenAPI document reject clients without mTLS or
  `read:jit-leases`.
- Audit records contain correlation data and valid HMAC signatures but no
  credential material.

## Troubleshooting

| Symptom | Check |
|---|---|
| Server refuses startup | Confirm all required JIT variables, API mTLS files, and `AUDIT_HMAC_KEY_FILE` are present |
| API returns `403` | Match the client certificate CN exactly to the RBAC `users` entry and permission |
| API returns `503` | Verify PostgreSQL TLS trust, credentials, migration state, and network policy |
| Authentication rejects a valid-looking user | Confirm canonical lowercase EID, trusted TLS or legacy NAD identity, lease binding, expiry, and revocation state |
| Swagger cannot execute requests | Present the authorized client certificate to the browser and use the same management API origin |
