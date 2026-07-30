---
icon: lucide/shield-alert
---

# Administrator guide

This guide is for the people who design and administer a USG TACACS
installation. It describes desired-state configuration, administrative
security boundaries, and the interfaces used to manage the service.

Day-to-day procedures, alerts, upgrades, and incident response are in the
[Operator guide](../operator/index.md). Instructions for people connecting to
network devices are in the [User guide](../user/index.md).

## Architecture and trust boundaries

A production deployment separates three runtime roles built from the same
server image:

| Role | Purpose | Typical listener |
| --- | --- | --- |
| `management` | Management API, Swagger UI, health, and reconciliation | TCP/8443, TLS 1.3 mTLS |
| `legacy` | TACACS+ for NADs without TACACS-over-TLS | TCP/49 |
| `tls` | TACACS+ over TLS for capable NADs | TCP/300 |

The roles should run as independent Kubernetes workloads. A failure or rollout
of one data-plane listener must not take down management or the other listener.
PostgreSQL holds API-owned NAD desired state, management operations, JIT lease
verifiers, and forensic NAD audit records. YAML remains authoritative for
baseline resources.

## Authoritative configuration

USG TACACS uses one strict, typed YAML document. Start with
`docs/config/server.example.yaml`:

```yaml
apiVersion: tacacs.usg.mil/v1alpha1
kind: TacacsServer
metadata:
  name: production
  description: Production TACACS service
spec:
  role: management
  listeners:
    health: 0.0.0.0:8080
  nads:
    - name: oopl-an-001
      description: IOS-XE access switch
      sourceAddress: 192.0.2.10
      mode: legacy
      secretFile: /run/secrets/nads/oopl-an-001
  authorization:
    defaultAllow: false
    rules: []
  management:
    listener:
      address: 0.0.0.0:8443
      certificateFile: /run/secrets/management/tls.crt
      privateKeyFile: /run/secrets/management/tls.key
      clientCaFile: /run/secrets/management/client-ca.crt
      minimumVersion: "1.3"
    rbac:
      roles: {}
      subjects: []
  audit:
    hmacKeyFile: /run/secrets/audit/hmac-key
```

Unknown fields and invalid combinations fail validation. File references are
paths, never secret values. Do not put shared secrets, database passwords,
private keys, JIT verifier keys, or audit keys in YAML, Helm values, ConfigMaps,
environment variables, or command lines.

### Configuration ownership

Every NAD has exactly one owner:

- **YAML-owned NADs** are immutable through the Management API. Change them in
  the reviewed configuration repository and roll out the resulting release.
- **API-owned NADs** are created by an authorized administrator or automation
  through the Management API. They become usable only after reconciliation
  validates the resource and resolves its external secret reference.

Use `GET /api/mgmt/v1/nads/inventory` to see both sources, ownership, and
mutability. A name or source-address collision between the two sources fails
closed and appears in reconciliation status.

## Authorization and management RBAC

These are separate controls:

- `spec.authorization` governs what authenticated network users may do on
  devices. Rules should be deny-by-default, narrowly scoped, ordered, reviewed,
  and identified with stable rule IDs.
- `spec.management.rbac` governs which certificate-authenticated clients may
  use Management API operations.

Use typed certificate selectors (`cn:`, `dns:`, `email:`, or `uri:`). Grant
automation only the permissions it requires. NAD automation normally needs
`read:nads` and/or `write:nads`; forensic export requires `read:audit`.

See [Policy](../policy.md) and
[Management API](management-api.md) for the complete formats and permissions.

## Secret management

`secretFile: /run/secrets/nads/oopl-an-001` names a file inside the server
container. In Kubernetes it should be provided by a Secret volume or approved
CSI secret-store driver. It is not a path on the administrator workstation and
it is not created by the YAML ConfigMap.

Required controls:

1. Give each legacy NAD a unique, randomly generated shared secret.
2. Mount secrets read-only and only into the workload that needs them.
3. Restrict the secret provider identity to the smallest required path.
4. Rotate one NAD at a time using the documented recovery path.
5. Never return resolved secrets through the Management API or log them.
6. Back up keys only under the organization's approved key-custody procedure.

TLS-capable NADs should use unique certificate identities. Legacy TACACS+
remains supported for devices that cannot use TACACS-over-TLS and should be
protected by source-address enforcement and a dedicated management network or
IPsec.

## Deployment

The supported Kubernetes packaging is the Helm chart under
`deploy/charts/usg-tacacs`. Site values belong under `deploy/sites/<site>`,
which is ignored by Git except for the tracked example. Kubernetes Secrets are
provisioned separately.

Before installation:

1. Install the independently managed CloudNativePG operator.
2. Provision separate migration/runtime database identities and install the
   `usg-tacacs-postgresql` chart.
3. Wait for database readiness and successful migrations.
4. Provision management mTLS, optional data-plane TLS, NAD, audit, and JIT
   secrets.
5. Render the chart and review every listener, Service, NetworkPolicy, volume,
   and security context.
6. Run the configuration checker with file checking enabled in the target
   environment.
7. Install or upgrade the chart and wait for every role to become ready.
8. Verify Management API mTLS, reconciliation, legacy/TLS authentication,
   authorization, accounting, and signed audit delivery.

See [Container deployment](../container.md), the repository `deploy/README.md`,
[CloudNativePG deployment](cloudnativepg.md), and the
[Operator guide](../operator/index.md).

## Management API

The Management API is separate from the JITPW API. Its authoritative OpenAPI
3.1.1 contract and Swagger UI are served by the management role. Production
access requires TLS 1.3 mutual authentication and RBAC; a proxy must preserve
the authenticated client identity by using TCP passthrough.

Administrative changes require a UUID correlation ID. Creates use an
`Idempotency-Key`; updates and deletes use the current ETag in `If-Match`.
Accepted changes are desired state, not proof that the NAD is active. Always
check reconciliation.

See [Management API](management-api.md) and
[NAD lifecycle](../operator/nad-lifecycle.md).

## JIT password leases

JITPW issues short-lived, NAD-bound credentials through the dedicated lease
interface. USG TACACS stores a keyed verifier rather than a recoverable
password. Managed NADs fail closed and cannot fall back to LDAP, ICAM, or
static credentials. Maximum lease lifetime is 15 minutes.

The JITPW issuer needs only its lease-write permission. It must not receive
general Management API administrator privileges. See
[JIT password leases](jit-leases.md).

## Administrative readiness checklist

- All configuration passes strict typed validation.
- Management uses TLS 1.3 mTLS with typed certificate identities.
- YAML and API ownership are unambiguous.
- Each legacy NAD has a unique external secret and exact source mapping.
- Authorization and management RBAC are deny-by-default.
- PostgreSQL uses certificate-validated TLS and least-privilege roles.
- CloudNativePG uses at least three production instances, encrypted storage,
  restricted ingress, monitored backups, and tested point-in-time recovery.
- Audit HMAC keys and JIT verifier keys are independent.
- Raw signed audit records reach immutable centralized storage.
- Restore, rotation, rollback, and break-glass procedures have been exercised.
- Operators can distinguish accepted API state from reconciled runtime state.

## Related guides

- [Configuration reference](../config.md)
- [TLS setup](../tls.md)
- [Security hardening](security.md)
- [Reverse proxy mTLS](reverse-proxy-mtls.md)
- [Operator guide](../operator/index.md)
- [Forensic incident response](../operator/incident-response.md)
