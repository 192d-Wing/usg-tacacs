---
icon: lucide/settings
---

# Typed configuration reference

Production workloads consume one strict YAML `TacacsServer` document. The Rust
type in `crates/tacacs-config` and its generated schema are authoritative.
Unknown fields, invalid role/listener combinations, duplicate NADs or rule IDs,
untyped RBAC identities, non-absolute secret paths, and JIT TTLs above 900
seconds are rejected.

```yaml
apiVersion: tacacs.usg.mil/v1alpha1
kind: TacacsServer
metadata:
  name: lab
  description: Lab TACACS service
spec:
  role: management
  listeners:
    health: 0.0.0.0:8080
  nads: []
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

## Top-level fields

| Field | Requirement |
| --- | --- |
| `apiVersion` | Exactly `tacacs.usg.mil/v1alpha1` |
| `kind` | Exactly `TacacsServer` |
| `metadata.name` | Non-empty instance name |
| `metadata.description` | Optional operator description |
| `spec.role` | `management`, `legacy`, or `tls` |

## Roles and listeners

Each document represents exactly one runtime role:

```yaml
# Legacy data plane
spec:
  role: legacy
  listeners:
    legacy: 0.0.0.0:49
    health: 0.0.0.0:8080
```

```yaml
# TLS data plane
spec:
  role: tls
  listeners:
    tls:
      address: 0.0.0.0:300
      certificateFile: /run/tls/dataplane/server.crt
      privateKeyFile: /run/tls/dataplane/server.key
      clientCaFile: /run/tls/dataplane/client-ca.crt
      minimumVersion: "1.3"
    health: 0.0.0.0:8080
```

A management document contains `spec.management` and no data-plane listener.
A legacy or TLS document must not contain `spec.management`.

## NADs

Names and source addresses must be unique.

```yaml
nads:
  - name: oopl-an-001
    description: IOS-XE lab switch
    sourceAddress: 192.0.2.10
    mode: legacy
    secretFile: /run/secrets/nads/oopl-an-001
  - name: tls-nad-001
    description: Verified RFC 9887 device
    sourceAddress: 192.0.2.11
    mode: tls
    certificateIdentities:
      - tls-nad-001.example.mil
```

`secretFile` is an absolute path inside the container containing only that
NAD's secret. A TLS NAD requires at least one certificate identity. Declaring
`mode: tls` does not make a device TLS-capable; verify vendor/platform support
and packet-level behavior before enabling the TLS role.

## Authorization

```yaml
authorization:
  defaultAllow: false
  rules:
    - id: network-admin-show
      priority: 100
      effect: allow
      users: []
      groups: [network-admins]
      nadGroups: []
      command: "^show(?: .*)?$"
```

Rule IDs are unique. `effect` is `allow` or `deny`; omitted match arrays are
empty. Keep `defaultAllow: false`. See [Authorization policy](policy.md).

## Management and RBAC

Management TLS always uses version 1.3 and client certificates:

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
        description: NAD lifecycle automation
        permissions:
          - tacacs:ListNads
          - tacacs:GetNad
          - tacacs:CreateNad
          - tacacs:UpdateNad
          - tacacs:DeleteNad
    subjects:
      - certificateIdentity: uri:spiffe://example.mil/tacacs/nad-automation
        role: nad-automation
```

Certificate identities require a typed `cn:`, `dns:`, `email:`, or `uri:`
prefix. DNS and email forms must be lowercase. Roles must contain at least one
permission and bindings must reference a defined role.

## Audit and JIT

```yaml
audit:
  hmacKeyFile: /run/secrets/audit/hmac-key
jit:
  storeUrl: postgresql://tacacs_jit@postgres.example.mil:5432/tacacs?sslmode=verify-full
  storePasswordFile: /run/secrets/postgres/password
  storeCaFile: /run/tls/postgres/ca.crt
  verifierKeyFile: /run/secrets/jit/verifier-key
  maximumTtlSeconds: 900
```

All paths are absolute. `maximumTtlSeconds` must be 1 through 900.

## Validation

```shell
cargo run --locked -p usg-tacacs-config \
  --bin usg-tacacs-config-check -- ./server.yaml
```

Use `--check-files` in the target container or an equivalent environment where
referenced files are mounted. The Management API also provides dry-run
validation and schema/effective-config inspection.

## Compatibility configuration

The server still exposes CLI/environment options for integrations not yet
represented by `TacacsServer`, including some LDAPS, ICAM/OIDC, EST, telemetry,
rate-limit, and compatibility modes. They are not a second declarative source
and must not be represented as `config.json`. Track and review them in the
workload definition until their typed-YAML migration is complete.
