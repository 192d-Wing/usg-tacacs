---
icon: lucide/key-round
---

# EST certificate provisioning

USG TACACS includes an RFC 7030 EST integration for certificate enrollment and
renewal. EST settings are currently compatibility CLI/environment
configuration; certificate file paths consumed by listeners remain in typed
YAML.

## Boundary

EST provisions or renews certificate material. It does not:

- change the listener's TLS 1.3 requirement;
- authorize a management client or NAD;
- replace RBAC certificate identity bindings;
- prove a vendor NAD supports RFC 9887; or
- permit private keys or bootstrap credentials in YAML.

## Production requirements

- Validate the EST server certificate and trust chain.
- Store bootstrap credentials in mounted secret files where supported.
- Generate private keys in the approved cryptographic boundary.
- Restrict enrollment identities and certificate profiles.
- Write renewed material atomically with restrictive permissions.
- Reload only after parsing and validating the complete new chain/key pair.
- Retain the prior certificate for a bounded rollback window.
- Audit enrollment, renewal, rejection, reload, and rollback without secrets.

## Kubernetes lifecycle

Prefer a dedicated certificate controller or approved secret/CSI integration
when it can satisfy the key-custody requirement. The listener reads:

```yaml
certificateFile: /run/tls/dataplane/server.crt
privateKeyFile: /run/tls/dataplane/server.key
clientCaFile: /run/tls/dataplane/client-ca.crt
minimumVersion: "1.3"
```

The provisioning mechanism updates the mounted source; the workload then
performs a controlled reload/rollout. Do not bake issued keys into an image or
write them to a ConfigMap.

## Validation

Test initial enrollment, renewal, failed renewal, expired bootstrap identity,
untrusted EST server, mismatched key/certificate, rollback, replica
coordination, and audit evidence in a non-production environment.

Migration of EST options into typed YAML remains future configuration work.
