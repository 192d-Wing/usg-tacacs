---
icon: lucide/key-round
---

# EST certificate provisioning

USG TACACS includes an RFC 7030 EST integration for certificate enrollment and
renewal. EST settings remain compatibility CLI/environment configuration. The
Helm chart renders those settings only for the management workload and keeps
listener paths in typed YAML.

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

The chart can bootstrap and renew the management server certificate in each
management Pod:

```yaml
est:
  management:
    enabled: true
    serverUrl: https://est.example.mil/.well-known/est/usg-tacacs
    commonName: tacacs-management.lab.example.mil
    dnsSans:
      - tacacs-management.lab.example.mil
      - usg-tacacs-management.tacacs.svc
      - usg-tacacs-management.tacacs.svc.cluster.local
    organization: Example Organization
    caLabel: ""
    bootstrapSecret: tacacs-est-bootstrap
    authentication: basic
    username: tacacs-bootstrap
    renewalThreshold: 70
    renewalCheckIntervalSeconds: 3600
    bootstrapTimeoutSeconds: 300
```

For HTTP Basic bootstrap authentication, create a Secret containing only the
password:

```shell
kubectl -n tacacs create secret generic tacacs-est-bootstrap \
  --from-file=password=./est-bootstrap-password
```

For EST mTLS bootstrap, set `authentication: mtls` and create the Secret with
`client.crt` and `client.key` instead:

```shell
kubectl -n tacacs create secret generic tacacs-est-bootstrap \
  --from-file=client.crt=./est-bootstrap.crt \
  --from-file=client.key=./est-bootstrap.key
```

The management client trust bundle remains separate. The `tacacs-api-tls`
Secret must contain `client-ca.crt`; for CAC access this is the approved DoD
client trust bundle. EST issuer certificates do not replace it.

When EST is enabled, the listener reads:

```yaml
certificateFile: /run/tls/est/server.crt
privateKeyFile: /run/tls/est/server.key
clientCaFile: /run/tls/api/client-ca.crt
minimumVersion: "1.3"
```

Initial enrollment is required: the management listener does not start with a
missing or failed certificate. Each Pod generates its own key and CSR, requests
the configured DNS SANs, and stores the P-384 key in a memory-backed
`emptyDir`. Renewal rotates the key and uses `simplereenroll`; after validating
the renewed certificate, the server atomically swaps the management TLS
acceptor. Existing connections are not terminated and new connections receive
the renewed certificate.

This file-backed mode is intended for the lab and for deployments whose
approved key-custody boundary permits Pod-local memory-backed keys. A Pod
replacement generates a new key and enrollment. Production deployments that
require TPM or Luna HSM custody must use the planned PKCS#11/TPM key-provider
integration rather than exporting an HSM key into this volume. P-384 is a
FIPS-approved algorithm, but this software enrollment path is not itself a
claim that key generation occurs inside a validated FIPS 140-3 module.

The operations UI ingress is not served by the management process. Its
`tacacs-ui-tls` Secret must currently be populated by an external EST
controller or another approved certificate lifecycle system. Do not grant the
TACACS workload permission to mutate arbitrary Kubernetes Secrets.

## Validation

Test initial enrollment, renewal, failed renewal, expired bootstrap identity,
untrusted EST server, mismatched key/certificate, rollback, replica
coordination, and audit evidence in a non-production environment.
