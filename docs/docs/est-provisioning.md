---
icon: lucide/key-round
---

# EST certificate provisioning

The USG TACACS Helm chart delegates server certificate lifecycle to
cert-manager and the namespace-scoped `usg-est-issuer`. This provides one
audited RFC 7030 path for the management API, TACACS-over-TLS data plane, and
UI Ingress certificates.

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

## Prerequisites

Install cert-manager, a CertificateRequest approver policy, and one
`usg-est-issuer` controller watching the TACACS namespace. Create the immutable
EST transport-trust and authentication Secrets in that namespace. The chart
can create the namespace-local `EstIssuer`, or a PKI administrator can manage
it separately. Issuer credential Secrets must carry
`pki.usg.mil/est-issuer: "true"` and `immutable: true`.

Application operators must not be able to create or relabel issuer credential
Secrets. The approver policy must constrain the three expected DNS identities,
P-384 ECDSA keys, requested durations, and `server auth` usage. Approval and
issuer policy are independent gates and must both accept a request.

## Kubernetes lifecycle

Enable all three certificate resources in site values:

```yaml
pki:
  enabled: true
  issuerRef:
    name: enterprise-est
    kind: EstIssuer
    group: pki.usg.mil
  issuer:
    create: true
    serverUrl: https://est.example.mil/.well-known/est
    authentication:
      trustSecretName: est-server-trust
      method: mutualTls
      secretName: est-bootstrap-identity
    policy:
      allowedDnsSuffixes:
        - example.mil
        - tacacs.svc.cluster.local
      maxDnsSans: 10
      maxDuration: 720h
  duration: 720h
  renewBefore: 168h
  privateKey:
    algorithm: ECDSA
    size: 384
    rotationPolicy: Always
  management:
    enabled: true
    secretName: tacacs-management-tls
    commonName: tacacs-management.example.mil
    dnsNames:
      - tacacs-management.example.mil
      - usg-tacacs-management.tacacs.svc
      - usg-tacacs-management.tacacs.svc.cluster.local
  dataPlane:
    enabled: true
    secretName: tacacs-dataplane-tls
    commonName: tacacs.example.mil
    dnsNames:
      - tacacs.example.mil
      - usg-tacacs-tls.tacacs.svc
      - usg-tacacs-tls.tacacs.svc.cluster.local
  ui:
    enabled: true
    secretName: tacacs-ui-tls
    commonName: tacacs-ui.example.mil
    dnsNames:
      - tacacs-ui.example.mil
```

With `pki.issuer.create=true`, Helm creates the `EstIssuer` in the release
namespace. The EST URL and policy are ordinary configuration, but the
transport trust and bootstrap identity remain references to pre-provisioned
Secrets. Set `create=false` if that issuer is managed outside this release.

cert-manager generates each private key and stores it in its Kubernetes
certificate lifecycle Secrets. `usg-est-issuer` reads the immutable CSR from
the CertificateRequest and never reads or returns the private key.

The management and data-plane listeners consume standard `tls.crt` and
`tls.key` keys. Their client trust bundles remain separate:

```yaml
secrets:
  managementClientCa: tacacs-management-client-ca
  dataPlaneClientCa: tacacs-dataplane-client-ca
  postgresCa: tacacs-postgres-ca
```

Each trust Secret contains `ca.crt`. The management bundle authorizes
management clients; the data-plane bundle validates TLS-capable NADs; and the
PostgreSQL bundle validates the database server. None is an EST bootstrap
credential.

A management or TLS Pod cannot start until Kubernetes can mount its certificate
and trust Secrets. Denied or unavailable enrollment therefore fails closed.

## Validation

Test initial enrollment, renewal, failed renewal, expired bootstrap identity,
untrusted EST server, mismatched key/certificate, rollback, replica
coordination, and audit evidence in a non-production environment.

Check the `Certificate`, `CertificateRequest`, `EstIssuer`, approver, and
`usg-est-issuer` conditions before investigating the TACACS container.
