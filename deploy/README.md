# Deployment

Helm charts live under `deploy/charts`. Site-specific, non-secret values live
under `deploy/sites/<site-name>` and are intentionally ignored by Git. The
tracked `deploy/sites/example` directory documents the required shape without
containing operational addresses or credentials.

Kubernetes Secrets are not Helm values and must not be committed. Provision
them through the approved secret manager or CSI driver before installing a
chart.

## CloudNativePG

`deploy/charts/usg-tacacs-postgresql` creates the namespaced CloudNativePG
`Cluster`, its restricted ingress policy, and the JIT lease migration Job. It
does not install the cluster-scoped CloudNativePG operator and does not create
credentials.

Install a reviewed, version-pinned CloudNativePG operator first. Provision two
`kubernetes.io/basic-auth` Secrets:

- `tacacs-postgres-migration` with username `tacacs_migrator`;
- `tacacs-postgres-runtime` with username `tacacs_jit`.

The migration identity owns the `tacacs` database. The runtime identity is
non-owner, non-superuser, and receives only `USAGE` on the `jitpw` schema and
`SELECT`, `INSERT`, and `UPDATE` on `jitpw.jit_leases`. Remote superuser access
remains disabled. The migration Job uses PostgreSQL TLS 1.3 with
`sslmode=verify-full` and the operator-managed cluster CA.

Install the database chart before the TACACS chart:

```text
helm upgrade --install tacacs-db deploy/charts/usg-tacacs-postgresql \
  --namespace tacacs --values deploy/sites/<site>/usg-tacacs-postgresql.values.yaml
kubectl --namespace tacacs wait --for=condition=Ready cluster/tacacs-db --timeout=10m
kubectl --namespace tacacs wait --for=condition=Complete \
  job --selector=app.kubernetes.io/component=migration --timeout=10m
helm upgrade --install tacacs deploy/charts/usg-tacacs \
  --namespace tacacs --values deploy/sites/<site>/usg-tacacs.values.yaml
```

The chart defaults to one database instance for a lab. Use at least three
instances, topology-aware scheduling, tested backups, and point-in-time
recovery for production. Backup object stores and CNPG-I plugins are site
infrastructure and deliberately remain outside this chart.

The existing k3s manifests remain reference baselines while their workloads
are migrated into Helm charts.

## Typed server configuration

The `usg-tacacs` chart renders the declarative configuration to
`/etc/usg-tacacs/server.yaml`. A non-root init container runs
`usg-tacacs-config-check` before the server container starts. Invalid syntax,
unknown top-level fields, duplicate NADs or rules, invalid RBAC bindings,
non-TLS-1.3 management settings, and JIT lease durations over 15 minutes cause
the Pod to remain in the init phase.

Set `configuration.checkFiles=true` after the referenced Kubernetes Secret keys
and certificate files are mounted. This additionally verifies that every file
reference exists. Keep it disabled only while initially provisioning those
Secrets.

The server consumes `server.yaml` directly. Each legacy NAD `secretFile` must
refer to a file containing only that NAD's TACACS shared secret; do not point it
at the former aggregate `IP=secret` file. JIT store settings, authorization, and
management RBAC are no longer supplied through separate environment variables
or JSON files when `--config` is used.

The chart deploys independent `management`, `legacy`, and optional `tls`
workloads from the same server image. Each rendered configuration has exactly
one runtime role and one externally meaningful listener. This prevents a
legacy listener failure or rollout from coupling management availability to
the TLS data plane.

## EST-issued workload certificates

Set `pki.enabled=true` to create three cert-manager `Certificate` resources:

- the management API server certificate;
- the TACACS-over-TLS data-plane server certificate; and
- the UI Ingress server certificate.

All three reference the configured namespace-scoped
`pki.usg.mil/EstIssuer`. Install cert-manager, an explicit CertificateRequest
approver policy, and `usg-est-issuer` in the TACACS namespace before enabling
this option. Set `pki.issuer.create=true` to have the chart render the
namespace-local `EstIssuer` named by `pki.issuerRef.name`. The issuer's labeled,
immutable EST credential and trust Secrets remain PKI-administrator
prerequisites; this chart references but never renders or owns them. Leave
`pki.issuer.create=false` when a PKI administrator manages the `EstIssuer`
separately.

The resulting Secrets use the Kubernetes TLS convention (`tls.crt` and
`tls.key`). Pods remain Pending until their required certificate Secret exists,
so a failed or denied enrollment fails closed. The UI certificate is emitted
even though the UI Ingress is currently deployed separately.

Server certificates and client trust have different lifecycles and are never
combined. Provision these trust-only Secrets separately:

- `secrets.managementClientCa`: approved management clients, including CAC and
  JITPW workload issuers;
- `secrets.dataPlaneClientCa`: TACACS-over-TLS NAD client issuers; and
- `secrets.postgresCa`: PostgreSQL server trust.

When `pki.enabled=false`, an approved external certificate controller may
populate the same Secrets named under `pki.management.secretName` and
`pki.dataPlane.secretName`. Enable only the certificate targets used at the
site. Certificate policy is P-384 ECDSA, key rotation on every renewal,
`digital signature`, and `server auth`.

Management certificate identities must use an explicit typed selector:
`cn:`, `dns:`, `email:`, or `uri:`. The chart's NetworkPolicy admits port 8443
only from a declared namespace and matching Pod labels. Both selectors are
applied to the same peer; a matching Pod name in another namespace is not
sufficient.
