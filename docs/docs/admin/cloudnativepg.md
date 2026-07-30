---
icon: lucide/database
---

# CloudNativePG deployment

USG TACACS uses a separately installed CloudNativePG operator and the
`deploy/charts/usg-tacacs-postgresql` Helm chart. The database chart creates
the namespaced `Cluster`, database ingress policy, and JIT lease migration Job.
It does not install the cluster-scoped operator, create credentials, configure
object storage, or own the site's recovery policy.

The editable deployment diagram is
[`tacacs-cloudnativepg.drawio`](https://github.com/192d-Wing/usg-tacacs/blob/main/docs/api/mgmt/tacacs-cloudnativepg.drawio).

## Security boundary

| Identity | Purpose | Required privilege |
| --- | --- | --- |
| `tacacs_migrator` | Bootstrap the database and apply reviewed schema migrations | Database owner and schema owner |
| `tacacs_jit` | Management and TACACS workload access to active JIT leases | `USAGE` on `jitpw`; `SELECT`, `INSERT`, and `UPDATE` on `jitpw.jit_leases` |
| CloudNativePG operator | Reconcile instances, certificates, and failover | Operator permissions defined by its independently reviewed installation |

The runtime identity is not a database owner, superuser, role administrator,
replication identity, or row-security bypass identity. The chart disables
remote PostgreSQL superuser access. Do not give TACACS workloads the migration
credential.

Both referenced Secrets must be `kubernetes.io/basic-auth` Secrets containing
matching `username` and `password` keys:

- `tacacs-postgres-migration` for `tacacs_migrator`;
- `tacacs-postgres-runtime` for `tacacs_jit`.

Provision them through the approved external secret controller, CSI provider,
or sealed GitOps workflow. Do not place their values in Helm values, manifests,
shell history, CI output, or repository files.

## Production prerequisites

Before installing the database chart:

1. Install a reviewed and version-pinned CloudNativePG operator.
2. Enforce Pod Security Admission at the namespace boundary.
3. Provision an encrypted StorageClass with expansion and the required failure
   domain behavior.
4. Provision the two database credential Secrets.
5. Select digest-pinned PostgreSQL and migration images.
6. Configure and test encrypted backups, object-store access, retention, and
   point-in-time recovery using site-managed CloudNativePG resources.
7. Verify that monitoring and alerts cover cluster readiness, replication lag,
   failed backups, storage capacity, certificate expiry, and repeated failover.

The example values use one instance and local storage for a lab. Production
deployments should use at least three instances distributed across independent
failure domains. Backup configuration and topology constraints are deliberate
site concerns and are not silently supplied by this chart.

## Values

Create an untracked
`deploy/sites/<site>/usg-tacacs-postgresql.values.yaml`:

```yaml
cluster:
  name: tacacs-db
  instances: 3
  imageName: ghcr.io/cloudnative-pg/postgresql:18.4-system-trixie@sha256:REVIEWED_DIGEST
  storage:
    size: 100Gi
    storageClass: encrypted-production
  resources:
    requests:
      cpu: 500m
      memory: 2Gi
    limits:
      cpu: "2"
      memory: 4Gi

database:
  name: tacacs
  migrationRole: tacacs_migrator
  runtimeRole: tacacs_jit
  migrationSecret: tacacs-postgres-migration
  runtimeSecret: tacacs-postgres-runtime

migration:
  enabled: true
  image: ghcr.io/cloudnative-pg/postgresql:18.4-system-trixie@sha256:REVIEWED_DIGEST

networkPolicy:
  enabled: true
  operator:
    namespace: cnpg-system
    podLabels:
      app.kubernetes.io/name: cloudnative-pg
  tacacsPodLabels:
    app.kubernetes.io/name: usg-tacacs

monitoring:
  enablePodMonitor: true
```

Keep the operator namespace and Pod labels aligned with the installed operator.
The database NetworkPolicy permits PostgreSQL only from cluster peers, matching
TACACS Pods, and the migration Job. It admits the operator on its management
port using both namespace and Pod selectors. Treat disabling this policy as a
security exception requiring an equivalent enforced control.

## Render and install

Validate both the schema and rendered resources before changing the cluster:

```shell
helm lint deploy/charts/usg-tacacs-postgresql

helm template tacacs-db deploy/charts/usg-tacacs-postgresql \
  --namespace tacacs \
  --values deploy/sites/<site>/usg-tacacs-postgresql.values.yaml
```

Review the image digests, instance count, storage class, resources, role names,
Secret references, NetworkPolicy selectors, migration security context, and
TLS settings. Then install the database before the TACACS workloads:

```shell
helm upgrade --install tacacs-db deploy/charts/usg-tacacs-postgresql \
  --namespace tacacs \
  --create-namespace \
  --values deploy/sites/<site>/usg-tacacs-postgresql.values.yaml

kubectl --namespace tacacs wait \
  --for=condition=Ready cluster/tacacs-db --timeout=10m

kubectl --namespace tacacs wait \
  --for=condition=Complete \
  job --selector=app.kubernetes.io/component=migration --timeout=10m
```

Do not install or roll forward USG TACACS if the Cluster is not ready or the
migration Job did not complete successfully.

## TACACS connection

Configure the TACACS chart to use the CloudNativePG read/write Service and
operator-managed server CA:

```yaml
postgres:
  url: postgresql://tacacs_jit@tacacs-db-rw.tacacs.svc.cluster.local:5432/tacacs?sslmode=verify-full

secrets:
  postgresCredentials: tacacs-postgres-runtime
  postgresCa: tacacs-db-ca
```

The hostname in the URL must match a name covered by the database server
certificate. All production connections use `sslmode=verify-full`; do not
replace it with `require`, disable verification, or use an IP address that is
not present in the certificate.

## Enforced database controls

The chart configures:

- PostgreSQL TLS minimum version 1.3;
- SCRAM-SHA-256 password storage;
- data checksums at initialization;
- connection and disconnection logging;
- DDL statement logging;
- disabled remote superuser access;
- a 50-connection limit for the runtime role;
- no default read-only or replica Services;
- a non-root, read-only, capability-free migration container;
- a short-lived password file on a size-limited `emptyDir`;
- `sslmode=verify-full` for migrations.

These controls do not replace encryption at rest, Kubernetes audit logging,
central log protection, backup encryption, or database activity monitoring.

## Verification

After installation, retain evidence for:

```shell
kubectl --namespace tacacs get cluster tacacs-db
kubectl --namespace tacacs get pods -l cnpg.io/cluster=tacacs-db
kubectl --namespace tacacs get jobs \
  -l app.kubernetes.io/component=migration
kubectl --namespace tacacs get networkpolicy tacacs-db
```

Also verify:

- three healthy instances occupy the intended failure domains;
- an unauthorized test Pod cannot reach TCP/5432;
- TACACS connects only with the runtime identity and validated CA;
- the runtime identity cannot create schemas, roles, or tables;
- backup completion and restore-to-new-cluster exercises succeed;
- loss of the primary promotes a replica within the approved recovery target;
- audit and database timestamps are synchronized to the approved time source.

Never print Secret objects, connection passwords, lease verifier material, or
database dumps into validation logs.

## Upgrade and recovery

Back up and verify recovery metadata before operator, PostgreSQL image, chart,
or schema changes. Upgrade the operator only through its documented compatible
version path. Render and review every chart diff, apply migrations once, and
verify database health before rolling TACACS workloads.

Restore into a new recovery Cluster rather than overwriting the damaged
Cluster. Preserve the original database, Kubernetes audit records, CloudNativePG
events, and signed TACACS evidence when compromise is suspected. Rotate both
database identities after credential exposure; rotate the migration identity
again after the repair window closes.
