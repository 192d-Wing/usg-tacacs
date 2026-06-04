# TODO

## SSH Public Key Feature — Cluster Test Readiness

The `ssh_pub_key` user-store feature is implemented and compiles cleanly. CI now
builds and pushes a multi-arch image (`linux/amd64` + `linux/arm64`) to GHCR on
every push to master and on version tags — no manual image build needed.

Two gaps remain before cluster testing can begin.

### 1. Create the database Secret in k3s and update the deployment

The deployment at `deploy/k3s/manifests/deployment-tacacs.yaml` does not yet
pass `TACACS_DB_URL`. Create a Kubernetes Secret and reference it:

```bash
kubectl -n tacacs create secret generic tacacs-db \
  --from-literal=url='postgresql://tacacs:<pass>@<patroni-primary>:5432/tacacs'
```

Add to the Deployment under `spec.containers[].env`:

```yaml
- name: TACACS_DB_URL
  valueFrom:
    secretKeyRef:
      name: tacacs-db
      key: url
```

Also update the image tag in the Deployment to the new multi-arch tag produced
by CI (e.g. `ghcr.io/192d-wing/usg-tacacs:master` or the SHA tag). No arch
suffix is required — the manifest list routes to the right arch automatically.

The server runs schema migrations (`CREATE TABLE IF NOT EXISTS`) at startup, so
no separate init job is needed.

### 2. Decide on the PostgreSQL endpoint

The external Patroni cluster (deployed via `iac/ansible/playbooks/deploy-postgresql-ha.yml`)
is the right target — it is already HA and managed. No in-cluster PostgreSQL is
deployed and none is needed.

Point `TACACS_DB_URL` at the Patroni primary VIP or PgBouncer endpoint.
