---
icon: lucide/container
---

# Kubernetes and Helm deployment

The supported production packaging is `deploy/charts/usg-tacacs`. It renders
independent `management`, `legacy`, and optional `tls` workloads from one
server image. Docker Compose material, where retained in repository history,
is not the production deployment model.

## Prepare

1. Create a site values file outside Git under `deploy/sites/<site>`.
2. Pin the released image tag and preferably its digest.
3. Install the independently managed CloudNativePG operator.
4. Provision the database credential Secrets, install
   `deploy/charts/usg-tacacs-postgresql`, and wait for its migration Job.
5. Provision runtime, API TLS, optional data-plane TLS, PostgreSQL CA, NAD,
   audit, and verifier secrets.
6. Configure NetworkPolicy management peers.
7. Set workload replica counts and LoadBalancer addresses.

Never put Kubernetes Secret data in values files.

The database chart defaults to a single lab instance. Production requires a
site-reviewed multi-instance topology, encrypted durable storage, tested
backups and point-in-time recovery, monitoring, and failure-domain placement.
See [CloudNativePG deployment](admin/cloudnativepg.md).

## Validate and render

```shell
helm lint deploy/charts/usg-tacacs

helm template usg-tacacs deploy/charts/usg-tacacs \
  --namespace usg-tacacs \
  --values deploy/sites/example/usg-tacacs.values.yaml
```

Review rendered roles, listeners, images, service accounts, volumes,
NetworkPolicies, Services, probes, and security contexts. The init container
runs `usg-tacacs-config-check`; enable `configuration.checkFiles` after all
referenced files are mounted.

## Install

```shell
helm upgrade --install usg-tacacs deploy/charts/usg-tacacs \
  --namespace usg-tacacs \
  --create-namespace \
  --values deploy/sites/example/usg-tacacs.values.yaml
```

Production site values must replace the example. Verify management first, then
each enabled data-plane transport, reconciliation, AAA, and signed audit
delivery.

Database installation and migration must complete before installing or
upgrading the TACACS workloads:

```shell
helm upgrade --install tacacs-db deploy/charts/usg-tacacs-postgresql \
  --namespace usg-tacacs \
  --values deploy/sites/<site>/usg-tacacs-postgresql.values.yaml

kubectl --namespace usg-tacacs wait \
  --for=condition=Ready cluster/tacacs-db --timeout=10m

kubectl --namespace usg-tacacs wait \
  --for=condition=Complete \
  job --selector=app.kubernetes.io/component=migration --timeout=10m
```

## Source identity

Legacy per-NAD secret selection and forensic attribution require the original
NAD source address. Use `externalTrafficPolicy: Local` with the documented
Cilium/BGP behavior and confirm the peer address after deployment.

See [Operator guide](operator/index.md) and the repository `deploy/README.md`.
