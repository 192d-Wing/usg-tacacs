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
3. Provision PostgreSQL and apply release migrations.
4. Provision runtime, API TLS, optional data-plane TLS, PostgreSQL CA, NAD,
   audit, and verifier secrets.
5. Configure NetworkPolicy management peers.
6. Set workload replica counts and LoadBalancer addresses.

Never put Kubernetes Secret data in values files.

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

## Source identity

Legacy per-NAD secret selection and forensic attribution require the original
NAD source address. Use `externalTrafficPolicy: Local` with the documented
Cilium/BGP behavior and confirm the peer address after deployment.

See [Operator guide](operator/index.md) and the repository `deploy/README.md`.
