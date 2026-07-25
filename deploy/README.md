# Deployment

Helm charts live under `deploy/charts`. Site-specific, non-secret values live
under `deploy/sites/<site-name>` and are intentionally ignored by Git. The
tracked `deploy/sites/example` directory documents the required shape without
containing operational addresses or credentials.

Kubernetes Secrets are not Helm values and must not be committed. Provision
them through the approved secret manager or CSI driver before installing a
chart.

The existing k3s manifests remain reference baselines while their workloads
are migrated into Helm charts.
