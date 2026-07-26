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
the TLS data plane. Enable the required roles under `workloads`; enabling TLS
requires the `secrets.dataPlaneTls` certificate Secret.

Management certificate identities must use an explicit typed selector:
`cn:`, `dns:`, `email:`, or `uri:`. The chart's NetworkPolicy admits port 8443
only from a declared namespace and matching Pod labels. Both selectors are
applied to the same peer; a matching Pod name in another namespace is not
sufficient.
