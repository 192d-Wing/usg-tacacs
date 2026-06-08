# usg-tacacs Helm chart

Reusable, hardened packaging of the usg-tacacs TACACS+ server (RFC 8907 / RFC
9887) and its optional Redis group cache. The defaults are **secure by
default** and equivalent to — and in places stricter than — the hand-written
`deploy/k3s/manifests/` baseline.

> NIST SP 800-53 Rev. 5: CM-2/CM-6 (baseline configuration & settings),
> AC-6/CM-7 (least privilege / least functionality), SC-7 (boundary protection).

## What it deploys

| Object | Purpose | Notes |
|---|---|---|
| Namespace | Trust boundary | Pod Security Admission `restricted` enforced |
| ServiceAccount | Pod identity | No API token mounted |
| Deployment (tacacs) | TACACS+ server | non-root, read-only rootfs, dropped caps, seccomp |
| Deployment/Service (redis) | Group cache | in-memory, password, Iron Bank image |
| Service (LoadBalancer) | Anycast :49/:300 | `externalTrafficPolicy: Local` |
| Service (headless) | Metrics :8080 | Prometheus discovery |
| NetworkPolicy ×4 | default-deny + ingress + egress + redis | SC-7 |
| PodDisruptionBudget | Availability | `minAvailable: 2` |
| ResourceQuota + LimitRange | Namespace guardrails | SC-5/SC-6 |
| ConfigMap (policy) | Authorization policy | optional / `existingConfigMap` |

## Install

```bash
# 1. Create the Secrets out-of-band (see KUBE_HARDENING.md §Secrets).
# 2. Install / upgrade:
helm upgrade --install tacacs deploy/helm/usg-tacacs \
  -n tacacs --create-namespace \
  -f deploy/helm/usg-tacacs/values-prod-k3s.yaml
```

Render without applying (review the diff):

```bash
helm template tacacs deploy/helm/usg-tacacs -f deploy/helm/usg-tacacs/values-prod-k3s.yaml
```

## Required Secrets (not templated by default)

| Secret | Keys |
|---|---|
| `tacacs-tls` | `server.pem`, `server-key.pem`, `ca.pem`, `secret`, `audit-hmac-key` |
| `tacacs-icam` | `client-secret` |
| `oopl-ca` | `ca.pem` |
| `tacacs-group-cache` | `password` |
| `registry1-pull` | dockerconfigjson (Redis Iron Bank pull) |

`secrets.create=true` can template them for **dev/CI only** — never in
production (values land in Helm release history). Prefer sealed-secrets,
external-secrets, or SOPS.

## Key values

See [values.yaml](values.yaml) for the full, commented set. Most-overridden:

- `image.tag` / `image.digest` — pin a digest for immutable deploys.
- `replicaCount`, `resources`, `podDisruptionBudget.minAvailable`.
- `networkPolicy.ingress.nadCidrs` — **must** match your real NAD/management
  ranges or devices are denied at :49/:300.
- `networkPolicy.egress.icamCidrs` — lock egress to the Keycloak host(s).
- `config.icam.*`, `config.groupCache.url`.
- `redis.enabled` — set `false` to use an external cache.

## Verify the posture after install

```bash
kubectl -n tacacs get pods,netpol,pdb,resourcequota
kubectl -n tacacs get ns tacacs -o jsonpath='{.metadata.labels}' | grep pod-security
helm template tacacs deploy/helm/usg-tacacs | trivy config -   # 0 HIGH/CRITICAL
```

## Tested with

`helm lint` (0 failures) and `trivy config` (0 HIGH/CRITICAL). Remaining
LOW/MEDIUM trivy notes are documented, justified deviations — see
KUBE_HARDENING.md §Residual risk.
