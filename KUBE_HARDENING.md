# Kubernetes Hardening & Vulnerability Assessment — usg-tacacs

> **Scope:** the usg-tacacs TACACS+ server, its Redis group cache, and the
> Kubernetes deployment (`deploy/k3s/` baseline + the reusable
> `deploy/helm/usg-tacacs/` chart).
> **Date of assessment:** 2026-06-07 · **Server version:** 0.81.11
> **Frameworks:** NIST SP 800-53 Rev. 5, CIS Kubernetes Benchmark, Pod Security
> Standards (`restricted`), NSA/CISA *Kubernetes Hardening Guidance*.

This document is the authoritative reference for **how the deployment is locked
down, why, and how to keep it that way.** It pairs with the Helm chart at
[`deploy/helm/usg-tacacs/`](deploy/helm/usg-tacacs/), which encodes every
control below as version-controlled, reusable configuration.

---

## 1. Executive summary

The usg-tacacs workload was already strongly hardened (non-root, read-only root
filesystem, dropped capabilities, seccomp, ingress NetworkPolicies, resource
limits, HMAC-signed audit, mTLS). This assessment **found no critical or high
vulnerabilities** in the code or the running deployment. It closed a set of
**defense-in-depth gaps** by adding:

| Gap closed | Control | Where |
|---|---|---|
| No egress restriction (allow-all) | Default-deny + egress allow-list NetworkPolicies | chart `networkpolicy.yaml` |
| No Pod Security Admission enforcement | Namespace `enforce: restricted` labels | chart `namespace.yaml` |
| No PodDisruptionBudget | `minAvailable: 2` | chart `poddisruptionbudget.yaml` |
| Default ServiceAccount reused | Dedicated SA, no token automount | chart `serviceaccount.yaml` |
| No namespace resource guardrails | ResourceQuota + LimitRange | chart `quota.yaml` |
| Mutable image tags only | Optional digest pinning | chart `image.digest` |
| Config drift / not reusable | Parameterized Helm chart | whole chart |

**Verification:** `helm lint` → 0 failures; `trivy config` on the rendered
chart → **0 HIGH/CRITICAL** misconfigurations. Remaining LOW/MEDIUM notes are
documented, justified deviations (§7).

---

## 2. Code & supply-chain vulnerability assessment

### 2.1 Methodology
- **Dependency advisories:** `cargo audit` against `Cargo.lock` (532 crates).
- **Policy/license/bans:** `cargo deny` (CI), `deny.toml`.
- **Memory safety:** `grep` for `unsafe` across all crates.
- **Secret leakage:** `git ls-files` / `git check-ignore` over `deploy/k3s/pki/`,
  `gitleaks` (`.gitleaks.toml`, pre-commit + CI).
- **Container/manifest misconfig:** `trivy config`.

### 2.2 Findings

| ID | Severity | Finding | Status |
|----|----------|---------|--------|
| CODE-1 | Informational | **0 `unsafe` blocks** in `crates/`; Rust 2024 edition; memory-safe throughout. | ✅ Pass |
| DEP-1 | Medium (accepted) | `rsa 0.9` Marvin timing side-channel (RUSTSEC-2023-0071). No upstream fix. | ✅ Mitigated — see below |
| DEP-2 | Low (accepted) | `rustls-pemfile` unmaintained (RUSTSEC-2025-0134), transitive only. | ✅ Accepted, tracked in `audit.toml` |
| DEP-3 | Low (doc fix) | `audit.toml` states `rsa` is "NOT [pulled] by sqlx" — inaccurate: `sqlx-mysql` (via `sqlx-macros-core`) is a second path. | ⚠️ Correct the note (see below) |
| SEC-1 | Informational | PKI private keys / `secret` / `creds.txt` under `deploy/k3s/pki/` are **gitignored and untracked** — correct hygiene, no leak. | ✅ Pass |
| SEC-2 | Informational | oauth2-proxy `OAUTH2_PROXY_CLIENT_SECRET: "unused-public-client-pkce"` is an intentional placeholder for a **public PKCE client**, not a secret. | ✅ Pass |
| SEC-3 | Informational | All runtime secrets sourced from files/env (K8s Secrets), `zeroize` on drop, `subtle` constant-time compares. | ✅ Pass |

**DEP-1 / DEP-3 — `rsa` Marvin attack (RUSTSEC-2023-0071).** The vulnerable
`rsa 0.9.10` reaches the tree via **two** paths:
1. `usg-est-client → usg-tacacs-secrets → usg-tacacs-server` — the EST
   certificate-enrollment path. **Disabled in this deployment** (no `--est-*`
   flags), so RSA PKCS#1 v1.5 decryption is never exercised at runtime.
2. `sqlx-mysql → sqlx-macros-core → sqlx → tacacs-policy-ingest` — a
   **compile-time macro** path. The workspace enables only the `postgres`
   feature; the MySQL driver is never used at runtime.

**Runtime exposure: none.** Re-evaluate if EST is enabled or `policy-ingest`
gains a MySQL backend.

> **Action item (DEP-3):** update the comment in [`audit.toml`](audit.toml) —
> `rsa` *is* also pulled transitively through `sqlx` (via `sqlx-macros-core →
> sqlx-mysql`), even though only the Postgres driver is used at runtime. The
> MySQL path can be removed by building `policy-ingest` with
> `sqlx` `default-features = false` and only the needed features, dropping the
> `sqlx-mysql` crate (and thus this `rsa` path) from the graph.

### 2.3 Application-layer security controls (already present)
- **Transport:** TLS 1.2+ (`rustls 0.23` + `aws-lc-rs`), mTLS client-CA
  enforcement on :300; secret ≠ TLS PSK check.
- **AuthN backends:** ICAM/OIDC (ROPC), LDAP(S), RFC 8628 device flow, optional
  Argon2 static creds (off by default, gated by `--allow-static-credentials`).
- **Brute force:** per-username + per-source-IP lockout, ASCII attempt limits,
  exponential backoff (AC-7 / SC-5).
- **Audit integrity:** HMAC-SHA256 signing of every audit event (AU-9/AU-10),
  ≥32-byte key.
- **Input validation:** policy JSON validated against JSON Schema on load/reload
  (SI-10).
- **Availability:** session caps, idle sweep, graceful SIGTERM drain.

---

## 3. Threat model (Kubernetes surface)

| Threat | Vector | Primary mitigation |
|---|---|---|
| Container breakout → node | Privileged/root pod, host mounts | `runAsNonRoot`, drop ALL caps, `readOnlyRootFilesystem`, seccomp `RuntimeDefault`, PSA `restricted`, no `hostPath`/`hostNetwork` |
| Lateral movement in cluster | Flat pod network | Default-deny + scoped ingress/egress NetworkPolicies |
| Credential theft from pod | Mounted SA token, env secrets | `automountServiceAccountToken: false`, file/Secret mounts read-only, `zeroize` |
| Supply-chain (poisoned image) | Mutable tag swap | `imagePullPolicy: Always`, optional `@sha256` digest pin, Iron Bank base, SBOM |
| DoS / resource exhaustion | Unbounded CPU/mem | Per-container limits + namespace ResourceQuota/LimitRange |
| Availability loss during ops | Node drain takes all replicas | PodDisruptionBudget `minAvailable: 2`, podAntiAffinity |
| Audit log forgery | Injected accounting records | HMAC-signed events downstream verify |
| Spoofed NAD source IP | SNAT hides real client | `externalTrafficPolicy: Local` (no SNAT) + ingress CIDR allow-list |

---

## 4. Control inventory & NIST 800-53 mapping

Legend: ✅ enforced by chart defaults · ⚙️ operator-supplied · 📋 procedural.

### 4.1 Pod / container hardening (AC-6, CM-6, CM-7, SC-39)
| Control | Setting | Status |
|---|---|---|
| Run as non-root | `runAsNonRoot: true`, `runAsUser: 1000` (redis 997) | ✅ |
| No privilege escalation | `allowPrivilegeEscalation: false` | ✅ |
| Read-only root FS | `readOnlyRootFilesystem: true` (+ `emptyDir` `/tmp`) | ✅ |
| Drop all capabilities | `capabilities.drop: [ALL]` | ✅ |
| Minimum capability add | `NET_BIND_SERVICE` only (ports 49/300) | ✅ |
| Seccomp | `seccompProfile.type: RuntimeDefault` | ✅ |
| No host namespaces | no `hostNetwork`/`hostPID`/`hostIPC`/`hostPath` | ✅ |
| Pod Security Admission | namespace `enforce/audit/warn: restricted` | ✅ |

### 4.2 Network boundary (AC-4, SC-7)
| Control | Setting | Status |
|---|---|---|
| Default-deny ingress+egress | `*-default-deny` NetworkPolicy | ✅ |
| Ingress allow-list :49/:300 | NAD/management CIDRs only | ⚙️ set `nadCidrs` |
| Ingress allow-list :8080 | node CIDR (probes) + monitoring ns | ✅ |
| Egress allow-list | DNS + Redis + ICAM:443 (+extra) | ✅/⚙️ |
| Redis reachability | only from `app: tacacs` pods | ✅ |
| Real source IP preserved | `externalTrafficPolicy: Local` | ✅ |

### 4.3 Identity & secrets (AC-6, IA-5, SC-12, SC-28)
| Control | Setting | Status |
|---|---|---|
| Dedicated ServiceAccount | created, **no token automount** | ✅ |
| Secrets as files/env from K8s Secret | read-only volumes | ✅ |
| Secrets not in chart by default | `secrets.create: false` | ✅ |
| Encryption at rest (etcd) | enable `EncryptionConfiguration` or KMS | 📋 §6 |
| Rotation | documented procedure | 📋 §6 / `deploy/k3s/SECRET-ROTATION.md` |

### 4.4 Availability & resources (CP-10, SC-5, SC-6)
| Control | Setting | Status |
|---|---|---|
| Requests + limits (all containers) | CPU/mem/ephemeral-storage | ✅ |
| Namespace ResourceQuota | `requests/limits.cpu/memory`, `pods` | ✅ |
| LimitRange defaults | per-container default req/limit | ✅ |
| PodDisruptionBudget | `minAvailable: 2` | ✅ |
| Anti-affinity | spread across nodes | ✅ |
| Health probes | startup/liveness/readiness | ✅ |

### 4.5 Supply chain (CM-14, SA-12, SR-3/SR-4/SR-11)
| Control | Setting | Status |
|---|---|---|
| Pinned base (Iron Bank) | server/ingest/redis | ✅ |
| Image digest pinning | `image.digest` (recommended) | ⚙️ |
| `imagePullPolicy: Always` | re-resolve tag each start | ✅ |
| SBOM | `sbom.spdx.json` in repo | ✅ |
| Advisory gating in CI | `cargo audit` / `cargo deny` | ✅ |
| Image signing / attestation | cosign + SLSA provenance | 📋 §8 backlog |
| Admission verification | Kyverno/sigstore policy-controller | 📋 §8 backlog |

---

## 5. Deploying the hardened baseline (Helm)

```bash
# 0. Prereqs: a CNI that enforces NetworkPolicy (Cilium on the k3s cluster).

# 1. Create Secrets (see §6). Then:
helm upgrade --install tacacs deploy/helm/usg-tacacs \
  -n tacacs --create-namespace \
  -f deploy/helm/usg-tacacs/values-prod-k3s.yaml

# 2. Verify (see §9).
```

To migrate from the raw `deploy/k3s/manifests/`, the chart produces equivalent
objects; apply it into the same namespace and remove the superseded raw YAML.
`policy.existingConfigMap: tacacs-policy` reuses the existing
`deploy/k3s/apply-policy.sh` ConfigMap unchanged.

---

## 6. Secrets management & rotation

### 6.1 Create the required Secrets

```bash
NS=tacacs

# TLS material + shared secret + audit HMAC key (single Secret, multiple keys)
kubectl -n $NS create secret generic tacacs-tls \
  --from-file=server.pem=deploy/k3s/pki/server.pem \
  --from-file=server-key.pem=deploy/k3s/pki/server-key.pem \
  --from-file=ca.pem=deploy/k3s/pki/ca.pem \
  --from-file=secret=deploy/k3s/pki/secret \
  --from-file=audit-hmac-key=deploy/k3s/pki/audit-hmac-key

# ICAM client secret + Keycloak CA
kubectl -n $NS create secret generic tacacs-icam --from-file=client-secret=./client-secret
kubectl -n $NS create secret generic oopl-ca     --from-file=ca.pem=deploy/k3s/pki/oopl-ca.pem

# Redis group-cache password
kubectl -n $NS create secret generic tacacs-group-cache --from-literal=password="$(openssl rand -base64 32)"

# Iron Bank pull secret (Redis image)
kubectl -n $NS create secret docker-registry registry1-pull \
  --docker-server=registry1.dso.mil --docker-username=<robot> --docker-password=<cli-token>
```

> Generate the audit HMAC key with `openssl rand -hex 32`. Minimum 32 bytes.

### 6.2 Rotation (zero/low downtime)
- **Shared secret / audit key:** update the `tacacs-tls` Secret, then
  `kubectl -n tacacs rollout restart deploy/tacacs`. For the TACACS shared
  secret, stage the new key on NADs in the same window (devices and server must
  agree). See [`deploy/k3s/SECRET-ROTATION.md`](deploy/k3s/SECRET-ROTATION.md).
- **Redis password:** update `tacacs-group-cache`, restart `redis` then
  `tacacs` (cache is non-fatal; a brief miss only re-resolves groups).
- **TLS certs:** swap `server.pem`/`server-key.pem`; rollout restart.
- **Recommended:** drive all of the above from **external-secrets** or
  **sealed-secrets** so rotation is a Git commit, never `secrets.create=true`.

### 6.3 Encryption at rest
Enable etcd encryption (k3s: `--secrets-encryption`, or a KMS provider /
`EncryptionConfiguration`) so Secrets are not stored as plain base64 in etcd
(SC-28). Verify: `kubectl get secret tacacs-tls -o yaml` value must be
ciphertext at the etcd layer.

---

## 7. Residual risk & justified deviations

`trivy config` on the rendered chart reports **0 HIGH/CRITICAL** and a small set
of LOW/MEDIUM notes that are **intentional**:

| Trivy ID | Note | Why accepted |
|---|---|---|
| KSV-0022 (MEDIUM) | `capabilities.add` on tacacs | `NET_BIND_SERVICE` is the **single** added cap, required to bind privileged ports **49/300**. All others dropped. Removing it would force a >1024 port + proxy, increasing surface. |
| KSV-0020/0021 (LOW) | `runAsUser`/`runAsGroup` not `> 10000` | tacacs runs as `1000`, redis as `997` (Iron Bank image's fixed uid). Both are non-root; the `>10000` guidance only reduces host-UID collision risk, irrelevant with user namespaces / dedicated nodes. |
| KSV-0039 (LOW) | "configure a LimitRange" | False positive when scanning loose multi-doc YAML — the chart **does** ship a `LimitRange` (`quota.yaml`). |

Open backlog items (tracked, not blocking):
- Image **signing (cosign)** + **SLSA provenance** in `release.yml`, and
  **admission-time verification** (Kyverno / sigstore policy-controller).
- Move `policy-ingest` to `sqlx` `default-features = false` to drop the
  `sqlx-mysql`→`rsa` graph edge (DEP-3).
- Container image **CVE scanning** (`trivy image`) gate in CI.

---

## 8. Supply-chain backlog (recommended next steps)

```yaml
# release.yml (sketch) — sign + attest after push
- uses: sigstore/cosign-installer@v3
- run: cosign sign --yes ghcr.io/192d-wing/usg-tacacs-server@${DIGEST}
- run: cosign attest --yes --predicate sbom.spdx.json --type spdx \
         ghcr.io/192d-wing/usg-tacacs-server@${DIGEST}
```

Then enforce at admission so only signed images run:

```yaml
# Kyverno ClusterPolicy (sketch)
verifyImages:
  - imageReferences: ["ghcr.io/192d-wing/usg-tacacs-*"]
    attestors:
      - entries: [{ keyless: { issuer: "https://token.actions.githubusercontent.com" } }]
```

---

## 9. Verification & continuous checking

Run after every deploy and in CI (CM-6 / CA-7):

```bash
NS=tacacs

# Pod Security Admission is enforced on the namespace
kubectl get ns $NS -o jsonpath='{.metadata.labels}' | grep -q 'enforce":"restricted\|enforce: restricted' \
  && echo "PSA restricted: OK"

# Every container: non-root + read-only rootfs + no privilege escalation
kubectl -n $NS get pods -o jsonpath='{range .items[*].spec.containers[*]}{.name}{" roFS="}{.securityContext.readOnlyRootFilesystem}{" noPE="}{.securityContext.allowPrivilegeEscalation}{"\n"}{end}'

# NetworkPolicies present (default-deny + ingress + egress + redis)
kubectl -n $NS get networkpolicy

# Disruption budget + quota guardrails
kubectl -n $NS get pdb,resourcequota,limitrange

# No service-account tokens mounted
kubectl -n $NS get pods -o jsonpath='{range .items[*]}{.metadata.name}{" token="}{.spec.automountServiceAccountToken}{"\n"}{end}'

# Static re-scan of what WILL be applied
helm template tacacs deploy/helm/usg-tacacs -f deploy/helm/usg-tacacs/values-prod-k3s.yaml \
  | trivy config --severity HIGH,CRITICAL -      # expect: 0 findings

# Dependency advisories
cargo audit --ignore RUSTSEC-2023-0071 --ignore RUSTSEC-2025-0134
```

### Hardening checklist (sign-off)
- [ ] Namespace carries `pod-security.kubernetes.io/enforce: restricted`.
- [ ] All pods: non-root, read-only rootfs, `allowPrivilegeEscalation: false`, caps dropped.
- [ ] `automountServiceAccountToken: false` on every workload.
- [ ] Default-deny + scoped ingress/egress NetworkPolicies applied; CNI enforces them.
- [ ] `networkPolicy.ingress.nadCidrs` matches real NAD/management ranges.
- [ ] Egress locked to DNS + Redis + ICAM host(s).
- [ ] Secrets created out-of-band; `secrets.create=false`; etcd encryption on.
- [ ] Images digest-pinned (or `imagePullPolicy: Always` + signature verification).
- [ ] PDB, ResourceQuota, LimitRange present.
- [ ] `helm template … | trivy config` → 0 HIGH/CRITICAL.
- [ ] `cargo audit` clean except the two accepted, documented advisories.

---

## 10. References
- NIST SP 800-53 Rev. 5 — control catalog (see `docs/NIST-CONTROLS-MAPPING.md`).
- NSA/CISA — *Kubernetes Hardening Guidance*.
- CIS Kubernetes Benchmark.
- Kubernetes Pod Security Standards — `restricted` profile.
- Chart: [`deploy/helm/usg-tacacs/`](deploy/helm/usg-tacacs/) · Secret rotation:
  [`deploy/k3s/SECRET-ROTATION.md`](deploy/k3s/SECRET-ROTATION.md).
