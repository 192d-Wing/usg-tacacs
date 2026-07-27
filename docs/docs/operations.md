---
icon: lucide/server-cog
---

# Deployment and operations reference

The production runbook is the [Operator guide](operator/index.md). This page
records deployment-specific constraints that apply to the TACACS data plane.

## Runtime separation

Deploy the `management`, `legacy`, and optional `tls` roles as independent
Kubernetes workloads from the same image. The Helm chart renders a typed
`TacacsServer` YAML document for each role and runs the configuration checker
before starting the server.

Static listener, YAML-owned NAD, RBAC, secret-mount, and trust changes require a
controlled rollout. API-owned NAD changes reconcile dynamically and publish an
atomic runtime snapshot after validation.

## Source identity preservation

### `externalTrafficPolicy: Local`

The external legacy TACACS+ Service must preserve the real NAD source address.
On k3s/Cilium, use `externalTrafficPolicy: Local` unless an independently
validated design provides equivalent identity preservation.

With source NAT, the server sees a cluster node address instead of the NAD.
That causes:

1. incorrect forensic attribution in the signed audit record; and
2. failure of exact source-address-to-secret/NAD selection.

Ensure the load balancer advertises or sends traffic only to nodes with a ready
local TACACS replica. Confirm the observed peer address with a synthetic test
after every networking change.

Do not switch to `externalTrafficPolicy: Cluster` without a server and network
design that authenticates the original connection identity. An untrusted
forwarding header is not sufficient.

## Logging and telemetry

- Emit structured records with UTC timestamps, correlation ID, NAD identity,
  peer, session, user, result, reason, rule ID, instance, and release.
- Never log passwords, keyed verifiers, shared secrets, database credentials,
  private keys, or audit keys.
- Forward raw signed audit records to immutable centralized storage.
- Alert on delivery gaps, hash-chain/signature failure, reconciliation errors,
  fallback attempts, and unexpected configuration hashes.
- Keep operational logs distinct from the authoritative forensic stream.

## Health and connection handling

- Monitor each runtime role independently.
- Treat readiness, management status, reconciliation, synthetic AAA, and audit
  delivery as separate signals.
- Configure single-connection idle and keepalive limits for the NAD population.
- Bound connections per source and reject malformed or unauthenticated peers.
- A JIT-managed NAD fails closed if the JIT store or verifier material is
  unavailable.

## Troubleshooting checklist

1. Identify the affected role (`management`, `legacy`, or `tls`).
2. Capture UTC time, correlation ID, NAD, user, source, release, and
   configuration hash.
3. Check reconciliation state and mounted reference availability.
4. For management mTLS, verify TLS 1.3, trust chain, certificate validity, and
   the exact typed identity selector.
5. For legacy TACACS+, verify the preserved peer address and unique per-NAD
   secret reference without displaying its contents.
6. For TACACS-over-TLS, verify the NAD certificate identity and trust.
7. For policy denial, identify the stable rule/reason rather than weakening the
   default-deny policy.
8. Correlate data-plane events with PostgreSQL and the signed audit stream.

See [NAD lifecycle](operator/nad-lifecycle.md) for changes and
[Forensic incident response](operator/incident-response.md) before taking
actions that could destroy evidence.
