---
icon: lucide/shield-check
---

# Security hardening

This baseline applies to the Helm/Kubernetes production profile. Tailor it
through the organization's risk process without weakening the documented
identity and audit invariants.

## Workloads

- Separate management, legacy, and TLS roles.
- Run as non-root with read-only root filesystem and no added capabilities.
- Pin release images by digest and verify signatures/SBOMs.
- Set CPU, memory, process, and connection limits.
- Use dedicated service accounts and default-deny NetworkPolicy.
- Admit management traffic only from declared peers.
- Preserve real source addresses for legacy NAD attribution.

## Cryptography and trust

- Require TLS 1.3 mTLS for management and RFC 9887.
- Use validated certificate identities, not forwarding headers.
- Keep management, data-plane, PostgreSQL, audit, and JIT keys independent.
- Mount private material read-only from an approved secret provider.
- Monitor expiry/revocation and exercise rotation.
- Treat legacy TACACS as a compatibility transport; protect it with network
  controls or IPsec and unique per-NAD secrets.

## Configuration

- Use only typed YAML as production desired state.
- Keep `defaultAllow: false`.
- Require reviewed changes, strict validation, and rendered Helm diffs.
- Reject unknown fields and ambiguous YAML/API ownership.
- Treat API acceptance and reconciliation as distinct states.
- Record release and effective configuration hash in every change.

## Data and audit

- Install and upgrade the CloudNativePG operator independently through a
  reviewed, version-pinned release path.
- Use at least three database instances across independent failure domains.
- Use PostgreSQL TLS 1.3 with `verify-full` and separate migration/runtime
  roles; never mount the migration credential into TACACS workloads.
- Keep remote superuser access disabled and retain the runtime role's
  non-owner, non-administrator privilege boundary.
- Enforce database NetworkPolicy for cluster peers, TACACS workloads, the
  migration Job, and the specifically selected operator Pods only.
- Use encrypted durable storage. Encrypt backups, restrict object-store
  credentials, monitor backup age, and test point-in-time recovery.
- Alert on replication lag, failed backups, storage pressure, unexpected
  failover, certificate expiry, and repeated database authentication failure.
- Forward raw signed audit records to immutable centralized storage.
- Alert on gaps, invalid chains/signatures, unexpected actors, fallback
  attempts, and configuration changes.
- Never log passwords, verifiers, shared secrets, database credentials, or
  private keys.

## Authentication

- JIT-managed NADs fail closed and have no alternate backend.
- Canonicalize EIDs to lowercase at trust boundaries.
- Keep JIT TTL at or below 900 seconds.
- Disable static credentials unless an approved lab/break-glass design needs
  them.
- Bound authentication attempts while accounting for NAD aggregation at the
  source IP.

## Verification checklist

- [ ] All typed configurations pass `usg-tacacs-config-check --check-files`
- [ ] Management rejects missing/untrusted certificates and TLS below 1.3
- [ ] Legacy NADs have unique secrets and exact source mappings
- [ ] TLS NADs have lab-verified RFC 9887 handshakes
- [ ] YAML/API conflicts fail closed
- [ ] JIT fallback tests fail as designed
- [ ] Runtime database credentials cannot perform DDL or role administration
- [ ] Unauthorized Pods cannot reach PostgreSQL
- [ ] CloudNativePG failover and restore-to-new-cluster exercises pass
- [ ] Audit verification and restore exercises pass
- [ ] Break-glass procedures are tested and independently audited

See [CloudNativePG deployment](cloudnativepg.md) and
[Forensic incident response](../operator/incident-response.md).
