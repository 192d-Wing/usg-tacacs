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

- Use PostgreSQL TLS with separate migration/runtime roles.
- Encrypt backups and test point-in-time recovery.
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
- [ ] Audit verification and restore exercises pass
- [ ] Break-glass procedures are tested and independently audited

See [Forensic incident response](../operator/incident-response.md).
