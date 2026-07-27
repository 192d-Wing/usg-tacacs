---
icon: lucide/server-cog
---

# Operator guide

This guide covers normal production operation of USG TACACS on Kubernetes.
Operators execute approved changes and respond to service conditions;
administrators define configuration, access policy, and trust.

## Start-of-shift checks

Confirm all of the following before treating the service as healthy:

1. The `management`, `legacy`, and enabled `tls` workloads have their intended
   replica counts and no restart loop.
2. Management API status succeeds with an authorized mTLS identity.
3. NAD reconciliation has no new `conflict`, `invalid`, or
   `secret_unavailable` state.
4. PostgreSQL connections use validated TLS and migrations match the release.
5. Legacy and TLS Services preserve the real NAD source identity.
6. Signed audit events are arriving centrally without sequence gaps or
   signature failures.
7. Authentication, authorization, and accounting error rates remain within the
   site baseline.
8. Certificates, database credentials, and mounted secrets are not approaching
   expiration.

## Health model

Do not use Pod readiness alone as the service-level signal:

| Signal | What it proves |
| --- | --- |
| Pod ready | The process passed its local readiness checks |
| Management status | The authenticated management path is available |
| Reconciliation healthy | Desired NAD state was validated and published |
| Synthetic AAA test | A representative NAD path can authenticate and account |
| Audit delivery current | Security evidence is leaving the workload intact |

A NAD mutation returning success proves only that desired state was accepted.
It is active only after reconciliation reports the expected applied state.

## Safe change procedure

For every production change:

1. Assign a ticket and UUID correlation ID.
2. Capture current release, configuration hash, reconciliation summary, and
   relevant audit-chain verification.
3. Validate typed YAML and referenced files in a production-equivalent
   environment.
4. Render and diff the Helm release.
5. Apply required database migrations before workloads that depend on them.
6. Roll out one runtime role at a time, preserving quorum and a rollback path.
7. Wait for readiness and reconciliation before proceeding.
8. Run authentication, authorization, accounting, and audit-delivery tests.
9. Record the result, release, configuration hash, and evidence locations.

Never restore service by removing a JIT-managed NAD from managed scope or
enabling an authentication fallback. Use the approved break-glass procedure.

## NAD operations

Use the [NAD lifecycle runbook](nad-lifecycle.md) for creation, change,
rotation, disablement, and deletion. The critical rules are:

- Never reuse a shared secret between legacy NADs.
- Never submit the secret value to the Management API.
- Respect YAML/API ownership.
- Use idempotency and optimistic concurrency controls.
- Verify reconciliation and a device-side AAA test after every change.

## Deployment and upgrades

The chart deploys independent workloads from one image. Upgrade them in this
order unless the release notes specify otherwise:

1. Back up PostgreSQL and verify recovery metadata.
2. Apply forward-compatible migrations.
3. Upgrade `management` and confirm API/reconciliation/audit health.
4. Upgrade one data-plane role at a time.
5. Run a synthetic test against every enabled transport.
6. Observe error rates and audit continuity for the approved soak period.

Application rollback must not automatically reverse a database migration.
Retain forensic tables and JIT rows. If the previous binary is not compatible
with the migrated schema, follow the release-specific recovery procedure.

## Kubernetes requirements

- Use `externalTrafficPolicy: Local` where source identity is required for
  legacy per-NAD secret selection and forensic attribution.
- Ensure traffic lands only on nodes with a ready local replica.
- Limit the management Service with NetworkPolicy in addition to mTLS/RBAC.
- Run containers as non-root with read-only filesystems and minimal
  capabilities.
- Keep secret volumes read-only and out of diagnostic bundles.
- Treat site value files as sensitive operational configuration even though
  they contain no secret values.

## Backup and recovery

Back up:

- PostgreSQL with point-in-time recovery;
- reviewed YAML and Helm values;
- certificate inventory and renewal metadata;
- audit evidence in immutable centralized storage;
- separately escrowed keys only when approved by key-management policy.

Restore testing must prove that the database, configuration version, secret
versions, and application release are compatible. A restored JIT database is
not sufficient without the exact verifier key; if continuity cannot be proven,
revoke all restored active leases before admitting traffic.

## Alerts requiring immediate action

- Audit signature, hash-chain, sequence, or delivery failure
- Unexpected management certificate identity or authorization denial burst
- NAD reconciliation conflict or secret-resolution failure
- PostgreSQL TLS, integrity, or availability failure
- Managed NAD authentication fallback attempt
- Configuration hash change outside an approved deployment
- Large authentication failure increase from one source
- Certificate expiration inside the site's response window

Preserve evidence before restarting, deleting Pods, rotating keys, or changing
the database. Follow [Forensic incident response](incident-response.md).

## Routine maintenance

| Frequency | Activity |
| --- | --- |
| Daily | Health, reconciliation, audit continuity, AAA error trends |
| Weekly | Failed/denied management operations and stale API-owned NADs |
| Monthly | Restore sample, access review, certificate/secret inventory |
| Quarterly | Full recovery exercise and break-glass test |
| Per release | Migration rehearsal, rendered Helm diff, rollback exercise |

## Troubleshooting order

1. Identify the affected runtime role and transport.
2. Capture correlation ID, NAD identity, source address, time, and release.
3. Check reconciliation before debugging the TACACS protocol.
4. Confirm the secret/certificate reference exists without displaying it.
5. Check network source preservation and NetworkPolicy.
6. Correlate management, data-plane, PostgreSQL, and signed audit events.
7. Reproduce with an approved synthetic account or lab NAD.
8. Escalate without weakening authentication or authorization controls.

For protocol-specific checks, see [Deployment and operations](../operations.md).
