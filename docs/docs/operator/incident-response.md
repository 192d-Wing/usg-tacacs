---
icon: lucide/shield-alert
---

# Forensic incident response

USG TACACS audit records are security evidence. The objective is to preserve
their original form and establish a defensible timeline across management,
reconciliation, TACACS, JITPW, PostgreSQL, Kubernetes, and the NAD.

## First actions

1. Open an incident record and assign a UUID correlation ID.
2. Record who observed the condition, UTC time, affected NADs/users, cluster,
   namespace, release, and configuration hash.
3. Restrict further administrative mutation using the approved control plane.
4. Preserve raw signed audit records and database/storage snapshots.
5. Export the bounded NAD audit chain and run the verification endpoint.
6. Preserve Kubernetes events, Pod metadata, image digests, and read-only logs.
7. Preserve relevant JITPW, network, secret-provider, and NAD accounting data.
8. Document every collection action, actor, time, tool, and resulting digest.

Do not delete or restart Pods, rewrite audit rows, rotate the audit key, purge
leases, or restore a database until volatile evidence has been assessed and
preserved. Availability actions may still be necessary, but must be authorized
and documented.

## Evidence handling

For every artifact:

- retain the native/raw representation;
- calculate an approved cryptographic digest;
- record collection time in UTC and source identity;
- use read-only or snapshot-based collection when possible;
- store working copies separately from originals;
- restrict access and log every transfer;
- record clock sources and known skew;
- never include resolved secrets or temporary passwords in a case bundle.

The audit verification endpoint establishes application-level chain and HMAC
validity. It does not replace storage provenance, database logs, Kubernetes
evidence, or chain-of-custody records.

## Correlation fields

Build the timeline around:

- correlation ID and idempotency key digest;
- management certificate identity;
- NAD ID, name, source address, and certificate identity;
- canonical user identity;
- JIT lease ID, without credential or verifier material;
- TACACS session and accounting identifiers;
- Pod UID, node, image digest, release, and configuration hash;
- PostgreSQL transaction/event identifiers and normalized UTC timestamps.

## Audit-integrity failure

If verification returns invalid:

1. Record the first failing event and stable failure code.
2. Preserve the entire affected chain, not only the reported page.
3. Snapshot PostgreSQL and centralized raw storage.
4. Determine whether the failure is a missing event, ordering change, field
   mutation, signature mismatch, or unsupported hash version.
5. Compare independently collected application output with stored rows.
6. Treat audit-key exposure as a separate key-compromise incident.
7. Do not repair or reseal historical events in place.

## Credential or key exposure

- A legacy NAD secret affects only that NAD if unique secrets were enforced.
  Disable or isolate it, rotate under the NAD runbook, and review its events.
- JIT password exposure requires immediate lease revocation; passwords are not
  recoverable from stored keyed verifiers.
- JIT verifier-key exposure affects verification of active/restored leases.
  Drain or revoke leases and coordinate rotation across all replicas.
- Audit HMAC-key exposure invalidates future trust until controlled rotation;
  preserve pre-rotation evidence and record the exact boundary.
- Management client-key exposure requires certificate revocation, RBAC review,
  and examination of every action attributed to that identity.

## Recovery and closure

Recovery must restore a known configuration, release, database state, trust
store, and secret version. Before returning traffic:

1. Validate typed configuration and referenced files.
2. Verify migrations and reconciliation.
3. Confirm management mTLS/RBAC.
4. Test every enabled TACACS transport.
5. Verify authorization, accounting, and new audit-chain continuity.
6. Record residual risk, evidence location, retention, and lessons learned.
