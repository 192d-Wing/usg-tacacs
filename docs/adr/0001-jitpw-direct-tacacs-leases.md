# ADR 0001: Direct JITPW credential leases

- Status: Accepted
- Date: 2026-07-22
- Decision owners: JITPW and USG TACACS maintainers

## Context

JITPW grants a network administrator a short-lived device credential after CAC or
PIV authentication through ICAM. The administrator connects through an SSH
bastion with an SSH key. The bastion only forwards the TCP stream and must never
receive the device password. Network devices authenticate the administrator
against USG TACACS.

High-frequency LDAP password changes introduce replication delay, ambiguous
revocation semantics, and unnecessary exposure of temporary credentials. Direct
lease delivery from JITPW to USG TACACS avoids LDAP as the temporary-password
authority.

## Decision

USG TACACS will expose an mTLS-only management API described by
[`jit-lease.openapi.yaml`](../api/jit-lease.openapi.yaml). Only an explicitly
authorized JITPW workload certificate may create, inspect, or revoke leases.

ICAM is authoritative for the administrator identity. JITPW obtains the EID from
the authenticated ICAM assertion, converts it to lowercase ASCII, and sends it as
`eid`. Users and client software cannot override this value. The same lowercase
EID, for example `john.e.willman3.mil`, is submitted to TACACS by the network
device.

A lease is bound to all of the following:

- an opaque lease identifier;
- the lowercase ICAM EID and immutable ICAM subject identifier;
- one authenticated network access device (NAD) identity;
- a keyed password verifier, never the plaintext password at rest;
- authorization groups asserted by JITPW;
- issuance and expiration times, with a maximum lifetime of 15 minutes; and
- an idempotency key for safe create retries.

JIT-managed NADs use the JIT backend exclusively. A missing, unavailable,
expired, revoked, malformed, or mismatched lease is an authentication failure.
USG TACACS must not fall through to ICAM, LDAP, or static credentials. Backend
selection is based on trusted NAD configuration and the authenticated NAD
identity, never on a username prefix or an untrusted request field.

The create operation accepts the temporary password only over mutually
authenticated TLS. The password is a write-only API field, is bounded before
processing, is never logged, and is converted immediately to a keyed verifier.
The implementation must erase mutable plaintext buffers on every exit path.
The Redis record contains only the verifier and lease metadata.

## Security invariants

1. TLS 1.3 and a validated client certificate are mandatory for the management
   API in production.
2. `tacacs:CreateJitLease`, `tacacs:GetJitLease`, and
   `tacacs:RevokeJitLease` are distinct RBAC actions.
3. EIDs are lowercase ASCII and match `^[a-z0-9](?:[a-z0-9.-]{0,126}[a-z0-9])?$`.
4. Lease lifetime is positive and no greater than 900 seconds.
5. One active lease may exist for an `(eid, nad_identity)` pair. An idempotent
   retry returns the original metadata but never returns a credential.
6. Lease reads, verifier comparisons, revocation, and expiry fail closed when
   the authoritative store is unavailable.
7. A verifier comparison is constant time and uses an approved keyed hash from
   the configured cryptographic provider.
8. PAP and ASCII keyboard-interactive are supported initially. CHAP is rejected
   for JIT-managed NADs because verifier-only storage cannot validate CHAP.
9. Audit events include the lease ID, ICAM subject, EID, NAD identity, mTLS
   caller, outcome, reason code, timestamp, and correlation ID. They exclude the
   password, verifier, idempotency key, and TLS private material.
10. The received TACACS username and canonical EID are both retained when they
    differ. Authentication uses the canonical lowercase form.

## Audit events

The implementation emits signed structured events for `jit_lease_created`,
`jit_lease_create_rejected`, `jit_lease_authenticated`,
`jit_lease_authentication_rejected`, `jit_lease_revoked`, `jit_lease_expired`,
and `jit_lease_store_unavailable`. Event production is mandatory; audit pipeline
delivery failures follow the deployment's fail-safe policy and raise an alert.

## Consequences

LDAP is no longer in the temporary-password path. Revocation and expiry become
authoritative at TACACS authentication time, and the EID remains consistent in
device accounting. USG TACACS now operates a credential-bearing API and must
protect its verifier key, Redis transport, API certificate policy, audit trail,
and memory-handling paths as security-critical components.

Future SSH certificates can reuse the ICAM identity, authorization, lease, and
audit model while replacing the password authenticator.

## NIST SP 800-53 Rev. 5 controls

This decision supports AC-2, AC-3, AC-6, AC-12, AU-2, AU-3, AU-9, AU-12, IA-2,
IA-5, IA-8, SC-8, SC-12, SC-13, SC-23, SI-4, and SI-10.
