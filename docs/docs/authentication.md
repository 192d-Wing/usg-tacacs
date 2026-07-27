---
icon: lucide/key-round
---

# Authentication

Authentication method is selected by deployment profile and NAD policy. The
JITPW-managed profile is the preferred model for interactive device access.

## JITPW-managed NADs

JITPW creates a short-lived lease through mTLS. USG TACACS stores only a keyed
verifier and authenticates the exact lowercase EID on the bound NAD. Leases
expire within 15 minutes and may be revoked immediately.

Managed NADs fail closed. They cannot fall back to LDAPS, ICAM, or static
credentials when the lease store or verifier material is unavailable.

## NAD authentication

This is distinct from user authentication:

- A legacy NAD is identified by its preserved source address and unique
  external shared secret.
- An RFC 9887 NAD is authenticated by its validated client certificate and
  configured certificate identity.

The server must establish NAD identity before accepting a user credential.

## Enterprise compatibility backends

LDAPS and ICAM/OIDC integrations remain available for non-JIT profiles. Their
options are currently compatibility CLI/environment settings rather than
fields in typed `TacacsServer` YAML. Keep them in reviewed workload
configuration and external secret files.

Security requirements:

- use `ldaps://` with validated server identity; StartTLS is rejected;
- keep bind/client secrets in mounted files where supported;
- use least-privilege directory/service identities;
- bound timeouts and rate limits;
- map groups into deny-by-default authorization; and
- never enable these backends as fallback for a JIT-managed NAD.

Static credentials are disabled unless explicitly allowed. Use Argon2id hashes
and mounted files for an approved lab or break-glass design; never put
plaintext credentials in YAML, Helm values, process arguments, or Git.

## Troubleshooting

Capture the NAD, canonical user, UTC time, correlation ID, transport, and
non-secret reason code. Check NAD reconciliation and identity before debugging
the credential backend. Do not weaken managed scope or enable fallback to
restore service.
