# Management API Adversarial Test Matrix

This matrix is a release gate for the TACACS management control plane. A row is
complete only when an automated test exercises the stated failure mode.

| Boundary | Attack or failure | Expected result | Automated evidence |
| --- | --- | --- | --- |
| TLS | TLS 1.2 or older | handshake rejected | TLS configuration is constructed with TLS 1.3 only |
| TLS | no client certificate | handshake rejected | rustls `WebPkiClientVerifier` requires a client certificate |
| TLS | certificate from an untrusted CA | handshake rejected | management CA trust-store tests |
| Identity | HTTP identity-header spoofing | ignored in production | header fallback is compiled only for tests |
| Identity | spoofed header plus authenticated untrusted certificate | certificate identity wins; request denied | `peer_certificate_identity_precedes_test_header_fallback` |
| Identity | two configured identities in one certificate | request denied as ambiguous | `peer_identity_selection_fails_closed_on_multiple_rbac_matches` |
| Identity | untyped or noncanonical RBAC selector | startup/config validation fails | config and RBAC typed-identity tests |
| Authorization | undefined role | startup/config validation fails | typed configuration validation |
| Authorization | malformed or partial wildcard | startup validation fails | `rbac_validation_rejects_broad_or_malformed_wildcards` |
| Authorization | authenticated identity lacks permission | problem-details 403 response | API viewer/operator tests |
| Request | malformed correlation identifier | request rejected | middleware correlation tests |
| Request | oversized mutation body | 413 response | Axum body limits |
| Request | excessive list or verification limit | 422 response | NAD, reconciliation, and audit bound tests |
| Concurrency | stale NAD resource version | 409 response | PostgreSQL lifecycle test |
| Idempotency | same key with different request | 409 response | PostgreSQL idempotency test |
| Reconciliation | missing or escaping secret reference | resource remains inactive | reconciler fail-closed tests |
| Reconciliation | duplicate identity | conflicting API NAD remains inactive | reconciler conflict tests |
| Audit | event state, metadata, hash, or HMAC changed | verification identifies first failure | v1/v2 audit tamper tests |
| Audit | audit update or delete attempted | database trigger rejects mutation | PostgreSQL append-only test |
| HA | operation is read or completed by another replica | same durable operation returned | PostgreSQL replica-handoff test |
| Availability | policy replacement fails validation | prior policy remains active | policy reload tests |

## Remaining environment-level gates

The following tests require the deployment harness and must run before release:

1. complete TLS handshakes for trusted, untrusted, expired, revoked, missing,
   TLS 1.2, and TLS 1.3 client cases;
2. Kubernetes NetworkPolicy checks proving only approved namespaces can reach
   the management listener;
3. multi-replica restart testing during a running policy operation;
4. PostgreSQL failover during NAD mutation, audit verification, and operation
   completion;
5. sustained rate-limit and request-body exhaustion tests;
6. external log collection verification for allowed and denied administration.
