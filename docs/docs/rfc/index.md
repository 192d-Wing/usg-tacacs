---
icon: lucide/book-open-check
---

# Protocol and RFC conformance

USG TACACS implements TACACS+ packet handling based on RFC 8907 and a
TACACS-over-TLS transport based on RFC 9887. This page describes scope; test
evidence and release artifacts determine conformance for a specific release.

## RFC 8907 scope

The codec supports authentication, authorization, accounting, session IDs,
sequence validation, flags, attributes, and legacy shared-secret body
obfuscation. Legacy obfuscation is protocol compatibility, not modern
cryptographic confidentiality; protect TCP/49 with network controls or IPsec.

The server rejects invalid lengths, sequences, service/protocol combinations,
unsupported/deprecated paths, and unauthenticated legacy peers according to
its fail-closed validation rules. Resource and session limits must be exercised
by negative tests.

## RFC 9887 scope

The TLS role:

- listens conventionally on TCP/300;
- requires TLS 1.3;
- requires and validates a client certificate;
- maps the validated certificate to a configured NAD identity; and
- runs independently from the legacy role.

Port number is not a conformance test. A device using ordinary TACACS+ shared
secret framing on TCP/300 is not using RFC 9887.

## Release verification

For each release, retain:

1. protocol unit and malformed-packet test results;
2. TLS 1.3/mTLS handshake tests and packet captures;
3. supported/unsupported authentication action/type matrix;
4. authorization and accounting semantic tests;
5. single-connection and keepalive tests;
6. vendor interoperability evidence by exact platform/release;
7. fuzzing and resource-bound results; and
8. documented deviations or unimplemented optional behavior.

Avoid unqualified “fully compliant” claims. Conformance statements must name
the release, RFC sections, test suite, and known limitations.

## References

- [RFC 8907 — The TACACS+ Protocol](https://www.rfc-editor.org/rfc/rfc8907)
- [RFC 9887 — TACACS+ over TLS 1.3](https://www.rfc-editor.org/rfc/rfc9887)
