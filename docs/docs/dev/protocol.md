---
icon: lucide/binary
---

# Protocol implementation

`tacacs-proto` owns packet representation, parsing, serialization, and legacy
body obfuscation. `tacacs-server` owns connection/session state and AAA
semantics. Keep parsing independent from authorization and secret resolution.

## Parser invariants

- Validate header version, type, sequence, flags, and body length before use.
- Bound every allocation by protocol and configured limits.
- Reject truncated, trailing, overflowed, and inconsistent fields.
- Do not continue a session after sequence or identity failure.
- Keep peer-controlled text out of structured log keys.
- Zeroize temporary secret material where practical.

## Legacy transport

RFC 8907 shared-secret processing is obfuscation, not encryption. Use the exact
protocol algorithm for interoperability and never substitute it for TLS,
IPsec, or a protected management network. NAD secret selection occurs only
after exact preserved-source lookup.

## TLS transport

The RFC 9887 role accepts TLS 1.3 with client certificates. The validated
certificate identity is bound to the connection before TACACS packets are
processed. Do not derive identity from application headers or an untrusted
proxy.

## Session behavior

Connection state tracks peer/NAD identity, session and sequence, single-connect
behavior, limits, and accounting task IDs. Authentication identity and groups
must be carried into authorization without trusting NAD-supplied claims that
were not validated.

## Testing

Required classes include round trips, golden vectors, boundary lengths,
malformed/truncated bodies, invalid sequence/type combinations, obfuscation
vectors, TLS downgrade/client-certificate rejection, single-connect reuse,
timeout/limit behavior, fuzzing, and cross-NAD identity isolation.

Protocol changes require an RFC-section citation, compatibility analysis,
negative tests, and an update to [Protocol conformance](../rfc/index.md).
