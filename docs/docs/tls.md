---
icon: lucide/shield-check
---

# TLS and mTLS

`usg-tacacs` defaults to TLS 1.3 with mutual authentication on `listen_tls` (TCP/300 by default). Legacy TACACS+ on TCP/49 is optional; when enabled, obfuscation is required if a shared secret exists.

## Required inputs

- `tls_cert` / `tls_key`: server certificate and private key (PEM).
- `client_ca`: CA bundle to validate client certificates (PEM).
- `listen_tls`: host:port to bind (e.g., `0.0.0.0:300`).

**Note**: Server certificates can be provisioned automatically using [EST (RFC 7030)](./est-provisioning.md) for zero-touch deployment.

## Optional controls

- `tls_trust_root` (array): extra trust anchors for client auth.
- `tls_allowed_client_cn` / `tls_allowed_client_san` (arrays): allowlists for client identities; match-any. Use SAN when possible.
- `tls_psk`: pre-shared key for PSK-based TLS (if you enable it).
- `secret`: TACACS+ shared secret (used for obfuscation on legacy TCP/49); min length 8. `forbid_unencrypted` true by default to drop `TAC_PLUS_UNENCRYPTED_FLAG`.
- `legacy_nad_secret`: per-NAD legacy secrets (IP + secret). When present, legacy connections must come from a listed IP; unmatched legacy peers are rejected.

## Example run

```sh
cargo run -p tacacs-server -- \
  --listen-tls 0.0.0.0:300 \
  --tls-cert ./certs/server.pem \
  --tls-key ./certs/server-key.pem \
  --client-ca ./certs/client-ca.pem \
  --tls-allowed-client-cn router1.example.com \
  --tls-allowed-client-san tacacs-client.example.com \
  --tls-trust-root ./certs/extra-root.pem \
  --policy ./policy/policy.example.json
```

## Legacy listener (optional)

Enable only if you must serve TCP/49:

```sh
--listen-legacy 0.0.0.0:49 --secret "strong-shared-secret" --forbid-unencrypted true
```

Packets with `TAC_PLUS_UNENCRYPTED_FLAG` are dropped when `forbid_unencrypted` is true (default). Secrets must not be empty or reused across TLS PSKs.

## Certificate guidance

- Prefer SANs over CNs; use CN allowlist only when SANs are absent.
- Separate PKI for client certs vs server cert if possible.
- Rotate certs/keys regularly; reload with SIGHUP to pick up new files.
- For automated certificate lifecycle management, see [EST Certificate Provisioning](./est-provisioning.md).

## Troubleshooting

- **Client mTLS fails**: verify client presented a cert chaining to `client_ca`/`tls_trust_root`; check CN/SAN allowlists.
- **Legacy obfuscation errors**: ensure `secret` is set and meets minimum length; keep `forbid_unencrypted` true in production.
- **PSK not working**: confirm both ends share `tls_psk` and use matching TLS versions.
