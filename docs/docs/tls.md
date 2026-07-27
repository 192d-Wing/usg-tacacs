---
icon: lucide/lock-keyhole
---

# TLS and trust

Management and TACACS-over-TLS listeners require TLS 1.3 and mutual
certificate authentication. Legacy TACACS+ on TCP/49 is a separate supported
transport for NADs that cannot implement RFC 9887.

## Management listener

```yaml
management:
  listener:
    address: 0.0.0.0:8443
    certificateFile: /run/tls/api/server.crt
    privateKeyFile: /run/tls/api/server.key
    clientCaFile: /run/tls/api/client-ca.crt
    minimumVersion: "1.3"
```

The certificate identity is mapped to typed RBAC subjects. A reverse proxy may
use TCP passthrough; it must not replace certificate identity with an HTTP
header.

## TACACS-over-TLS listener

```yaml
spec:
  role: tls
  listeners:
    tls:
      address: 0.0.0.0:300
      certificateFile: /run/tls/dataplane/server.crt
      privateKeyFile: /run/tls/dataplane/server.key
      clientCaFile: /run/tls/dataplane/client-ca.crt
      minimumVersion: "1.3"
```

Each TLS NAD is declared with certificate identities. Validate the full chain,
extended key usage, validity period, device identity, and revocation design.

## Legacy is not TLS

Changing a TACACS+ port to 300 does not enable RFC 9887. A configuration that
still uses an ordinary TACACS shared secret and does not establish a TLS
handshake remains legacy TACACS+, regardless of port number.

Use packet capture in an isolated lab to verify a TLS 1.3 handshake and mutual
certificate authentication before classifying a vendor/platform as TLS.

## Key handling and rotation

- Mount private keys read-only from the approved secret provider.
- Use distinct keys and trust domains for management and data plane.
- Never place keys or passwords in ConfigMaps or Helm values.
- Monitor expiry and test renewal before the response window.
- Roll certificates without accepting an unvalidated identity.
- Preserve audit evidence before emergency trust changes.

See [EST provisioning](est-provisioning.md) for the optional compatibility
enrollment integration.
