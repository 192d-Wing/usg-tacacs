---
icon: lucide/server-cog
---

# Deployment & operations

## Systemd hardening (example)

```sh
[Service]
User=tacacs
Group=tacacs
ExecStart=/usr/local/bin/usg-tacacs --config /etc/usg-tacacs/config.json
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_INET AF_INET6
LimitNOFILE=4096
LimitNPROC=256
MemoryAccounting=yes
TasksAccounting=yes
ProtectControlGroups=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
LockPersonality=yes
RuntimeDirectory=usg-tacacs
StateDirectory=usg-tacacs
ReadWritePaths=/var/log/usg-tacacs
```

Place certs/policy/config inside the controlled directories or chroot if required.

## Logging and telemetry

- UTC timestamps via `tracing`; include peer/session/user/outcome fields.
- Forward logs to TLS/syslog and configure rotation (journald or logrotate).
- Audit events cover authn/authz/acct allows/denies/errors with rule IDs and reasons.

## Health and keepalive

- Single-connection idle and keepalive timers are configurable (`single_connect_idle_secs`, `single_connect_keepalive_secs`).
- Capability/keepalive packets are parsed/acknowledged; sessions exceeding keepalive misses are dropped.

## Troubleshooting checklist

- **mTLS failures**: verify `client_ca`/`tls_trust_root`, CN/SAN allowlists, and cert validity.
- **Legacy TACACS+ failures**: ensure `secret` is set (min length 8) and `forbid_unencrypted` true.
- **LDAP auth failures**: check `ldaps_url`, bind credentials, search base, username/group attributes, required_group values, and CA file.
- **Policy denies**: run `--check-policy` against `policy.schema.json`; confirm `users`/`groups` and regex patterns.
- **Connection storms**: tune `max_connections_per_ip`; consider OS-level SYN backlog and firewall rate limits.

## Kubernetes deployment (k3s / Cilium)

### `externalTrafficPolicy: Local` — required for auditing

The k3s LoadBalancer service **must** use `externalTrafficPolicy: Local`. With
the default `Cluster` policy, Cilium SNATs cross-node traffic before forwarding
it to the pod. The server receives the forwarding node's IP (`10.0.111.x`)
instead of the real Network Access Device (NAD) IP. This has two consequences:

1. **Audit log corruption** — every `peer` field in the structured log (AU-3:
   Content of Audit Records) records a cluster-internal node IP instead of the
   NAD IP. Audit records become useless for device attribution.
2. **Per-NAD secret lookup failure** — the legacy listener selects the per-NAD
   shared secret by matching the peer IP. With SNAT the lookup always misses,
   causing all legacy connections to be rejected or to fall back to a single
   default secret.

With `externalTrafficPolicy: Local`, Cilium's BGP control plane restricts route
advertisements to nodes that have a local TACACS pod. Incoming traffic lands
directly on a pod-bearing node with no SNAT; the real NAD IP is visible at the
socket. ECMP continues across as many paths as there are replicas (three for the
default 3-replica deployment).

Do not switch to `Cluster` policy without also implementing PROXY protocol
support in the server and the Cilium service annotation
`service.cilium.io/proxy-protocol: "true"`.

## Upgrade/reload

- Send `SIGHUP` to reload policy/config (ensure files are readable by the service user).
- Keep `Cargo.lock` committed; build with `cargo build --locked` for reproducibility.

## File layout suggestion

```sh
/etc/usg-tacacs/
  config.json
  policy.json
  policy.schema.json
  tls/
    server.pem
    server-key.pem
    client-ca.pem
    extra-roots.pem
/var/log/usg-tacacs/
  tacacs.log
```
