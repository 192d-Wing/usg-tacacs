---
icon: lucide/shield-alert
---

# Administrator Guide

This guide covers the deployment, configuration, and management of `usg-tacacs` in production environments.

## Overview

`usg-tacacs` is a high-performance TACACS+ server written in Rust that provides:

- **RFC 8907** compliant TACACS+ protocol implementation
- **RFC 9887** TACACS+ over TLS 1.3 with mutual authentication
- Policy-driven command authorization
- LDAPS integration for enterprise authentication
- Comprehensive audit logging

## Deployment Options

### Standalone Binary

The simplest deployment is running the compiled binary directly:

```sh
./usg-tacacs-server --config /etc/usg-tacacs/config.json
```

### Systemd Service

For production Linux deployments, use systemd with security hardening:

```ini
[Unit]
Description=USG TACACS+ Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=tacacs
Group=tacacs
ExecStart=/usr/local/bin/usg-tacacs-server --config /etc/usg-tacacs/config.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5

# Security hardening
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

[Install]
WantedBy=multi-user.target
```

### Container Deployment

See the [Container Guide](../container.md) for Docker Compose deployment with:

- HAProxy L4 load balancing
- FRR BGP Anycast advertisement
- Health-based BGP withdraw

## Directory Structure

Recommended file layout:

```
/etc/usg-tacacs/
  config.json           # Server configuration
  policy.json           # Authorization policy
  policy.schema.json    # Policy validation schema
  tls/
    server.pem          # Server certificate
    server-key.pem      # Server private key
    client-ca.pem       # Client CA bundle
    extra-roots.pem     # Additional trust anchors

/var/log/usg-tacacs/
  tacacs.log            # Application logs
```

## Initial Setup Checklist

1. **Create service account**
   ```sh
   useradd -r -s /usr/sbin/nologin -d /var/lib/usg-tacacs tacacs
   ```

2. **Generate TLS certificates** (see [TLS Guide](../tls.md))

3. **Create configuration file** from template
   ```sh
   cp config.example.json /etc/usg-tacacs/config.json
   ```

4. **Create authorization policy** (see [Policy Guide](../policy.md))

5. **Validate configuration**
   ```sh
   usg-tacacs-server --check-policy /etc/usg-tacacs/policy.json \
     --schema /etc/usg-tacacs/policy.schema.json
   ```

6. **Set permissions**
   ```sh
   chown -R tacacs:tacacs /etc/usg-tacacs
   chmod 600 /etc/usg-tacacs/tls/server-key.pem
   chmod 640 /etc/usg-tacacs/config.json
   ```

7. **Start and enable service**
   ```sh
   systemctl enable --now usg-tacacs
   ```

## Configuration Management

### Hot Reload

Send `SIGHUP` to reload policy and configuration without restart:

```sh
systemctl reload usg-tacacs
# or
kill -HUP $(pidof usg-tacacs-server)
```

The server will:

- Re-read the policy file
- Re-read the configuration file
- Apply changes without dropping connections

### Configuration Validation

Always validate before deploying:

```sh
usg-tacacs-server --check-policy ./policy.json --schema ./policy.schema.json
```

## Monitoring

### Log Analysis

Logs use structured JSON with UTC timestamps:

```json
{
  "timestamp": "2025-01-01T00:00:00.000000Z",
  "level": "INFO",
  "target": "usg_tacacs_server",
  "message": "authn_pass",
  "peer": "192.0.2.10:54321",
  "user": "admin",
  "session": 12345678
}
```

Key audit events:

| Event | Description |
|-------|-------------|
| `conn_open` | Client connection established |
| `conn_close` | Client connection closed |
| `authn_pass` | Authentication succeeded |
| `authn_fail` | Authentication failed |
| `authz_allow` | Authorization allowed |
| `authz_deny` | Authorization denied |
| `acct_accept` | Accounting record accepted |
| `acct_error` | Accounting record rejected |

### Health Checks

For load balancer integration, monitor:

- TCP connection to port 300 (TLS) or 49 (legacy)
- Process status via systemd
- Log output for error patterns

## Backup and Recovery

### What to Backup

- `/etc/usg-tacacs/config.json`
- `/etc/usg-tacacs/policy.json`
- `/etc/usg-tacacs/tls/*` (certificates and keys)
- `/var/log/usg-tacacs/*` (if local logging)

### Recovery Procedure

1. Restore configuration files
2. Verify permissions
3. Validate policy: `--check-policy`
4. Start service
5. Test authentication from a network device

## Troubleshooting

See the [Troubleshooting section](../operations.md#troubleshooting-checklist) for common issues.

## Next Steps

- [Management API](management-api.md) - REST API for runtime administration
- [TLS Configuration](../tls.md) - Certificate setup and mTLS
- [Authentication](../authentication.md) - LDAPS and static credentials
- [Policy Guide](../policy.md) - Authorization rules
- [Operations](../operations.md) - Day-to-day management
