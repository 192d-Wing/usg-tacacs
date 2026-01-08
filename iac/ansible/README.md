# TACACS+ Ansible Deployment

Ansible roles and playbooks for deploying TACACS+ servers across multiple locations.

## Directory Structure

```
ansible/
├── roles/
│   ├── tacacs_server/      # Main TACACS+ server deployment
│   ├── tacacs_ha/          # High availability (keepalived/HAProxy)
│   └── tacacs_common/      # Common setup tasks
├── inventory/
│   ├── production/         # Production inventory
│   └── staging/            # Staging inventory
├── playbooks/
│   ├── deploy.yml          # Standard deployment
│   ├── upgrade.yml         # Rolling upgrade
│   ├── rollback.yml        # Emergency rollback
│   └── rotate-certs.yml    # Certificate rotation
└── requirements.yml        # Galaxy dependencies
```

## Quick Start

1. Install dependencies:
   ```bash
   ansible-galaxy collection install -r requirements.yml
   ```

2. Configure inventory for your environment:
   ```bash
   cp -r inventory/production inventory/myenv
   vim inventory/myenv/hosts.yml
   vim inventory/myenv/group_vars/all.yml
   ```

3. Set secrets (use Ansible Vault):
   ```bash
   ansible-vault create inventory/myenv/group_vars/vault.yml
   # Add: tacacs_shared_secret, tacacs_ldap_bind_password, etc.
   ```

4. Deploy:
   ```bash
   ansible-playbook -i inventory/myenv playbooks/deploy.yml --ask-vault-pass
   ```

## Roles

### tacacs_server

Deploys the TACACS+ server binary, configuration, and systemd service.

**Key variables:**
- `tacacs_version`: Version to deploy
- `tacacs_binary_url`: URL to download binary
- `tacacs_shared_secret`: TACACS+ shared secret (vault this!)
- `tacacs_tls_enabled`: Enable TLS (default: true)
- `tacacs_ldap_enabled`: Enable LDAP authentication (default: false)

### tacacs_ha

Configures high availability with keepalived and optional HAProxy.

**Key variables:**
- `tacacs_ha_vip`: Virtual IP address for HA pair
- `tacacs_ha_priority`: VRRP priority (100=primary, 90=secondary)
- `tacacs_ha_haproxy_enabled`: Enable HAProxy load balancing

### tacacs_common

Common setup: user/group creation, directories, firewall rules.

## Playbooks

### deploy.yml
Standard deployment to new or existing servers.

```bash
ansible-playbook -i inventory/production playbooks/deploy.yml
```

### upgrade.yml
Rolling upgrade with graceful connection draining.

```bash
ansible-playbook -i inventory/production playbooks/upgrade.yml \
  -e tacacs_version=0.77.0 \
  -e tacacs_binary_url=https://... \
  -e tacacs_binary_checksum=sha256:...
```

### rollback.yml
Emergency rollback to previous version.

```bash
ansible-playbook -i inventory/production playbooks/rollback.yml \
  -e rollback_binary_url=https://... \
  -e rollback_binary_checksum=sha256:...
```

### rotate-certs.yml
TLS certificate rotation with automatic reload.

```bash
ansible-playbook -i inventory/production playbooks/rotate-certs.yml \
  -e cert_src_dir=/path/to/new/certs
```

## Security Notes

- Always use Ansible Vault for sensitive variables
- The systemd unit includes security hardening (NoNewPrivileges, ProtectSystem, etc.)
- Certificates should have restricted permissions (0600 for keys)
- Shared secrets should be unique per location when possible

## License

Apache-2.0
