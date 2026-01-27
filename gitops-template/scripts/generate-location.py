#!/usr/bin/env python3
"""
Generate a new location directory with templates.

Usage:
    python generate-location.py NYC01 --ip 10.1.1.10 --region US-EAST

NIST SP 800-53 Controls:
- CM-2: Baseline Configuration (Consistent location templates)
- CM-6: Configuration Settings (Standardized configuration)
"""

import argparse
import json
import os
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description='Generate a new TACACS+ location')
    parser.add_argument('location_code', help='Location code (e.g., NYC01)')
    parser.add_argument('--ip', required=True, help='TACACS server IP address')
    parser.add_argument('--region', required=True, help='Region (e.g., US-EAST)')
    parser.add_argument('--name', help='Full location name (e.g., "New York 01")')
    parser.add_argument('--ldap-server', help='LDAP server URL')
    parser.add_argument('--environment', default='production', help='Environment (production/staging)')

    args = parser.parse_args()

    # Validate location code format
    if not args.location_code.isalnum():
        print(f"ERROR: Location code must be alphanumeric: {args.location_code}")
        sys.exit(1)

    # Create location directory
    location_dir = Path('locations') / args.location_code
    if location_dir.exists():
        print(f"ERROR: Location {args.location_code} already exists")
        sys.exit(1)

    location_dir.mkdir(parents=True, exist_ok=True)
    print(f"✓ Created directory: {location_dir}")

    # Generate config.json
    config = {
        "$schema": "../../schemas/config.schema.json",
        "version": "1.0",
        "comment": f"{args.location_code} location configuration",
        "location": {
            "name": args.name or f"{args.location_code} Datacenter",
            "site_code": args.location_code,
            "region": args.region,
            "environment": args.environment
        },
        "listen_tls": f"{args.ip}:300",
        "listen_http": "127.0.0.1:8080"
    }

    # Add LDAP if provided
    if args.ldap_server:
        config["ldap"] = {
            "enabled": True,
            "server": args.ldap_server,
            "bind_dn": f"CN=tacacs-svc,OU=Service Accounts,DC=corp,DC=internal",
            "bind_password": "${LDAP_BIND_PASSWORD}",
            "base_dn": "OU=Network Admins,DC=corp,DC=internal",
            "user_filter": "(sAMAccountName={username})",
            "required_groups": [],
            "timeout_secs": 5
        }

    config_path = location_dir / 'config.json'
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=2)
    print(f"✓ Created: {config_path}")

    # Generate policy.json (default deny template)
    policy = {
        "$schema": "../../schemas/policy.schema.json",
        "version": "1.0",
        "comment": f"{args.location_code} location policy",
        "rules": [
            {
                "id": f"{args.location_code.lower()}-default-deny",
                "comment": "Default deny - customize with specific allow rules",
                "priority": 0,
                "match": {"any": True},
                "effect": "deny",
                "server_msg": f"Access denied at {args.location_code}. Contact NOC."
            }
        ],
        "metadata": {
            "location": args.location_code,
            "managed_by": "gitops",
            "contact": "neteng@example.com"
        }
    }

    policy_path = location_dir / 'policy.json'
    with open(policy_path, 'w') as f:
        json.dump(policy, f, indent=2)
    print(f"✓ Created: {policy_path}")

    # Generate secrets template
    secrets_template = f"""# Secrets for {args.location_code}
#
# IMPORTANT: Encrypt this file with SOPS before committing!
#
# Commands:
#   sops --encrypt secrets.yaml > secrets.enc.yaml
#   rm secrets.yaml
#   git add secrets.enc.yaml

tacacs_shared_secret: "CHANGE-ME-{args.location_code.lower()}-secret"
ldap_bind_password: "CHANGE-ME-ldap-password"

tls_server_cert: |
  -----BEGIN CERTIFICATE-----
  CHANGE-ME
  -----END CERTIFICATE-----

tls_server_key: |
  -----BEGIN PRIVATE KEY-----
  CHANGE-ME
  -----END PRIVATE KEY-----

_metadata:
  location: "{args.location_code}"
  created: "$(date -I)"
"""

    secrets_path = location_dir / 'secrets.yaml.example'
    with open(secrets_path, 'w') as f:
        f.write(secrets_template)
    print(f"✓ Created: {secrets_path}")

    # Generate README
    readme = f"""# {args.location_code} - {args.name or args.location_code + ' Datacenter'}

**Location Code:** {args.location_code}
**Region:** {args.region}
**Environment:** {args.environment}

## Network Details

- **TACACS Server IP:** {args.ip}
- **Management Network:** TBD
- **VLAN:** TBD

## LDAP Integration

{f"- **LDAP Server:** {args.ldap_server}" if args.ldap_server else "- **LDAP:** Not configured"}
- **Required Groups:** TBD

## Policy

Current policy: Default deny all
**Action Required:** Customize `policy.json` with location-specific rules

## Contacts

- **Primary:** TBD
- **Secondary:** TBD
- **Emergency:** 24/7 SOC - soc@example.com

## Setup Checklist

- [ ] Customize `config.json` with location details
- [ ] Create `policy.json` with appropriate access rules
- [ ] Generate and encrypt secrets: `secrets.enc.yaml`
- [ ] Update this README with contact information
- [ ] Deploy to staging for testing
- [ ] Deploy to production
- [ ] Update monitoring dashboards
- [ ] Document in network inventory

## Deployment

```bash
# Deploy with ArgoCD
argocd app sync tacacs-{args.location_code.lower()}

# Or with Ansible
ansible-playbook ansible/pull-deploy.yml --limit tacacs-{args.location_code.lower()}
```

## Documentation

- [Base Configuration](../../base/config.json)
- [Policy Schema](../../schemas/policy.schema.json)
"""

    readme_path = location_dir / 'README.md'
    with open(readme_path, 'w') as f:
        f.write(readme)
    print(f"✓ Created: {readme_path}")

    print(f"\n✅ Location {args.location_code} created successfully!")
    print(f"\nNext steps:")
    print(f"1. Review and customize: {config_path}")
    print(f"2. Define access policy: {policy_path}")
    print(f"3. Create secrets file: {location_dir}/secrets.yaml")
    print(f"4. Encrypt secrets: sops --encrypt {location_dir}/secrets.yaml > {location_dir}/secrets.enc.yaml")
    print(f"5. Update README: {readme_path}")
    print(f"6. Commit and push to git")


if __name__ == '__main__':
    main()
