# NYC01 - New York Datacenter 01

**Location Code:** NYC01
**Region:** US-EAST
**Environment:** Production
**Site Type:** Primary Datacenter

## Overview

Primary datacenter in New York serving the US East region. Houses core network infrastructure including:
- 2x Core routers (Cisco ASR 9000)
- 4x Distribution switches (Cisco Nexus 9000)
- 12x Access switches (Cisco Catalyst 9300)

## Network Details

- **TACACS Server IP:** 10.1.1.10
- **Management Network:** 10.1.0.0/16
- **VLAN:** 100 (Management)
- **Gateway:** 10.1.0.1

## LDAP Integration

- **LDAP Server:** ldaps://ldap.nyc.corp.internal:636
- **Base DN:** OU=Network Admins,DC=corp,DC=internal
- **Groups:**
  - `Network-Senior-Engineers-NYC` - Full privileged access (priv 15)
  - `Network-Engineers-NYC` - Read-only access (priv 1) + show commands
  - `NOC-NYC` - Monitoring only (show/ping/traceroute)

## Policy Highlights

### Allowed Commands
- **Senior Engineers:** All commands (priv 15)
- **Engineers:** Show commands only
- **NOC:** Show, ping, traceroute

### Denied Commands
- `reload` - Requires change control approval
- Configuration changes for regular engineers

### Emergency Access
- Username: `emergency-admin`
- Must originate from management network (10.1.0.0/16)
- Full access (priv 15)
- **All actions are logged**

## Monitoring

- **Prometheus:** Metrics exported to Prometheus cluster
- **OTLP:** Traces sent to otel-collector.nyc.internal:4317
- **Logs:** Forwarded to ELK stack
- **Health Check:** http://10.1.1.10:8080/health

## Contacts

- **Primary:** NYC NOC Team - noc-nyc@example.com
- **Secondary:** Network Engineering - neteng@example.com
- **Emergency:** 24/7 SOC - soc@example.com

## Change Management

All changes to this location's configuration must go through:

1. Create branch from `main`
2. Modify files in `locations/NYC01/`
3. Create pull request
4. CI/CD validation runs automatically
5. Peer review required
6. Merge to `main`
7. ArgoCD auto-deploys within 3 minutes

## Rollback Procedure

```bash
# Immediate rollback via ArgoCD
argocd app rollback tacacs-nyc01

# Or revert Git commit
git revert <commit-hash>
git push origin main
```

## Troubleshooting

### TACACS Server Not Responding

```bash
# Check pod status
kubectl get pods -n tacacs-nyc01

# View logs
kubectl logs -n tacacs-nyc01 deployment/tacacs-server -f

# Check health endpoint
curl http://10.1.1.10:8080/health
```

### LDAP Authentication Failures

```bash
# Test LDAP connectivity
kubectl exec -n tacacs-nyc01 deployment/tacacs-server -- \
  ldapsearch -H ldaps://ldap.nyc.corp.internal:636 \
  -D "CN=tacacs-svc,OU=Service Accounts,DC=corp,DC=internal" \
  -W -b "OU=Network Admins,DC=corp,DC=internal"
```

### Policy Not Applied

```bash
# Trigger policy reload
curl -X POST http://127.0.0.1:8080/api/v1/policy/reload \
  -H "X-User-CN: CN=admin.tacacs.internal"

# Or send SIGHUP
kubectl exec -n tacacs-nyc01 deployment/tacacs-server -- \
  kill -HUP 1
```

## Compliance

This location is subject to:
- SOC 2 Type II
- PCI-DSS v4.0
- NIST SP 800-53 Rev. 5

Last audit: 2025-12-15
Next audit: 2026-06-15

## Documentation

- [Base Configuration](../../base/config.json)
- [Policy Schema](../../schemas/policy.schema.json)
- [TACACS+ Documentation](../../../docs/)
