# TACACS+ GitOps Repository Template

This repository provides a GitOps structure for managing TACACS+ server deployments across 184 locations using ArgoCD or Ansible.

## Architecture

```
┌─────────────────┐
│   Git Repository │ (Single Source of Truth)
│   (this repo)    │
└────────┬─────────┘
         │
         ├─── ArgoCD ────────> Kubernetes Clusters
         │                     (containerized deployments)
         │
         └─── Ansible ───────> On-Prem VMs/Bare Metal
                               (systemd deployments)
```

## Directory Structure

```
tacacs-gitops/
├── argocd/              # ArgoCD configuration
│   ├── applicationset.yaml   # Generates 184 apps automatically
│   ├── project.yaml          # ArgoCD project definition
│   └── rbac.yaml             # ArgoCD RBAC rules
│
├── base/                # Base configuration (inherited by all locations)
│   ├── config.json           # Default server config
│   ├── policy.json           # Default policy rules
│   ├── rbac.json             # Default API RBAC
│   └── kustomization.yaml    # Kustomize base
│
├── overlays/            # Environment-specific overlays
│   ├── production/
│   │   └── kustomization.yaml
│   └── staging/
│       └── kustomization.yaml
│
├── locations/           # Per-location configuration (184 directories)
│   ├── NYC01/
│   │   ├── config.json       # Location-specific overrides
│   │   ├── policy.json       # Location-specific rules
│   │   ├── secrets.enc.yaml  # SOPS-encrypted secrets
│   │   └── README.md         # Location notes
│   ├── LAX01/
│   └── ... (184 locations)
│
├── policies/            # Shared policy templates
│   ├── global/
│   │   ├── deny-dangerous.json    # Global deny rules
│   │   └── compliance.json        # Compliance policies
│   └── templates/
│       ├── standard-policy.json   # Standard template
│       └── privileged-policy.json # High-security template
│
├── schemas/             # JSON schemas for validation
│   ├── policy.schema.json
│   ├── config.schema.json
│   └── secrets.schema.json
│
└── scripts/             # Automation scripts
    ├── validate-policy.py         # CI policy validation
    ├── generate-location.py       # Scaffold new location
    ├── sync-secrets.sh            # SOPS key management
    └── test-config.sh             # Config validation
```

## Quick Start

### 1. Fork This Repository

```bash
# Fork to your organization
git clone https://github.com/your-org/tacacs-gitops
cd tacacs-gitops
```

### 2. Configure SOPS Encryption

```bash
# Generate age key for SOPS
age-keygen -o ~/.config/sops/age/keys.txt

# Or use AWS KMS
export SOPS_KMS_ARN="arn:aws:kms:us-east-1:123456789:key/your-key-id"

# Create .sops.yaml
cat > .sops.yaml <<EOF
creation_rules:
  - path_regex: locations/.*/secrets\.enc\.yaml$
    age: age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
EOF
```

### 3. Create Your First Location

```bash
# Generate location directory
python scripts/generate-location.py NYC01 \
  --ip 10.1.1.10 \
  --network 10.1.0.0/16 \
  --ldap-server ldap.nyc.corp.internal

# Edit the generated files
vim locations/NYC01/config.json
vim locations/NYC01/policy.json

# Encrypt secrets
sops --encrypt locations/NYC01/secrets.yaml > locations/NYC01/secrets.enc.yaml
rm locations/NYC01/secrets.yaml
```

### 4. Deploy with ArgoCD

```bash
# Apply ArgoCD ApplicationSet
kubectl apply -f argocd/project.yaml
kubectl apply -f argocd/applicationset.yaml

# ArgoCD will automatically create 184 applications
argocd app list | grep tacacs
```

### 5. Deploy with Ansible (On-Prem)

```bash
# Run Ansible playbook
ansible-playbook -i inventory/production ansible/pull-deploy.yml \
  --limit tacacs-nyc01

# Or use AWX/Tower with webhook trigger
curl -X POST https://awx.example.com/api/v2/job_templates/123/launch/ \
  -H "Authorization: Bearer $AWX_TOKEN" \
  -d '{"extra_vars": {"location": "NYC01"}}'
```

## Features

### 🔐 Security

- **SOPS Encryption**: All secrets encrypted at rest
- **GPG/Age Support**: Flexible key management
- **AWS KMS Integration**: Cloud-native secret management
- **Audit Trail**: Git history tracks all changes

### 🚀 Automation

- **ArgoCD Sync**: Automatic deployment on git push
- **Policy Validation**: CI/CD validates before merge
- **Schema Validation**: JSON schemas prevent misconfigurations
- **Rollback Support**: Git revert for instant rollback

### 📊 Observability

- **ArgoCD Dashboard**: Visual deployment status
- **Sync Health**: Per-location health monitoring
- **Drift Detection**: Detects manual changes
- **Audit Logs**: Complete change history

## Deployment Patterns

### Pattern 1: ArgoCD (Kubernetes)

**Best for:** Cloud deployments, containerized environments

```yaml
# ApplicationSet generates per-location apps
locations/NYC01/ ──> tacacs-nyc01 (App)
locations/LAX01/ ──> tacacs-lax01 (App)
```

**Advantages:**
- Automatic sync on git push
- Visual dashboards
- Built-in rollback
- Multi-cluster support

### Pattern 2: Ansible Pull (On-Prem VMs)

**Best for:** Bare metal, legacy infrastructure

```yaml
# Ansible pulls from git and applies
Git Repo ──> Ansible Pull ──> TACACS Server
```

**Advantages:**
- No Kubernetes required
- Works with existing Ansible
- SOPS integration
- Scheduled sync

### Pattern 3: Hybrid (Both)

**Best for:** Mixed environments

```yaml
# Cloud locations use ArgoCD
locations/AWS-* ──> ArgoCD

# On-prem locations use Ansible
locations/ONPREM-* ──> Ansible
```

## Configuration Management

### Inheritance Model

```
base/config.json          # Global defaults
  ↓
overlays/production/      # Environment overrides
  ↓
locations/NYC01/config.json  # Location-specific
```

### Example: Location Override

**base/config.json:**
```json
{
  "listen_tls": "0.0.0.0:300",
  "ldap": {
    "enabled": false
  }
}
```

**locations/NYC01/config.json:**
```json
{
  "ldap": {
    "enabled": true,
    "server": "ldaps://ldap.nyc.internal:636"
  }
}
```

**Result:** NYC01 inherits `listen_tls` but overrides `ldap` config.

## Secret Management

### Encrypting Secrets

```bash
# Create secrets file
cat > locations/NYC01/secrets.yaml <<EOF
tacacs_shared_secret: "super-secret-key-12345"
ldap_bind_password: "ldap-password"
api_tls_key: |
  -----BEGIN PRIVATE KEY-----
  MIIEvQIBADANBgkqhki...
  -----END PRIVATE KEY-----
EOF

# Encrypt with SOPS
sops --encrypt locations/NYC01/secrets.yaml > locations/NYC01/secrets.enc.yaml

# Delete plaintext
rm locations/NYC01/secrets.yaml
```

### Decrypting in Deployment

**ArgoCD with SOPS Plugin:**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: tacacs-secrets
stringData:
  # ArgoCD SOPS plugin decrypts automatically
  config: |
    {{- sops "locations/NYC01/secrets.enc.yaml" | nindent 4 }}
```

**Ansible:**
```yaml
- name: Decrypt secrets
  command: sops -d locations/{{ location }}/secrets.enc.yaml
  register: secrets

- name: Apply secrets
  template:
    content: "{{ secrets.stdout }}"
    dest: /etc/tacacs/secrets.yaml
```

## CI/CD Validation

### GitHub Actions

```yaml
# .github/workflows/validate.yml
name: Validate Configurations
on: [pull_request]

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Validate JSON Schemas
        run: |
          pip install jsonschema
          python scripts/validate-policy.py

      - name: Test Policy Compilation
        run: |
          for policy in locations/*/policy.json; do
            cargo run --bin tacacs-policy-check -- --policy "$policy"
          done

      - name: Check SOPS Encryption
        run: |
          # Ensure secrets are encrypted
          ! grep -r "BEGIN PRIVATE KEY" locations/
```

### Pre-commit Hooks

```bash
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: validate-json
        name: Validate JSON
        entry: python scripts/validate-policy.py
        language: python
        files: \\.json$

      - id: check-secrets
        name: Check for unencrypted secrets
        entry: scripts/check-secrets.sh
        language: script
        files: secrets
```

## Rollback Procedures

### ArgoCD Rollback

```bash
# Rollback to previous commit
argocd app rollback tacacs-nyc01

# Or revert git commit
git revert HEAD
git push
# ArgoCD auto-syncs the revert
```

### Ansible Rollback

```bash
# Checkout previous version
git checkout HEAD~1

# Re-run Ansible
ansible-playbook ansible/pull-deploy.yml --limit tacacs-nyc01

# Or use git revert
git revert HEAD && git push
```

## Monitoring

### ArgoCD Health Checks

```yaml
# ApplicationSet includes health checks
health:
  http:
    url: http://tacacs-server:8080/health
    expectedStatus: 200
```

### Prometheus Alerts

```yaml
# Alert on sync failures
- alert: TacacsGitOpsSyncFailed
  expr: argocd_app_sync_status{app=~"tacacs-.*"} != 3
  for: 10m
  annotations:
    summary: "TACACS GitOps sync failed for {{ $labels.app }}"
```

## Best Practices

### 1. Location Naming

Use consistent naming: `{SITE}{NUMBER}` (e.g., NYC01, LAX02)

### 2. Policy Templates

Start from templates, customize minimally:

```bash
cp policies/templates/standard-policy.json locations/NYC01/policy.json
# Edit only what's needed
```

### 3. Secret Rotation

Rotate secrets regularly:

```bash
# Generate new secret
python scripts/rotate-secret.py locations/NYC01/secrets.enc.yaml

# Commit and push
git commit -m "rotate: NYC01 secrets"
git push
# ArgoCD/Ansible auto-deploys
```

### 4. Testing

Test in staging first:

```bash
# Deploy to staging overlay
git checkout -b test-nyc01-policy
# Make changes to locations/NYC01/
git push origin test-nyc01-policy

# ArgoCD deploys to staging cluster
# Verify, then merge to main for production
```

## Troubleshooting

### Sync Failures

```bash
# Check ArgoCD application status
argocd app get tacacs-nyc01

# View sync errors
argocd app logs tacacs-nyc01

# Manual sync
argocd app sync tacacs-nyc01 --force
```

### SOPS Decryption Errors

```bash
# Verify SOPS key access
sops -d locations/NYC01/secrets.enc.yaml

# Re-encrypt with correct key
sops --rotate --in-place locations/NYC01/secrets.enc.yaml
```

### Schema Validation Errors

```bash
# Validate locally
python scripts/validate-policy.py locations/NYC01/policy.json

# Fix and re-validate
vim locations/NYC01/policy.json
python scripts/validate-policy.py locations/NYC01/policy.json
```

## References

- [ArgoCD Documentation](https://argo-cd.readthedocs.io/)
- [SOPS Documentation](https://github.com/mozilla/sops)
- [Kustomize Documentation](https://kustomize.io/)
- [TACACS+ Server Documentation](../../docs/)

## Support

For issues and questions:
- **Internal**: #tacacs-gitops Slack channel
- **Documentation**: [docs/](../../docs/)
- **Issues**: Open a GitHub issue
