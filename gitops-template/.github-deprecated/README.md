# Deprecated: GitHub Actions for GitOps Template

**Status:** ⚠️ DEPRECATED as of 2026-01-27

This directory contained GitHub Actions workflow for GitOps template validation.

## Migration to GitLab

The GitOps template workflow should be migrated to GitLab CI if this template is actively used.

### Previous Workflow

**File:** `workflows/validate.yml`
- **Purpose:** Validate GitOps configuration files
- **Triggers:** Push, PR, scheduled validation

### Migration Path

If you need to reactivate GitOps validation:

1. **Convert to GitLab CI** - Create `.gitlab-ci.yml` in gitops-template:
```yaml
validate-gitops:
  stage: test
  image: appropriate-image
  script:
    - # Validation commands here
  only:
    - merge_requests
    - master
```

2. **Or use as reference** - Keep this for historical reference if no longer needed

## Cleanup

This directory can be safely deleted if GitOps template is no longer in use:

```bash
rm -rf .github-deprecated
```

---

**Deprecation Date:** 2026-01-27
**Parent Project CI:** See [main .gitlab-ci.yml](../../.gitlab-ci.yml)
