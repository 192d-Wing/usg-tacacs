# Deprecated: GitHub Actions

**Status:** ⚠️ DEPRECATED as of 2026-01-27

This directory contains deprecated GitHub Actions workflows. The project has migrated to **GitLab CI/CD**.

## Migration to GitLab

All CI/CD pipelines are now managed via GitLab CI:
- **Configuration:** [.gitlab-ci.yml](../.gitlab-ci.yml)
- **Pipeline URL:** https://gitlab.com/192d-wing/usg-tacacs/-/pipelines

## Previous GitHub Workflows

### 1. `workflows/nist-compliance.yml`
**Purpose:** NASA Power of 10 & NIST SP 800-53 compliance validation

**Migrated to GitLab Jobs:**
- `nist-control-coverage` - NIST control header validation
- `nasa-power-of-10-rule4` - Function length validation
- `runtime-unwrap-check` - Safe error handling validation
- `cargo-tests` - Full test suite
- `cargo-audit` - Security vulnerability scanning
- `rustdoc-validation` - Documentation build verification

### 2. `workflows/docs.yml`
**Purpose:** Documentation deployment

**Status:** Superseded by GitLab's `rustdoc-build` job

### 3. `dependabot.yml`
**Purpose:** Automated dependency updates

**Status:** Can be migrated to GitLab's dependency scanning or Renovate bot if needed

## Why GitLab?

The project moved to GitLab CI/CD for:
- ✅ **Better integration** with GitLab hosting
- ✅ **More control** over runner configuration
- ✅ **Unified platform** for code + CI/CD
- ✅ **Advanced features** like scheduled pipelines, manual jobs, and compliance stages

## For Contributors

If you need to run CI checks:
1. Push to GitLab (origin: `gitlab.com:192d-wing/usg-tacacs`)
2. View pipeline at: https://gitlab.com/192d-wing/usg-tacacs/-/pipelines
3. Or run locally: `cargo test`, `cargo clippy`, `cargo fmt --check`

## Cleanup

This directory can be safely deleted after confirming GitLab CI is working correctly.

To remove:
```bash
rm -rf .github-deprecated
git add .github-deprecated
git commit -m "chore: remove deprecated GitHub Actions"
```

---

**Deprecation Date:** 2026-01-27
**GitLab CI Active:** ✅
**Last GitHub Workflow Run:** Check GitHub Actions tab for historical runs
