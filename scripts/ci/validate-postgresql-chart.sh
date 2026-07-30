#!/usr/bin/env bash
set -euo pipefail

chart="${1:-deploy/charts/usg-tacacs-postgresql}"
values="${2:-deploy/sites/example/usg-tacacs-postgresql.values.yaml}"
source_migration="crates/tacacs-server/migrations/0001_jit_leases.sql"
packaged_migration="$chart/files/0001_jit_leases.sql"
rendered="$(mktemp)"
invalid_role="$(mktemp)"
normalized_source="$(mktemp)"
normalized_packaged="$(mktemp)"
trap 'rm -f "$rendered" "$invalid_role" "$normalized_source" "$normalized_packaged"' EXIT

tr -d '\r' <"$source_migration" >"$normalized_source"
tr -d '\r' <"$packaged_migration" >"$normalized_packaged"
if ! cmp "$normalized_source" "$normalized_packaged"; then
    echo "FAIL: packaged migration differs from the authoritative server migration" >&2
    exit 1
fi
helm lint "$chart" --values "$values"
helm template postgresql-security-test "$chart" --values "$values" >"$rendered"

require_rendered() {
    local pattern="$1"
    local description="$2"
    if ! grep -Eq "$pattern" "$rendered"; then
        echo "FAIL: rendered PostgreSQL chart does not contain $description" >&2
        exit 1
    fi
}

require_rendered '^kind: Cluster$' "a CloudNativePG Cluster"
require_rendered 'enableSuperuserAccess: false' "disabled remote superuser access"
require_rendered 'ssl_min_protocol_version: TLSv1.3' "the TLS 1.3 floor"
require_rendered 'password_encryption: scram-sha-256' "SCRAM password hashing"
require_rendered 'superuser: false' "a non-superuser runtime role"
require_rendered 'createrole: false' "a runtime role without role creation"
require_rendered 'replication: false' "a runtime role without replication"
require_rendered 'PGSSLMODE, value: verify-full' "verified migration TLS"
require_rendered 'readOnlyRootFilesystem: true' "a read-only migration root filesystem"
require_rendered 'automountServiceAccountToken: false' "no migration API token"
require_rendered 'port: 8000' "operator instance-manager access"
require_rendered 'port: 5432' "restricted PostgreSQL access"

cat >"$invalid_role" <<'EOF'
database:
  runtimeRole: 'tacacs-jit;DROP ROLE postgres'
EOF
if helm lint "$chart" --values "$values" --values "$invalid_role" \
    >/dev/null 2>&1; then
    echo "FAIL: chart accepted an unsafe PostgreSQL role identifier" >&2
    exit 1
fi

echo "CloudNativePG chart security validation passed."
