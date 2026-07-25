#!/usr/bin/env bash
set -euo pipefail

chart="${1:-deploy/charts/usg-tacacs}"
values="${2:-deploy/sites/example/usg-tacacs.values.yaml}"
rendered="$(mktemp)"
invalid_identity="$(mktemp)"
invalid_peer="$(mktemp)"
trap 'rm -f "$rendered" "$invalid_identity" "$invalid_peer"' EXIT

helm lint "$chart" --values "$values"
helm template chart-security-test "$chart" --values "$values" >"$rendered"

require_rendered() {
    local pattern="$1"
    local description="$2"
    if ! grep -Eq "$pattern" "$rendered"; then
        echo "FAIL: rendered chart does not contain $description" >&2
        exit 1
    fi
}

require_rendered 'certificateIdentity: (cn|dns|email|uri):' \
    "a typed management certificate identity"
require_rendered 'kubernetes.io/metadata.name: "jitpw-system"' \
    "the management peer namespace selector"
require_rendered 'app.kubernetes.io/name: jitpw-api' \
    "the management peer Pod selector"
require_rendered 'port: 8443' "the protected management port"
require_rendered 'type: ClusterIP' "a cluster-internal management Service"

identities="$(sed -n 's/^[[:space:]]*- certificateIdentity: //p' "$rendered")"
if printf '%s\n' "$identities" |
    grep -Ev '^(cn|dns|email|uri):[^[:space:]]+$' |
    grep -q .; then
    echo "FAIL: rendered chart contains an untyped certificate identity" >&2
    exit 1
fi

echo "Management chart security validation passed."

cat >"$invalid_identity" <<'EOF'
management:
  subjects:
    - certificateIdentity: tacacs-admin.example.mil
      role: admin
EOF

if helm lint "$chart" --values "$values" --values "$invalid_identity" \
    >/dev/null 2>&1; then
    echo "FAIL: chart accepted an untyped certificate identity" >&2
    exit 1
fi

cat >"$invalid_peer" <<'EOF'
networkPolicy:
  managementPeers:
    - podLabels:
        app.kubernetes.io/name: jitpw-api
EOF

if helm lint "$chart" --values "$values" --values "$invalid_peer" \
    >/dev/null 2>&1; then
    echo "FAIL: chart accepted a management peer without a namespace" >&2
    exit 1
fi

echo "Management chart negative validation passed."
