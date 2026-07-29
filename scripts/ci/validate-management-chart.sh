#!/usr/bin/env bash
set -euo pipefail

chart="${1:-deploy/charts/usg-tacacs}"
values="${2:-deploy/sites/example/usg-tacacs.values.yaml}"
rendered="$(mktemp)"
invalid_identity="$(mktemp)"
invalid_peer="$(mktemp)"
invalid_pki="$(mktemp)"
invalid_lifetime="$(mktemp)"
without_pki="$(mktemp)"
trap 'rm -f "$rendered" "$invalid_identity" "$invalid_peer" "$invalid_pki" "$invalid_lifetime" "$without_pki"' EXIT

helm lint "$chart" --values "$values"
helm template chart-security-test "$chart" --values "$values" \
    --set workloads.tls.enabled=true >"$rendered"

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
require_rendered 'role: management' "the management-only server role"
require_rendered 'role: legacy' "the legacy-only server role"
require_rendered 'role: tls' "the TLS-only server role"
require_rendered 'app.kubernetes.io/component: management' \
    "the management workload selector"
require_rendered 'app.kubernetes.io/component: legacy' \
    "the legacy workload selector"
require_rendered 'app.kubernetes.io/component: tls' \
    "the TLS workload selector"
require_rendered 'port: 49' "the legacy TACACS service"
require_rendered 'port: 300' "the TACACS-over-TLS service"
require_rendered 'kind: Certificate' "cert-manager Certificate resources"
require_rendered 'kind: EstIssuer' "the namespace-scoped EST issuer reference"
require_rendered 'group: pki.usg.mil' "the USG EST issuer API group"
require_rendered 'secretName: tacacs-management-tls' \
    "the management server certificate Secret"
require_rendered 'secretName: tacacs-dataplane-tls' \
    "the data-plane server certificate Secret"
require_rendered 'secretName: tacacs-ui-tls' "the UI server certificate Secret"
require_rendered 'certificateFile: /run/tls/management/tls.crt' \
    "the standard management certificate path"
require_rendered 'clientCaFile: /run/trust/management-client/ca.crt' \
    "the separate management client trust path"
require_rendered 'certificateFile: /run/tls/dataplane/tls.crt' \
    "the standard data-plane certificate path"
require_rendered 'clientCaFile: /run/trust/dataplane-client/ca.crt' \
    "the separate data-plane client trust path"

certificate_count="$(grep -c '^kind: Certificate$' "$rendered")"
if [[ "$certificate_count" -ne 3 ]]; then
    echo "FAIL: expected 3 Certificate resources, found $certificate_count" >&2
    exit 1
fi

helm template chart-security-test "$chart" --values "$values" \
    --set pki.enabled=false >"$without_pki"
if grep -q '^kind: Certificate$' "$without_pki"; then
    echo "FAIL: chart rendered Certificate resources while pki.enabled=false" >&2
    exit 1
fi

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

cat >"$invalid_pki" <<'EOF'
pki:
  privateKey:
    algorithm: RSA
    size: 2048
    rotationPolicy: Never
EOF

if helm lint "$chart" --values "$values" --values "$invalid_pki" \
    >/dev/null 2>&1; then
    echo "FAIL: chart accepted a non-P-384 or non-rotating workload key" >&2
    exit 1
fi

cat >"$invalid_lifetime" <<'EOF'
pki:
  duration: 24h
  renewBefore: 24h
EOF

if helm template invalid-lifetime "$chart" --values "$values" --values "$invalid_lifetime" \
    >/dev/null 2>&1; then
    echo "FAIL: chart accepted renewBefore greater than or equal to duration" >&2
    exit 1
fi

echo "Management chart negative validation passed."
