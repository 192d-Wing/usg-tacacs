#!/usr/bin/env bash
# NIST SP 800-53 Rev5: CM-2 (Baseline Configuration), CM-6 (Configuration
# Settings), SI-7 (Software, Firmware, and Information Integrity).
#
# Build/refresh the `tacacs-policy` ConfigMap from BOTH files the server needs.
#
# The tacacs-server process reads two files from the mounted policy volume:
#   --policy  /etc/tacacs/policy/policy.json
#   --schema  /etc/tacacs/policy/policy.schema.json
# It validates the policy against the schema AT STARTUP and exits non-zero if
# the schema is missing — so the ConfigMap MUST contain both keys. Creating it
# with only `policy.json` (e.g. a bare `kubectl create configmap
# --from-file=policy.json=...`) drops the schema key and crash-loops every new
# pod. Always use this script so both keys are present.
set -euo pipefail

NS="${NS:-tacacs}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

POLICY="${SCRIPT_DIR}/policy.json"
SCHEMA="${REPO_ROOT}/policy/policy.schema.json"

for f in "${POLICY}" "${SCHEMA}"; do
  if [[ ! -f "${f}" ]]; then
    echo "error: required file not found: ${f}" >&2
    exit 1
  fi
done

kubectl create configmap tacacs-policy -n "${NS}" \
  --from-file=policy.json="${POLICY}" \
  --from-file=policy.schema.json="${SCHEMA}" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "applied configmap/tacacs-policy in ns/${NS} with keys: policy.json, policy.schema.json"
