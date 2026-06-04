#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Delete the local kind cluster created by up.sh.
set -euo pipefail
CLUSTER="${1:-usg-tacacs}"
kind delete cluster --name "$CLUSTER"
echo "Deleted kind cluster '$CLUSTER'."
