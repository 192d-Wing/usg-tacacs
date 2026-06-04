#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Bring up usg-tacacs in a local kind cluster. Cilium provides the CNI,
# kube-proxy-replacement service load balancing, and LoadBalancer-IP
# advertisement via L2 announcements (anycast, no HAProxy and no BGP).
# Both TACACS+ listeners are exposed: :49 legacy and :300 mTLS.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
CLUSTER="usg-tacacs"
IMAGE="usg-tacacs:kind"
CILIUM_VERSION="${CILIUM_VERSION:-1.16.5}"

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$1"; }

step "Building image $IMAGE (first build is slow: cold Rust dep compile)"
docker build -f "$HERE/Dockerfile" -t "$IMAGE" "$REPO_ROOT"

step "Creating kind cluster '$CLUSTER' (no kindnet, no kube-proxy)"
if ! kind get clusters | grep -qx "$CLUSTER"; then
  kind create cluster --name "$CLUSTER" --config "$HERE/kind-config.yaml"
else
  echo "cluster already exists, reusing"
fi
kubectl config use-context "kind-${CLUSTER}"

step "Installing Cilium $CILIUM_VERSION via Helm"
# The agent runs in the node's host-network namespace and cannot resolve the
# `kind-control-plane` hostname via Docker DNS, so pass the node's IP directly.
CP_IP="$(docker inspect "${CLUSTER}-control-plane" \
  --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')"
echo "control-plane API IP: $CP_IP"
helm repo add cilium https://helm.cilium.io >/dev/null 2>&1 || true
helm repo update cilium >/dev/null
helm upgrade --install cilium cilium/cilium \
  --version "$CILIUM_VERSION" \
  --namespace kube-system \
  -f "$HERE/cilium-values.yaml" \
  --set k8sServiceHost="$CP_IP" \
  --wait --timeout 5m

step "Waiting for nodes to be Ready"
kubectl wait --for=condition=Ready nodes --all --timeout=180s

step "Loading $IMAGE into kind"
kind load docker-image "$IMAGE" --name "$CLUSTER"

step "Generating PKI"
bash "$HERE/gen-certs.sh"

step "Applying namespace + secrets + config"
kubectl apply -f "$HERE/manifests/namespace.yaml"
kubectl create secret generic tacacs-tls -n tacacs \
  --from-file=server.pem="$HERE/pki/server.pem" \
  --from-file=server-key.pem="$HERE/pki/server-key.pem" \
  --from-file=ca.pem="$HERE/pki/ca.pem" \
  --from-file=secret="$HERE/pki/secret" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl create configmap tacacs-policy -n tacacs \
  --from-file=policy.json="$HERE/policy.json" \
  --from-file=policy.schema.json="$REPO_ROOT/policy/policy.schema.json" \
  --dry-run=client -o yaml | kubectl apply -f -

step "Configuring Cilium LoadBalancer IPAM + L2 announcements"
kubectl apply -f "$HERE/manifests/cilium-lb.yaml"

step "Deploying TACACS+ workload and LoadBalancer Service"
kubectl apply -f "$HERE/manifests/deployment-tacacs.yaml"
kubectl apply -f "$HERE/manifests/service-tacacs.yaml"

step "Waiting for rollout"
kubectl -n tacacs rollout status deploy/tacacs --timeout=180s

step "Status"
kubectl -n tacacs get pods -o wide
LB_IP="$(kubectl -n tacacs get svc tacacs -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)"
kubectl -n tacacs get svc tacacs
cat <<EOF

Done. Cilium load-balances across the TACACS+ pods; LoadBalancer IP: ${LB_IP:-<pending>}
Reachable from this host (kind maps host 49/300 -> NodePort 30049/30300):
  Legacy  : nc -vz localhost 49
  TLS/mTLS: openssl s_client -connect localhost:300 \\
              -cert $HERE/pki/client.pem -key $HERE/pki/client-key.pem \\
              -CAfile $HERE/pki/ca.pem
From inside the cluster the LoadBalancer IP serves :49 and :300 directly.

Tear down with: $HERE/down.sh
EOF
