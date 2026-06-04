#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Generate a self-signed PKI for the kind deployment.
#   - ca.pem / ca-key.pem        self-signed CA (also the mTLS client CA)
#   - server.pem / server-key.pem  TACACS+ server cert (SANs for in-cluster + host)
#   - client.pem / client-key.pem  test client cert for mTLS into :300
#   - secret                       TACACS+ shared obfuscation secret
#
# NIST SP 800-53 Rev. 5: SC-8/SC-17 (TLS material), IA-5 (key generation).
# Self-signed material is for LOCAL TESTING ONLY.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pki"
mkdir -p "$DIR"
cd "$DIR"

DAYS=825

echo "==> Generating CA"
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout ca-key.pem -out ca.pem -days "$DAYS" \
  -subj "/CN=usg-tacacs-kind-ca/O=usg-tacacs" 2>/dev/null

gen_leaf() {
  local name="$1" cn="$2" ext="$3"
  openssl req -newkey rsa:2048 -nodes \
    -keyout "${name}-key.pem" -out "${name}.csr" \
    -subj "/CN=${cn}/O=usg-tacacs" 2>/dev/null
  openssl x509 -req -in "${name}.csr" \
    -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
    -out "${name}.pem" -days "$DAYS" \
    -extfile <(printf '%s' "$ext") 2>/dev/null
  rm -f "${name}.csr"
}

echo "==> Generating server cert"
gen_leaf server "tacacs" \
"subjectAltName=DNS:tacacs,DNS:tacacs.tacacs.svc,DNS:tacacs.tacacs.svc.cluster.local,DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth"

echo "==> Generating client cert (mTLS test)"
gen_leaf client "tacacs-test-client" \
"extendedKeyUsage=clientAuth"

echo "==> Generating shared secret"
openssl rand -base64 32 | tr -d '\n' > secret

rm -f ca.srl
chmod 600 ./*-key.pem secret
echo "==> PKI written to $DIR"
ls -1 "$DIR"
