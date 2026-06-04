#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Generate a self-signed PKI for the k3s TACACS+ deployment.
#   - ca.pem / ca-key.pem        self-signed CA (also the mTLS client CA)
#   - server.pem / server-key.pem  server cert (SANs incl. the anycast IPs)
#   - client.pem / client-key.pem  test client cert for mTLS into :300
#   - secret                       TACACS+ shared secret (set to ciscotest12-)
#
# NIST SP 800-53 Rev. 5: SC-8/SC-17 (TLS material), IA-5 (key generation).
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pki"
mkdir -p "$DIR"
cd "$DIR"
DAYS=825

echo "==> CA"
openssl req -x509 -newkey rsa:4096 -nodes -keyout ca-key.pem -out ca.pem \
  -days "$DAYS" -subj "/CN=usg-tacacs-k3s-ca/O=usg-tacacs" 2>/dev/null

gen_leaf() {
  local name="$1" cn="$2" ext="$3"
  openssl req -newkey rsa:2048 -nodes -keyout "${name}-key.pem" -out "${name}.csr" \
    -subj "/CN=${cn}/O=usg-tacacs" 2>/dev/null
  openssl x509 -req -in "${name}.csr" -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
    -out "${name}.pem" -days "$DAYS" -extfile <(printf '%s' "$ext") 2>/dev/null
  rm -f "${name}.csr"
}

echo "==> server cert (SANs include anycast 10.10.10.55 / ::55)"
gen_leaf server "tacacs" \
"subjectAltName=DNS:tacacs,DNS:tacacs.tacacs.svc,DNS:tacacs.tacacs.svc.cluster.local,IP:10.10.10.55,IP:2601:443:c200:575::55
extendedKeyUsage=serverAuth"

echo "==> client cert (mTLS test)"
gen_leaf client "tacacs-test-client" "extendedKeyUsage=clientAuth"

echo "==> shared secret"
printf '%s' "ciscotest12-" > secret

rm -f ca.srl
chmod 600 ./*-key.pem secret
echo "==> PKI written to $DIR"
ls -1 "$DIR"
