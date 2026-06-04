#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Generate an argon2id user-password hash file for --user-password-hash-file.
#
# Reads cleartext "user:password" lines from deploy/k3s/pki/creds.txt (gitignored;
# copy from creds.example.txt) and writes "user:$argon2id$..." lines to
# deploy/k3s/pki/user-hashes. The cleartext never leaves your machine; only the
# argon2 hashes are mounted into the cluster (as the tacacs-creds Secret).
#
# NIST SP 800-53 Rev. 5: IA-5(1) (no cleartext stored authenticators).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IN="${1:-$HERE/pki/creds.txt}"
OUT="$HERE/pki/user-hashes"
mkdir -p "$HERE/pki"

[ -f "$IN" ] || { echo "ERROR: $IN not found. Copy $HERE/creds.example.txt to it and set real passwords." >&2; exit 1; }
python3 -c "import argon2" 2>/dev/null || { echo "ERROR: need argon2-cffi (pip install argon2-cffi)." >&2; exit 1; }

: > "$OUT"
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in ''|\#*) continue;; esac
  user="${line%%:*}"; pass="${line#*:}"
  hash="$(USER_PW="$pass" python3 -c 'import os,argon2; print(argon2.PasswordHasher().hash(os.environ["USER_PW"]))')"
  printf '%s:%s\n' "$user" "$hash" >> "$OUT"
done < "$IN"
chmod 600 "$OUT"
echo "wrote $(grep -c . "$OUT") argon2 hashes to $OUT"
