<!-- NIST SP 800-53 Rev. 5: IA-5 (authenticator management), SC-12 (key establishment), AC-4 (network restriction). -->
# Legacy TACACS+ Shared-Secret Rotation (Phase 0 containment)

The `:49` listener's entire trust boundary is the MD5 obfuscation shared secret.
The previous value (`ciscotest12-`) was weak and had leaked into the repo, so it
must be treated as compromised. This runbook rotates it.

> **Production impact:** every real NAD using the old secret stops authenticating
> the moment the pods restart. Schedule a window and re-key NADs in lockstep.

## 0. Where the secret lives

| Context | How `TACACS_SECRET` is set |
|---------|----------------------------|
| **Running server (cluster)** | Env var injected from the `tacacs-tls` Secret, key `secret` → see [manifests/deployment-tacacs.yaml](manifests/deployment-tacacs.yaml) lines 97-102. The server reads the `TACACS_SECRET` env at startup. |
| **PKI generation (workstation)** | `gen-certs.sh` reads `TACACS_SECRET` from your shell if exported; otherwise it generates a random one. `export TACACS_SECRET=...` before running the script to pin a value. |

## 1. Generate the new secret (already done once for you)

```bash
NEW_SECRET="$(openssl rand -base64 32)"   # >=32 bytes, high entropy
```

## 2. Update the cluster Secret and restart

```bash
# Patch the 'secret' key of the tacacs-tls Secret (base64 of the raw value).
kubectl -n tacacs patch secret tacacs-tls \
  --type=merge \
  -p "{\"data\":{\"secret\":\"$(printf '%s' "$NEW_SECRET" | base64 -w0)\"}}"

# Roll the deployment so all 3 pods pick up the new env value.
kubectl -n tacacs rollout restart deployment/tacacs
kubectl -n tacacs rollout status  deployment/tacacs
```

## 3. Re-key the NADs

Set the same `$NEW_SECRET` on each network device's TACACS+ server config during
the window. **Preferred:** migrate to per-NAD secrets so one secret is not shared
fleet-wide (`--legacy-nad-secret <IP>:<secret>` — Phase 2).

## 4. Verify

```bash
# Old secret must now FAIL; new secret handshakes.
# (uses the pentest harness in /tmp/tacacs_pt)
python3 - <<'PY'
from tacacs import pap_login
HOST="10.10.10.55"
print("old:", end=" "); pap_login(HOST,49,b"ciscotest12-","alice","x")     # expect drop/close
print("new:", end=" "); pap_login(HOST,49,b"<NEW_SECRET>","alice","x")      # expect FAIL invalid creds
PY
```
Old secret → connection reset (rejected). New secret → reaches auth (`FAIL invalid credentials`).

## 5. Local PKI script

If you regenerate PKI with `gen-certs.sh`, pin the same secret:
```bash
export TACACS_SECRET="$NEW_SECRET"
./deploy/k3s/gen-certs.sh
```
