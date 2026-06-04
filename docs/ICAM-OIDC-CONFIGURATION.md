# ICAM/OIDC Authentication Configuration

**Project:** usg-tacacs TACACS+ Server.  
**Date:** 2026-06-04.  
**Audience:** Platform Engineers, Security Architects.

Replaces local username/password storage with enterprise ICAM-delegated authentication.
The TACACS+ server acts as a proxy: NAD credentials are forwarded to Keycloak via the
OIDC Resource Owner Password Credentials (ROPC) grant, and the returned JWT group claims
are mapped directly to TACACS+ authorization policy rules.

## Auth flow

```plain
NAD
 │  PAP/ASCII (username + password)
 ▼
TACACS pod
 │  POST /realms/{realm}/protocol/openid-connect/token
 │  grant_type=password, username=X, password=Y, client_id=Z, client_secret=W
 ▼
Keycloak (icam.oopl.dev.mil)
 │  200 OK — JWT access token
 │  {"sub":"alice","groups":["netops","read-only"]}
 ▼
TACACS pod
 │  maps "netops" → policy rule → priv-lvl 15
 ▼
NAD  ← PASS + AV-pairs
```

## NIST SP 800-53 Rev. 5 controls

| Control | Family | Implementation |
| --------- | -------- | ---------------- |
| IA-2 | Identification and Authentication | Credentials validated by enterprise ICAM, not local store |
| IA-5 | Authenticator Management | No local password hashes; secret rotated in Keycloak |
| IA-8 | Non-Organizational User Auth | OIDC federation via Keycloak realm |
| SC-8 | Transmission Confidentiality | All ICAM calls over HTTPS; plaintext endpoint rejected |
| AC-2 | Account Management | Group membership managed centrally in Keycloak |
| AC-3 | Access Enforcement | JWT groups claim drives TACACS+ rule evaluation |
| AU-2 | Audit Events | Auth outcomes and group resolution logged via tracing |

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Step 1 — Keycloak: Create the TACACS+ client](#step-1--keycloak-create-the-tacacs-client)
3. [Step 2 — Keycloak: Add a groups mapper](#step-2--keycloak-add-a-groups-mapper)
4. [Step 3 — Keycloak: Create groups and assign users](#step-3--keycloak-create-groups-and-assign-users)
5. [Step 4 — Store the client secret](#step-4--store-the-client-secret)
6. [Step 5 — Update the Deployment manifest](#step-5--update-the-deployment-manifest)
7. [Step 6 — Update the policy](#step-6--update-the-policy)
8. [Step 7 — Apply and verify](#step-7--apply-and-verify)
9. [Helm values reference](#helm-values-reference)
10. [Troubleshooting](#troubleshooting)
11. [Migration checklist](#migration-checklist)

---

## Prerequisites

- Keycloak running at `https://icam.oopl.dev.mil` with a configured realm (e.g. `dcim`)
- `kubectl` access to the `tacacs` namespace
- Existing TACACS+ deployment at `deploy/k3s/manifests/deployment-tacacs.yaml`

---

## Step 1 — Keycloak: Create the TACACS+ client

In the Keycloak admin console (`https://icam.oopl.dev.mil/admin`):

1. Select your realm (e.g. **dcim**).
2. Go to **Clients → Create client**.
3. Set the following:

   | Field | Value |
   |-------|-------|
   | Client type | OpenID Connect |
   | Client ID | `tacacs-server` |
   | Name | usg-tacacs ROPC client |
   | Client authentication | **ON** (confidential) |
   | Standard flow | OFF |
   | Direct access grants | **ON** (enables ROPC) |
   | Service accounts roles | OFF |

4. Click **Save**.
5. On the **Credentials** tab, copy the **Client secret** — you will store it in a Kubernetes Secret in Step 4.

> **Why confidential, not public?**  The TACACS+ server authenticates to Keycloak with a
> client secret so that only authorised services can perform ROPC flows.  This limits the
> blast radius if an attacker obtains a user's password; they still need the client secret
> to exchange it for a token.

---

## Step 2 — Keycloak: Add a groups mapper

The JWT access token must carry a `groups` claim that the TACACS+ server reads.

1. In the `tacacs-server` client, open the **Client scopes** tab.
2. Click **tacacs-server-dedicated → Add mapper → By configuration**.
3. Select **Group Membership**.
4. Configure it:

   | Field | Value |
   |-------|-------|
   | Name | `tacacs-groups` |
   | Token Claim Name | `groups` |
   | Full group path | OFF |
   | Add to ID token | OFF |
   | Add to access token | **ON** |
   | Add to userinfo | OFF |

5. Click **Save**.

> If your realm already emits a `groups` or `realm_access.roles` claim at the top level,
> you can skip this step and set `--icam-groups-claim` to match that field instead.

---

## Step 3 — Keycloak: Create groups and assign users

Create groups that mirror the names used in your TACACS+ policy.

```
Realm → Groups → Create group
```

Suggested groups:

| Group name | TACACS+ use |
|------------|-------------|
| `netops` | Full shell + all commands |
| `netops-ro` | Shell + show commands only |
| `noc` | Read-only monitoring access |

Assign each network operator to the appropriate group via **Users → {user} → Groups → Join**.

The group names are **lowercased** by the TACACS+ server before policy matching, so
`NetOps` and `netops` are treated identically.

---

## Step 4 — Store the client secret

Create a Kubernetes Secret holding the Keycloak client secret.  Never put it in a
ConfigMap, a manifest checked into git, or a pod environment variable in cleartext.

```bash
kubectl create secret generic tacacs-icam \
  --namespace tacacs \
  --from-literal=client-secret='<paste-secret-from-step-1>'
```

Verify:

```bash
kubectl get secret tacacs-icam -n tacacs -o jsonpath='{.data.client-secret}' | base64 -d
```

---

## Step 5 — Update the Deployment manifest

Edit `deploy/k3s/manifests/deployment-tacacs.yaml`.

### 5a — Remove the local credential args

Delete these lines (local creds are no longer used when ICAM is active):

```yaml
# REMOVE these lines:
- "--allow-static-credentials"
- "--user-password-hash-file"
- "/etc/tacacs/creds/user-hashes"
```

Also remove the `creds` volume and its `volumeMount`.

### 5b — Add ICAM args

Under `args`, add:

```yaml
args:
  # ... existing args ...

  # ICAM/OIDC authentication (replaces local credentials)
  - "--icam-token-endpoint"
  - "https://icam.oopl.dev.mil/realms/dcim/protocol/openid-connect/token"
  - "--icam-client-id"
  - "tacacs-server"
  - "--icam-client-secret-file"
  - "/run/secrets/icam/client-secret"
  - "--icam-groups-claim"
  - "groups"
  - "--icam-timeout-ms"
  - "5000"
```

### 5c — Mount the secret

Under `volumeMounts` (in the container):

```yaml
volumeMounts:
  - { name: tls,    mountPath: /etc/tacacs/tls,  readOnly: true }
  - { name: policy, mountPath: /etc/tacacs/policy, readOnly: true }
  - { name: icam,   mountPath: /run/secrets/icam,  readOnly: true }
  - { name: tmp,    mountPath: /tmp }
```

Under `volumes` (in the pod spec):

```yaml
volumes:
  - name: tls
    secret:
      secretName: tacacs-tls
  - name: policy
    configMap:
      name: tacacs-policy
  - name: icam
    secret:
      secretName: tacacs-icam
  - name: tmp
    emptyDir: {}
```

> Mounting as a file (`--icam-client-secret-file`) means the secret value is never
> visible in `kubectl describe pod` args, `/proc/{pid}/cmdline`, or container logs.

### Complete diff (for review)

```diff
-           - "--allow-static-credentials"
-           - "--user-password-hash-file"
-           - "/etc/tacacs/creds/user-hashes"
+           - "--icam-token-endpoint"
+           - "https://icam.oopl.dev.mil/realms/dcim/protocol/openid-connect/token"
+           - "--icam-client-id"
+           - "tacacs-server"
+           - "--icam-client-secret-file"
+           - "/run/secrets/icam/client-secret"
+           - "--icam-groups-claim"
+           - "groups"
+           - "--icam-timeout-ms"
+           - "5000"

         volumeMounts:
           - { name: tls,    mountPath: /etc/tacacs/tls,   readOnly: true }
           - { name: policy, mountPath: /etc/tacacs/policy, readOnly: true }
-          - { name: creds,  mountPath: /etc/tacacs/creds,  readOnly: true }
+          - { name: icam,   mountPath: /run/secrets/icam,  readOnly: true }
           - { name: tmp,    mountPath: /tmp }

       volumes:
         - name: tls
           secret:
             secretName: tacacs-tls
         - name: policy
           configMap:
             name: tacacs-policy
-        - name: creds
-          secret:
-            secretName: tacacs-creds
+        - name: icam
+          secret:
+            secretName: tacacs-icam
         - name: tmp
           emptyDir: {}
```

---

## Step 6 — Update the policy

Policy rules reference ICAM groups by name in the `groups` array.  The TACACS+ server
resolves these after a successful ICAM auth — no LDAP query is needed.

Example `policy.json`:

```json
{
  "default_allow": false,
  "rules": [
    {
      "id": "netops-shell",
      "priority": 10,
      "effect": "allow",
      "pattern": ".*",
      "groups": ["netops"]
    },
    {
      "id": "netops-ro-show",
      "priority": 20,
      "effect": "allow",
      "pattern": "^show\\b",
      "groups": ["netops-ro", "noc"]
    },
    {
      "id": "deny-all",
      "priority": 99,
      "effect": "deny",
      "pattern": ".*"
    }
  ],
  "shell_start": {
    "netops":    ["priv-lvl=15"],
    "netops-ro": ["priv-lvl=5"],
    "noc":       ["priv-lvl=1"]
  }
}
```

Group names in the policy must exactly match the lowercased Keycloak group names.

Update the `tacacs-policy` ConfigMap:

```bash
kubectl create configmap tacacs-policy \
  --namespace tacacs \
  --from-file=policy.json=policy/policy.json \
  --from-file=policy.schema.json=policy/policy.schema.json \
  --dry-run=client -o yaml | kubectl apply -f -
```

---

## Step 7 — Apply and verify

### Apply the deployment

```bash
kubectl apply -f deploy/k3s/manifests/deployment-tacacs.yaml
kubectl rollout status deployment/tacacs -n tacacs --timeout=120s
```

### Smoke-test ICAM auth end-to-end

Use `tacacs_client` (or any PAP-capable test tool) pointing at the service:

```bash
# Should return PASS for a user who is a member of 'netops' in Keycloak
tacacs_client -H 10.10.10.55 -p 49 -k "$TACACS_SECRET" \
  authen pap alice <password>

# Should return FAIL for a user with no groups
tacacs_client -H 10.10.10.55 -p 49 -k "$TACACS_SECRET" \
  authen pap nobody <wrong>
```

### Verify JWT groups are visible in logs

The TACACS+ server logs at `DEBUG` level when ICAM succeeds.  In Loki/Grafana:

```logql
{app="tacacs"} |= "ICAM authentication succeeded"
```

You should see:

```json
{
  "level": "DEBUG",
  "user": "alice",
  "group_count": 2,
  "message": "ICAM authentication succeeded"
}
```

### Verify authorization uses ICAM groups

```logql
{app="tacacs"} |= "authz_policy_allow" | json | groups != ""
```

The `groups` field in the authorization audit event will show the ICAM-derived groups
used for the decision.

---

## Helm values reference

If the deployment is wrapped in a Helm chart, the recommended `values.yaml` structure is:

```yaml
tacacs:
  image:
    repository: ghcr.io/192d-wing/usg-tacacs
    tag: "0.78.1-arm64"

  icam:
    enabled: true
    tokenEndpoint: "https://icam.oopl.dev.mil/realms/dcim/protocol/openid-connect/token"
    clientId: "tacacs-server"
    # clientSecret is never in values.yaml — provide via external secret or sealed secret
    clientSecretSecretName: "tacacs-icam"
    clientSecretKey: "client-secret"
    groupsClaim: "groups"
    timeoutMs: 5000

  # Disable local credentials when ICAM is active
  staticCredentials:
    enabled: false

  policy:
    configMapName: tacacs-policy
```

A corresponding Helm template fragment (`templates/deployment.yaml`):

```yaml
{{- if .Values.tacacs.icam.enabled }}
- "--icam-token-endpoint"
- {{ .Values.tacacs.icam.tokenEndpoint | quote }}
- "--icam-client-id"
- {{ .Values.tacacs.icam.clientId | quote }}
- "--icam-client-secret-file"
- "/run/secrets/icam/client-secret"
- "--icam-groups-claim"
- {{ .Values.tacacs.icam.groupsClaim | quote }}
- "--icam-timeout-ms"
- {{ .Values.tacacs.icam.timeoutMs | toString | quote }}
{{- end }}
{{- if .Values.tacacs.staticCredentials.enabled }}
- "--allow-static-credentials"
- "--user-password-hash-file"
- "/etc/tacacs/creds/user-hashes"
{{- end }}
```

Volume section:

```yaml
{{- if .Values.tacacs.icam.enabled }}
- name: icam
  secret:
    secretName: {{ .Values.tacacs.icam.clientSecretSecretName }}
{{- end }}
```

VolumeMount section:

```yaml
{{- if .Values.tacacs.icam.enabled }}
- name: icam
  mountPath: /run/secrets/icam
  readOnly: true
{{- end }}
```

---

## Troubleshooting

### TACACS returns FAIL — unexpected

1. **Check Keycloak logs** for a rejected token request:

   ```bash
   kubectl logs -n icam -l app=keycloak | grep -i "invalid_grant\|unauthorized"
   ```

   Common causes: wrong client secret, user account disabled, user not in any group.

2. **Verify the ROPC grant is enabled** on the client:
   In Keycloak admin → Clients → `tacacs-server` → Settings → **Direct access grants: ON**.

3. **Test the token endpoint directly** from inside the pod:

   ```bash
   kubectl exec -n tacacs deploy/tacacs -- \
     wget -qO- --post-data \
       'grant_type=password&client_id=tacacs-server&client_secret=<secret>&username=alice&password=<pass>&scope=openid' \
       https://icam.oopl.dev.mil/realms/dcim/protocol/openid-connect/token
   ```

   A `200` response with `access_token` confirms the ICAM path is reachable.

4. **Decode the JWT** to verify the `groups` claim is present:

   ```bash
   # Paste the access_token value from step 3
   echo '<access_token>' | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
   ```

   You should see `"groups": ["netops"]` (or whatever claim you configured).

### TACACS authenticates but authorization always fails

The `groups` claim exists in the JWT but the policy does not match.  Check:

- The `--icam-groups-claim` flag matches the exact JWT field name (case-sensitive).
- The policy rule `groups` values are lowercase and match the Keycloak group names exactly.
- The policy ConfigMap was reloaded after editing (`kubectl rollout restart deployment/tacacs -n tacacs`).

### ICAM timeout errors

If Keycloak is slow or unreachable:

```json
{"level":"DEBUG","error":"operation timed out","message":"ICAM token endpoint request failed"}
```

- Increase `--icam-timeout-ms` (default 5000).
- Check network policy allows the `tacacs` namespace to reach the `icam` namespace on port 443.
- Verify the pod can resolve `icam.oopl.dev.mil`:

  ```bash
  kubectl exec -n tacacs deploy/tacacs -- nslookup icam.oopl.dev.mil
  ```

---

## Migration checklist

Complete in order when migrating from local credentials to ICAM:

- [ ] Keycloak `tacacs-server` client created (confidential, ROPC enabled)
- [ ] `groups` mapper added to access token
- [ ] All network operators added to appropriate Keycloak groups
- [ ] Client secret stored in `tacacs-icam` Secret in the `tacacs` namespace
- [ ] Policy `groups` fields updated to match Keycloak group names
- [ ] Deployment manifest updated (ICAM args added, local cred args removed)
- [ ] `kubectl rollout status` confirms all 3 replicas healthy
- [ ] Smoke-test PAP auth succeeds for a known-good user
- [ ] Smoke-test PAP auth fails for a user with no groups
- [ ] Loki shows `ICAM authentication succeeded` events with correct `group_count`
- [ ] `tacacs-creds` Secret deleted (no longer needed)
- [ ] Old local credential generation script (`gen-creds.sh`) archived or removed
