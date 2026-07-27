---
icon: lucide/scroll-text
---

# Authorization policy

In the production profile, authorization is part of the authoritative typed
YAML under `spec.authorization`. A separate policy JSON upload is disabled
while declarative configuration is active.

```yaml
authorization:
  defaultAllow: false
  rules:
    - id: deny-reload
      priority: 1000
      effect: deny
      groups: [network-admins]
      command: "^reload(?: .*)?$"
    - id: allow-show
      priority: 100
      effect: allow
      groups: [network-admins]
      command: "^show(?: .*)?$"
```

## Rule fields

| Field | Meaning |
| --- | --- |
| `id` | Stable unique identifier included in decisions/audit |
| `priority` | Signed integer used by policy ordering |
| `effect` | `allow` or `deny` |
| `users` | Optional canonical user matches |
| `groups` | Optional identity-group matches |
| `nadGroups` | Optional NAD-group matches |
| `command` | Optional regular expression for normalized command text |

Use anchored expressions and test both intended matches and near misses. Avoid
catch-all allow rules. A deny-by-default policy limits the effect of missing
attributes, new commands, and integration failures.

## Change procedure

1. Give every rule a stable, descriptive ID.
2. Add positive and negative tests.
3. Validate the complete typed YAML.
4. Review the effective configuration hash.
5. Deploy through the declarative workflow.
6. Confirm the reload operation succeeded on every replica.
7. Test allowed and denied commands and verify signed audit results.

The Management API policy endpoint reloads the authorization portion of the
authoritative YAML. Uploading an independent JSON policy is intentionally
rejected in declarative mode.

## Compatibility mode

The server retains a legacy JSON policy loader for standalone compatibility and
migration testing. It is not the Kubernetes production source of truth. Do not
operate YAML and JSON authorization simultaneously.
