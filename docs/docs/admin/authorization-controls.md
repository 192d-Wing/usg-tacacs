---
icon: lucide/shield-check
---

# Authorization controls

USG TACACS applies authorization to each API operation. The current service
uses a validated mTLS certificate identity, a subject-to-role binding, and an
exact action grant. A successful TLS connection alone does not authorize an
API request.

The permission format is:

```text
tacacs:{Action}{Object}
```

Examples are `tacacs:ListNads`, `tacacs:GetNad`, and `tacacs:CreateNad`.
Permissions are case-sensitive. Wildcards, legacy `read:*` or `write:*`
permissions, duplicate grants, and unknown actions are rejected during
configuration validation.

## Decision attributes

| Attribute or control | Source | What it allows | Failure behavior |
| --- | --- | --- | --- |
| TLS server identity | Server certificate and configured client trust | Lets the client validate that it reached the intended TACACS API | TLS connection fails before HTTP |
| TLS client identity | Client certificate validated by the management client CA | Establishes the cryptographic caller identity | TLS connection is rejected |
| Typed identity selector | One configured `cn:`, `dns:`, `email:`, or `uri:` selector | Selects a canonical certificate identity for RBAC | No match or multiple matches fail closed |
| Subject binding | Exact certificate identity mapped to one role | Selects the caller's configured role | Unbound identities receive `403 Forbidden` |
| Role action grant | Exact `tacacs:{Action}{Object}` string | Allows only the corresponding API operation | Missing action receives `403 Forbidden` |
| HTTP method and route | Router middleware | Binds the action to a specific operation | A grant for an adjacent route is not accepted |
| Resource identifier | Path parameter such as `{nadId}` or `{leaseId}` | Limits the request to the named object | Invalid or unknown identifiers are rejected |
| Mutation precondition | `If-Match`, `Idempotency-Key`, and `X-Correlation-ID` where required | Prevents stale writes, unsafe replay, and unaudited mutation | Missing or invalid preconditions are rejected |
| Runtime ownership | YAML-owned versus API-owned resource state | Allows mutation only where the API owns the resource | YAML-owned resources remain immutable through the API |
| NetworkPolicy | Namespace, Pod, IP, port, and protocol selectors | Limits which network paths can reach the service | Traffic outside the allow-list is dropped |
| Audit context | Authenticated actor, action, resource, result, and correlation ID | Produces attributable structured evidence | Authorization denials and mutations remain observable |

NetworkPolicy is a defense-in-depth reachability control. It does not replace
mTLS identity or application authorization.

## Action catalog

### Status, sessions, and metrics

| Action | Method and path | Allows |
| --- | --- | --- |
| `tacacs:GetStatus` | `GET /api/mgmt/v1/status` | Read server status and runtime statistics |
| `tacacs:ListSessions` | `GET /api/mgmt/v1/sessions` | List active TACACS sessions |
| `tacacs:DeleteSession` | `DELETE /api/mgmt/v1/sessions/{id}` | Terminate one active session |
| `tacacs:GetMetrics` | `GET /api/mgmt/v1/metrics` | Read the management metrics response |

### Policy and asynchronous operations

| Action | Method and path | Allows |
| --- | --- | --- |
| `tacacs:GetPolicy` | `GET /api/mgmt/v1/policy` | Read current policy metadata |
| `tacacs:ReplacePolicy` | `POST /api/mgmt/v1/policy` | Validate and replace the active policy |
| `tacacs:ReloadPolicy` | `POST /api/mgmt/v1/policy/reload` | Reload policy from the configured source |
| `tacacs:GetOperation` | `GET /api/mgmt/v1/operations/{id}` | Read one asynchronous operation result |

`tacacs:ReplacePolicy` does not imply `tacacs:ReloadPolicy`, and neither action
implies `tacacs:GetPolicy` or `tacacs:GetOperation`.

### Runtime configuration

| Action | Method and path | Allows |
| --- | --- | --- |
| `tacacs:GetRuntimeConfig` | `GET /api/mgmt/v1/config` | Read the sanitized runtime configuration |
| `tacacs:GetEffectiveConfig` | `GET /api/mgmt/v1/config/effective` | Read effective declarative configuration and its hash |
| `tacacs:GetConfigSchema` | `GET /api/mgmt/v1/config/schema` | Read the typed configuration schema |
| `tacacs:ValidateConfig` | `POST /api/mgmt/v1/config/validate` | Validate proposed configuration without applying it |

Configuration responses may contain secret file references. They never return
the referenced secret contents.

### NAD inventory and lifecycle

| Action | Method and path | Allows |
| --- | --- | --- |
| `tacacs:ListNads` | `GET /api/mgmt/v1/nads` | List the paginated API-owned NAD collection |
| `tacacs:GetNad` | `GET /api/mgmt/v1/nads/{nadId}` | Read one API-owned NAD by identifier |
| `tacacs:ListNadInventory` | `GET /api/mgmt/v1/nads/inventory` | Read the unified YAML-owned and API-owned inventory |
| `tacacs:GetNadReconciliation` | `GET /api/mgmt/v1/nads/reconciliation` | Read bounded reconciliation state and health counts |
| `tacacs:CreateNad` | `POST /api/mgmt/v1/nads` | Create an API-owned NAD using an opaque secret reference |
| `tacacs:UpdateNad` | `PATCH /api/mgmt/v1/nads/{nadId}` | Update one API-owned NAD with the current ETag |
| `tacacs:DeleteNad` | `DELETE /api/mgmt/v1/nads/{nadId}` | Delete one API-owned NAD with the current ETag |

List and Get are intentionally distinct. `tacacs:ListNads` does not allow
`tacacs:GetNad`, and `tacacs:GetNad` does not allow collection enumeration.
Neither grants create, update, or delete.

### NAD audit evidence

| Action | Method and path | Allows |
| --- | --- | --- |
| `tacacs:ListNadAuditEvents` | `GET /api/mgmt/v1/audit/nads` | Export a bounded page of structured NAD audit events |
| `tacacs:VerifyNadAuditEvents` | `GET /api/mgmt/v1/audit/nads/verify` | Verify a bounded audit hash-chain page |

Reading evidence does not implicitly allow verification, and verification does
not authorize NAD lifecycle changes.

### JIT leases

| Action | Method and path | Allows |
| --- | --- | --- |
| `tacacs:CreateJitLease` | `POST /api/jit/v1/leases` | Create a bounded, device-bound JIT credential lease |
| `tacacs:GetJitLease` | `GET /api/jit/v1/leases/{leaseId}` | Read non-secret metadata for one lease |
| `tacacs:RevokeJitLease` | `DELETE /api/jit/v1/leases/{leaseId}` | Revoke one lease idempotently |

The compatibility paths under `/api/v1/jit-leases` require the same actions.
There is no lease-list operation or corresponding list permission.

### API documentation

| Action | Path | Allows |
| --- | --- | --- |
| `tacacs:GetManagementOpenApi` | `/api/docs/mgmt` and `/api/docs/mgmt/openapi.yaml` | Use the management Swagger UI and read its OpenAPI document |
| `tacacs:GetJitOpenApi` | `/api/docs/jit` and `/api/docs/jit/openapi.yaml` | Use the JIT Swagger UI and read its OpenAPI document |

The OpenAPI operations publish their required action through the
`x-required-permission` extension.

## Helm roles

The chart currently renders these fixed roles:

| Role | Grants | Intended caller |
| --- | --- | --- |
| `admin` | All explicitly enumerated actions | Fully authorized management identity |
| `jitpw-issuer` | `tacacs:CreateJitLease`, `tacacs:RevokeJitLease` | JITPW lease automation |
| `jitpw-auditor` | `tacacs:GetJitLease` | JITPW lease metadata reader |

Role names are conveniences; the action list is the security boundary. A new
API operation must introduce a new supported action and an explicit route
mapping before any role can use it.

## Public PIV UI and API boundary

The current TACACS backend authorizes validated mTLS certificate identities.
It does not yet implement the planned public PIV-protected UI, public
automation API, or signed identity-delegation assertion described in the
target architecture.

At that boundary, PIV authentication should establish the human identity, but
each requested operation must still be checked against an exact TACACS action.
The public tier must not convert "PIV authenticated" into unrestricted admin
access. Any identity or authorization context forwarded to the backend must be
cryptographically protected, audience-bound, short-lived, and independently
validated; an ordinary HTTP identity header is not trusted.

## Example least-privilege roles

```yaml
roles:
  nad-reader:
    permissions:
      - tacacs:ListNads
      - tacacs:GetNad
      - tacacs:ListNadInventory
      - tacacs:GetNadReconciliation
  nad-provisioner:
    permissions:
      - tacacs:CreateNad
      - tacacs:GetOperation
  forensic-reader:
    permissions:
      - tacacs:ListNadAuditEvents
      - tacacs:VerifyNadAuditEvents
```

Do not grant a mutation action merely so a caller can observe the result. Add
the corresponding exact read action only when that observation is required.
