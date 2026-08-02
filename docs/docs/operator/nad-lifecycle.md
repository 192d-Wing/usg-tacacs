---
icon: lucide/router
---

# NAD lifecycle runbook

This runbook applies to Network Access Devices created in typed YAML, the web
UI, or Management API automation.

## Choose ownership

Use YAML ownership for baseline and infrastructure-managed devices. Use API
ownership where an authorized administrative workflow needs independent
lifecycle management. Do not define the same NAD in both stores.

## Create an API-owned NAD

1. Generate a UUID correlation ID and an idempotency key.
2. For a legacy NAD, generate a unique shared secret in the approved secret
   manager and mount it at the path represented by the API's opaque
   `secretRef`. Never include the secret value in the request.
3. Submit `POST /api/mgmt/v1/nads` using an mTLS identity with
   `tacacs:CreateNad`.
4. Record the resource ID, ETag, actor, correlation ID, and audit event.
5. Poll reconciliation until the resource is applied or returns a stable
   failure.
6. Configure the NAD with its transport-specific settings.
7. Test authentication, authorization, and accounting.
8. Verify the real source address and NAD identity in signed audit records.

Retry the same logical create with the same idempotency key. Do not generate a
new key merely because the client timed out.

## Create a YAML-owned NAD

1. Add the NAD to `spec.nads` in a reviewed site configuration change.
2. Provision any external secret or certificate before deployment.
3. Run strict configuration validation with file checks.
4. Render and review the Helm diff.
5. Deploy using the standard change procedure.
6. Confirm inventory reports `owner: yaml` and `mutable: false`.
7. Test AAA and signed audit attribution.

## Update

For an API-owned NAD, retrieve the current representation and ETag, then use
`PATCH` with `If-Match`. A stale ETag must return a concurrency error; retrieve
the current resource and consciously reconcile the competing change.

For a YAML-owned NAD, update the declarative source and deploy it. API mutation
of YAML-owned resources must remain prohibited.

Any source address, transport, certificate identity, or secret-reference
change requires a new reconciliation check and AAA test.

## Rotate a legacy shared secret

Shared-secret rotation requires a coordinated device/server window because
many NADs cannot hold overlapping secrets:

1. Confirm local break-glass access under the organization's procedure.
2. Create a new unique secret version without exposing it in logs or tickets.
3. Make the new version available at the existing secret reference.
4. Update the device in the approved order for that platform.
5. Trigger or wait for secret reconciliation on every replica.
6. Test a new TACACS connection, authorization, and accounting.
7. Remove the old secret version after the rollback window.
8. Verify audit continuity and close the change record.

Do not rotate multiple unrelated NADs simultaneously unless the recovery plan
has been explicitly tested.

## Disable or delete

Prefer disablement and an observation period before deletion:

1. Confirm the exact NAD and owner.
2. Preserve its configuration, audit references, and active-session context.
3. Disable admission or remove the NAD through its owning source.
4. Confirm reconciliation and that new connections fail closed.
5. Revoke associated JIT leases where applicable.
6. Remove the external secret or certificate only after the retention window.
7. Delete API-owned desired state with the current ETag.
8. Preserve forensic audit records according to retention policy.

Deletion of desired state is not authorization to destroy audit evidence.

## Failure states

| State | Operator response |
| --- | --- |
| Conflict | Remove duplicate name/source/certificate identity from one owner |
| Invalid | Correct the typed resource; do not bypass validation |
| Secret unavailable | Repair the mount/provider reference without printing it |
| Certificate rejected | Verify trust, SAN identity, validity, and time |
| Applied but AAA fails | Check device configuration, source preservation, and policy |
| Audit verification fails | Stop mutation and invoke incident response |
