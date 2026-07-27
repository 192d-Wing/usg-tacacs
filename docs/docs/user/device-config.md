---
icon: lucide/router
---

# Device onboarding

Vendor syntax changes across platforms and releases. Treat this page as a
security checklist, not copy-and-paste configuration. Validate commands
against the exact vendor release and maintain tested site templates.

## Choose the transport

Use RFC 9887 only when the exact NAD software supports TACACS+ over TLS 1.3
with mutual certificates and it has been verified in the lab. Otherwise use
legacy TACACS+ on TCP/49 with a unique per-NAD secret on a protected management
network or IPsec.

Port 300 alone is not evidence of TLS. Ordinary `tacacs-server ... key ...`
syntax typically describes legacy TACACS+ even when a nonstandard port is
selected.

## Legacy onboarding checklist

1. Preserve a tested local break-glass account and console recovery path.
2. Create a unique, high-entropy secret for this NAD.
3. Store it in the approved provider and mount it at the configured
   `secretFile`.
4. Configure the server address on TCP/49 using the vendor's supported syntax.
5. Configure AAA authentication with an explicitly approved local fallback
   design.
6. Configure exec and command authorization.
7. Configure start/stop and command accounting.
8. Restrict VTY/management access to SSH.
9. Reconcile the NAD and confirm its real source address at USG TACACS.
10. Test success, rejection, authorization denial, accounting, and server
    unavailability before closing the recovery session.

Example server-side declaration:

```yaml
- name: oopl-an-001
  description: IOS-XE lab switch
  sourceAddress: 192.0.2.10
  mode: legacy
  secretFile: /run/secrets/nads/oopl-an-001
```

## RFC 9887 onboarding checklist

1. Verify vendor documentation for the exact platform and release.
2. Issue a unique client certificate with the required identity and client
   authentication usage.
3. Install the server trust chain on the NAD.
4. Configure RFC 9887/TLS 1.3 on TCP/300 using vendor-supported commands.
5. Declare the exact certificate identity in typed YAML.
6. Capture the lab handshake and verify TLS 1.3, mutual authentication, peer
   identity, and absence of downgrade.
7. Complete the same AAA failure and accounting tests as legacy onboarding.

```yaml
- name: tls-nad-001
  description: Lab-verified RFC 9887 device
  sourceAddress: 192.0.2.11
  mode: tls
  certificateIdentities:
    - tls-nad-001.example.mil
```

Do not reuse a shared-secret example and label it TLS.

## Required validation

- Correct NAD identity and source appear in signed audit.
- A valid user succeeds only on an authorized NAD.
- Unauthorized commands are denied with the expected rule ID.
- Accounting start, command, and stop records arrive.
- An incorrect secret/certificate fails closed.
- A JIT credential fails on another NAD and after expiry/revocation.
- Loss of TACACS does not silently grant privileged access.

Record the exact vendor configuration in the site's controlled runbook after
validation.
