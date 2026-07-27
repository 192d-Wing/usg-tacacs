---
icon: lucide/user
---

# User guide

This guide is for network engineers who connect to devices protected by USG
TACACS. Your organization may use ordinary enterprise authentication, JITPW
short-lived credentials, or both for different devices.

## What the service does

The network device sends authentication, command-authorization, and accounting
requests to USG TACACS. The server identifies the device, validates your
credential, evaluates authorization policy, and emits signed audit events.

You are responsible for using your own canonical identity, protecting your
workstation and CAC, following change procedures, and closing sessions when
work is complete.

## JITPW access

For a JIT-managed device, use your organization's `jit-ssh` client rather than
requesting or handling a password:

```powershell
jit-ssh john.e.willman3.mil@a-an-001
```

If `User` is set by a matching OpenSSH configuration entry, the hostname form
may be sufficient:

```powershell
jit-ssh a-an-001
```

The client authenticates to JITPW with the PIV Authentication certificate on
your CAC, requests an authorized NAD-bound lease, and launches the system
OpenSSH client through the configured bastion. The password is passed only to
the network-device authentication prompt and is never displayed. The bastion
authenticates your SSH key and proxies encrypted bytes; it does not receive the
device password.

Leases expire no later than 15 minutes after issuance. Expiration limits new
authentication; it does not grant permission to retain an unattended session.
Authorization policy still governs every command.

## Identity rules

- Use the lowercase EID assigned by ICAM, such as
  `john.e.willman3.mil`.
- An explicit `user@host` argument takes precedence when supported by the
  client workflow.
- Otherwise, `jit-ssh` uses the effective `User` selected by OpenSSH
  configuration for the target.
- Do not use aliases, shared accounts, uppercase variants, or another person's
  identity.

If no effective user is available, stop and correct the command or SSH
configuration. Do not guess.

## Expected connection flow

1. Insert the CAC and run `jit-ssh`.
2. Select the PIV Authentication certificate if more than one eligible
   certificate exists.
3. Enter the CAC PIN only in the operating-system smart-card prompt.
4. JITPW evaluates certificate identity, requested device, and ABAC policy.
5. OpenSSH authenticates to the bastion using the configured SSH key.
6. The bastion opens the TCP connection to the target device.
7. The hidden JIT password satisfies only the device's password prompt.
8. USG TACACS authorizes and accounts for the session and commands.

Neither support personnel nor the web UI should ask you to reveal the JIT
password, CAC PIN, private SSH key, or session credential.

## Authorization denials

Successful login does not imply unrestricted access. When a command is denied:

1. Do not repeatedly modify and retry a destructive command.
2. Record the device, UTC time, exact command, and displayed error.
3. Record the client correlation ID if it is available.
4. Confirm you selected the intended device and identity.
5. Request the required role through the approved access process.

Administrators can correlate the request without knowing the temporary
password.

## Troubleshooting

| Symptom | User action |
| --- | --- |
| No eligible CAC certificate | Confirm the CAC is inserted and the PIV Authentication certificate is visible to the OS |
| CAC PIN prompt repeats | Stop before PIN lockout and contact smart-card support |
| JIT request denied | Confirm lowercase EID/device and request authorization through the approved process |
| Bastion authentication fails | Check VPN/network reachability and your registered SSH public key |
| Device authentication fails | Retry once with a fresh lease, then report device, UTC time, and correlation ID |
| Command denied | Preserve the exact command/error and request the appropriate authorization |
| Connection times out | Report target, bastion/region, time, and network context |

Never work around a JIT failure by requesting the temporary password, placing a
password in SSH configuration, or bypassing the approved bastion.

## Ordinary TACACS access

Some non-JIT devices may use enterprise credentials according to site policy.
Enter credentials only into the device's expected SSH prompt. Never place
passwords in command history, scripts, tickets, or SSH configuration. Device
authentication, authorization, and accounting remain subject to the same audit
and acceptable-use requirements.

## What to provide to support

- device hostname and region;
- canonical EID;
- UTC date and time;
- correlation ID, when shown;
- whether failure occurred at CAC, JITPW, bastion, device login, or command
  authorization;
- exact non-secret error message;
- `jit-ssh` and OpenSSH versions.

Do not send screenshots containing certificates, private paths, tokens,
passwords, or PIN prompts without following the approved sanitization process.

## Related material

- [Device configuration](device-config.md) (for device administrators)
- [JIT password lease security model](../admin/jit-leases.md)
