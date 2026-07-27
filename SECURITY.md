# Security Policy

## Supported Versions

Security fixes are provided for the latest published release of
`usg-tacacs`. Older releases should be upgraded before requesting a
security fix.

| Version | Supported |
| --- | --- |
| Latest published release | Yes |
| Earlier releases | No |

Deployment hardening guidance is maintained in
[`docs/HARDENING_GUIDE.md`](./docs/HARDENING_GUIDE.md).

## Reporting a Vulnerability

Do not report suspected vulnerabilities in a public issue, discussion,
pull request, or other public channel.

Contact the repository owners through an established private
organizational channel and ask for a secure reporting path. Do not
include exploit details or sensitive data in the initial message.

GitHub private vulnerability reporting is not currently enabled for this
repository. When it becomes available, this policy will be updated with
the private reporting URL.

Include the following when it is safe to do so:

- affected version and deployment configuration;
- a concise description of the issue and its potential impact;
- reproducible steps or a minimal proof of concept;
- relevant logs with credentials, keys, tokens, passwords, personal
  data, and network-sensitive information removed;
- whether the issue is known to have been exploited; and
- a secure method for follow-up contact.

Do not access data that is not yours, disrupt production services, or
retain secrets while researching or validating an issue.

## What to Expect

Maintainers will:

1. acknowledge the report through the private reporting channel;
2. validate the issue and determine affected versions;
3. coordinate remediation and disclosure with the reporter;
4. publish a security advisory and patched release when appropriate; and
5. credit the reporter when requested and operationally permissible.

Response and remediation time depend on severity, exploitability, and
the complexity of safely testing a fix. Please keep vulnerability
details confidential until the maintainers confirm that coordinated
disclosure is appropriate.

## Scope

Reports are especially useful when they involve:

- authentication or authorization bypass;
- exposure of TACACS+ credentials, shared secrets, JIT credentials,
  cryptographic keys, or management API tokens;
- weaknesses in password-verifier or lease handling;
- unsafe handling of TACACS+, TACACS+ over TLS, mTLS, or PostgreSQL
  input;
- privilege escalation, command-authorization bypass, or audit-log
  tampering;
- denial of service with a practical attack path; or
- vulnerable dependencies with a demonstrated effect on this project.

General support requests, deployment questions, and non-sensitive bugs
should use the repository's normal issue process.
