---
icon: lucide/download
---

# Policy ingest compatibility service

`tacacs-policy-ingest` ingests versioned legacy JSON policy/config bundles over
mTLS and stores promotion metadata in PostgreSQL. It predates authoritative
typed `TacacsServer` YAML.

It is not part of the Helm production path documented for new deployments and
must not be used as a second active configuration owner. When declarative YAML
is active, policy JSON upload to the server is rejected.

## Existing interface

- `POST /api/v1/ingest` accepts a bounded `tar.gz` bundle with repository and
  commit headers.
- `POST /api/v1/promote/:repo_id/:location_code/:commit_sha` selects a stored
  legacy version.
- The service requires mTLS and uses repository allowlisting.
- Stored bundles are validated against the legacy JSON schemas.

## Security constraints

- Treat archive paths, expansion ratio, entry count, and total size as
  untrusted and bounded.
- Validate the full client certificate and explicit allowlist.
- Use PostgreSQL TLS and least-privilege roles.
- Bind promotion to an authenticated actor; do not trust an optional header as
  identity.
- Audit ingest digest, repository, commit, actor, result, and promotion.
- Never permit a promoted legacy bundle to override YAML-owned production
  state.

## Direction

New automation should validate and deliver typed YAML through the reviewed
configuration/Helm workflow or use narrowly scoped Management API resources.
Retain this service only for explicitly documented migration consumers.
