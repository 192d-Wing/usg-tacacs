# TACACS+ E2E Interoperability Lab

End-to-end test suite that validates the USG TACACS+ server against the
Shrubbery `tac_plus` reference implementation.

## Quick start

```bash
docker compose -f tests/e2e/compose.yaml up \
  --build --abort-on-container-exit --exit-code-from test-runner
```

The exit code is **0** when every USG TACACS+ scenario passes, **1** otherwise.

## Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  test-runner │────▶│  usg-tacacs  │     │   tac_plus   │
│  (Python)    │────▶│  :49 (legacy)│     │   :49        │
│  172.30.0.99 │     │  172.30.0.10 │     │  172.30.0.11 │
└──────────────┘     └──────────────┘     └──────────────┘
        ▲                                        ▲
        └────────────────────────────────────────┘
              same shared secret, same users
```

All three containers share a dedicated bridge network (`172.30.0.0/24`).
The test runner connects to both servers on port 49 using the legacy
TACACS+ protocol (MD5 obfuscation, no TLS), which is the common
denominator that `tac_plus` supports.

## Test scenarios

| # | Scenario             | What it tests                                    |
|---|----------------------|--------------------------------------------------|
| 1 | valid_auth           | PAP login with correct credentials                |
| 2 | invalid_password     | PAP login with wrong password → FAIL              |
| 3 | unknown_user         | PAP login for nonexistent user → FAIL/ERROR       |
| 4 | empty_credentials    | Empty username and password → FAIL/ERROR          |
| 5 | long_credentials     | 1000-char username/password → FAIL/ERROR          |
| 6 | secret_mismatch      | Wrong shared secret → crypto failure              |
| 7 | author_permit        | `show version` authorized for alice → PASS        |
| 8 | author_deny          | `reload` denied for bob → FAIL                   |
| 9 | acct_start_stop      | Accounting START + STOP → SUCCESS                 |
| 10| malformed_packet     | Garbage header/body → no crash                   |
| 11| truncated_packet     | Header claims 100 bytes, body is 4 → no crash    |
| 12| invalid_length       | Header claims 4 GB length → no OOM crash          |
| 13| concurrent_burst     | 20 simultaneous PAP requests → all PASS           |

## Artifacts

After a run, `tests/e2e/artifacts/` contains:

- **results.json** — full machine-readable results for CI integration
- **matrix.md** — Markdown interoperability matrix

## Configuration

| File | Purpose |
|------|---------|
| `config/usg-tacacs/policy.json` | Authorization policy for USG server |
| `config/usg-tacacs/policy.schema.json` | JSON Schema for policy validation |
| `config/tac_plus/tac_plus.conf` | Shrubbery tac_plus configuration |

Both servers are configured with:

- **Shared secret:** `e2e-shared-secret-k8s`
- **Users:** `alice:alice-secret` (priv-lvl 15), `bob:bob-secret` (priv-lvl 1)
- **Authorization:** `show` and `ping` allowed for all; `reload` denied
  for all; `configure` allowed only for alice

## CI integration

The compose file is designed for non-interactive CI:

- `--abort-on-container-exit` tears down all services when the test
  runner finishes
- `--exit-code-from test-runner` propagates the runner's exit code
- Health checks gate the runner so it only starts once both servers
  accept connections
- Deterministic fixed IPs prevent DNS race conditions
- All timeouts are finite to avoid CI hangs

### GitLab CI example

```yaml
e2e-interop:
  stage: test
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker compose -f tests/e2e/compose.yaml up
        --build --abort-on-container-exit --exit-code-from test-runner
  artifacts:
    paths:
      - tests/e2e/artifacts/
    when: always
```

## Known differences between servers

Shrubbery `tac_plus` and USG TACACS+ may differ in:

1. **Authorization response codes** — `tac_plus` may return `PASS_ADD`
   vs `PASS_REPL`; both are valid PASS outcomes.
2. **Error vs Fail for unknown users** — some servers return
   `AUTHEN_STATUS_ERROR`, others `AUTHEN_STATUS_FAIL`.
3. **Accounting** — `tac_plus` writes to a file; USG TACACS+ uses
   structured audit forwarding. Both return `SUCCESS`.
4. **Malformed packet handling** — `tac_plus` may silently close;
   USG TACACS+ may send an error response. Both are acceptable.
