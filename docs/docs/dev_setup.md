---
icon: lucide/wrench
---

# Development setup

## Prerequisites

- Rust toolchain pinned by the repository
- PostgreSQL for management/JIT integration tests
- Podman or Docker for lab dependencies
- Helm for chart validation
- `uv` for the Zensical documentation site

## Build and test

```shell
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

Validate the example configuration:

```shell
cargo run --locked -p usg-tacacs-config \
  --bin usg-tacacs-config-check -- docs/config/server.example.yaml
```

For mounted-file validation, run the checker with `--check-files` inside the
rendered container environment.

## Run a role locally

Create a lab-only typed YAML document with loopback listeners and test
certificates, then run:

```shell
cargo run --locked -p tacacs-server -- \
  --config ./server.lab.yaml \
  --log-format json
```

Do not use production secrets. Legacy CLI flags exist for compatibility tests,
but new production behavior and documentation should exercise typed YAML.

## Helm

```shell
helm lint deploy/charts/usg-tacacs
helm template usg-tacacs deploy/charts/usg-tacacs \
  --values deploy/sites/example/usg-tacacs.values.yaml
```

## Documentation

```shell
cd docs
uv run zensical build
uv run zensical serve
```

Update navigation in `docs/zensical.toml`. Verify inline icons and Mermaid
rendering, not only Markdown syntax.

## Contributions

Use conventional commits, keep changes reviewable, add negative security tests,
and update OpenAPI/configuration documentation with behavior changes. Never
commit credentials, certificates with private keys, site values, or generated
forensic evidence.
