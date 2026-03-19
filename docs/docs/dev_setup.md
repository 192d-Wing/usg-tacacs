---
icon: lucide/code
---

# Development environment setup

This project is Rust-first, with a small docs site under `docs/`. Below are steps to set up both code and docs.

## Prerequisites

- Rust toolchain: `rustup toolchain install stable && rustup default stable`
- `just` (optional, for command aliases) if you use it locally.
- For docs (Zensical): Python 3.11+ and `uv` (optional helper), or plain `pip`.

## Clone and build

```sh
git clone https://github.com/192d-Wing/usg-tacacs.git
cd usg-tacacs
cargo build --locked
cargo test --locked
```

## Running the server (dev)

```sh
cargo run -p tacacs-server -- \
  --listen-tls 127.0.0.1:300 \
  --tls-cert ./certs/server.pem \
  --tls-key ./certs/server-key.pem \
  --client-ca ./certs/client-ca.pem \
  --policy ./policy/policy.example.json \
  --secret "dev-secret"
```

Adjust paths to your local certs; consider `--check-policy` during edits.

## Docs (Zensical) setup

```sh
cd docs
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt  # or `uv sync` if you prefer uv
zensical build
```

Preview locally (if supported by your tooling) or publish per your pipeline.

## Submitting an issue

Open an issue for bugs, content fixes, or feature requests. Include:

- Steps to reproduce
- Expected vs actual behavior
- Environment (OS, Rust version, client used)
- Relevant logs or commands

## Contributing code

1. Create a branch.
2. Make changes and add tests where applicable.
3. Run `cargo fmt`, `cargo clippy -- -D warnings`, and `cargo test`.
4. Commit with Conventional Commit style (`feat: ...`, `fix: ...`, etc.).
5. Open a pull request; CI will run checks.

## Style and validation

- Keep `Cargo.lock` committed; use `--locked` in builds/tests.
- Validate policies with `--check-policy --schema policy/policy.schema.json`.
- Run docs build (`zensical build`) if you change `docs/docs/*`.
