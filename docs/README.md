# USG TACACS documentation site

The published documentation is built with Zensical from `docs/docs`.

Content is organized by audience:

- `docs/admin` — architecture, configuration, security, and administrative APIs
- `docs/operator` — production operations, NAD lifecycle, and incident response
- `docs/user` — network-user access and device configuration references
- `docs/dev` — development and protocol implementation

Build the site locally:

```shell
uv run zensical build
```

Preview it while editing:

```shell
uv run zensical serve
```

Update `zensical.toml` whenever a new page should appear in site navigation.
Run the build before submitting documentation changes.
