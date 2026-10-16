# Authelia Configurator

A small, self-hosted web UI for the parts of an [Authelia](https://www.authelia.com) file-based
configuration that change often: **access control rules** and **OIDC clients** (users later).
Everything else stays hand-edited YAML. Every change is validated by Authelia itself, committed to a
local git repo, and rolled back automatically if Authelia is unhealthy after a restart.

> **Status: Phase 0 (foundation).** The web UI is not built yet. What exists today: the migration
> script, the verified config-split layout, the hardened image and the CI/release pipeline.
> The full design is in [SPEC.md](SPEC.md).

## Internal-only tool

This tool can change who may access your services. **Never expose it to the public internet.**

- Do not create a public DNS record, CDN proxy or tunnel route for its hostname. Resolve it only
  through VPN DNS, split-horizon DNS or a hosts file.
- Serve it on an internal Traefik entrypoint bound to your VPN address (recommended), or behind an
  IP allow-list middleware.
- The app also fails closed: it refuses to start without `ALLOWED_CLIENT_CIDRS`, and trusts
  forwarded or identity headers only from `TRUSTED_PROXY_CIDRS`.
- The container publishes no ports and never mounts the Docker socket.

## What works now

### Split an existing configuration

Authelia merges several config files. The configurator owns only dedicated files and never writes
your main `configuration.yml`. The migration script moves `access_control` and
`identity_providers.oidc.clients` into managed files, and imports commented-out rules as disabled rules:

```sh
uv sync
uv run python -m scripts.split_config --config /path/to/configuration.yml --out ./split-out
```

- The input is never modified, and the output directory must not exist.
- The result is verified structurally and with `authelia config validate` on both sets.
- It prints key paths and counts only, never secret values.
- Review the output, then point Authelia at it:
  `X_AUTHELIA_CONFIG=/config/configuration.yml,/config/managed/access_control.yml,/config/managed/oidc_clients.yml`

How Authelia merges these files was measured, see [docs/merge-behaviour.md](docs/merge-behaviour.md).

### Image

`ghcr.io/<owner>/authelia-configurator:authelia-<version>` bundles the Authelia CLI at exactly that
version (used for validation, hashing and key generation). Pin both images to the same version:

```yaml
authelia:     { image: "authelia/authelia:${AUTHELIA_VERSION}" }
configurator: { image: "ghcr.io/<owner>/authelia-configurator:authelia-${AUTHELIA_VERSION}" }
```

Applying changes is blocked while the bundled and running Authelia versions differ.

## Lockout recovery

If a bad change locks you out, over SSH on the Docker host:

```sh
git -C /path/to/config/managed revert HEAD
docker restart authelia
```

## Backups

The managed git repo is local only and contains password hashes. Back up `CONFIG_MANAGED_DIR`
together with the rest of your Authelia config folder, and never push it anywhere public.

## Development

Requires Docker, [uv](https://docs.astral.sh/uv/), gitleaks and trivy.

```sh
uv sync
make lint              # ruff, mypy, public-repo hygiene
make test              # unit tests
make test-integration  # real Authelia at the pinned version
make test-e2e          # compose stack + Playwright (needs: uv run playwright install chromium)
make scan              # gitleaks + image scan
uv run pytest tests/unit/test_split_config.py::test_counts_and_disabled_rule_positions   # one test
```

The pinned Authelia version lives only in the `Dockerfile` (`ARG AUTHELIA_VERSION`). See
[CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

Apache-2.0, see [LICENSE](LICENSE).
