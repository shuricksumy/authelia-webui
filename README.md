# Authelia Configurator

A small, self-hosted web UI for the parts of an [Authelia](https://www.authelia.com) file-based
configuration that change often: **access control rules** and **OIDC clients** (users later).
Everything else stays hand-edited YAML. Every change is validated by Authelia itself, committed to a
local git repo, and rolled back automatically if Authelia is unhealthy after a restart.

> **Status: Phase 1b.** The rules UI edits a **draft** (view, reorder by drag or buttons, add, edit
> as a form or raw YAML, lint, test a URL against the rules, review the diff) and **applies** it
> safely: validate with Authelia, atomic write, git commit, restart through a locked-down socket
> proxy, health check, and an automatic rollback if Authelia is not healthy. History with
> revert-to-version, an audit log and a version check are included. Disabled rules, the access
> test suite, OIDC clients and users come later. The full design is in [SPEC.md](SPEC.md).

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

### Try it locally

Needs Docker and [uv](https://docs.astral.sh/uv/). Everything is synthetic (`*.example.test`):

```sh
uv sync
make dev      # Traefik + Authelia + the app, with generated test data and a seeded 2FA secret
make totp     # prints the URL, the login, the current 2FA code and an authenticator link
make browse   # opens a browser window already logged in as alice (no hosts entry needed)
make dev-down
```

Add one line to `/etc/hosts`, then open <https://authcfg.example.test:8444> and accept the
self-signed certificate. You log in through the real Authelia portal (password + one-time code),
exactly like production:

```
127.0.0.1 auth.example.test authcfg.example.test locked.example.test
```

The app is only routed on Traefik's `internal` entrypoint (8444), never on the portal's (8443).
`locked.example.test` is a second instance that allows only `192.0.2.0/24`, so it answers 403 even
to a valid admin: that is the network-isolation check.

**Behind a reverse proxy other than Traefik:** make sure client-supplied `Remote-User` /
`Remote-Groups` headers are removed before they reach the app. Traefik's forwardAuth does this for
the headers in `authResponseHeaders`; the e2e suite checks it.

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

## How applying works

1. **Review** shows the diff, lint, protected-rule status and Authelia's own verdict on the draft.
2. **Validate & apply** is only enabled when everything is in order; otherwise it says why
   (stale draft, blocking lint, a protected rule weakened, hand-edited files, a version mismatch...).
3. The change is written atomically, committed to the local git repo in `CONFIG_MANAGED_DIR`
   (author = the admin), and Authelia is restarted **through the socket proxy**
   (`wollomatic/socket-proxy`, allowing exactly *inspect* and *restart* of the Authelia container).
4. It counts as healthy only after Authelia really restarted **and** `/api/health` answers 200 within
   30 s. Otherwise the commit is reverted, Authelia is restarted again, and your change comes back
   into the draft with the reason.
5. Without Redis, Authelia keeps sessions in memory, so **every restart signs everyone out**. The
   apply keeps running on the server; after you log in again the result is shown (banner, `History`).
   If the change is rolled back, Authelia restarts a second time and you may have to log in again.
6. The running Authelia version must match the version bundled in this image
   (`VERSION_MISMATCH=block`, the default), otherwise applying is disabled and the banner names the
   image tag to deploy.

The audit log (`audit.log`, who/when/from where/result, never config content) and the git history
live in `CONFIG_MANAGED_DIR` and are never pushed anywhere.

## Access tests, disabled rules, hand edits

- **Disabled rules**: *Disable* switches a rule off without deleting it; *Enable* puts it back
  at its old position, byte for byte. Authelia never sees disabled rules.
- **Access tests**: saved "this request must get this policy" checks (page *Access tests*, or
  *Add as test* in the URL tester). Review shows each test live → draft; a test that would fail
  blocks Apply until you tick *I accept these changes*. After every restart the anonymous tests
  are also probed against the real Authelia and compared with the preview; a mismatch rolls back.
- **Hand edits**: files edited outside the configurator are committed as "External change" the
  next time a page loads or an apply starts, and announced in a banner. A change to the main
  `configuration.yml` shows a banner with *Re-validate*.

## Notifications (optional)

Set `NOTIFY_WEBHOOK_URL` to get a message when an apply finishes (applied, rolled back, failed)
and when the Authelia version mismatch is first seen. The configurator POSTs JSON with a 5 s
timeout and never sends diffs, rules or secrets:
`{"title", "message", "text", "event", "result", "user", "commit", "ts", "host"}`. A failing
webhook never breaks an apply. The URL may contain a token, so keep it in your `.env`.

| Service | `NOTIFY_WEBHOOK_URL` |
|---|---|
| Gotify | `https://gotify.example.com/message?token=APP_TOKEN` (uses `title` and `message`) |
| Home Assistant | `https://ha.example.com/api/webhook/WEBHOOK_ID` (read `trigger.json.message`) |
| Telegram | `https://TELEGRAM_BOT_API_HOST/botTOKEN/sendMessage?chat_id=CHAT_ID` (uses `text`) |
| ntfy | `https://ntfy.example.com/TOPIC?tpl=1&t={{.title}}&m={{.message}}` |

## Production setup

See [`docs/migration.md`](docs/migration.md) and the commented files in [`examples/`](examples/)
(compose with the socket proxy, Traefik static and dynamic configuration, the protected rules).

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
make test-e2e          # full stack + Playwright (needs: uv run playwright install chromium)
make screenshots       # every screen at 1280/390 px, light and dark -> docs/screenshots/
make scan              # gitleaks + image scan
uv run pytest tests/unit/test_split_config.py::test_counts_and_disabled_rule_positions   # one test
```

The pinned Authelia version lives only in the `Dockerfile` (`ARG AUTHELIA_VERSION`). See
[CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

Apache-2.0, see [LICENSE](LICENSE).
