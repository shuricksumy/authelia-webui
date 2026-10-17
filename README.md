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

## OIDC clients

The *OIDC Clients* page edits `oidc_clients.yml` through the same draft, review and safe apply as
the rules (one restart for both).

- **New client** opens a preset picker: generic confidential, generic public (PKCE), Immich,
  Home Assistant, Nextcloud (two apps), Portainer, Cloudflare Zero Trust, LibreChat and Grafana.
  Each preset holds what Authelia's integration guide for that app says (checked against 4.39 and
  validated by Authelia in CI); you enter the app's address and review everything before saving.
  Presets that need a claims policy or scope in your main configuration say so and show the snippet.
- **Secrets** are generated by the bundled `authelia` binary, shown **once** (masked until *Show*),
  and only their PBKDF2-SHA512 hash is stored. A new secret takes effect when you apply; until then
  the old one keeps working. Hashes never appear on a page or in a diff (`<hash>`).
- Existing hashes (PBKDF2, Argon2id, ...) are kept byte for byte. Clients using `client_secret_jwt`
  or `private_key_jwt` can be edited, but their secrets are not generated here.
- Setting up the OIDC provider itself (`hmac_secret`, signing keys) stays in the main configuration.

## Users and groups

The *Users* and *Groups* pages edit the users file. It must live in the managed folder (see
[`docs/migration.md`](docs/migration.md) step 5b); otherwise the pages are read-only.

- **Saved at once.** Authelia reloads the users file by itself (`watch: true`), so there is no
  draft and no restart: nobody is signed out. Every change is a commit in History (`Users: ...`) and
  an audit entry. Authelia's own writes (password resets) are committed as "External change".
- **Passwords** are generated by the bundled `authelia` (shown once, meeting your `password_policy`)
  or typed (checked against the policy). Hashed with your configured algorithm and parameters.
  A password never reaches a file, a log or a later page; hashes are never shown.
- **Guards:** you cannot remove, disable or demote yourself, and the admin group never ends up
  empty. A broken users file is refused before it is written (Authelia would silently ignore it).
- **Groups** are names on users: the page lists members and the rules that use each group. Renaming
  a group does not change rules; it lists the ones to adjust.

## Overview and logs

`/` is an overview: Authelia's health and versions, the draft and the last apply, counts, and a
**Needs attention** list built from the checks the other pages already run (rule and client
problems, failing access tests, a single admin, errors in the log). **Logs** reads Authelia's log
file (`AUTHELIA_LOG_FILE`) plus the copies logrotate leaves next to it, read-only: filter by level,
time, text and remote IP, see the **top problems** grouped by message, page back through older
entries, or download the filtered lines. Password hashes, tokens and keys are hidden before
anything is shown. The configurator never rotates logs; the host does, see
`examples/production/logrotate/authelia`.

## Keys and certificates

**Keys** rotates Authelia's OIDC signing keys in three reviewed steps (add a new key, make it
sign, remove the old one), each through the safe apply with a check of the live key set, and lists
certificate expiry (signing-key certificates and the live TLS certificates) with a banner and a
notification before anything expires. It needs a one-time move of the keys out of the main file:
`docs/jwks.md`.

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

- **Fresh install:** [`examples/production/`](examples/production/) is a complete, production-like
  stack (Traefik with HTTPS and a VPN-only entrypoint, Authelia, the configurator, the socket
  proxy, a demo app). Its README walks through secrets, networks and the first login; CI validates
  it with the real Authelia.
- **Existing Authelia:** [`docs/migration.md`](docs/migration.md) and the snippets in
  [`examples/`](examples/) (compose with the socket proxy, Traefik configuration, protected rules).

## Lockout recovery

If Authelia is down and you want the web UI anyway, the optional emergency door gives you a
password-protected port on the server's loopback address (reach it with an SSH tunnel):
`docs/emergency.md`.

Otherwise, if a bad change locks you out, over SSH on the Docker host:

```sh
git -C /path/to/config/managed revert HEAD
docker restart authelia
```

## Backups

The managed git repo is local only and contains password hashes. **History → Backup** downloads
one `.tar.gz` of everything the configurator manages: the rules, clients, users, the full history,
the audit log and the OIDC private key files (which are not in git). It asks for a confirmation,
is recorded in the audit log, and the archive holds password hashes and private keys: keep it
encrypted. Restore by stopping the configurator, extracting it into the Authelia config folder
(`tar -xzf authelia-managed-....tar.gz -C /path/to/authelia`, which recreates `managed/`), keeping
`managed/secrets/` at mode 700, and starting it again. The main `configuration.yml` is not part of
it: back that up with your normal host backups. Never push any of this anywhere public.

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

`main` is protected: every change is a pull request that merges only when CI is green. Besides
CI (lint, tests, gitleaks, Trivy) the repository runs:
- **CodeQL** (Python and the workflows, `security-extended`), weekly and on every PR;
- **dependency review** on PRs (fails on a new dependency with a high/critical advisory);
- **zizmor** on workflow changes (injection, credential persistence, unpinned actions);
- **OpenSSF Scorecard** weekly;
- **secret scanning with push protection**, **Dependabot alerts and security updates**
  (Dependabot opens security PRs only; Renovate owns version updates), and private
  vulnerability reporting.

Releases are built only from `main` (`release.yml` runs the full CI first), signed with cosign,
with SBOM and provenance.

## License

Apache-2.0, see [LICENSE](LICENSE).
