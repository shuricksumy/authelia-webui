# Authelia Configurator — Specification

A small, self-hosted web UI for managing the parts of an Authelia file-based
configuration that change often: **access control rules**, **OIDC clients**
and (later) **users**. Everything else stays hand-edited YAML.

> **This is a public open-source repository.** It must contain no real
> domains, hostnames, IPs, emails, usernames, secrets, hashes or keys. All
> deployment-specific values come from environment variables at runtime.
> Examples use `example.com`, `*.example.test` and RFC 5737 / RFC 1918 ranges.

Assumed environment (generic): single Docker host, Traefik as reverse proxy,
Authelia with the file authentication backend, a VPN (e.g. WireGuard) for
admin access.

---

## 1. Goals and non-goals

### Goals
- Add / edit / delete / reorder `access_control.rules` from a browser.
- Add / edit / delete OIDC clients, including secret generation and hashing.
- Validate every change with Authelia's own validator before it is applied.
- Every applied change is a git commit; one-click rollback.
- Automatic rollback if Authelia is unhealthy after a restart.
- **Internal-only admin tool**: reachable only from VPN / allow-listed
  networks, never from the public internet (§8).
- **Image rebuilt automatically for every new Authelia release**, tested
  against that release, published per version (§11).
- Low footprint (< 100 MB RAM), one container plus a socket proxy.

### Non-goals (v1)
- Editing core settings (session, storage, notifier, TOTP, WebAuthn, server).
- Multi-instance / HA Authelia.
- LDAP backends.
- Replacing Authelia's login portal or user self-service.

---

## 2. Runtime configuration (env vars)

Nothing deployment-specific is hard-coded. Required vars missing → app refuses
to start (fail closed).

| Variable | Example | Purpose |
|---|---|---|
| `AUTH_DOMAIN` | `auth.example.com` | Authelia portal host (issuer, protected rules) |
| `CONFIGURATOR_DOMAIN` | `authcfg.example.com` | Host this app is served on |
| `ADMIN_GROUP` | `admin` | Group required to use the app |
| `ALLOWED_CLIENT_CIDRS` | `10.8.0.0/24,192.168.1.0/24` | **Required.** Client networks allowed (VPN/LAN). Empty → refuse to start |
| `TRUSTED_PROXY_CIDRS` | `172.20.0.0/16` | Docker network of Traefik; only these may set forwarded headers |
| `AUTHELIA_CONTAINER` | `authelia` | Container name for restart / version check |
| `AUTHELIA_HEALTH_URL` | `http://authelia:9091/api/health` | Health endpoint |
| `CONFIG_MAIN` | `/config/configuration.yml` | Read-only main config |
| `CONFIG_MANAGED_DIR` | `/config/managed` | Files owned by this app |
| `USERS_FILE` | `/config/users.yml` | Phase 3 |
| `RESTART_MODE` | `socket-proxy` \| `signal` | §7 |
| `DOCKER_PROXY_URL` | `http://socket-proxy:2375` | §7 |
| `VERSION_MISMATCH` | `block` \| `warn` | §11.5, default `block` |
| `APP_SECRET_KEY` | (random, ≥ 32 bytes) | **Required.** Session/CSRF signing (§16.7) |
| `AUTHELIA_LOG_FILE` | `/config/authelia.log` | Optional, read-only, for rollback diagnosis (§16.4) |
| `NOTIFY_WEBHOOK_URL` | `https://ntfy.example.com/topic` | Optional notifications (§16.5) |

---

## 3. Config split (Phase 0 — migration)

Authelia merges multiple configuration files (`X_AUTHELIA_CONFIG` accepts a
comma-separated list). The configurator **only owns dedicated files** and never
writes the main configuration file.

```
/config/
├── configuration.yml          # hand-edited, mounted READ-ONLY into the configurator
├── users.yml                  # Authelia file backend (watch: true) — Phase 3
├── db.sqlite3                 # Authelia storage — never touched
└── managed/                   # local git repo, owned by the configurator
    ├── access_control.yml     # whole `access_control:` block
    ├── oidc_clients.yml       # `identity_providers.oidc.clients:` only
    ├── disabled_rules.yml     # rules switched off in the UI (never read by Authelia)
    └── access_tests.yml       # saved access tests (§16.2)
```

Authelia container:
```yaml
environment:
  X_AUTHELIA_CONFIG: /config/configuration.yml,/config/managed/access_control.yml,/config/managed/oidc_clients.yml
```

### Phase 0 tasks
1. **Verify merge behaviour against a real Authelia container** before writing
   app code:
   - `access_control` fully in `access_control.yml` → validate passes.
   - `identity_providers.oidc` keys (hmac_secret, jwks, claims_policies, scopes,
     authorization_policies, …) stay in the main file, only `clients:` moves
     → confirm nested-map merge works.
   - If nested merge does NOT work: fall back to moving the whole
     `identity_providers` block into a managed file; non-client keys then
     editable only as raw YAML and never displayed in the browser.
   - Record results in `docs/merge-behaviour.md`; turn them into integration
     tests that run on every Authelia version (§11).
2. Migration script `scripts/split_config.py`:
   - Reads an existing config; extracts `access_control` and
     `identity_providers.oidc.clients` into managed files (preserve comments
     and order).
   - Writes the reduced main config to a **new file**; never overwrites the
     original.
   - Runs `authelia config validate` on the split set and diffs the effective
     merged config old vs new — must be identical.
   - Prints nothing secret to stdout (diff shows keys, masks values matching
     secret fields).

---

## 4. Access control rules (Phase 1)

### Data model (per rule)
| Field | Type | Notes |
|---|---|---|
| `domain` | list[str] or str | Wildcards supported |
| `domain_regex` | list[str] | Optional |
| `resources` | list[regex] | Validate each compiles as Go RE2 — warn on lookaheads `(?!` etc. |
| `subject` | list[list[str]] | Outer = OR, inner = AND. `user:x`, `group:x`, `oauth2:client:x` |
| `methods` | list[str] | Optional |
| `networks` | list[str] | Optional |
| `query` | raw | Raw YAML |
| `policy` | enum | `bypass`, `one_factor`, `two_factor`, `deny` |
| `_extra` | map | Unknown keys, preserved verbatim |
| `_comment` | str | Stored as YAML comment above the rule |

Plus top-level `default_policy` and `networks` (raw YAML).

### UI
- Rules table in evaluation order: #, domain(s), resources count, subject
  summary, policy badge, note.
- Drag-and-drop + keyboard move up/down.
- Group-by-domain read-only view.
- Add/edit form with list editors; "Raw YAML" tab per rule.
- **Rule tester**: URL + method + user + groups → first matching rule and
  resulting policy (first match wins, else default_policy). Labelled as preview.

### Lint warnings (non-blocking unless marked)
- Subject references a user not in the users file.
- Subject references a group no user has.
- Rule shadowed by an earlier broader rule for the same domain.
- `bypass` without `resources`.
- Regex invalid / unsupported RE2 syntax — **blocking**.
- Duplicate rules.

### Protected rules
Derived from the environment, not from a file (a `protected_rules.yml` was dropped in Phase 1a:
protection is checked by *behaviour* through the rule tester, so a reordered or widened rule is
caught too, and nothing deployment-specific can drift out of sync). The protected set:
- `${AUTH_DOMAIN}` bypass for `/.well-known/openid-configuration`,
  `/jwks.json`, `/api/oidc/.*`.
- The rule protecting `${CONFIGURATOR_DOMAIN}`: must remain `two_factor`,
  must require `group:${ADMIN_GROUP}`, and must include a `networks:` match
  limited to `ALLOWED_CLIENT_CIDRS` (§8). Deleting or weakening is blocked.

---

## 5. OIDC clients (Phase 2)

| Field | UI control |
|---|---|
| `client_id` | text + "Generate"; warn on change after create |
| `client_name` | text |
| `client_secret` | never shown; "Generate new secret" → plaintext shown **once** in modal, only hash stored |
| `public` | toggle |
| `authorization_policy` | `one_factor`, `two_factor` + names from main config `authorization_policies` |
| `claims_policy` | names from main config `claims_policies` |
| `scopes` | standard (`openid`, `profile`, `email`, `groups`, `offline_access`, `address`, `phone`) + custom scopes from main config |
| `redirect_uris` | list; validate absolute https (allow custom schemes for native apps) |
| `grant_types`, `response_types`, `response_modes` | multi-select |
| `token_endpoint_auth_method` | select |
| `require_pkce`, `pkce_challenge_method` | toggle + select |
| `consent_mode`, `pre_configured_consent_duration` | select + duration |
| `*_signed_response_alg` | select |
| `_extra` | raw YAML tab |

Only key **names** (policy names, scope names) are read from the main config
for dropdowns. Secret values (hmac, jwks, session, storage, SMTP) are never
parsed into objects sent to templates.

### Templates
`templates/oidc/*.yml` presets using placeholder hosts (`app.example.com`):
generic confidential, generic public (PKCE), Immich, Home Assistant,
Nextcloud (oidc_login), Portainer, Cloudflare Zero Trust, LibreChat, Grafana.
Placeholders are substituted in the form; user must review before save.

### Rules
- Existing `$pbkdf2-…` and `$argon2id$…` hashes preserved untouched unless rotated.
- Plaintext never written to disk, logs, git, test snapshots or HTML after the modal.
- After create, show copyable client setup snippet (issuer
  `https://${AUTH_DOMAIN}`, discovery URL, client_id, redirect URIs).
- Lint: duplicate client_id (blocking), `public: true` with secret (blocking),
  non-https redirect (warning), public client without PKCE (warning), auth
  method/secret mismatch.

---

## 6. Apply flow

```
Edit ──► Draft ──► "Review & apply" ──► diff + lint ──► Confirm
                                                          │
            Write temp ──► authelia config validate ──fail──► errors, no change
                                  │ ok
            Atomic move ──► git commit (author = Remote-User)
                                  │
            Restart Authelia (if rules/clients changed)
                                  │
            Poll AUTHELIA_HEALTH_URL (1s interval, 30s timeout)
                    ┌─────────────┴────────────┐
                 healthy                    unhealthy
              "Applied ✓"        git revert, restart, health check,
                                 "Rolled back" + error summary
```

- One apply at a time (file lock).
- Refuse apply if managed files changed on disk since draft started.
- History page: commits, diffs, "revert to this version" (same flow).
- Audit log `managed/audit.log`: who, when, client IP, action, result.

---

## 7. Restart mechanism

Default `RESTART_MODE=socket-proxy`: `wollomatic/socket-proxy` (per-method regex
allow-list, so restart can be limited to the one Authelia container; Tecnativa's
`ALLOW_RESTARTS` cannot) on an internal network shared only with the configurator, allowing
only `GET /containers/{name}/json` (version check, §11.5) and
`POST /containers/{name}/restart`. All else denied. Verify the proxy's flags
for the pinned version and add an integration test that a forbidden call
(e.g. `POST /containers/create`, `exec`) is rejected.

Alternative `RESTART_MODE=signal`: write `/signal/restart-authelia`; host-side
systemd path unit restarts the container. Example unit in `examples/`.

Never mount `/var/run/docker.sock` into the configurator.

---

## 8. Network isolation — internal-only tool

The admin UI must be unreachable from the public internet. Defense in depth,
all layers required:

### Layer 1 — DNS / edge
- No public DNS record, CDN proxy or tunnel route for `CONFIGURATOR_DOMAIN`.
  Resolve it only via VPN DNS / split-horizon / hosts file.
- README explicitly warns: do not add it to a public tunnel or CDN.

### Layer 2 — Traefik
Provide both options in `examples/`; README recommends A.
- **A. Dedicated internal entrypoint** bound to the VPN interface address
  only (e.g. `--entrypoints.internal.address=10.8.0.1:8443`). The router for
  the configurator uses only this entrypoint, so it is not even routable on the
  public `websecure` entrypoint.
- **B. IP allow-list middleware** on the router
  (`ipAllowList.sourceRange` = VPN/LAN CIDRs). Document the pitfall: behind a
  CDN/proxy the source IP is the proxy's — must configure `ipStrategy`
  correctly or prefer A.
- TLS: internal certificate via DNS-01 challenge works without public exposure.

### Layer 3 — Authelia
- Rule for `CONFIGURATOR_DOMAIN`: `networks: <ALLOWED_CLIENT_CIDRS>`,
  `subject: group:<ADMIN_GROUP>`, `policy: two_factor`, placed **before** any
  wildcard catch-all. Followed by an explicit `deny` rule for the same domain.
  Both are protected rules (§4).

### Layer 4 — Application
- Container publishes **no ports**; only on internal Docker networks.
- Determine client IP: take `X-Forwarded-For` only if the direct peer is in
  `TRUSTED_PROXY_CIDRS`; otherwise use the peer address. Reject (403, logged)
  if client IP not in `ALLOWED_CLIENT_CIDRS`.
- Require `Remote-User` and `Remote-Groups` (from Authelia forwardAuth) with
  `ADMIN_GROUP`; reject otherwise. Ignore these headers if the peer is not a
  trusted proxy.
- The proxy must never pass client-supplied `Remote-*` headers through. Traefik's
  forwardAuth removes the headers listed in `authResponseHeaders` when Authelia does
  not set them (pinned by an e2e test on a deliberately bypassed host). With any other
  proxy, strip them explicitly before the auth request.
- Fail closed: missing/empty `ALLOWED_CLIENT_CIDRS` → refuse to start.

### Other app security
- CSRF tokens on all state-changing requests; session cookie
  `Secure; HttpOnly; SameSite=Strict`.
- Strict CSP, no inline scripts, all static assets served locally (no CDN).
- Non-root user, read-only root filesystem, writable only
  `CONFIG_MANAGED_DIR`, `/tmp`, `/signal`. `cap_drop: [ALL]`,
  `no-new-privileges`.
- Main config mounted read-only; file contents never logged.
- Managed git repo is local only, never pushed (it contains hashes).
- Lockout recovery in README: SSH →
  `git -C /config/managed revert HEAD && docker restart authelia`.

### Tests for isolation (integration)
- Request from a non-allowed CIDR → 403 at app level even with valid
  Authelia headers.
- Spoofed `X-Forwarded-For` from an untrusted peer → ignored, 403.
- Forged `Remote-User` / `Remote-Groups` from untrusted peer → 403.
- App refuses to start without `ALLOWED_CLIENT_CIDRS`.
- Router not reachable on the public entrypoint in the test Traefik config.

---

## 9. Users (Phase 3, optional)

`users.yml` with `watch: true` → no restart needed.
- List / add / edit / disable users: username, displayname, email, groups,
  disabled, extra attributes from `authentication_backend.file.extra_attributes`
  (types honoured, e.g. integer).
- Set password via bundled `authelia crypto hash generate argon2` with the
  configured params; enforce `password_policy` from main config.
- Never display existing hashes.
- Git tracking of users file decided in Phase 3 planning.

---

## 10. Phase 4 ideas (only when requested)
- JWKS key rotation: generate RSA key/cert with the bundled binary
  (`crypto certificate rsa generate`), store under `/config/secrets/`,
  reference via Authelia's template filter, support two keys during rotation.
- Certificate expiry warning.
- Read-only dashboard.

---

## 11. Build, release and auto-update

The configurator bundles the Authelia CLI, so it must track Authelia releases.

### 11.1 Version source of truth
- `Dockerfile`:
  ```dockerfile
  ARG AUTHELIA_VERSION=4.39.x   # exact version, updated by automation
  FROM authelia/authelia:${AUTHELIA_VERSION} AS authelia
  ...
  COPY --from=authelia /app/authelia /usr/local/bin/authelia
  ```
- The runtime image is Debian-based (`python:3.13-slim`): the Authelia release binary is
  dynamically linked against glibc and does not run on Alpine. The build fails if
  `authelia --version` differs from the ARG.
- `AUTHELIA_VERSION` is also written into the image as a label
  (`org.opencontainers.image.authelia-version`) and exposed at `/version`.

### 11.2 Automatic detection of new Authelia releases
Two mechanisms (both in repo):
- **Renovate** (`renovate.json`) tracks the `AUTHELIA_VERSION` ARG and base
  images, opening a PR when Authelia releases. Auto-merge allowed for
  patch/minor **only if all CI checks pass**; major versions require manual
  review.
- **Scheduled workflow** (`.github/workflows/authelia-watch.yml`, daily) as a
  fallback: queries the latest Authelia release tag from the GitHub Releases
  API; if newer than the Dockerfile ARG and no open PR exists, opens one.

### 11.3 CI pipeline (`.github/workflows/ci.yml`)
On every PR and push to main:
1. Lint (ruff, mypy), unit tests.
2. Integration tests with the **exact** `AUTHELIA_VERSION` from the Dockerfile,
   including Phase 0 merge-behaviour tests and validate/apply/rollback.
3. E2E (Playwright) against the compose test stack.
4. Secret scan (gitleaks) on the full diff — blocking.
5. Image vulnerability scan (Trivy) — fail on critical with fix available.
6. Multi-arch build (`linux/amd64`, `linux/arm64`).

### 11.4 Release (`.github/workflows/release.yml`)
On merge to main (after CI green):
- Push to GHCR with tags:
  - `authelia-<AUTHELIA_VERSION>` (e.g. `authelia-4.39.13`) — immutable pairing tag
  - `<app-semver>` and `latest`
- Sign image with cosign (keyless OIDC), attach SBOM and provenance.
- GitHub Release with changelog.
- **Weekly scheduled rebuild** of the current version for OS/base-image
  security patches, same tests, same tags (pairing tag gets a new digest).

### 11.5 Runtime version-match check
Bundled CLI and running Authelia must match:
- On startup and before every apply, query the running Authelia container's
  image/version via the socket proxy (`GET /containers/{name}/json`), or, in
  `signal` mode, from env `AUTHELIA_RUNNING_VERSION`.
- Compare with bundled version:
  - equal → OK
  - differs → `VERSION_MISMATCH=block` (default): apply disabled, banner
    explains which image tag to deploy; `warn`: banner only.
- `/version` endpoint returns both versions.

### 11.6 Deployment auto-update (documented in README, not enforced)
- Recommended: pin both images to the same version in the user's private
  compose via one variable:
  ```yaml
  authelia:      image: authelia/authelia:${AUTHELIA_VERSION}
  configurator:  image: ghcr.io/<owner>/authelia-configurator:authelia-${AUTHELIA_VERSION}
  ```
  Bump the variable once (manually or via Renovate in the user's private infra
  repo) → both update together.
- If the user runs Authelia on `latest` with an auto-updater (e.g.
  Watchtower), use configurator `latest` with the same updater; the version
  check (§11.5) blocks applies during any gap until both match.

---

## 12. Testing summary

All fixtures synthetic: `example.com` / `*.example.test` domains, fake users
(`alice`, `bob`), hashes and keys generated at test time, never committed.

### Unit
- YAML round-trip byte-identical for unchanged files; unknown keys survive.
- Each lint rule positive/negative.
- Rule tester semantics (first match, OR/AND subjects, wildcards, regex, default).
- Protected rules cannot be removed/weakened.
- Plaintext secrets never in files, logs, HTML.
- Client-IP resolution and trusted-proxy logic.

### Integration (compose: Traefik, Authelia pinned, configurator, socket-proxy, whoami)
- Merge behaviour checks (§3).
- Valid apply → restart → healthy → whoami access matches policy.
- Invalid config rejected; files unchanged; no restart.
- Startup failure after apply → automatic revert, healthy.
- Concurrent apply blocked; external edit detected.
- New OIDC client completes auth-code flow with generated secret.
- Socket proxy denies non-allowed calls.
- Network isolation tests (§8).
- Version mismatch → apply blocked.

### E2E (Playwright)
- Admin from allowed network logs in (TOTP from test seed) → app works.
- Non-admin → 403; disallowed network → 403.
- Add/reorder rule → diff → apply → success.
- Create client from template; one-time secret modal can't be reopened.
- Revert from history.

### Definition of done per phase
CI fully green (incl. integration + secret scan), README updated, no real data.

---

## 13. Public repository hygiene

- `LICENSE` (MIT or Apache-2.0 — decide in Phase 0), `README.md`,
  `SECURITY.md` (private vulnerability reporting via GitHub advisories),
  `CONTRIBUTING.md`.
- `.gitignore` excludes `*.sqlite3`, `configuration.yml`, `users.yml`,
  `managed/`, `.env`, `keys/`, `*.pem`, `*.crt`, `*.key`, `notification.txt`,
  `*.log`.
- Only `*.example.yml` / `.env.example` files with placeholders are committed.
- Pre-commit hooks: gitleaks, ruff, end-of-file fixer.
- CI blocks any commit containing hash-like strings
  (`$argon2id$`, `$pbkdf2-`), PEM blocks, or non-example domains outside
  `tests/fixtures/generated/` (which is gitignored).
- Branch protection on main: CI required; Renovate auto-merge only via CI.
- Dependabot/Renovate also for Python deps and GitHub Actions (pin actions by SHA).

---

## 14. Repository layout

```
authelia-webui/                # repo name; product "Authelia Configurator",
│                              # image ghcr.io/<owner>/authelia-configurator
├── .claude/settings.json      # shared Claude Code permissions
├── CLAUDE.md
├── SPEC.md
├── README.md
├── SECURITY.md
├── LICENSE
├── Dockerfile                 # multi-stage, ARG AUTHELIA_VERSION
├── renovate.json
├── .github/workflows/{ci,release,authelia-watch}.yml
├── compose.test.yml           # integration stack (example.test domains)
├── examples/
│   ├── compose.example.yml    # configurator + socket-proxy + Authelia changes
│   ├── traefik-static.example.yml     # internal entrypoint bound to the VPN address
│   ├── traefik-dynamic.example.yml    # router + forwardAuth (+ ipAllowList variant)
│   ├── authelia-rules.example.yml
│   ├── restart-authelia.path / .service   # signal mode (later)
│   └── configurator.env.example
├── app/
├── templates/oidc/
├── scripts/split_config.py
├── tests/{unit,integration,e2e}/
└── docs/merge-behaviour.md
```

## 15. UI design

Goal: a plain, fast admin tool that looks like a tidy settings page — closer
to Portainer / Uptime Kuma than to a marketing site. Usable by one admin on a
laptop over VPN; must also work on a phone (390 px) for quick fixes.

### 15.1 Fixed technical choices (don't substitute without asking)
- **Pico.css** (vendored, no CDN) for base styling: semantic HTML, automatic
  light/dark mode, no build step. Small custom `app.css` for badges, tables,
  drag handles only.
- **HTMX** (vendored) for partial updates; no SPA framework.
- **SortableJS** (vendored) for drag-and-drop rule ordering, with up/down
  buttons as the keyboard/mobile alternative.
- Python 3.13, FastAPI + uvicorn, managed with uv; tests with pytest + Playwright.
- Jinja2 templates, one base layout, one partial per component.
- No icons font; a handful of inline SVG icons max.

### 15.2 Layout shell
```
┌──────────────────────────────────────────────────────────────────┐
│ Authelia Configurator     Rules  OIDC Clients  Users  History    │
│                            ─────                   alice (admin) │
├──────────────────────────────────────────────────────────────────┤
│ ⚠ 2 unapplied changes   [Review & apply]   [Discard]             │  ← sticky bar, only when draft exists
├──────────────────────────────────────────────────────────────────┤
│                         page content                             │
├──────────────────────────────────────────────────────────────────┤
│ Authelia 4.39.x ✓ healthy · bundled 4.39.x ✓ · last apply 10:42  │  ← status footer
└──────────────────────────────────────────────────────────────────┘
```
- Version mismatch or unhealthy → footer turns red and the apply button is
  disabled with the reason in plain words.

### 15.3 Rules list
```
Rules                       default policy: [deny ▾]   [+ Add rule] [Test a URL]
Filter: [ domain or group…        ]   View: (•) Order  ( ) By domain

 ⋮⋮  #  Domain                  Paths        Who                 Policy        
 ⋮⋮  1  auth.example.com        3 paths      anyone              BYPASS   🔒   
 ⋮⋮  2  auth.example.com        all          anyone              1FA      🔒   
 ⋮⋮  3  photos.example.com      11 paths     anyone              BYPASS   ⚠1  [Edit]
 ⋮⋮  4  photos.example.com      all          group:family        2FA          [Edit]
 ⋮⋮  5  *.example.com           all          group:admin         2FA          [Edit]
```
- Policy badges: BYPASS = amber, 1FA = blue, 2FA = green, DENY = red.
  Colour is never the only signal (text label always shown).
- 🔒 = protected rule (edit opens read-only with explanation).
- ⚠n = lint warnings; hover/tap shows them.
- "Paths" expands inline to show the regex list.
- Moving a rule shows a subtle "order changed" marker until applied.

### 15.4 Rule editor (side panel on desktop, full page on mobile)
```
Edit rule #4
Domain(s)      [ photos.example.com         ] [+]
Paths (regex)  ( ) All paths   (•) Only these:
               [ ^/api/.*$                   ] [✕]
               [+ add path]       ✓ valid RE2
Who            (•) Anyone   ( ) Only:
                 Any of these groups of conditions:
                 ┌ group:family ┐  OR  ┌ user:bob AND group:dev ┐  [+ OR]
Policy         [ Two-factor ▾ ]
Note           [ Immich web UI                ]
▸ Advanced (methods, networks, query, raw YAML)

[Cancel]                                 [Delete]  [Save to draft]
```
- Plain-language labels first; Authelia key names shown as small hints.
- Implementation note (1a): list fields are one-entry-per-line textareas; the subject field takes
  one OR-alternative per line with `and` joining AND-terms. Chips/list inputs may replace them
  if the owner annotates a screenshot.
- Inline validation on blur; Save disabled while blocking errors exist.
- Users/groups fields autocomplete from the users file.

### 15.5 Rule tester (modal)
```
URL  [ https://photos.example.com/api/assets ]  Method [GET ▾]
User [ bob ▾ ]  Groups: family, dev (from users file, editable)
                                                       [Test]
Result: rule #3 matches → BYPASS
        (rules #1–2 skipped: different domain)
```

### 15.6 Review & apply
```
Review changes
 Rules:   +1 added   ~1 edited   ↕ order changed
 Clients: none
 Lint:    ⚠ 1 warning  (rule #4: user "carol" not found)   — not blocking

 ┌ diff (access_control.yml) ───────────────────────────────┐
 │ -      policy: one_factor                                │
 │ +      policy: two_factor                                │
 └──────────────────────────────────────────────────────────┘
 Applying will restart Authelia (~5 s of errors on protected apps).

[Back]                                     [Validate & apply]
```
Progress shown as steps: Validating ✓ → Saving ✓ → Restarting… → Healthy ✓
(or Rolled back ✗ with reason).

### 15.7 OIDC clients
List: name, client ID (truncated, copy button), redirect host(s), auth
policy badge, PKCE yes/no, [Edit]. "+ New client" opens a template picker
(cards with app name + one line), then the editor.

Editor sections (collapsible): Basics (name, id, public/confidential),
Redirect URIs, Security (auth policy, PKCE, token auth method), Scopes &
claims, Advanced (signing algs, consent, raw YAML).

One-time secret modal:
```
Client secret — copy it now
[ •••••••••••••••••••••••••••••••• ] [Show] [Copy]
This secret will never be shown again. Only its hash is stored.
☐ I have copied the secret                          [Done]  ← enabled after tick
```
Followed by a "Setup info" box with issuer, discovery URL, client ID and
redirect URIs, each with a copy button.

### 15.8 History
Table: time, author, summary, result (applied / rolled back). Row expands to
diff. [Revert to this version] opens the same review screen.

### 15.9 UX rules
- Every destructive action has a confirm step naming the object.
- Empty states explain what to do ("No OIDC clients yet — + New client").
- Errors in plain language first, raw Authelia message in a details toggle.
- Works at 1280 px and 390 px widths; no horizontal page scroll (tables may
  scroll inside their container).
- Keyboard accessible: all actions reachable with Tab/Enter; visible focus.

### 15.10 Visual verification workflow (mandatory)
Claude Code must check the UI visually, not only by tests:
1. `make screenshots` runs a Playwright script against the test stack with
   synthetic seed data and saves PNGs for every screen in 15.2–15.8 at
   1280 px and 390 px, light and dark mode, to `docs/screenshots/`.
2. After any UI change, Claude Code regenerates screenshots, **opens and
   reviews them itself**, compares them with the wireframes above, and fixes
   layout problems before reporting done.
3. Each UI PR includes the updated screenshots so the owner can review the
   result visually.
4. Owner feedback is given as annotated screenshots; treat them as the
   source of truth over these wireframes.

## 16. Additional requirements

### 16.1 Disabled rules (instead of commented-out YAML)
Configs often keep old rules as YAML comments. Comments can't move
reliably when rules are reordered, so:
- Rules can be **disabled** in the UI. Disabled rules live in
  `managed/disabled_rules.yml` (with their original position) and are not
  passed to Authelia. Re-enable restores them.
- Migration (§3) detects commented-out rule blocks inside `access_control`
  and offers to import them as disabled rules; anything it can't parse is
  kept in `managed/migration_leftovers.yml` and reported, never silently lost.
- Commented-out entries **inside** a live rule (e.g. a disabled `resources` line) stay in the
  YAML. If that rule is later edited in the form, the review screen warns that its inline
  commented lines will be moved to `migration_leftovers.yml`.
- Free-text comments become the rule's `_comment` note.

### 16.2 Access test suite (regression checks for rules)
Saved test cases, edited in the UI and stored in `managed/access_tests.yml`:
```yaml
- url: https://photos.example.com/api/server/ping
  user: anonymous
  expect: bypass
- url: https://photos.example.com/
  user: bob
  groups: [family]
  expect: two_factor
- url: https://admin.example.com/
  user: bob
  groups: [family]
  expect: deny
```
- **Before apply**: run all cases with the rule tester on the draft and on
  the current live rules; show a table of results and highlight any case whose
  result changed or no longer matches `expect`. Failures block apply unless
  the admin ticks "I accept these changes".
- **After restart**: for anonymous cases, probe the real Authelia authz
  endpoint (`/api/authz/forward-auth` with `X-Original-URL` /
  `X-Forwarded-*` headers) and confirm bypass vs. redirect/401. Mismatch →
  automatic rollback, same as a failed health check.
- One-click "Add as test" from the rule tester.

### 16.3 Authelia upgrades and deprecated keys
- CI treats `authelia config validate` **warnings** (deprecations) as
  failures, so a new Authelia version that deprecates a key the forms write
  is caught in the Renovate PR, not in production.
- The app shows validator warnings on the review screen.

### 16.4 Logs for diagnosis
- Optional read-only mount of Authelia's log file (`AUTHELIA_LOG_FILE`). On
  failed apply or rollback, show the last error lines (JSON log parsed to
  level/message). If not configured, show a hint where to look.

### 16.5 Notifications
- Optional webhook on apply / rollback / version mismatch
  (`NOTIFY_WEBHOOK_URL`, generic JSON POST; examples for ntfy, Gotify, Home
  Assistant webhook, Telegram bot in README). Payload contains no secrets and
  no diff content, only summary, author, result.

### 16.6 Backups
- Managed git repo is local only, so README documents backing up
  `CONFIG_MANAGED_DIR` with the rest of the Authelia config folder.
- "Download backup" button: tar.gz of managed files (hashes included, so it
  is gated behind a confirm and logged in the audit log).

### 16.7 App secrets and health
- `APP_SECRET_KEY` (required) for session/CSRF signing; refuse to start if
  missing or shorter than 32 bytes. `.env.example` shows how to generate it.
- `/healthz` (no auth, returns only `ok`) for Docker healthcheck; reachable
  only on the internal network.

### 16.8 External changes
- If managed files are edited by hand (e.g. over SSH), the app detects the
  change on next load, commits it as "external change", and shows a banner.
  Main config changes are detected by hash and shown as "main config changed
  since last apply" with a re-validate button.

## 17. Phase order
0. Repo skeleton, hygiene, CI, Dockerfile + auto-update workflows, merge
   verification, migration script (incl. disabled-rule import).
1. Access control rules + disabled rules + access test suite + apply flow +
   history + network isolation.
2. OIDC clients.
3. Users (optional).
4. Extras (optional).

Each phase is a PR-sized chunk; stop for review between phases.
