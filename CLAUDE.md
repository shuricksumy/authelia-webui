# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# Authelia Configurator

Read `SPEC.md` before doing anything. It is the source of truth; if something
here conflicts with it, ask.

## Current state
Phase 0 (foundation) is done. **Phase 1 is delivered in three reviewed steps**; steps **1a** and
**1b** (apply/rollback/history/audit/version check, see below) are implemented. Step 1a is: security layer (`app/security.py`), rule tester (`app/rules/tester.py`), rules
document/form/lint/protected/store (`app/rules/`), the UI (`app/web.py`, `app/ui.py`,
`app/templates/`, `app/static/`) and the Traefik dev stack. The UI edits a **draft** only
(`CONFIG_MANAGED_DIR/.draft/`); the live file is never written. Next: **1c** disabled rules, access test
suite, external changes (auto-commit hand edits), notifications; signal restart mode later. Target layout: SPEC §14.

## Architecture notes (Phase 1b: apply)
- `app/apply/engine.py` is the only code that writes the live file. Order: preconditions ->
  `authelia config validate` -> atomic write -> git commit -> restart -> wait until `StartedAt`
  changed **and** health is 200 -> else revert commit, restart, report. `.apply/in-progress.json`
  marks an interrupted apply; `engine.recover()` resolves it at startup.
- Docker is only reachable through the socket proxy (`app/apply/runtime.py`); nothing else
  mounts the socket. The proxy allows exactly inspect + restart of `AUTHELIA_CONTAINER`.
- Authelia restarts sign everyone out (memory sessions). `JobBoard` persists the last result
  (`.apply/last.json`, re-read when it changes, so several instances agree); the progress panel's
  script sends the browser to `/apply/result` once Authelia answers again.
- Test-only pieces (never in examples/production): `configurator-broken` + `health-switch`
  (unhealthy while the live rules contain `break-health`), and the bypassed `forge.example.test`
  host. e2e tests that apply restart Authelia; `AliceSession` re-logs in when a session is gone,
  and `tests/e2e/test_zz_apply.py` sorts last for that reason.

## Architecture notes (Phase 1a)
- `app/rules/document.py` treats `access_control.yml` as **text blocks** (prefix | rule blocks |
  suffix). Untouched rules stay byte-identical; a comment directly above a rule travels with it.
  Only a rule edited through the form is re-serialised (ruamel round trip on that one rule).
- `app/rules/tester.py` is a port of Authelia's matcher; `tests/integration/test_tester_vs_authelia.py`
  compares it with the real forward-auth endpoint. Re-run it on every Authelia bump.
- `app/rules/protected.py` checks protected rules by **behaviour** (probing the tester), not by
  rule text, so reordering or widening a protected rule is caught too.
- Every UI mutation carries the draft revision; HTMX applies out-of-band swaps *before* the main
  swap, so scripts must wait for the new section (see `tests/e2e/screenshots.py`).
- The Authelia binary runs with a minimal environment (`child_environment`): Authelia reads every
  `AUTHELIA_*` variable as config, and the app's own settings use that prefix.
- Strict CSP: no inline scripts/styles/handlers anywhere (a unit test scans the templates).
- The editor uses one-entry-per-line textareas for list fields instead of the chip/list inputs in
  the SPEC wireframes (simpler, accessible, mobile friendly); the owner can override with an
  annotated screenshot.

## Local dev login
`make dev` then `make totp`. Add `127.0.0.1 auth.example.test authcfg.example.test
locked.example.test` to `/etc/hosts`; open https://authcfg.example.test:8444 (self-signed cert).
Credentials and the TOTP seed are generated per run into the gitignored
`tests/fixtures/generated/`. Authelia rejects a TOTP code used twice
(`tests/e2e/auth.py::fresh_totp` waits for the next one).

## Real-world reference
`docs/real-world-patterns.md` lists the structural patterns found in a real
deployment (commented-out rules, inline comments, mixed quoting and indent,
redundant rules, OIDC field variants). `tests/fixtures/realistic/*.example.yml`
is a synthetic replica of it, with `__GEN_*__` placeholders that are filled at
test time. Use the replica for migration, round-trip, lint and form tests.
Update the replica when you learn new patterns; never add real data to it.

## Naming
Repo `authelia-webui`. Product name "Authelia Configurator". Image
`ghcr.io/<owner>/authelia-configurator`.

## Claude Code setup
- `.claude/settings.json` (shared): sessions start in **plan mode**. It
  allow-lists the project toolchain and denies reading `.env`, keys, real
  `configuration.yml`/`users.yml`, `managed/` and sqlite files. Leave those
  deny rules in place; real deployment data must never enter the context.
- Personal overrides go in `.claude/settings.local.json` (gitignored).
- `gitleaks` must be installed locally (`brew install gitleaks`).

## Architecture (big picture)
- **Config split.** Authelia merges several files listed in `X_AUTHELIA_CONFIG`.
  The hand-edited `configuration.yml` is mounted read-only. The app owns only
  `CONFIG_MANAGED_DIR` (`access_control.yml`, `oidc_clients.yml`,
  `protected_rules.yml`, `disabled_rules.yml`, `access_tests.yml`,
  `audit.log`), which is a local git repo that is never pushed. Phase 0 must
  confirm the nested-merge behaviour of `identity_providers.oidc.clients`
  (results go in `docs/merge-behaviour.md`) before any app code depends on it.
- **Draft → apply pipeline** (SPEC §6, §16.2): edits accumulate in a draft.
  Review shows the diff, lint results and access-test results for the draft
  vs. live. Then: file lock → check that managed files haven't changed on disk
  → write temp → `authelia config validate` → atomic move → git commit
  (author = `Remote-User`) → restart through the socket proxy or the signal
  file → poll health and probe forward-auth for anonymous test cases → on
  failure, git revert and restart. History "revert" reuses this same flow.
- **Trust model** (SPEC §8): the client IP comes from `X-Forwarded-For` only
  when the peer is in `TRUSTED_PROXY_CIDRS`. The app then requires the client
  IP to be in `ALLOWED_CLIENT_CIDRS` and requires
  `Remote-User`/`Remote-Groups` (containing `ADMIN_GROUP`), which are also
  ignored from untrusted peers.
- **Version coupling** (SPEC §11): the image bundles the `authelia` binary from
  `authelia/authelia:${AUTHELIA_VERSION}`, which is used for validation,
  hashing and key generation. The running container's version is checked at
  startup and before every apply.
- **Rule tester** is a pure-Python reimplementation of Authelia's matching:
  first match wins, subjects are OR-of-ANDs, otherwise `default_policy`. It
  backs the tester modal, the shadowing lint and the access test suite, so its
  semantics must stay in step with Authelia.

## This is a PUBLIC repository
- Never commit real domains, hostnames, IPs, emails, usernames, secrets,
  password hashes, OIDC client IDs/secrets, keys or certificates.
- Use only `example.com`, `*.example.test`, RFC 5737 (`192.0.2.0/24`) and
  RFC 1918 ranges, and fake users (`alice`, `bob`).
- If the user pastes their real config for context, use it only to understand
  structure. Never copy values from it into code, docs, fixtures or commit
  messages.
- Generated test data (hashes, keys) is created at test time in a gitignored
  directory.
- Run `gitleaks detect` before declaring any task done.

## How to work
- Start each phase in **plan mode**: propose design, files and test list; wait
  for approval.
- One phase at a time (SPEC §17). Stop after each phase for review.
- Check current Authelia docs for field names and behaviour (access_control,
  OIDC clients, multi-file config, template filter, CLI flags). Don't guess.
- `AUTHELIA_VERSION` (Dockerfile ARG) is the single version source; compose
  test files and CI read it from there.

## Hard rules
- Never write to the main Authelia config. Only files in `CONFIG_MANAGED_DIR`.
- Never reimplement hashing/randomness — call the bundled `authelia` binary.
- Never put plaintext secrets in files, logs, git, snapshots or HTML (except
  the one-time secret modal).
- Never mount the Docker socket directly; use the socket proxy or signal mode.
- Every apply: validate → atomic write → git commit → restart → health check →
  auto-revert on failure.
- Preserve unknown YAML keys and comments (ruamel.yaml round-trip).
- Protected rules cannot be deleted or weakened.
- Internal-only: fail closed if `ALLOWED_CLIENT_CIDRS` is unset; trust
  forwarded/identity headers only from `TRUSTED_PROXY_CIDRS`.
- Apply is blocked when bundled and running Authelia versions differ (default).

## UI work
- Follow SPEC §15: Pico.css + HTMX + SortableJS (all vendored), wireframes as
  the layout reference.
- After every UI change run `make screenshots`, open the PNGs and review them
  yourself against the wireframes (desktop 1280 px and mobile 390 px, light
  and dark). Fix issues before saying the work is done.
- Include updated screenshots in the PR description.
- When the owner sends an annotated screenshot, that overrides the wireframe.

## Testing
- Tests alongside code. A phase is done only when unit, integration, e2e,
  secret scan and image scan pass in CI.
- Integration tests use a real Authelia container at the pinned version —
  never mock `authelia config validate`.

## Commands
Docker must be running for integration, e2e and scan. Tooling: uv.
- `make lint` — ruff, mypy, public-repo hygiene (`scripts/check_public_hygiene.py`)
- `make test` — unit tests; one test: `uv run pytest tests/unit/test_split_config.py::test_name`
- `make test-integration` — real pinned Authelia (merge behaviour, image, split script)
- `make test-e2e` — compose stack + Playwright (first: `uv run playwright install chromium`)
- `make scan` — gitleaks + Trivy via Docker images; `make fixtures` / `make stack` — generate
  gitignored test data; `make version` — pinned Authelia version; `make dev` / `make totp` /
  `make dev-down` — local stack with hot reload
- `make screenshots` — brings the stack up, captures every screen, tears it down; then open the PNGs

## Gotchas learned in Phase 0
- The Authelia binary is glibc-linked: keep the runtime image Debian, never Alpine.
- Authelia 403s portal requests whose host is outside the session cookie domain; e2e maps
  `auth.example.com` with a Chromium host-resolver rule.
- `authelia config validate` exits 0 with warnings; parse them, don't rely on the exit code.
- Lists are replaced, maps merged, across config files: never split one section over two files.
- gitleaks `dir` scans gitignored generated fixtures; use `git --staged` for the commit check.
