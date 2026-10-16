# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# Authelia Configurator

Read `SPEC.md` before doing anything. It is the source of truth; if something
here conflicts with it, ask.

## Current state
Phase 0 (foundation) is implemented: `app/` (settings, Authelia CLI wrapper, `/healthz`,
`/version`), `scripts/split_config.py`, Dockerfile, CI/release workflows, test fixtures. No UI
yet. Target layout: SPEC §14. Measured Authelia merge behaviour: `docs/merge-behaviour.md`.

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
  gitignored test data; `make version` — pinned Authelia version; `make dev` — test stack
- `make screenshots` — not available until the Phase 1 UI exists

## Gotchas learned in Phase 0
- The Authelia binary is glibc-linked: keep the runtime image Debian, never Alpine.
- Authelia 403s portal requests whose host is outside the session cookie domain; e2e maps
  `auth.example.com` with a Chromium host-resolver rule.
- `authelia config validate` exits 0 with warnings; parse them, don't rely on the exit code.
- Lists are replaced, maps merged, across config files: never split one section over two files.
- gitleaks `dir` scans gitignored generated fixtures; use `git --staged` for the commit check.
