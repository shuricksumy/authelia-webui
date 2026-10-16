# Authelia multi-file merge behaviour

Measured against the real Authelia container at the pinned version (**4.39.28**) by
`tests/integration/test_merge_behaviour.py`. Re-run on every Authelia bump (CI), so this
page stays true. Nothing here was mocked.

## Result: the split layout works

| # | Case | Result |
|---|---|---|
| A | `access_control` only in `managed/access_control.yml` | validates, no warnings |
| B | `identity_providers.oidc.clients` only in `managed/oidc_clients.yml`; `hmac_secret`, `jwks`, `authorization_policies`, `claims_policies`, `scopes` stay in the main file | validates, no warnings. Without the clients file the set is **invalid** (a client is required), so the clients really came from the second file and the `oidc` map was merged, not replaced |
| C | `access_control.rules` defined in two files | the later list **replaces** the earlier one (no append). File 1 held an invalid rule and the set validated once file 2 redefined `rules` |
| D | `networks` under both `definitions.network` and `access_control.networks` | error |
| E | a deprecated key (`server.host`/`server.port` instead of `server.address`) | warning, **exit code stays 0** |

So no fallback is needed: the SPEC §3 "move the whole `identity_providers` block" plan is not used.

**Consequences for the app**
- Maps are deep-merged, lists and scalars are replaced by the later file. `app/config_merge.py`
  models exactly that, and `scripts/split_config.py` checks structural equality with it.
- Never define the same section in two files. Authelia's docs say the same for access control
  rules and OIDC clients. The reduced main file therefore holds no `access_control` at all and no `oidc.clients`.
- Warnings do not change the exit code, so callers must inspect them (CI treats them as failures, SPEC §16.3).

## `authelia config validate` output format

```
Configuration parsed and loaded with errors:

	 - <section>: <message>        (messages can repeat)

Error: configuration validation failed
Usage: ...                         (usage dump, ignored)
```

- Errors: exit status 1. Warnings use the heading `Configuration parsed and loaded with warnings:`
  and, alone, exit 0. Both sections can appear in one run, in either order.
- Parsed by `app/authelia_cli.py::parse_validate_output` (deduplicated, usage dump ignored).
- Message text can quote config values; everything is passed through `redact()` before display.

## Other measured facts

- The Authelia release binary is **dynamically linked against glibc** (Ubuntu base). It does not
  run on Alpine (musl), so the image uses `python:3.13-slim` (Debian). The Dockerfile fails the
  build if `authelia --version` does not report the pinned version.
- Accessing the portal by IP gives 403 on `/api/state`: the request host must sit under a
  configured session cookie domain. E2E therefore maps `auth.example.com` to the test port.
