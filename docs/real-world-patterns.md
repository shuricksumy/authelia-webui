# Real-world config patterns

Structural observations from a real single-host deployment (Traefik + Authelia
file backend + OIDC for ~8 apps). **No values were copied**; the synthetic
replica lives in `tests/fixtures/realistic/`. Use this to drive Phase 0
migration tests and Phase 1/2 lint and form design.

## access_control

| Pattern | Affects |
|---|---|
| Commented-out whole rules, both at the top of `rules:` and between live rules | §16.1 disabled-rule import |
| Commented-out **list items inside a live rule** (`resources:` entries, a trailing commented `resources:` block with a lookahead regex `(?!…)`) | §16.1 — not covered yet: decide what happens to these when the rule is edited in the form (keep as leftovers? drop with warning?) |
| Inline trailing comments on list items (`- '^/api/oidc/.*' # Required for OIDC flows`) and on `policy:` | ruamel round-trip; form edits must not silently drop them without a warning |
| Numbered / descriptive comment block directly above a rule | becomes `_comment` |
| Several consecutive blank lines between rules | byte-identical round-trip test |
| Mixed quoting: `"domain"`, `'domain'`, bare domain | round-trip must keep the style of untouched values |
| `subject` written as a list of single-element lists (`- ['group:x']`) — i.e. pure OR | rule tester, subject summary in the table |
| Subjects referencing users **not** in the users file | lint "unknown user" — real case, not hypothetical |
| Same domain split into several rules: narrow bypass list → broad bypass (`^/api/.*$`) → `two_factor` with subject | narrow bypass rule is **redundant** (fully covered by a later rule with the same policy). SPEC §4 only has "shadowed" (later rule unreachable); consider a "redundant" lint |
| Bypass of a whole `/api/.*` tree so the app validates its own tokens | lint "bypass without resources" does not fire; it is intentional — don't over-warn |
| Wildcard catch-all `*.<domain>` with `group:admin` as the **last** rule | migration must insert the configurator's protected rules (§8 layer 3) **before** it |
| Auth-portal rules match the SPEC §4 default protected set (bypass discovery/jwks/`/api/oidc/.*`, then `one_factor`) | protected-rule detection on migration should recognise an existing equivalent rule instead of adding a duplicate |
| `default_policy: deny` | |

## identity_providers.oidc

- Main file holds secrets inline: `hmac_secret`, `jwks[].key` (PEM block
  scalar) and `certificate_chain`. The app must load the file to read
  **names** (`authorization_policies`, `claims_policies`, `scopes`) but never
  pass these values to templates/logs.
- Custom named `authorization_policies` (with rules), several
  `claims_policies` (one using `custom_claims` mapped to a user extra
  attribute), a custom scope exposing that claim.
- Clients mix PBKDF2-SHA512 and Argon2id secret hashes.
- Fields seen: `client_id`, `client_name` (often absent), `authorization_policy`,
  `claims_policy`, `client_secret`, `public: false`, `require_pkce`
  (explicit `false` and `true`), `pkce_challenge_method` (`'S256'` **and empty
  string `''`**), `token_endpoint_auth_method` (`client_secret_basic`,
  `client_secret_post`, sometimes absent), `scopes`, `redirect_uris`
  (with trailing comment `# adjust to your domains`, multiple URIs differing
  only by trailing slash), `grant_types`, `response_types`, `response_modes`
  (`form_post`, sometimes absent), `consent_mode` (`auto`/`explicit`, with the
  alternative commented out next to it), `pre_configured_consent_duration`,
  `*_signed_response_alg` (`none`, `RS256`).
- Blank lines between some clients, none between others.
- Indentation inside `claims_policies` differs from the rest (4 vs 2).
- Forms must distinguish "absent" from "empty string" from "false".

## Users file

- 4-space indentation (main config uses 2).
- Groups: an admin group, service groups, and a group used by exactly one
  user that is referenced by an access rule and by nothing else.
- A non-human "device" account in normal groups.
- `extra_attributes` with `value_type: integer` declared in the main config.

## Other main-config facts relevant to the app

- `log.format: json`, `log.file_path` set, `keep_stdout: false` → `docker
  logs` is empty; `AUTHELIA_LOG_FILE` (§16.4) is the only diagnosis source.
- `server.endpoints.authz: {}` with a commented custom `forward-auth` block →
  §16.2 probe uses the default `/api/authz/forward-auth`, but should read
  `server.endpoints.authz` and adapt if customised.
- Password hashing: argon2id with explicit params in
  `authentication_backend.file.password` — Phase 3 must pass `--config`.
- `password_policy.standard` enabled with all character classes.
- Commented-out top-level keys and alternative values (`#level: debug`,
  `#default_2fa_method`) are common.

## CLI commands the owner currently runs by hand

Verify flags against the docs for the pinned version before use.

- Client ID: `authelia crypto rand --length 72 --charset rfc3986`
- Client secret: `authelia crypto hash generate pbkdf2 --variant sha512 --random --random.length 72 --random.charset rfc3986`
- User password: `authelia crypto hash generate --config <main config>`
- JWKS key (Phase 4): `authelia crypto certificate rsa generate --common-name <uuid> --duration 87600h --directory <dir>`, with the UUID reused as `key_id`; PEM pasted inline into the main config today.

Note: the owner runs these with `authelia/authelia:latest`, which is the
version-drift problem §11.5 exists to prevent.
