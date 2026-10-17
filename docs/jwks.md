# OIDC signing keys: moving them and rotating them

Authelia signs ID tokens with the **first** key of `identity_providers.oidc.jwks` and publishes
**all** of them at `/jwks.json`. Rotating a key safely means the new key must be published, and
cached by every app, *before* it signs. The configurator's **Keys** page does this in three
reviewed steps. It needs a one-time change first, because the main configuration file is never
written by the configurator and the private keys must not live in git.

## One-time move (on the host)

1. Back up the configuration (see `docs/migration.md`, step 1).
2. Check that no configuration file contains a literal `{{` (the template filter would read it):

   ```sh
   grep -rn '{{' /path/to/authelia/config/*.yml /path/to/authelia/config/managed/*.yml
   ```

   No output is what you want.
3. Run the move from the configurator image (same user as Authelia and the configurator; the
   config folder is mounted at `/config`, as Authelia sees it):

   ```sh
   docker run --rm --network none --user 1000:1000 \
     -v /path/to/authelia/config:/config \
     ghcr.io/<owner>/authelia-configurator:authelia-<version> \
     python -m scripts.migrate_jwks --config /config/configuration.yml --managed /config/managed
   ```

   It writes every private key to `managed/secrets/jwks/<key_id>.pem` (mode 600, folder 700) and
   `managed/oidc_jwks.yml`, which only *names* those files. Nothing is overwritten, the main file
   is not touched, and no key is printed. Keys without a `key_id` get one invented (`key-1`, ...):
   apps then see a different `kid`, which they pick up from `/jwks.json` on their next refresh.
   The main file's `jwks:` list may stay where it is: lists are replaced across files, so the
   managed list wins. Remove it later to tidy up (`--reduced-main <file>` writes a copy without it).
4. In the compose file:
   - Authelia: add `/config/managed/oidc_jwks.yml` to the end of `X_AUTHELIA_CONFIG` and set
     `X_AUTHELIA_CONFIG_FILTERS: template`;
   - configurator: set `CONFIG_FILTERS: template` (validation must see the files exactly as
     Authelia does).
5. Restart both. Open **Keys**: the keys appear with their roles.

The template filter processes *every* configuration file. If another file of yours contains
literal `{{`, escape it before turning the filter on (see Authelia's "Filters" documentation).
While the filter is on, the configurator refuses to apply a draft whose rules, notes or clients
contain `{{` or `}}`: Authelia would evaluate them, and templates can read files and environment
variables.

The key files are mode 600: Authelia and the configurator must run as the **same user** (the
production example runs both as `AUTHELIA_UID:AUTHELIA_GID`), or Authelia cannot read a key the
configurator generated and the step is rolled back.

`managed/secrets/` is excluded from git on both new and existing repositories
(`.gitignore` and `.git/info/exclude`). **Back it up separately** (it is not in the managed
repository's history): without a key file Authelia cannot start.

## Rotation

| Step | What happens | When |
|---|---|---|
| 1. Add a new key | Authelia generates it; it is added *second*: published, not signing | any time |
| 2. Make it sign | the new key moves first | after apps refreshed their key set: a day is typical |
| 3. Remove the old key | its entry and then its file are removed | after the longest lifetime of tokens signed by it |

Each step is a normal safe apply: validate (with the key files in place), write, commit
(`OIDC keys: ...`), restart Authelia, wait until healthy, then check that the live `/jwks.json`
lists exactly the expected key ids. Any mismatch rolls the step back and restores the previous
file. The old private key file is deleted only after step 3 succeeded, so a rollback never points
at a missing file. Everyone is signed out once per step (Authelia restarts).

A rolled-back step on the History page is labelled; "Revert to this" is not offered for key
commits (a revert could point at a deleted file): use the steps instead.

## Certificates

The Keys page also lists certificate expiry: the `certificate_chain` of each signing key (when
present) and the live TLS certificates of `AUTH_DOMAIN` and `CONFIGURATOR_DOMAIN` (override with
`CERT_CHECK_HOSTS=host[:port],...`, empty disables it). `CERT_WARN_DAYS` (default 21) sets when a
banner appears; one notification is sent per certificate and threshold (21/7/0 days).
The live check only reads what the server presents: it never trusts it.
