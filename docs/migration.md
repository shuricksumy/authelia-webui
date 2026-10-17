# Migrating an existing Authelia to the configurator

This moves the `access_control:` block and the OIDC clients out of your hand-edited
`configuration.yml` into files the configurator owns. Your main file stays hand-edited and is
mounted read-only. Nothing is lost: the script only moves text, and it checks that the merged
result is the same configuration.

Expect about 20 minutes. Do it from a shell on the Docker host, not through the UI.

## 1. Back up

```sh
cp -a authelia authelia.backup-$(date +%F)
```

Keep the backup until you have done step 6 successfully.

## 2. Split the configuration (from the image)

The image contains the script and the exact Authelia binary, so nothing else needs installing.
Use the tag that matches the Authelia version you run (`authelia-<version>`):

```sh
mkdir -p work && cp authelia/configuration.yml work/
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD/work:/work" \
  ghcr.io/OWNER/authelia-configurator:authelia-4.39.28 \
  python -m scripts.split_config --config /work/configuration.yml --out /work/out
```

The output directory must not exist yet. The script validates the original and the split result
with the bundled Authelia binary and prints both summaries. It writes into `work/out/`:

| File | Content |
|---|---|
| `configuration.yml` | your main file without `access_control` and OIDC clients |
| `managed/access_control.yml` | the whole `access_control:` block, comments and quoting untouched |
| `managed/oidc_clients.yml` | `identity_providers.oidc.clients` only |
| `managed/disabled_rules.yml` | commented-out rules, imported so they can be enabled again (`--no-import-disabled` leaves them as comments) |

## 3. Review the result

```sh
diff -u authelia/configuration.yml work/out/configuration.yml
```

The only differences should be the removed blocks. The script refuses to finish if the merged
configuration would differ from the original; read its output if it complains. Comments inside
rules stay with their rule.

## 4. Make sure the configurator rules are in place

Add the rules from [`examples/authelia-rules.example.yml`](../examples/authelia-rules.example.yml)
to `work/out/managed/access_control.yml`, **above any broad catch-all** such as `'*.example.com'`.
The configurator refuses to run applies while they are missing, because without them you could
lock yourself out.

## 5. Wire it up

1. Replace `authelia/configuration.yml` with `work/out/configuration.yml` and copy
   `work/out/managed/` to `authelia/managed/` (owned by the uid the configurator runs as).
2. In the Authelia service set
   `X_AUTHELIA_CONFIG=/config/configuration.yml,/config/managed/access_control.yml,/config/managed/oidc_clients.yml`.
   Lists are *replaced* across files, so each block must live in exactly one file.
3. Add the configurator and the socket proxy from
   [`examples/compose.example.yml`](../examples/compose.example.yml) and the Traefik router from
   [`examples/traefik-dynamic.example.yml`](../examples/traefik-dynamic.example.yml). Bind the
   `internal` entrypoint to your VPN address ([`traefik-static.example.yml`](../examples/traefik-static.example.yml)).
4. `docker compose up -d`. Authelia restarts once with the split files; the behaviour must be
   unchanged. If it does not start, put the backup back (step 1) and read `docker logs authelia`.

## 5b. Let the configurator manage users (optional, Phase 3)

The configurator only writes inside `managed/`. To manage users from the UI, move the users file
there once:

```sh
cp -p authelia/users.yml authelia/managed/users.yml
```

then in `authelia/configuration.yml` set

```yaml
authentication_backend:
  file:
    path: /config/managed/users.yml
    watch: true   # Authelia reloads the file itself: user changes need no restart
```

and give the configurator `USERS_FILE=/config/managed/users.yml` (no separate users mount).
Restart Authelia once. Keep the old `users.yml` as a backup until you have logged in again.
Password resets that Authelia writes itself show up in History as "External change".

## 6. First login and a test apply

1. Open the configurator over the VPN and sign in with 2FA. The page should show your rules.
2. Open **Access tests** and add two or three requests you care about ("my app's API is public",
   "my admin page needs 2FA"). They are checked before every apply and against the real Authelia
   after each restart.
3. Make a harmless change (for example reorder two rules that do not overlap), **Review**, **Apply**.
   Authelia restarts and signs everyone out once; sign in again and the result is shown.
4. Check **History**: you should see the initial import and your apply.

## Lockout recovery

If a bad rule locks you out of the configurator, nothing is lost: the configurator's own rules
are protected, and an apply that makes Authelia unhealthy is rolled back automatically. To recover
by hand, on the Docker host:

```sh
git -C authelia/managed log --oneline        # find the last good commit
git -C authelia/managed revert --no-edit HEAD
docker restart authelia
```

Or restore your backup from step 1.
