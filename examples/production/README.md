# Production-like example

A complete stack: **Traefik** (HTTPS with Let's Encrypt, plus a VPN-only entrypoint) in front of
**Authelia** (sessions in **Redis**, signing keys as files), the **Authelia Configurator** with its
**socket proxy**, and a demo app (`whoami`).
Replace `example.com` everywhere with your domain. Migrating an existing Authelia instead? Follow
[`docs/migration.md`](../../docs/migration.md) and borrow from these files.

```
compose.yml                 services, networks, hardening
production.env.example      -> .env (domain, versions, VPN, secrets for the configurator)
traefik/traefik.yml         static config: entrypoints web / websecure / internal, ACME
traefik/dynamic.yml         routers: auth (public), authcfg (VPN only), whoami (demo)
authelia/configuration.example.yml        -> authelia/configuration.yml (your secrets)
authelia/managed/*.example.yml            -> authelia/managed/*.yml (starting rules, client, user,
                                             signing-key list; the key itself goes in managed/secrets/)
logrotate/authelia          host-side rotation of Authelia's log
```

## 1. Files and secrets

```sh
cp production.env.example .env
cp authelia/configuration.example.yml authelia/configuration.yml && chmod 600 authelia/configuration.yml
for f in access_control oidc_clients users oidc_jwks; do cp authelia/managed/$f.example.yml authelia/managed/$f.yml; done
mkdir -p authelia/logs redis letsencrypt authelia/managed/secrets/jwks
chmod 700 authelia/managed/secrets authelia/managed/secrets/jwks
```

Generate each secret with the Authelia binary of the version you run (`V=4.39.28`):

```sh
docker run --rm authelia/authelia:$V authelia crypto rand --length 64 --charset alphanumeric
#  -> jwt_secret, session secret, storage encryption_key, oidc hmac_secret (one run each)
docker run --rm --user 1000:1000 -v "$PWD/authelia/managed/secrets/jwks:/keys" authelia/authelia:$V \
  authelia crypto pair rsa generate --bits 2048 --directory /keys \
  --file.private-key main.pem --file.public-key main.pub.pem
rm authelia/managed/secrets/jwks/main.pub.pem && chmod 600 authelia/managed/secrets/jwks/main.pem
#  -> the OIDC signing key, named by managed/oidc_jwks.yml (never in git; back it up)
docker run --rm -it -v "$PWD/authelia:/config:ro" authelia/authelia:$V \
  authelia crypto hash generate --config /config/configuration.yml
#  -> the first admin's password hash for authelia/managed/users.yml
```

In `.env`: `APP_SECRET_KEY` = `openssl rand -base64 48`, `REDIS_PASSWORD` = `openssl rand -base64 32`.
Then give the files to the user the containers run as: `sudo chown -R 1000:1000 authelia redis`.

## 2. Networks and the client address

The configurator only opens for clients in `VPN_CIDR`, and it reads the client address from
Traefik's `X-Forwarded-For`. Traefik must therefore see the **real** client address:

- The `internal` entrypoint is published on `VPN_ADDRESS` only, so it is unreachable from the
  internet even if a router is misconfigured.
- Docker's published ports keep the source address for traffic arriving from other hosts. If your
  setup NATs it (userland proxy, some VPN containers), run Traefik with `network_mode: host`
  and update `TRUSTED_PROXY_CIDRS`.
- Test it from outside the VPN: the configurator must answer **403** there, even after login.
- A refused request shows **"Your address as seen here"**, and after login the status bar shows
  **you: …**. If that is a gateway's address rather than your device's (a VPN container that
  NATs), allow exactly that `/32` in `VPN_CIDR`, never a whole Docker subnet or its `.1`.
- The configurator's hostname must reach Traefik **directly** (VPN/LAN), not through a CDN proxy
  such as Cloudflare's orange cloud: through a proxy Traefik only ever sees the proxy's address.

## 3. Start

```sh
docker compose config -q && docker compose up -d
docker compose logs -f authelia configurator
```

Open `https://authcfg.example.com:8443` over the VPN, sign in as the first admin (register TOTP
when asked; the code arrives in `authelia/notification.txt` until SMTP is set up), then:

1. **Users**: create real users, then disable or delete the first `admin` once another admin exists.
2. **OIDC Clients**: add your apps from the presets, delete `placeholder`.
3. **Access tests**: add a few "must stay public / must need 2FA" checks.
4. **Rules**: add your apps; apply. Every apply is validated, committed and rolled back if
   Authelia does not come back healthy.

## Log rotation

Authelia's log grows without limit. Rotate it on the **host**: copy `logrotate/authelia` to
`/etc/logrotate.d/authelia`, set the path of `authelia/logs/authelia.log` and your container name,
and test with `sudo logrotate --debug /etc/logrotate.d/authelia`. Authelia reopens the file on
`SIGHUP`, so nothing is lost. The configurator only reads: its **Logs** page shows the live file
and the rotated copies (`.1`, `.2.gz`, ...).

## Notes

- Sessions are in Redis, so the restart every apply needs signs nobody out. User changes do not
  restart anything at all.
- **Backups**: History -> Backup downloads `managed/` with its git history and the private key
  files (which are not in git). Back up `authelia/configuration.yml` with the host, too.
- **Signing keys**: rotate them on the Keys page (add a new key, make it sign, remove the old one);
  each step is a safe apply. Certificate expiry of your TLS certificates is shown there as well.
- **Emergency access** when Authelia is down: `EMERGENCY_PORT` + `EMERGENCY_PASSWORD_HASH`
  (`docs/emergency.md`).
- **Hand edits** of files in `managed/` are fine: the configurator commits them as "External
  change" on the next page load. Edit as the containers' user, not root.
- Upgrading Authelia: change `AUTHELIA_VERSION` once; both images follow it. The configurator
  refuses to apply while the running and bundled versions differ.
