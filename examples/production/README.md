# Production-like example

A complete stack: **Traefik** (HTTPS with Let's Encrypt, plus a VPN-only entrypoint) in front of
**Authelia**, the **Authelia Configurator** with its **socket proxy**, and a demo app (`whoami`).
Replace `example.com` everywhere with your domain. Migrating an existing Authelia instead? Follow
[`docs/migration.md`](../../docs/migration.md) and borrow from these files.

```
compose.yml                 services, networks, hardening
production.env.example      -> .env (domain, versions, VPN, secrets for the configurator)
traefik/traefik.yml         static config: entrypoints web / websecure / internal, ACME
traefik/dynamic.yml         routers: auth (public), authcfg (VPN only), whoami (demo)
authelia/configuration.example.yml        -> authelia/configuration.yml (your secrets)
authelia/managed/*.example.yml            -> authelia/managed/*.yml (starting rules, client, user)
```

## 1. Files and secrets

```sh
cp production.env.example .env
cp authelia/configuration.example.yml authelia/configuration.yml && chmod 600 authelia/configuration.yml
for f in access_control oidc_clients users; do cp authelia/managed/$f.example.yml authelia/managed/$f.yml; done
touch authelia/authelia.log && mkdir -p letsencrypt
```

Generate each secret with the Authelia binary of the version you run (`V=4.39.28`):

```sh
docker run --rm authelia/authelia:$V authelia crypto rand --length 64 --charset alphanumeric
#  -> jwt_secret, session secret, storage encryption_key, oidc hmac_secret (one run each)
docker run --rm -v "$PWD/keys:/keys" authelia/authelia:$V \
  authelia crypto pair rsa generate --bits 2048 --directory /keys
#  -> paste keys/private.pem into jwks[0].key (keep the indentation), then delete keys/
docker run --rm -it -v "$PWD/authelia:/config:ro" authelia/authelia:$V \
  authelia crypto hash generate --config /config/configuration.yml
#  -> the first admin's password hash for authelia/managed/users.yml
```

`APP_SECRET_KEY` in `.env`: `openssl rand -base64 48`.

## 2. Networks and the client address

The configurator only opens for clients in `VPN_CIDR`, and it reads the client address from
Traefik's `X-Forwarded-For`. Traefik must therefore see the **real** client address:

- The `internal` entrypoint is published on `VPN_ADDRESS` only, so it is unreachable from the
  internet even if a router is misconfigured.
- Docker's published ports keep the source address for traffic arriving from other hosts. If your
  setup NATs it (userland proxy, some VPN containers), run Traefik with `network_mode: host`
  and update `TRUSTED_PROXY_CIDRS`.
- Test it from outside the VPN: the configurator must answer **403** there, even after login.

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

## Notes

- Sessions live in memory unless you add Redis: every apply restarts Authelia and signs everyone
  out once. User changes do not restart anything.
- Keep `authelia/managed/` in your backups: it is a local git repository with the full history
  (and password hashes). Never push it anywhere.
- Upgrading Authelia: change `AUTHELIA_VERSION` once; both images follow it. The configurator
  refuses to apply while the running and bundled versions differ.
