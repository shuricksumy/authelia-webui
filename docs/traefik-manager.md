# Traefik Manager (optional add-on)

[Traefik Manager](https://github.com/chr0nzz/traefik-manager) is a web UI for Traefik's **file
provider**: it adds and edits routers, middlewares and services in a dynamic config file, and
Traefik hot-reloads the file. It is a separate project; this page shows how to run it next to the
configurator with the same trust model. Everything here was checked against Traefik Manager
**1.15.2** and Traefik 3.7.

It can change who reaches what, so treat it like the configurator: VPN-only entrypoint, Authelia
in front, its own login on top, no Docker socket.

## How it talks to Traefik

```
browser -> Traefik (internal :8443, Authelia) -> traefik-manager:5000
traefik-manager --GET--> 172.30.0.2:8081/api   (tmapi entrypoint, IP allow-listed, read-only)
traefik-manager --write--> traefik/dynamic/dynamic.yml   (Traefik watches the folder)
```

- **Reads** Traefik's state from its API. The `tmapi` entrypoint is not published, and the router
  on it only answers Traefik Manager's fixed address.
- **Writes** one dynamic file. It saves through a temp file next to it and a rename, so it needs
  the **folder** mounted read-write; a single-file bind mount cannot be renamed over. Traefik
  ignores the temp files (`*.yml.tmp.<pid>.<n>`).
- **No restart, no static config, no socket.** Dynamic changes need no restart. Traefik Manager
  can restart Traefik only for static-config edits, through a Docker socket proxy; this add-on
  leaves that out on purpose (see [Static config](#static-config)).

## Setup (production example)

The production example's Traefik already loads a folder (`traefik/dynamic/`) and has the `tmapi`
entrypoint and the API without a dashboard. Nothing listens there until you add the add-on's file.

```sh
cd examples/production            # or your copy of it
cp traefik-manager/traefik-manager.yml traefik/dynamic/   # then replace example.com in it
mkdir -p traefik-manager/config traefik-manager/backups
sudo chown -R 1000:1000 traefik/dynamic traefik-manager   # TM_UID/TM_GID in .env if not 1000
docker compose -f compose.yml -f compose.traefik-manager.yml config -q
docker compose -f compose.yml -f compose.traefik-manager.yml up -d
docker compose logs traefik-manager | grep -i password     # one-time password for the first login
```

In the configurator, add a rule above any catch-all (its address is only reachable over the VPN,
like `authcfg`):

```yaml
- domain: tm.example.com
  networks: [vpn]
  subject: 'group:admin'   # or a dedicated group
  policy: two_factor
- domain: tm.example.com
  policy: deny
```

Open `https://tm.example.com:8443`. In the setup wizard the Traefik API URL is
`http://172.30.0.2:8081` (Traefik's fixed address; see the CrowdSec note below for why not the name). **Skip the "Self route" step**: the route already exists in
`traefik-manager.yml`, and the wizard writes a second router whose rule includes the scheme
(``Host(`https://tm.example.com`)``), which never matches. If that were "fixed" by hand it would
be a second router for the same host **without Authelia**, with equal priority.

`traefik-manager.yml` lives outside the file Traefik Manager edits (`CONFIG_PATH` is `dynamic.yml`),
so the UI cannot remove its own Authelia middleware or widen its API allow-list. It shows those two
routers under **File (external)**, read-only; that is expected.

## Existing setup with Docker labels

Same idea when Traefik uses the Docker provider and is configured by CLI flags. The pieces:

```yaml
# Traefik: a folder for the file provider and an unpublished entrypoint for the API
command:
  - --providers.file.directory=/etc/traefik/dynamic   # was --providers.file.filename=...
  - --providers.file.watch=true
  - --entryPoints.tmapi.address=:8081                 # NOT in ports:
volumes:
  - ./data/traefik/dynamic:/etc/traefik/dynamic:ro    # move your rules file in here
labels:
  - "traefik.http.routers.tm-api.rule=PathPrefix(`/api`)"
  - traefik.http.routers.tm-api.entryPoints=tmapi
  - traefik.http.routers.tm-api.service=api@internal
  - traefik.http.routers.tm-api.middlewares=tm-api-only
  - traefik.http.middlewares.tm-api-only.ipallowlist.sourcerange=${IP_TM}/32

# traefik-manager: hardened like compose.traefik-manager.yml, plus
environment:
  TRAEFIK_API_URL: http://${IP_TRAEFIK}:8081   # Traefik's fixed address, not its name
  CONFIG_DIR: /app/dynamic        # or CONFIG_PATH for one file (see "File (external)" below)
  CERT_RESOLVER: none             # when certificates come from files, not ACME
  TRUSTED_PROXIES: ${IP_TRAEFIK}/32
networks:
  proxy: {ipv4_address: "${IP_TM}"}
labels:
  - traefik.http.routers.tm.rule=Host(`tm.example.com`)
  - traefik.http.routers.tm.middlewares=authelia@docker
  - traefik.http.services.tm.loadbalancer.server.port=5000
```

Routes you add in the UI that need Authelia must reference `authelia@docker`: the middleware is
defined by labels, not in the file.

## Optional tabs

**Certs.** With ACME it reads `acme.json` (`ACME_JSON_PATH`, default `/app/acme.json`). That file
holds the **private keys** of every certificate, so think twice before mounting it. Without ACME it
reads the `certFile` of each entry in `tls.certificates` of the files it manages, **at the path
written there**, so mount the certificate at the same path Traefik sees it, certificate only:
`./crt/cert.crt:/etc/mycrt/cert.crt:ro`. It does not read `tls.stores.*.defaultCertificate`; list
the same certificate under `tls.certificates` too (harmless: those join the default store).
"acme.json not mounted" only means it found no certificate at all.

**Logs.** It only tails a file (`ACCESS_LOG_PATH`, default `/app/logs/access.log`), never
`docker logs`. Traefik writes the access log to a file *or* stdout, not both:

```yaml
accessLog:
  filePath: /logs/access.log
  format: json          # host, router, service and timings; the common format has none of them
```

Mount the log **folder** read-only (logrotate replaces the file), rotate it on the host and send
Traefik `USR1` afterwards. To keep `docker logs`, a sidecar can follow the file:
`busybox tail -n 0 -F /logs/access.log` with `network_mode: none`.

**Static config.** The Plugins tab and the static view need the static config as a **file**
(`STATIC_CONFIG_PATH`); a Traefik configured only by CLI flags has none (Traefik reads a file *or*
flags, never both). Mounted read-only, it works but Traefik Manager shows a permanent "Storage is
not writable" banner (its write check covers every path it knows; settings and backups are fine).
Do **not** mount it read-write when Traefik has the Docker socket: plugins in
`experimental.plugins` are code Traefik downloads and runs, so write access to the static config
plus a restart is the host. Leaving `STATIC_CONFIG_PATH` unset is the simplest choice.

**CrowdSec** (with [docs/hardening.md](hardening.md)): step by step in
[Connecting Traefik, Traefik Manager and CrowdSec](hardening.md#7-connecting-traefik-traefik-manager-and-crowdsec).
In short: Traefik Manager gets its **own** bouncer key (`cscli bouncers add traefik-manager`),
LAPI URL `http://crowdsec:8080`, and the `crowdsec` network (`compose.traefik-manager.crowdsec.yml`). A bouncer key shows the bans in force. Alerts (scenario, path, user agent)
need a machine login, which can also create and delete bans; if you want it, print the
credentials with `cscli machines add traefik-manager --auto -f -`. Without `-f -` the command
targets CrowdSec's own credentials file (and `--force` would overwrite its agent login).

Once Traefik Manager shares two networks with Traefik (e.g. `edge` and `crowdsec`), the name
`traefik` may resolve to either address and the API allow-list rejects it at random ("No object
list for: middlewares"). Use Traefik's fixed address in the API URL, and change it in Settings
too: `TRAEFIK_API_URL` only seeds the setting on the first start.

## Embedding in a dashboard

Traefik Manager hard-codes `X-Frame-Options: DENY`. To show it in a frame, remove the header and
allow only your dashboard, in a headers middleware on its router:

```yaml
tm-frame:
  headers:
    customResponseHeaders: {X-Frame-Options: ""}   # an empty value removes the header
    contentSecurityPolicy: "frame-ancestors 'self' https://home.example.com"
```

## Login through Authelia (OIDC)

Instead of its own password, Traefik Manager can log in with Authelia. In the configurator add a
client from the **Generic** preset: redirect URI `https://tm.example.com:8443/auth/oidc/callback`,
scopes `openid profile email groups`, `token_endpoint_auth_method: client_secret_post` (it tries
post first and uses PKCE S256). Then:

```yaml
OIDC_ENABLED: "true"
OIDC_PROVIDER_URL: https://auth.example.com
OIDC_CLIENT_ID: traefik-manager
OIDC_CLIENT_SECRET: ${TM_OIDC_CLIENT_SECRET}
OIDC_REDIRECT_URI: https://tm.example.com:8443/auth/oidc/callback
OIDC_ALLOWED_GROUPS: admin          # empty allow-lists deny everyone
OIDC_AUTO_LOGIN: "true"
```

The `OIDC_*` variables only seed `manager.yml` on the first start; later changes go in its
Settings. Traefik Manager calls the issuer itself, so it must trust the portal's certificate (a
private CA needs `REQUESTS_CA_BUNDLE`). Keep `AUTH_ENABLED` on: with it off, any container on the
same network could reach port 5000 directly, past Authelia.

## Things that look wrong but are not (and some that are)

- **File (external)** lists file-provider routers that are not in Traefik Manager's file. With
  `CONFIG_DIR` and several files, 1.15.2 counts only the alphabetically **first** file as its own
  (`/api/manager/router-names` reads `CONFIG_PATH` only), so routers in the others show there
  although the Routes tab edits them. One file per instance avoids it.
- A router **without `entryPoints`** is attached to every entrypoint, plain-HTTP TCP ports
  included, and Traefik reports one copy per entrypoint (`websecure-<name>`), so it shows as
  external too. Give every router its entry points.
- Saving rewrites the YAML: comments and ordering may move. A backup is made before every change;
  keep hand-written files that must stay byte-identical out of `CONFIG_PATH`/`CONFIG_DIR`.
- Top-level keys other than `http`, `tcp`, `udp` and `tls` do nothing in a dynamic file (an
  `accessLog:` block there is static config). YAML has no references by name: an `ipAllowList`
  needs the CIDR list itself, Traefik rejects a word such as `internalIPs` as an invalid CIDR.
