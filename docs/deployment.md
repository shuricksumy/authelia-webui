# Deployment, step by step

From an empty server to the full stack: Traefik, Authelia, the configurator, and optionally
Traefik Manager, CrowdSec and Cloudflare in front. Each phase ends with a check; do not start the
next one before it passes. Phases 4 to 8 are optional and can be added later, in this order.

| Phase | Gives you | Details |
|---|---|---|
| 1. Base stack | Traefik, Authelia, configurator (VPN-only) | [`examples/production/README.md`](../examples/production/README.md) |
| 2. First login | users, OIDC clients, rules, access tests | same |
| 3. Log rotation | logs that do not fill the disk | this page |
| 4. Traefik Manager | routes edited in a browser | [`traefik-manager.md`](traefik-manager.md) |
| 5. CrowdSec | automatic bans of scanners and brute force | [`hardening.md`](hardening.md) §2 |
| 6. Traefik Manager ↔ CrowdSec | bans and attacks in Traefik Manager | [`hardening.md`](hardening.md) §7 |
| 7. Cloudflare in front | real client IPs, WAF, origin locked to Cloudflare | [`hardening.md`](hardening.md) §1, §4 |
| 8. Login throttling per IP | Authelia bans per address too | [`hardening.md`](hardening.md) §3 |

Replace `example.com` with your domain everywhere. Commands run in the stack folder
(`/opt/authelia-stack` here, a copy of `examples/production/`).

## 0. Before you start

- A Linux server with Docker Engine and the Compose plugin (`docker compose version`), `jq`, and
  for phase 7 `ipset` and `curl`.
- A VPN (e.g. WireGuard) with a fixed address on this server (`VPN_ADDRESS`) and a client range
  (`VPN_CIDR`). The configurator and Traefik Manager are only reachable through it.
- DNS: `auth.example.com` public (the login portal), `authcfg.example.com` and
  `tm.example.com` resolvable from the VPN only (split DNS or the hosts file), never published.

```sh
sudo mkdir -p /opt/authelia-stack && sudo chown "$USER" /opt/authelia-stack
cp -r examples/production/. /opt/authelia-stack/
cp -r examples/hardening /opt/authelia-stack/hardening   # used from phase 5 on
cd /opt/authelia-stack
```

**One command for every phase.** Compose reads `COMPOSE_FILE` from `.env`, so add each add-on's
file there when you reach its phase and keep typing plain `docker compose`:

```sh
# phase 1:   COMPOSE_FILE=compose.yml
# phase 4:   COMPOSE_FILE=compose.yml:compose.traefik-manager.yml
# phase 5:   COMPOSE_FILE=compose.yml:compose.traefik-manager.yml:compose.crowdsec.yml
# phase 6:   COMPOSE_FILE=compose.yml:compose.traefik-manager.yml:compose.crowdsec.yml:compose.traefik-manager.crowdsec.yml
```

(Without Traefik Manager, leave its two files out.)

## 1. Base stack

Follow sections 1 to 3 of [`examples/production/README.md`](../examples/production/README.md):
`.env`, `authelia/configuration.yml`, the managed files, the secrets (generated with the Authelia
binary), ownership (`sudo chown -R 1000:1000 authelia redis`), then:

```sh
echo "COMPOSE_FILE=compose.yml" >> .env
docker compose config -q && docker compose up -d
docker compose ps                     # all running; socket-proxy healthy
docker compose logs authelia | tail   # no errors
```

**Check:**
- `https://auth.example.com` shows the Authelia login (from anywhere).
- Over the VPN, `https://authcfg.example.com:8443` asks for the login.
- **Outside the VPN**, the same address answers **403** even after login. If not, stop here and
  read section 2 of the production README (client addresses).

## 2. First login and configuration

Sign in over the VPN as the first admin (the 2FA registration code arrives in
`authelia/notification.txt` until SMTP is set up), then in the configurator, as the production
README lists: real users (then retire the first `admin`), OIDC clients from the presets, access
tests ("must stay public", "must need 2FA") and your rules. Every apply is validated, committed and
rolled back automatically if Authelia does not come back healthy.

**Check:** History lists your applies; the access tests pass.

## 3. Log rotation

Authelia's log grows without limit. Edit the path in the repo file, then install it:

```sh
sudo cp logrotate/authelia /etc/logrotate.d/authelia
sudo logrotate --debug /etc/logrotate.d/authelia     # no "error"
```

logrotate only allows comments on their own line; a comment after a directive makes it skip the
whole block. Check every file in `/etc/logrotate.d/` with
`sudo logrotate --debug /etc/logrotate.conf 2>&1 | grep -E '^error'` (expected: nothing).

## 4. Traefik Manager (optional)

A web UI for `traefik/dynamic/dynamic.yml`, VPN-only, behind Authelia, no Docker socket.

```sh
cp traefik-manager/traefik-manager.yml traefik/dynamic/    # then replace example.com in it
mkdir -p traefik-manager/config traefik-manager/backups traefik-manager/vendor
# the image ships these two root-only (empty Route Map, no 2FA QR code as uid 1000): readable copies
for f in dagre.min.js qrcode.min.js; do
  docker run --rm --entrypoint cat ghcr.io/chr0nzz/traefik-manager:1.15.2 /app/static/vendor/$f > traefik-manager/vendor/$f
done
chmod 644 traefik-manager/vendor/*.js
sudo chown -R 1000:1000 traefik/dynamic traefik-manager
sed -i 's/^COMPOSE_FILE=.*/COMPOSE_FILE=compose.yml:compose.traefik-manager.yml/' .env
docker compose config -q && docker compose up -d
docker compose logs traefik-manager | grep -i password      # one-time password, first login
```

In the configurator, add a rule above any catch-all (VPN, admin group, 2FA) and a deny rule for
`tm.example.com`, as in [`traefik-manager.md`](traefik-manager.md#setup-production-example).
Open `https://tm.example.com:8443`; in the wizard the Traefik API URL is `http://172.30.0.2:8081`
(an address, not a name) and **skip "Self route"**.

**Check:**

```sh
docker compose exec traefik-manager wget -qO- http://172.30.0.2:8081/api/version   # JSON
docker compose exec traefik-manager sh -c 'cat /app/static/vendor/dagre.min.js >/dev/null && echo readable'
```

When adding routes in the UI, pick the **authelia** chip (the file middleware) first. Never
reference Authelia only through Docker labels in routes Traefik Manager edits: saving such a route
drops it ([`traefik-manager.md`](traefik-manager.md#existing-setup-with-docker-labels)).

## 5. CrowdSec (optional)

Bans addresses that probe or brute-force, plus a community blocklist; enforced by a plugin in
Traefik on every router. Fails open: if CrowdSec stops, sites stay up.

**5.1 Key, folders, files.** Traefik runs as root with `cap_drop: ALL`, so it reads a mode-600
file and writes a folder **only if root owns them**: create them with `sudo`.

```sh
KEY=$(openssl rand -hex 32); echo "CROWDSEC_BOUNCER_KEY=$KEY" >> .env
printf '%s' "$KEY" | sudo tee traefik/crowdsec-bouncer.key >/dev/null; unset KEY
sudo chown root:root traefik/crowdsec-bouncer.key && sudo chmod 600 traefik/crowdsec-bouncer.key
sudo mkdir -p crowdsec/config crowdsec/data logs/traefik
cp hardening/acquis.yaml crowdsec/acquis.yaml
cp hardening/security.yml traefik/dynamic/security.yml
```

In `traefik/dynamic/security.yml`, set `clientTrustedIPs` to your VPN and LAN ranges (never
banned). Leave the `192.0.2.0/24` placeholder as it is until phase 7.

**5.2 Traefik static config** (`traefik/traefik.yml`). Three edits:

Replace `accessLog: {}` with:

```yaml
accessLog:
  filePath: /var/log/traefik/access.log
  format: json
```

Under `entryPoints:`, make `websecure` read:

```yaml
  websecure:
    address: ":443"
    http:
      middlewares: # before every router on this entry point, so before Authelia
        - realip@file
        - crowdsec@file
      aliasHeadersStrategy: delete
```

Append at the end of the file:

```yaml
experimental:
  plugins:
    bouncer:
      moduleName: github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin
      version: v1.8.1
    realip:
      moduleName: github.com/xethlyx/traefik-real-ip
      version: v1.0.4
```

**5.3 Start CrowdSec first, then Traefik.**

```sh
sed -i 's/^COMPOSE_FILE=.*/&:compose.crowdsec.yml/' .env      # appends the add-on
docker compose config -q && docker compose up -d crowdsec
sleep 30
docker compose exec crowdsec cscli lapi status                 # "successfully interact"
docker compose exec crowdsec cscli metrics show acquisition    # lines read appear after traffic
docker compose up -d --force-recreate traefik                  # static config: read at start only
```

**5.4 Log rotation for the access log.** Edit the path, then:

```sh
sudo cp logrotate/traefik-access /etc/logrotate.d/traefik-access
sudo logrotate --debug /etc/logrotate.d/traefik-access
```

**Check:**

```sh
docker compose exec crowdsec cscli bouncers list   # "traefik": Last API pull filled in (open a site once)
docker compose exec crowdsec cscli metrics show acquisition   # access.log and authelia.log: read > 0
```

Then the real test, from a phone on **mobile data** (not the VPN, not your Wi-Fi), whose address
you look up on any "what is my IP" page:

```sh
docker compose exec crowdsec cscli decisions add --ip <phone-ip> --duration 5m
# within ~60 s every site answers 403 on the phone
docker compose exec crowdsec cscli decisions delete --ip <phone-ip>
```

If `cscli bouncers list` shows no pull for `traefik`: the log level `ERROR` hides plugin loading,
ask the API instead (phase 4's check URL with `/api/http/middlewares/crowdsec@file`):
`"status":"enabled"` lists the routers it guards; `"disabled"` names the error. If
`authelia.log` is missing from the metrics, `docker compose logs crowdsec | grep -i denied`.

## 6. Traefik Manager ↔ CrowdSec (optional)

```sh
sed -i 's/^COMPOSE_FILE=.*/&:compose.traefik-manager.crowdsec.yml/' .env
docker compose up -d traefik-manager
docker compose exec crowdsec cscli bouncers add traefik-manager       # key, shown once
```

In Traefik Manager, **Settings → System Monitoring → CrowdSec**: LAPI URL `http://crowdsec:8080`,
API Key = that key. For the attack details (scenarios, paths, attackers) also a machine login,
printed rather than written (see [`hardening.md`](hardening.md#7-connecting-traefik-traefik-manager-and-crowdsec)
for why `-f -` matters):

```sh
docker compose exec crowdsec cscli machines add traefik-manager --auto -f -
```

`login` → Machine ID, `password` → Machine Password. **Check:** the CrowdSec tab shows no red
error; `cscli bouncers list` and `cscli machines list` list `traefik-manager`.

## 7. Cloudflare in front (optional)

Order matters: real client IPs first, then the origin lock.

**7.1 Proxy every public hostname** (orange cloud) in Cloudflare's DNS. Keep `authcfg` and `tm`
off Cloudflare's DNS (VPN only).

**7.2 Trust Cloudflare for X-Forwarded-For, with realip.** Fill Cloudflare's ranges into the two
placeholders (`security.yml` and the static config) and add `forwardedHeaders` to `websecure`:

```sh
CF=$(curl -fsS https://www.cloudflare.com/ips-v4) && [ "$(echo "$CF" | wc -l)" -ge 10 ]
LIST=$(echo "$CF" | sed 's/^/            - /')
awk -v l="$LIST" '/- 192\.0\.2\.0\/24 # PLACEHOLDER/{print l; next} {print}' \
  traefik/dynamic/security.yml > /tmp/security.yml && sudo cp /tmp/security.yml traefik/dynamic/security.yml
FLOW=$(echo "$CF" | sed 's/.*/"&"/' | paste -sd, -)
sed -i "s#^  websecure:\$#  websecure:\n    forwardedHeaders:\n      trustedIPs: [$FLOW] \# Cloudflare only, ALWAYS with realip@file#" traefik/traefik.yml
grep -c PLACEHOLDER traefik/dynamic/security.yml      # 0: the ranges are in
grep -n -A1 'forwardedHeaders' traefik/traefik.yml   # the Cloudflare list under websecure
docker compose up -d --force-recreate traefik
```

Never keep `forwardedHeaders` without `realip@file` first in the middlewares: Authelia reads the
leftmost `X-Forwarded-For`, and a visitor could pose as a VPN address (details in
[`hardening.md`](hardening.md#1-the-real-client-address-read-this-first-if-a-cdn-is-in-front)).

**Check:** from the phone on mobile data open a missing page on one of your hosts, then

```sh
tail -n 1 logs/traefik/access.log | jq -r '[.ClientHost, .RouterName] | @tsv'   # the phone's IP, not 162.158.x/172.64-71.x/104.16-31.x
```

**7.3 Cloudflare dashboard** (free plan): the WAF rule for obvious scanners, a country rule for
hosts that cannot sit behind Authelia, a rate limit on `/api/firstfactor` and
`/api/secondfactor` of the portal host, Bot Fight Mode ([`hardening.md`](hardening.md#4-behind-cloudflare)).

**7.4 Only Cloudflare may reach 80/443.** Without it, anyone using the server's address skips
everything above.

```sh
sudo apt install ipset
sudo hardening/cloudflare-only.bash show      # interface and rule, changes nothing
sudo hardening/cloudflare-only.bash apply
sudo hardening/cloudflare-only.bash status    # `remove` undoes it
```

Keep it across reboots and refresh the ranges weekly with the systemd unit and timer at the end of
the script. **Check:** sites still open on the phone; `curl -m 5 -kI https://<server-ip>` from
another network now times out.

## 8. Login throttling per address

Only once Authelia sees real client addresses (no CDN, or phase 7.2 done). In
`authelia/configuration.yml`:

```yaml
regulation:
  modes: [user, ip]
  max_retries: 3
  find_time: 10m
  ban_time: 1h
```

`docker compose restart authelia`. **Check:** three wrong passwords for one user from the phone
lock that user and that address for an hour; your VPN session is unaffected.

## Final checklist

```sh
docker compose ps                                             # all up; proxies healthy
docker compose exec crowdsec cscli bouncers list              # recent pulls
docker compose exec crowdsec cscli metrics show acquisition   # both logs read
sudo logrotate --debug /etc/logrotate.conf 2>&1 | grep -E '^error'   # nothing
ls -l traefik/traefik.yml traefik/crowdsec-bouncer.key        # 644 and 600, not world-writable
```

- Outside the VPN, `authcfg` and `tm` answer 403.
- Every router without Authelia in front is one you chose (see [`hardening.md`](hardening.md)).

## Rolling back a phase

| Phase | Undo |
|---|---|
| 4 | remove its file from `COMPOSE_FILE`, `docker compose up -d --remove-orphans`, delete `traefik/dynamic/traefik-manager.yml` |
| 5 | restore `traefik/traefik.yml`, delete `traefik/dynamic/security.yml`, remove the file from `COMPOSE_FILE`, `docker compose up -d --remove-orphans --force-recreate traefik` |
| 6 | remove its file from `COMPOSE_FILE`; `cscli bouncers delete traefik-manager`, `cscli machines delete traefik-manager` |
| 7 | `sudo hardening/cloudflare-only.bash remove`; delete `forwardedHeaders` (never realip alone first) |
| 8 | drop `ip` from `regulation.modes` |

Keep a copy of `traefik/traefik.yml` before phases 5 and 7 (`cp traefik/traefik.yml ~/traefik.yml.bak`).

## Day to day

- **Who is banned, and why:** `cscli decisions list`, `cscli alerts list`,
  `cscli alerts inspect <id> -d`. Unban: `cscli decisions delete --ip <ip>`.
- **Upgrades:** change `AUTHELIA_VERSION` once (both images follow; the configurator refuses to
  apply while versions differ). Traefik, CrowdSec and the plugins are pinned on purpose: bump
  them deliberately and re-run the checks of their phase.
- **Backups:** History → Backup in the configurator (managed files, history, private keys), plus
  `authelia/configuration.yml`, `.env` and `traefik/` from the host.
- **Cloudflare ranges** change rarely; the weekly timer of phase 7.4 refreshes the origin lock,
  the two YAML lists you refresh by repeating 7.2.
