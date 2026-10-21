# Hardening the edge (optional)

The production example already keeps the configurator VPN-only, behind Authelia, without the
Docker socket. This page adds the layers in front of everything else: the real client address,
automatic bans, a CDN in front, and the Docker socket out of Traefik. Each part is optional and
independent unless noted. Versions checked: Traefik 3.7.15, Authelia 4.39.28, CrowdSec 1.8.1,
CrowdSec Traefik bouncer 1.8.1, traefik-real-ip 1.0.4.

Files: [`examples/hardening/`](../examples/hardening/) and, for the production example,
[`examples/production/compose.crowdsec.yml`](../examples/production/compose.crowdsec.yml) (plus
`compose.traefik-manager.crowdsec.yml` when Traefik Manager runs too, section 7).

## 1. The real client address (read this first if a CDN is in front)

Authelia takes the client address from the **leftmost** `X-Forwarded-For` entry
(`RequestCtxRemoteIP` in `internal/middlewares/wrap.go`). Behind a CDN, a visitor can send their
own `X-Forwarded-For: 10.8.10.5`; the CDN appends the real address after it. If Traefik trusts
the CDN's forwarded headers and nothing else happens, Authelia sees `10.8.10.5`, and rules with
`networks: [vpn]` can be met **from the internet**. (The configurator itself is not affected: it
walks the chain from the right and stops at the first untrusted address.)

Without a CDN there is nothing to do: Traefik trusts nobody by default and deletes
`X-Forwarded-For` from untrusted clients.

With a CDN, set both of these, never only the first:

1. static `entryPoints.websecure.forwardedHeaders.trustedIPs`: the CDN's ranges, and
2. the `realip` middleware first on the entry point (`traefik-static.snippet.yml`, `security.yml`).
   From a trusted CDN it keeps only the rightmost untrusted address (the real client); from anyone
   else it replaces the header with the TCP address.

Tested with Traefik 3.7.15 and a forward-auth endpoint that records what it receives:

| Request | Authelia receives |
|---|---|
| via the CDN, visitor sends `X-Forwarded-For: 10.8.10.5`, CDN appends `203.0.113.9` | `203.0.113.9, …` |
| direct, visitor sends `X-Forwarded-For: 10.8.10.5` | the TCP address |
| via the CDN, **without** realip | `10.8.10.5, 203.0.113.9, …` (spoofed) |

Cloudflare's ranges: `curl -fsS https://www.cloudflare.com/ips-v4`. The example files carry a
documentation range as placeholder, which fails safe (real addresses are simply not restored).

Check: `jq -r '[.ClientHost, ."request_Cf-Connecting-Ip"] | @tsv' access.log` shows the same
address twice (with `accessLog.fields.headers.names.Cf-Connecting-IP: keep`).

## 2. CrowdSec: automatic bans

[CrowdSec](https://github.com/crowdsecurity/crowdsec) reads Traefik's access log and Authelia's
log, bans addresses that probe (more than 10 different failing paths on one host, sensitive
files, path traversal, known CVE paths) or brute-force Authelia, and adds a community blocklist.
The Traefik [bouncer plugin](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin)
enforces the bans as a `403`. The detection is behavioural: it does not need a list of paths.

**Production example:**

```sh
cd examples/production
KEY=$(openssl rand -hex 32); echo "CROWDSEC_BOUNCER_KEY=$KEY" >> .env
printf '%s' "$KEY" | sudo tee traefik/crowdsec-bouncer.key >/dev/null; unset KEY
# Traefik runs as root with cap_drop ALL: it reads a mode-600 file only if root owns it
sudo chown root:root traefik/crowdsec-bouncer.key && sudo chmod 600 traefik/crowdsec-bouncer.key
sudo mkdir -p crowdsec/config crowdsec/data logs/traefik   # root-owned: written by root without caps
cp ../hardening/acquis.yaml crowdsec/acquis.yaml
cp ../hardening/security.yml traefik/dynamic/security.yml   # set clientTrustedIPs to your VPN/LAN
# merge ../hardening/traefik-static.snippet.yml into traefik/traefik.yml (drop forwardedHeaders
# without a CDN), then:
docker compose -f compose.yml -f compose.crowdsec.yml up -d crowdsec
docker compose -f compose.yml -f compose.crowdsec.yml up -d --force-recreate traefik
```

`security.yml` reads the key from `/etc/traefik/crowdsec-bouncer.key`, which in the production
example is inside the existing `./traefik:/etc/traefik:ro` mount. Elsewhere, mount the key file
into Traefik only.

**Verify** (each line found a real mistake while this was set up):

```sh
docker compose exec crowdsec cscli bouncers list              # traefik: "Last API pull" filled in
docker compose exec crowdsec cscli metrics show acquisition   # both logs: lines read and parsed
docker compose exec crowdsec cscli lapi status
# a ban works: from a phone on mobile data (not the VPN), look up its address, then
docker compose exec crowdsec cscli decisions add --ip <phone-ip> --duration 5m   # phone gets 403 within ~60 s
docker compose exec crowdsec cscli decisions delete --ip <phone-ip>
```

Day to day: `cscli alerts list`, `cscli alerts inspect <id> -d`, `cscli decisions list`.

**Which router and host an attacker used** (optional): Traefik's parser already extracts both,
they only reach the alerts when listed in the alert context. Once:

```sh
docker compose exec crowdsec cscli lapi context add --key traefik_router_name --value evt.Meta.traefik_router_name
docker compose exec crowdsec cscli lapi context add --key target_fqdn --value evt.Meta.target_fqdn
docker compose restart crowdsec
docker compose exec crowdsec cscli lapi context status   # also lists http_base: path, method, status, agent
```

Applies to new alerts only.

Safety nets in the files: private ranges are never banned (`crowdsecurity/whitelists`, plus the
bouncer's `clientTrustedIPs`), CDN edge addresses are never banned (`whitelist-good-actors`),
and the bouncer fails open (`updateMaxFailure: -1`) so an outage of CrowdSec does not take the
sites down. The bouncer is attached to the **entry point**, so it covers every router, labels
included.

### Stricter on routes without Authelia (optional)

Some apps cannot sit behind Authelia (sync clients, mobile apps). `noauth-probing.yaml` bans
after 6 different failing paths on routers you list. Start in simulation (alerts, no bans):

```sh
cp ../hardening/noauth-probing.yaml crowdsec/config/scenarios/   # list your routers in it first
docker compose exec crowdsec cscli simulation enable local/noauth-probing
docker compose restart crowdsec
docker compose exec crowdsec cscli alerts list -s local/noauth-probing   # a week later
```

## 3. Authelia: throttle logins per address

```yaml
regulation:
  modes: [user, ip]   # per account and per address
  max_retries: 3
  find_time: 10m
  ban_time: 1h
```

Add `ip` only when Authelia sees real client addresses (section 1). Behind a CDN without that,
an address ban hits the CDN's edge, which is everyone.

## 4. Behind Cloudflare

- **WAF custom rule** (free plan), block obvious scanners before they reach you:
  `(http.request.uri.path contains "/wp-") or (http.request.uri.path contains "/.env") or
  (http.request.uri.path contains "/.git") or (http.request.uri.path contains "phpmyadmin")`.
  A short list is only a filter for noise; CrowdSec does the real work.
- **Countries** for hosts that cannot sit behind Authelia:
  `(http.host in {"cloud.example.com"}) and not (ip.src.country in {"IE"})`.
- **Rate limit** the login endpoints `/api/firstfactor` and `/api/secondfactor` on the portal host.
- **Only Cloudflare may reach 80/443** (`examples/hardening/cloudflare-only.bash`), otherwise anyone
  can bypass all of the above through the server's address. Docker's published ports bypass
  `ufw`, so the script uses the `DOCKER-USER` chain and an ipset; it only filters new connections
  to 80/443 on the public interface, refuses to load an empty range list, and `remove` undoes it.
  Every hostname on 80/443 must be proxied (orange cloud) first.

## 5. Traefik without the Docker socket

A Traefik that reads Docker labels does not need the raw socket, whose `:ro` mount does not
limit the Docker API at all. `examples/hardening/compose.socket-proxy.yml` allows exactly the
calls Traefik 3.7's Docker provider makes (`/_ping`, `/version`, `/events`, `/containers/json`,
`/containers/<id>/json`; taken from its source) and nothing else. The proxy anchors its rules.

Review other socket proxies the same way: a rule like `containers/.*` also allows
`/containers/<id>/archive` and `/export`, which read any file of any container.

## 6. Logs

- Traefik writes the access log to a file **or** stdout. To keep `docker logs`, a sidecar can
  follow the file: `busybox tail -n 0 -F /logs/access.log` with `network_mode: none`.
- Mount log **folders**, not files: logrotate replaces the file and a file mount goes stale.
- Rotate on the host. Either `copytruncate`, or a `postrotate` that sends Traefik `USR1`.
- logrotate only allows comments on their own line. A comment after a directive
  (`su root root  # …`) makes it skip the whole block silently, every log in it included.
- Authelia writes its log as `AUTHELIA_UID` with mode 600, so CrowdSec gets `DAC_READ_SEARCH`
  (read only) instead of loosening the file's permissions.

## 7. Connecting Traefik, Traefik Manager and CrowdSec

Three connections, each with its own credential. Production example values; with Docker labels
use your own fixed addresses.

```
Traefik ──(bouncer key, file)──────────► CrowdSec :8080     enforces bans          (section 2)
Traefik Manager ──(tmapi, IP allow-list)► Traefik  :8081    reads routes/services  (docs/traefik-manager.md)
Traefik Manager ──(own bouncer key)─────► CrowdSec :8080    bans in force
                └─(machine login, opt.)─► CrowdSec :8080    alerts: scenarios, paths, attackers
```

**1. Run everything together**

```sh
docker compose -f compose.yml -f compose.traefik-manager.yml -f compose.crowdsec.yml \
  -f compose.traefik-manager.crowdsec.yml up -d
```

`compose.traefik-manager.crowdsec.yml` only puts Traefik Manager on the `crowdsec` network.

**2. Traefik → CrowdSec** (section 2): `docker compose exec crowdsec cscli bouncers list` shows
`traefik` with a "Last API pull". Empty: Traefik still runs the old static config (recreate it).

**3. Traefik Manager → Traefik.** The API URL is Traefik's **fixed address**, never its name: once
the two share a second network (`crowdsec`), `traefik` can resolve there, the request comes from
another address, and the allow-list answers 403 ("No object list for: middlewares").

```sh
docker compose exec traefik-manager wget -qO- http://172.30.0.2:8081/api/version   # JSON = good
```

`TRAEFIK_API_URL` only seeds the setting on the first start: if the wizard already saved
`http://traefik:8081`, change it in **Settings → Traefik API URL** too. A 403 means the caller is
not the allow-listed address (`ipv4_address` in compose = `traefik-manager.yml`).

**4. Traefik Manager → CrowdSec, bans in force.** Its own key, never Traefik's:

```sh
docker compose exec crowdsec cscli bouncers add traefik-manager   # prints the key once
```

In **Settings → System Monitoring → CrowdSec**: LAPI URL `http://crowdsec:8080`, API Key = that
key, nothing else. `cscli bouncers list` then shows `traefik-manager` pulling.

**5. Traefik Manager → CrowdSec, alerts (optional).** Alerts need a machine login, which can also
create and delete bans (private ranges and CDN edges stay protected by the whitelists). Print the
credentials, do not let cscli write them:

```sh
docker compose exec crowdsec cscli machines add traefik-manager --auto -f -
```

Without `-f -` the command targets CrowdSec's **own** `local_api_credentials.yaml` (refused; with
`--force` it overwrites the agent's login and CrowdSec stops). Put `login` in **Machine ID** and
`password` in **Machine Password**; keep the LAPI URL `http://crowdsec:8080`, not the `0.0.0.0`
in the output. Check the login from Traefik Manager's container (the password stays out of the
shell history):

```sh
read -rs P; docker compose exec -T traefik-manager wget -qO- --header 'Content-Type: application/json' \
  --post-data "{\"machine_id\":\"traefik-manager\",\"password\":\"$P\"}" \
  http://crowdsec:8080/v1/watchers/login; echo; unset P
```

`{"code":200,...}` = good. In `cscli machines list` the machine shows `⚠️ -` as heartbeat: only
agents that send alerts heartbeat. Undo: `cscli machines delete traefik-manager`.

**Symptoms seen while setting this up**

| Traefik Manager says | Cause | Fix |
|---|---|---|
| "No object list for: middlewares", API 403 | API URL by name, second shared network | step 3 |
| "CrowdSec not configured" | no LAPI URL / key saved | step 4 |
| "Not permitted to read alerts", `401 cookie token is empty` | bouncer key only | step 5, or accept bans-only |
| "machine login failed", `/v1/alerts` 502 | machine fields filled, machine does not exist | `cscli machines list`; step 5 |
| "no geoip-enrich" / "no HTTP meta" | parser or alert context missing | `PARSERS`/`CONTEXTS` in the overlay; context add (section 2) |
| bans in force: 0, "0 subscribed" | nothing banned yet; blocklist not synced | `cscli capi status`; wait for the sync |

## 8. Apps on another machine (optional)

When heavy apps (Home Assistant, Nextcloud) run at home and only Traefik, Authelia and CrowdSec run
on a cloud server, the apps' own logs never reach the edge. A CrowdSec agent next to them reads
those logs and sends its alerts through the tunnel; the edge bans the address for every site.
Setup, per-app real client address, the tunnel route and the pitfalls (Home Assistant's UI-managed
proxy settings and coloured journal output, Nextcloud's unlogged WebDAV failures):
[`examples/remote-agent/`](../examples/remote-agent/).

## 9. Bans in the host firewall too (optional)

The Traefik bouncer only stops web requests. SSH, a VPN server or anything else that does not pass
Traefik needs CrowdSec's bans in the host firewall: the firewall bouncer, built as a small local
image from the official binary and run in the same compose project
([`firewall-bouncer.md`](firewall-bouncer.md), files in
[`examples/firewall-bouncer/`](../examples/firewall-bouncer/) and
`examples/production/compose.firewall-bouncer.yml`). The same page adds SSH's and OpenVPN's logs.

## 10. Bans at Cloudflare's edge (optional)

Behind Cloudflare, CrowdSec's own bans can also go into a Cloudflare IP list that a WAF rule blocks,
so banned addresses stop at the edge (free plan included). A small service mirrors them and removes
expired ones: [`cloudflare-list-sync.md`](cloudflare-list-sync.md), files in
[`examples/cloudflare-list-sync/`](../examples/cloudflare-list-sync/) and
`examples/production/compose.cloudflare-list-sync.yml`.

## 11. Permanent bans from a file (optional)

A text file of addresses and ranges that every bouncer enforces, applied within seconds of saving:
[`static-blocklist.md`](static-blocklist.md). How all the blocking pieces fit together, and the
order to deploy them: [`blocking.md`](blocking.md).

## Pitfalls met on a real deployment

- **Static config is read at start only.** After editing `traefik.yml`, recreate Traefik, then
  compare `docker inspect -f '{{.State.StartedAt}}' traefik` with the file's time.
- **`log.level: ERROR` hides "Plugins loaded".** Ask the API instead:
  `GET /api/http/middlewares/crowdsec@file` answers `"status":"enabled"` and lists `usedBy`.
- **Plugins need a writable `./plugins-storage`** under Traefik's working directory; a read-only
  Traefik needs a tmpfs there.
- **Two containers on two shared networks:** a name such as `traefik` can resolve to either
  address, and an `ipAllowList` for one fixed address then fails at random. Use the IP.
- **`cscli machines add` writes to CrowdSec's own `local_api_credentials.yaml`.** It refuses
  without `--force`; with `--force` it overwrites the agent's login and CrowdSec stops. For a
  second machine (e.g. a dashboard) print the credentials instead: `--auto -f -`.
- A bouncer key reads decisions only; alerts need a machine login, which can also create and
  delete decisions. Give dashboards their own bouncer key (`cscli bouncers add <name>`). A
  dashboard's machine shows `⚠️ -` as last heartbeat in `cscli machines list`: only agents that
  send alerts heartbeat, a reader never does.
- A dashboard that "cannot log in" although credentials are saved: check the machine exists
  (`cscli machines list`). A failed watcher login can surface as `502` rather than `401`.
- Keep the static config and anything next to it (old copies included) out of reach of other
  users: `chmod 644 traefik.yml`, no `-rw-rw-rw-` backups. Whoever can write it can load a plugin
  into Traefik at the next restart.
- A router without `entryPoints` is attached to **every** entry point, plain-TCP ports included.
- A host that is public by mistake shows up in a router list long before it shows in an attack:
  list the routers whose middlewares lack Authelia and check each one.
