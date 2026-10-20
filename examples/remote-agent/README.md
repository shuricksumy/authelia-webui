# Remote CrowdSec agent: apps at home, the edge in the cloud

For a split setup: Traefik, Authelia and CrowdSec run on a small cloud server (the **edge**),
while heavy apps such as Home Assistant and Nextcloud run on a machine at **home**, reached through
a WireGuard tunnel. CrowdSec on the edge sees Traefik's and Authelia's logs, but not the apps'
own logs, which stay at home. A small CrowdSec **agent** at home reads them and sends its alerts
to the edge, where Traefik's bouncer bans the address for **every** site.

```
visitor ─▶ CDN ─▶ edge: Traefik + Authelia + CrowdSec (LAPI, bans) ──tunnel──▶ home: HA, Nextcloud
                         ▲                                                          │ logs
                         └──── alerts: "203.0.113.9 failed 6 logins" ◀── crowdsec-agent (home)
```

Prerequisites: CrowdSec and the bouncer on the edge ([`docs/hardening.md`](../../docs/hardening.md),
section 2), the real client address on the edge (section 1), and a WireGuard tunnel between the
edge and the home machine. Checked with Traefik 3.7.15, CrowdSec 1.8.1, Home Assistant 2026.10
(Supervised), Nextcloud (fpm + nginx).

```
edge/traefik-static.snippet.yml   entry point cslapi (:8082) for the agent; merge, restart Traefik
edge/crowdsec-lapi.yml            router cslapi -> crowdsec:8080, allow-list; dynamic config
edge/webdav-auth-bf.yaml          scenario for failures no app logs (Nextcloud WebDAV), step 5
home/compose.yml                  the agent (no engine, no ports, no socket)
home/acquis.yaml                  what it reads: HA's journal (colour codes stripped), Nextcloud
home/wireguard-client.snippet.conf  the one AllowedIPs line the home tunnel needs
```

Addresses used below (all placeholders; replace them with yours):

| | |
|---|---|
| edge network (Docker), Traefik | `172.30.0.0/24`, Traefik `172.30.0.2` |
| WireGuard container on the edge network | `172.30.0.30` |
| tunnel | `10.99.0.0/24`: edge `10.99.0.1`, home `10.99.0.2` |
| home LAN | `192.168.1.0/24` |
| a visitor | `203.0.113.9` / `2001:db8::9` |

Which source catches what:

| Attack | Seen in | Caught by |
|---|---|---|
| passwords against anything behind Authelia | Authelia's log (edge) | edge CrowdSec, `LePresidente/authelia` |
| probing, scanners, CVE paths | Traefik's access log (edge) | edge CrowdSec, `crowdsecurity/traefik` etc. |
| Home Assistant's own login page | HA's log (home) | **home agent**, `crowdsecurity/home-assistant` |
| Nextcloud web login (if not behind Authelia) | Nextcloud's log (home) | **home agent**, `crowdsecurity/nextcloud` |
| Nextcloud WebDAV/OCS (sync apps, app passwords) | **only** Traefik's access log: Nextcloud logs nothing | edge, `webdav-auth-bf.yaml` |

## 1. The real client address, in every app (do this first)

An alert is only useful with the visitor's address. If an app logs a proxy (the edge's tunnel
address, a CDN address, a Docker gateway), the agent either reports nothing (private addresses are
whitelisted) or bans a CDN address. Home Assistant's own ban would then lock **everyone** out at the
first wrong password.

What the app receives from the edge, behind a CDN with `realip` (section 1 of the hardening guide):

```
connection from:  the edge's tunnel address (10.99.0.1)
X-Forwarded-For:  <visitor>, <CDN address>
```

`realip` cleans the left side (that is what Authelia reads); Traefik then appends the address that
connected to it, which is the CDN's. Apps that read the chain **from the right**, skipping trusted
proxies (Home Assistant, Nextcloud), must therefore trust **the edge's tunnel address and the CDN's
ranges** (`curl -fsS https://www.cloudflare.com/ips-v4` for Cloudflare). Trusting only the tunnel
address logs a CDN address for every visitor.

**Home Assistant.** Since the HTTP settings moved to the UI (Repairs shows "HTTP YAML configuration
is ignored after migration"), YAML `http:` no longer applies: `check_config` still shows it, the
running instance uses `.storage/http`. Set it in **Settings → System → Network**: use X-Forwarded-For,
trusted proxies = the edge's tunnel address + the CDN ranges, login attempts threshold = 5 (`-1`
never bans). Then remove the `http:` block from `configuration.yaml`. Older versions: the same three
keys under `http:` in YAML.

**Nextcloud:**

```sh
occ() { docker exec -u www-data nextcloud php occ "$@"; }
occ config:system:get trusted_proxies            # existing entries are indexes 0..n-1
occ config:system:set trusted_proxies <n> --value=10.99.0.1/32   # an existing index overwrites
occ config:system:set trusted_proxies <n+1> --value=<CDN range>  # one index per range
occ config:system:set forwarded_for_headers 0 --value=HTTP_X_FORWARDED_FOR
occ log:manage --level=warning                   # 0 = debug floods the log
```

Nextcloud as php-fpm behind its own nginx: PHP sees the address that connected to nginx (the edge),
so nginx is not a hop here.

**Check without a phone.** From the edge, through Traefik's network namespace (the same source as
real traffic), send requests with known headers and a wrong token:

```sh
for xff in '203.0.113.9' '203.0.113.9, 192.0.2.1' '2001:db8::9, 192.0.2.1'; do   # 192.0.2.1: a CDN address
  docker run --rm --network container:traefik curlimages/curl -s -o /dev/null -w "%{http_code}\n" \
    -H 'Authorization: Bearer invalid' -H "X-Forwarded-For: $xff" http://10.99.0.2:8123/api/
done
# home: HA must log 203.0.113.9, 203.0.113.9, 2001:db8::9
docker logs --since 2m homeassistant 2>&1 | sed 's/\x1b\[[0-9;]*m//g' \
  | grep 'invalid authentication' | grep -oE 'from [^ ]+'
```

Replace `192.0.2.1` with an address from your CDN's ranges. A `400` means the connecting address is
not trusted at all (HA logs `untrusted proxy <address>`); the CDN address appearing as the client
means the CDN ranges are not trusted (or not in effect: see the HA note above).

## 2. A path from home to the edge's CrowdSec

The agent connects **out**, to CrowdSec's API (LAPI) on the edge. Two things decide how:

- **Where the tunnel ends on the edge.** If WireGuard runs in a container (wg-easy, WGDashboard,
  linuxserver/wireguard), the edge host has no tunnel address: publishing LAPI as
  `ports: ["10.99.0.1:8080:8080"]` fails with `cannot assign requested address`, and the CrowdSec
  container restarts **without any network** (bans stop: the bouncer fails open). Do not publish it.
- **Who can answer.** Often only Traefik's container has a route back to the tunnel. CrowdSec
  replying to `10.99.0.2` directly would need its own route and `NET_ADMIN`.

So the agent talks to **Traefik**, which already has the route, on a dedicated entry point, and
Traefik forwards to CrowdSec on the network they share:

```
agent ─tunnel─▶ WireGuard container (masquerades to 172.30.0.30) ─▶ Traefik :8082 ─▶ crowdsec:8080
```

On the home machine, route **only Traefik's address** through the tunnel
(`home/wireguard-client.snippet.conf`): `AllowedIPs = 10.99.0.0/24, 172.30.0.2/32`, then restart the
tunnel. Check:

```sh
ip route get 172.30.0.2          # -> dev <your tunnel interface>, src 10.99.0.2
timeout 5 bash -c '</dev/tcp/172.30.0.2/443' && echo REACHABLE
```

A route `via <your router>` means the LAN router also has a path to the edge (and wins until the
`/32` is in place); `tracepath -n 172.30.0.2` shows the hops.

Which address does Traefik see? Send one marked request from home and look it up on the edge:

```sh
curl -sk -o /dev/null -H 'Host: probe.invalid' https://172.30.0.2/                       # home
grep 'probe.invalid' access.log | tail -1 | jq -r .ClientHost                             # edge
```

With a masquerading WireGuard container this is the container's edge address (`172.30.0.30`) for
**every** peer: the allow-list in step 3 then means "anything from the tunnel", and the agent's
password is what keeps other peers out.

## 3. Edge: entry point, router, agent login

1. Merge `edge/traefik-static.snippet.yml` into Traefik's static config (port `8082` must be free:
   `grep -n 'address:' traefik.yml`). Do **not** add it to Traefik's `ports:`. Restart Traefik and
   compare `docker inspect -f '{{.State.StartedAt}}' traefik` with the file's time.
2. Copy `edge/crowdsec-lapi.yml` into Traefik's dynamic directory and put the address from step 2
   in `sourceRange`.
3. Create the agent's login. Keep `-f -`: without it, `cscli` writes over the edge agent's own
   credentials file and CrowdSec stops.

   ```sh
   PW=$(openssl rand -hex 24); echo "$PW"      # goes into the home .env, nowhere else
   docker exec crowdsec cscli machines add home-agent --password "$PW" -f -
   ```

Check from home: `curl -s -m 5 http://172.30.0.2:8082/health` answers `{"status":"up"}`.

## 4. Home: the agent

```sh
mkdir -p crowdsec-agent/config crowdsec-agent/data
cp acquis.yaml crowdsec-agent/acquis.yaml
echo "CROWDSEC_AGENT_PASSWORD=<from step 3>" >> .env
docker compose -f compose.yml up -d
```

Adjust the Nextcloud path in `compose.yml` first. Checks:

```sh
docker logs crowdsec-agent --tail 20       # "Loaded N scenarios", one "Spawning process ... journalctl"
docker exec crowdsec cscli machines list   # edge: home-agent, debian (docker), heartbeat in seconds
```

The first heartbeat can take a minute; `⚠️ -` that stays means the agent cannot reach the edge
(`docker logs crowdsec-agent | grep -iE 'unauthorized|refused|timeout'`).

## 5. The apps

**Home Assistant (Supervised).** Its output goes to the journal (`docker inspect homeassistant
--format '{{.HostConfig.LogConfig.Type}}'` says `journald`); there is no `home-assistant.log`. The
lines carry colour codes, so without the `transform` in `acquis.yaml` every line is "unparsed".
Check after one wrong password:

```sh
docker exec crowdsec-agent cscli metrics show acquisition parsers
# journalctl:journalctl-CONTAINER_NAME=homeassistant  lines parsed > 0, poured to bucket > 0
journalctl CONTAINER_NAME=homeassistant -n 3 -o cat | cat -v    # ^[[32m ... = colour codes
```

**Nextcloud.** The agent reads `nextcloud.log` for the web login. Failed **WebDAV/OCS** logins
(sync apps with app passwords, usually bypassed in Authelia) are not logged by Nextcloud at all,
not even at warning; its brute-force throttling still counts them
(`occ security:bruteforce:attempts <address>`). The edge sees each of them as a `401` from the
Nextcloud router, so that part is detected **on the edge**: copy `edge/webdav-auth-bf.yaml` into
the edge's `crowdsec/config/scenarios/`, list your Nextcloud router, start in simulation:

```sh
docker exec crowdsec cscli simulation enable local/webdav-auth-bf
docker restart crowdsec
docker exec crowdsec cscli explain --log "$(grep '"DownstreamStatus":401' access.log | tail -1)" --type traefik
# ends with: 🟢 local/webdav-auth-bf
```

**Adding another app** (Gitea, Vaultwarden, Immich, ...):

1. the app trusts the edge's tunnel address and the CDN ranges, and logs the visitor (step 1);
2. it logs failed logins at all (try one, then look); if not, use an edge scenario like
   `webdav-auth-bf.yaml` on its router instead;
3. a hub collection exists (`cscli collections list -a | grep -i <app>`): add it to `COLLECTIONS`;
4. a source in `acquis.yaml` with the label type the collection expects (its hub page names it);
5. check with `cscli explain --file <log> --type <type>` and the metrics above.

## 6. End to end

From a network that is **not** whitelisted (see below), 6 wrong passwords in HA, then on the edge:

```sh
docker exec crowdsec cscli alerts list -m home-agent
docker exec crowdsec cscli decisions list          # the address, ban
docker exec crowdsec cscli decisions delete --ip <address>   # lift it again
```

HA's own ban (`ip_bans.yaml` in its config folder) may hold the address as well.

## Troubleshooting and pitfalls

| Symptom | Cause | Fix |
|---|---|---|
| HA logs a CDN address although the YAML lists the CDN ranges | HA uses `.storage/http`, YAML is ignored after migration | Settings → System → Network; remove the YAML block |
| HA answers `400`, logs `untrusted proxy <address>` | that hop is not trusted | add exactly that address, nothing wider |
| all HA lines "unparsed" | colour codes | `transform` in `acquis.yaml` (there is no `ReplaceRegexp`: an unknown function stops the agent) |
| agent restarts in a loop | an error in `acquis.yaml` | `docker logs crowdsec-agent \| grep fatal` |
| explain reaches the scenario, but no alert | a postoverflow whitelist (e.g. your own provider's AS number) drops it | test from another network |
| edge CrowdSec "Up less than a second", no networks | a host port it cannot bind (step 2) | remove the `ports:` entry, recreate |
| traffic flips between two tunnel interfaces, short drops | the same peer configured twice (e.g. NetworkManager and a container, same key) | keep one: `nmcli connection down <name>`, `autoconnect no` |
| test from a cloud server gets `403`, `cf-mitigated: challenge` | the CDN challenges datacenter clients | test from a home or mobile connection |

- A whitelist for your own internet provider (by AS number) keeps the family from being banned,
  but also means no CrowdSec scenario ever bans **anyone** on that provider; the apps' own
  throttling (HA's ban, Nextcloud's brute-force protection) still applies there.
- All devices behind one home connection share one public address. A sync app retrying an old
  password can trigger a ban for the whole household: keep new scenarios in simulation first.
- Trusted-proxy lists that contain a whole LAN or VPN range let any device there pretend to be any
  address. List the real proxies only.
