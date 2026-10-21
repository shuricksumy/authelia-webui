# Blocking attackers: how the pieces fit, and the order to deploy them

The hardening pages each add one piece. This page shows them together: who **detects**, who
**decides**, who **enforces**, and in which order to set them up. Every piece after CrowdSec is
optional; each one is a compose overlay next to the
[production example](../examples/production/), with its own guide and checks.

```
            DETECT                                DECIDE                      ENFORCE
Traefik access log ──┐
Authelia log ────────┤                                               ┌─▶ Traefik bouncer   403, websites
SSH / OpenVPN logs ──┼─▶ CrowdSec (scenarios) ──┐                     │
home agent: HA,      │                          ├─▶ ban list ─────────┼─▶ firewall bouncer  DROP, every port
  Nextcloud, …     ──┘   (remote-agent)         │   (CrowdSec LAPI)   │
static-blocklist.txt ──────(watcher)────────────┤                     └─▶ crowdsec-cf-sync  Cloudflare list
community blocklist (CAPI) ─────────────────────┘                          → WAF rule: blocked at the edge
                                                                      Cloudflare WAF rule: countries, ASNs
```

One ban list, many enforcers: an address banned for probing the websites is also dropped on SSH,
and the other way round. Bans expire by themselves (4 h by default), except the static list.

## The pieces

| Piece | Detects or enforces | Guide | Overlay / files |
|---|---|---|---|
| Real client address | prerequisite: logs and bans see the visitor, not the CDN | [`hardening.md`](hardening.md) §1 | `examples/hardening/` |
| CrowdSec + Traefik bouncer | detects probing and Authelia brute force; `403` on every router | [`hardening.md`](hardening.md) §2 | `compose.crowdsec.yml` |
| Remote agent | apps on another machine (HA, Nextcloud, …): their own logs | [`remote-agent`](../examples/remote-agent/README.md) | `examples/remote-agent/` |
| Firewall bouncer | `DROP` on every port: SSH, VPN servers, direct hits; adds SSH and OpenVPN logs | [`firewall-bouncer.md`](firewall-bouncer.md) | `compose.firewall-bouncer.yml`, `examples/firewall-bouncer/` |
| Cloudflare list sync | own bans blocked at Cloudflare's edge (free plan) | [`cloudflare-list-sync.md`](cloudflare-list-sync.md) | `compose.cloudflare-list-sync.yml`, `examples/cloudflare-list-sync/` |
| Static blocklist | permanent bans from a text file, applied on save | [`static-blocklist.md`](static-blocklist.md) | `compose.static-blocklist.yml`, `examples/static-blocklist/` |
| Countries, providers | Cloudflare WAF custom rule (`ip.src.country`, `ip.src.asnum`) | [`cloudflare-list-sync.md`](cloudflare-list-sync.md) §1 | Cloudflare dashboard |

## Order

Do them in this order; each step ends with a check, and the next one relies on it.

1. **Real client address** ([`hardening.md`](hardening.md) §1). Check: Traefik's access log shows
   the visitor's address (`ClientHost` equals `Cf-Connecting-IP`). Every later step bans what the
   logs show; with a CDN address there, the wrong address gets banned.
2. **CrowdSec and the Traefik bouncer** (§2). Check: a ban of your phone's mobile address gives
   `403`; `cscli bouncers list` shows a recent pull.
3. **Apps on another machine** (remote agent), if any. First make each app log the visitor's
   address (its trusted-proxy setting), then the agent. Check: `cscli machines list` on the edge
   shows the agent with a heartbeat in seconds; `cscli explain` on a real failed-login line reaches
   the app's scenario.
4. **Firewall bouncer** ([`firewall-bouncer.md`](firewall-bouncer.md)). Check: `CROWDSEC_CHAIN` on
   line 1 of `INPUT` and `DOCKER-USER`; a test ban lands in an IP set. Before logging out, make sure
   your own address is not banned.
5. **SSH and VPN logs** (same guide, step 4). Check: `cscli metrics show acquisition` lists them;
   `cscli explain` on a failure line reaches the scenario.
6. **Cloudflare list sync** ([`cloudflare-list-sync.md`](cloudflare-list-sync.md)): list, WAF rule,
   token (never the Global API Key), then the sync in dry run. Check: the dry-run log names only
   CrowdSec's own bans; live, the list shows them with the comment `crowdsec: …`.
7. **Static blocklist** ([`static-blocklist.md`](static-blocklist.md)). Check: a test line is
   banned within seconds, and at Cloudflare within a minute; deleting it lifts both.
8. **Countries and providers** in the same WAF rule as the list. Check: Cloudflare's Security
   Events show the rule blocking.

## Credentials

Each piece has its own, with the least it needs; all in `.env`, none in the config files.

| Who | Kind | Can |
|---|---|---|
| Traefik bouncer | bouncer key (`CROWDSEC_BOUNCER_KEY`) | read decisions |
| firewall bouncer | bouncer key (`CROWDSEC_FIREWALL_BOUNCER_KEY`) | read decisions |
| Cloudflare sync | bouncer key (`CROWDSEC_CF_SYNC_KEY`) + API token (`CF_API_TOKEN`, Account Filter Lists: Edit) | read decisions; edit the account's lists |
| static-blocklist watcher | machine login (`CROWDSEC_BLOCKLIST_PASSWORD`) | create and delete decisions |
| remote agent | machine login | send alerts |

Create machines with `cscli machines add <name> --password … -f -`: without `-f -` it writes over
CrowdSec's own credentials file and CrowdSec stops.

## Day to day

```sh
docker compose exec crowdsec cscli decisions list                 # bans in force (own + static)
docker compose exec crowdsec cscli alerts list                    # what was detected, by whom
docker compose exec crowdsec cscli bouncers list                  # every enforcer pulled recently
docker compose exec crowdsec cscli machines list                  # agents: heartbeats in seconds
docker compose exec crowdsec cscli decisions delete --ip <address>   # lift a ban everywhere
```

A new detection rule starts in simulation (`cscli simulation enable <scenario>`) for about a week:
every device behind one home connection shares one address, so one app retrying an old password
can ban the whole household.

## Keep in mind

- A whitelist for your own internet provider (by AS number) keeps the family from being banned,
  and keeps every scenario from banning anyone else on that provider.
- Fixed container addresses come from variables: a `docker compose up` that misses them (another
  folder, another env file) recreates containers without their addresses. Keep every variable in
  the stack's `.env`, and check with `docker compose config 2>&1 | grep -i 'not set'`.
- Geo-blocking is coarse: attackers rent servers and residential proxies everywhere. It reduces
  noise; it does not replace CrowdSec and Authelia.
