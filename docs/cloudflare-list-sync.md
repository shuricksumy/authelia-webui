# CrowdSec bans in a Cloudflare IP list (optional)

Behind Cloudflare, the Traefik bouncer ([`hardening.md`](hardening.md), section 2) answers a banned
address with `403`, but its requests still travel through Cloudflare to the server. A small sync
service puts CrowdSec's **own** bans into a Cloudflare IP list as well; one WAF custom rule then
blocks them at Cloudflare's edge. When a ban expires or is deleted, the address leaves the list.

```
CrowdSec (detects) ──▶ Traefik bouncer        403 at the server
                   ├─▶ firewall bouncer        DROP for non-web ports (firewall-bouncer.md)
                   └─▶ crowdsec-cf-sync ──▶ Cloudflare list ──▶ WAF rule: Block at the edge
```

It works on the **free plan** (1 custom list, 10 000 items in total) and replaces the common
fail2ban action that does the same with the Global API Key. Checked with CrowdSec 1.8.1 and the
Cloudflare API v4 (lists, bulk operations).

Files: [`examples/cloudflare-list-sync/crowdsec-cf-sync.py`](../examples/cloudflare-list-sync/crowdsec-cf-sync.py)
and [`examples/production/compose.cloudflare-list-sync.yml`](../examples/production/compose.cloudflare-list-sync.yml).

## What it does

Every `INTERVAL` seconds (60):

1. reads CrowdSec's active decisions with its own **bouncer key** (read-only);
2. keeps bans from the origins in `ORIGINS`: `crowdsec` (its own detections), `cscli` (bans you
   add by hand) and `static-blocklist` (your permanent list, [`static-blocklist.md`](static-blocklist.md)).
   The community blocklist (`CAPI`, tens of thousands of addresses) does not fit a
   free list and is enforced by the bouncers anyway;
3. reads the whole list (paged, 500 per page) and compares:
   - adds the missing bans, with the comment `crowdsec: <scenario>`;
   - removes items **whose comment starts with `crowdsec`** that are no longer banned.

Items you, or an older tool, added without that comment are never touched. IPv6 addresses are
listed as their `/64` (one host usually owns the whole prefix). If CrowdSec cannot be reached, the
cycle is skipped: a CrowdSec restart never empties the list. Cloudflare runs list writes as
asynchronous bulk operations, one per account at a time; the sync waits for each one to finish.
It uses Python's standard library only: no `pip`, nothing downloaded at run time.

| Variable | Default | |
|---|---|---|
| `LAPI_URL` | `http://crowdsec:8080` | CrowdSec's API |
| `LAPI_KEY` | | the bouncer key |
| `CF_API_TOKEN` | | API **token** (not the Global API Key) |
| `CF_ACCOUNT_ID`, `CF_LIST_ID` | | 32 hex characters each |
| `ORIGINS` | `crowdsec,cscli,static-blocklist` | which decisions to mirror |
| `INTERVAL` | `60` | seconds between cycles |
| `MAX_ITEMS` | `5000` | cap for the items the sync owns |
| `DRY_RUN` | unset | `1`: only log what would change |

## 1. Cloudflare: list, rule, token

1. **List.** Manage Account → Configurations → **Lists** → Create list, type **IP**. Its ID is in
   the address bar when you open it (`…/configurations/lists/<list id>`); the account ID is in the
   dashboard's address bar too.
2. **Rule.** Your domain → Security → WAF → **Custom rules** → Create, action **Block**:

   ```
   (ip.src in $<list name>)
   ```

   The free plan has few custom rules: put country or provider blocks into the **same** rule,
   e.g. `(ip.src in $<list name>) or (ip.src.country in {"XX"}) or (ip.src.asnum in {64496})`.
3. **Token.** My Profile → API Tokens → Create Token → **Custom token**, permission
   **Account → Account Filter Lists → Edit**, for your account only. Cloudflare shows the value
   once. Check it:

   ```sh
   curl -s https://api.cloudflare.com/client/v4/user/tokens/verify \
     -H "Authorization: Bearer <token>"          # "status":"active"
   ```

   Never use the **Global API Key** here: it controls the whole account (DNS, every zone). A token
   is 40 or more characters of letters, digits, `-` and `_`; a Global API Key is 37 hex characters.
   If a Global API Key was ever written into a script or pasted somewhere, roll it
   (My Profile → API Tokens → Global API Key → Change).

## 2. Start it in dry run

```sh
cd /opt/authelia-stack                 # the production example's folder
mkdir -p cloudflare-list-sync
cp <repo>/examples/cloudflare-list-sync/crowdsec-cf-sync.py cloudflare-list-sync/
cat >> .env <<EOF
CROWDSEC_CF_SYNC_KEY=$(openssl rand -hex 32)
CF_API_TOKEN=<token>
CF_ACCOUNT_ID=<account id>
CF_LIST_ID=<list id>
EOF
```

Add `compose.cloudflare-list-sync.yml` to `COMPOSE_FILE` in `.env` (or pass `-f`), then:

```sh
docker compose config 2>&1 | grep -i 'not set'   # nothing: every variable is set
docker compose up -d
docker compose logs crowdsec-cf-sync
```

The overlay registers the bouncer at CrowdSec's start (`BOUNCER_KEY_cloudflare_list`). A bouncer
added by hand (`cscli bouncers add <name> -o raw`) works as well: put its key in
`CROWDSEC_CF_SYNC_KEY` and drop that line from the overlay.

Expected log, with `DRY_RUN: "1"`:

```
syncing origins ['crowdsec', 'cscli', 'static-blocklist'] every 60s (dry run)
add 1: 192.0.2.10                        # only if CrowdSec has own bans right now
```

## 3. Go live

1. Compare what it would add with `docker compose exec crowdsec cscli decisions list`: own bans,
   with a scenario as the reason.
2. Remove `DRY_RUN` from the overlay, `docker compose up -d`. The log shows the same `add` line
   once; the next cycle prints nothing (the item is there and recognised as its own).
3. The list in the dashboard shows the address with the comment `crowdsec: <scenario>`.

Moving over from a fail2ban action: remove the action from its jails (and roll the key it used).
Its entries carry no `crowdsec` comment, so they stay in the list until you delete them by hand.

## Day to day

- **Unban:** `cscli decisions delete --ip <address>`; it leaves the list at the next cycle.
- **Ban by hand:** `cscli decisions add --ip <address> --duration 24h --reason manual`; origin
  `cscli`, so it is mirrored too.
- **Logs:** `docker compose logs -f crowdsec-cf-sync` (one line per change; errors are logged and
  retried at the next cycle).
- **Addresses you whitelisted** in CrowdSec (your provider, your own address) never get a ban, so
  they never reach the list.

## Pitfalls

| Symptom | Cause | Fix |
|---|---|---|
| `HTTP 400 … 9106 Authentication failed` | the value is not a token: often the Global API Key | create a token (step 1.3); check its length |
| `6003 … 6111 Invalid format for Authorization header` | quotes, spaces, `Bearer` or a Global API Key in `CF_API_TOKEN` | the bare token in `.env`, no quotes |
| `HTTP 403` from `api.cloudflare.com` | token without Account Filter Lists: Edit, or for another account | edit the token's permissions |
| `CrowdSec unreachable` | wrong `LAPI_KEY`, or not on CrowdSec's network | `cscli bouncers list` shows the bouncer; `networks: [crowdsec]` |
| the log still says `(dry run)` | `DRY_RUN` still set | remove it, recreate the container |
| `cap MAX_ITEMS=…` | more own bans than the cap | raise it (the free plan holds 10 000 items in total) |
| `bulk operation … pending` | another tool writes to the account's lists at the same time | only one bulk operation per account runs at a time |
