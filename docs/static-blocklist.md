# Static blocklist: permanent bans from a text file (optional)

A file with one IP address or CIDR range per line. Save it, and within seconds every address in it is
banned by CrowdSec, so **every bouncer** enforces it: Traefik (`403` on the sites), the firewall
bouncer (`DROP` on every port, [`firewall-bouncer.md`](firewall-bouncer.md)) and, with the
Cloudflare sync, Cloudflare's edge ([`cloudflare-list-sync.md`](cloudflare-list-sync.md)). Delete a
line, save, and the ban is lifted everywhere. Nothing to run by hand, no Docker socket, no cron, no
host service.

```
static-blocklist.txt ──(watcher, ~5 s)──▶ CrowdSec: ban, origin "static-blocklist", 10 years
                                               ├─▶ Traefik bouncer      403 on the websites
                                               ├─▶ firewall bouncer     DROP on every port
                                               └─▶ crowdsec-cf-sync     Cloudflare list (≤ 1 min)
```

Countries and providers (AS numbers) do not belong here: Cloudflare's WAF matches them directly
and keeps their ranges current (`ip.src.country`, `ip.src.asnum`; [`cloudflare-list-sync.md`](cloudflare-list-sync.md),
step 1). The file is for specific addresses and ranges.

Files: [`examples/static-blocklist/`](../examples/static-blocklist/) (the watcher and an example
list) and [`examples/production/compose.static-blocklist.yml`](../examples/production/compose.static-blocklist.yml).
Checked against CrowdSec 1.8.1.

## How it works

The watcher is a small Python script (standard library only) in a `python:3.13-alpine`
container, running as `nobody`, read-only, without capabilities. It talks to CrowdSec's API with a
**machine login** of its own:

- every `CHECK` seconds (5) it looks at the file; when it changed, it compares the file with the
  bans it owns and adds or deletes the difference;
- every `RECHECK` seconds (600) it compares anyway, so a ban someone deleted by hand comes back
  while its line is in the file;
- its bans carry origin and reason `static-blocklist` (`cscli decisions list --origin
  static-blocklist`); other bans are never touched;
- a missing or unreadable file changes nothing; an **empty** file lifts all its bans;
- lines that are not an IP or CIDR are skipped and logged.

Why not `cscli decisions import` in a script: it needs the Docker socket or a host job to run
`cscli` inside the CrowdSec container, and its bans get the origin `cscli-import`, shared with any
other import. The API with its own login needs neither.

## Deploy

On top of CrowdSec ([`hardening.md`](hardening.md), section 2). In the stack folder:

1. **Files.** The list gets a folder of its own: the container mounts the **folder**, because
   editors (`nano`, `vim`, `sed -i`) replace the file when saving, and a single-file mount would keep
   showing the old one.

   ```sh
   mkdir -p static-blocklist/app static-blocklist/list
   cp <repo>/examples/static-blocklist/crowdsec-static-blocklist.py static-blocklist/app/
   cp <repo>/examples/static-blocklist/static-blocklist.example.txt static-blocklist/list/static-blocklist.txt
   chmod 644 static-blocklist/app/*.py static-blocklist/list/static-blocklist.txt
   ```

2. **Login.** A machine for the watcher; keep `-f -` (without it, `cscli` writes over CrowdSec's
   own credentials file and CrowdSec stops):

   ```sh
   PW=$(openssl rand -hex 24); echo "CROWDSEC_BLOCKLIST_PASSWORD=$PW" >> .env
   docker compose exec crowdsec cscli machines add static-blocklist --password "$PW" -f - >/dev/null
   unset PW
   ```

3. **Start.** Add `compose.static-blocklist.yml` to `COMPOSE_FILE` in `.env` (or pass `-f`):

   ```sh
   docker compose config 2>&1 | grep -i 'not set'      # nothing
   docker compose up -d
   docker compose logs crowdsec-static-blocklist         # watching /data/static-blocklist.txt ...
   ```

4. **With the Cloudflare sync:** its `ORIGINS` must include `static-blocklist` (the default in
   `compose.cloudflare-list-sync.yml`).

## Test

With a documentation address, which belongs to nobody:

```sh
echo '192.0.2.202   # test' >> static-blocklist/list/static-blocklist.txt
sleep 8
docker compose logs --since 15s crowdsec-static-blocklist   # added 1: 192.0.2.202 (1 in the file)
docker compose exec crowdsec cscli decisions list --origin static-blocklist
sed -i '/192.0.2.202/d' static-blocklist/list/static-blocklist.txt
sleep 8
docker compose logs --since 15s crowdsec-static-blocklist   # removed 1: 192.0.2.202 (0 in the file)
```

With the Cloudflare sync, its log shows `add 1: 192.0.2.202` and, a cycle after the removal,
`remove 1: 192.0.2.202`.

## Day to day

- **Ban:** add a line (`203.0.113.9  # why`), save. **Lift:** delete the line, save.
- **What is in force:** `cscli decisions list --origin static-blocklist`.
- **Logs:** one line per change: `added N: …` / `removed N: …`, plus `skipped, not an IP or CIDR`.
- **Backup:** the text file is the source of truth; back it up with the stack.
- A whitelisted address (CrowdSec's `whitelists`, a provider whitelist) is not protected from this
  list: a manual ban wins. Do not list your own addresses.

## Pitfalls

| Symptom | Cause | Fix |
|---|---|---|
| `HTTP 401 … incorrect Username or Password` | wrong `CROWDSEC_BLOCKLIST_PASSWORD`, or the machine does not exist | `cscli machines list`; add it again with `-f -` |
| the same 401 with the right password (own scripts) | CrowdSec refuses a machine login whose User-Agent is not `name/version` (`bad user agent` in its log) | the watcher sends `crowdsec-static-blocklist/1.0` |
| edits are not picked up | the file is mounted instead of its folder | mount the folder (`./static-blocklist/list:/data:ro`) |
| `cannot read /data/static-blocklist.txt` | wrong name or permissions (it runs as `nobody`) | `chmod 644`, folder `755` |
| a deleted ban shows `0s` in `cscli decisions list` | CrowdSec keeps a deleted decision visible until cleanup; bouncers already ignore it | nothing; the watcher ignores it too |
| bans in CrowdSec, not at Cloudflare | `static-blocklist` missing from the sync's `ORIGINS` | add it, recreate the sync |
