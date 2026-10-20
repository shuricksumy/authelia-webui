# CrowdSec firewall bouncer in Docker (optional)

The Traefik bouncer ([`hardening.md`](hardening.md), section 2) enforces CrowdSec's bans on web
requests only. Anything that does not pass Traefik (SSH, an OpenVPN or WireGuard server, hits on the
server's own address) is not covered. The **firewall bouncer** puts the same ban list into the
host's firewall: one IP set, one `DROP` rule. Banned addresses get no answer on any port; everyone
else is untouched. It also applies CrowdSec's community blocklist (tens of thousands of known
attackers) before they try anything.

```
CrowdSec ban list ──▶ Traefik bouncer    web requests: 403
                 └──▶ firewall bouncer   everything else: DROP (INPUT and DOCKER-USER)
```

CrowdSec ships it as a host package; there is no official image. This page builds a small image
from the **official release binary** (pinned version, checksum verified), so it lives in the
compose project with the rest and is restored from the same backup. Checked with firewall bouncer
v0.0.38, CrowdSec 1.8.1, Debian/Ubuntu hosts with iptables 1.8 (nf_tables).

Files:

```
examples/firewall-bouncer/            build kit (copy to the server once)
  Dockerfile                          debian:12-slim + iptables/ipset + the release binary
  build.bash                          builds local/crowdsec-firewall-bouncer:<version>, checks iptables
  acquis.non-http.yaml                log sources for SSH and OpenVPN (step 4)
examples/production/
  compose.firewall-bouncer.yml        the service + CrowdSec's API on 127.0.0.1 (overlay)
  crowdsec/firewall-bouncer.yaml      its config; the key comes from .env, nothing secret inside
```

Same layout on a server: the build kit in a folder of its own, the service and its config in the
main compose project, so one `docker compose up -d` (re)starts everything:

```
/opt/authelia-stack/                  the main compose project (examples/production/)
  compose.firewall-bouncer.yml
  crowdsec/firewall-bouncer.yaml
  .env                                CROWDSEC_FIREWALL_BOUNCER_KEY=...
/opt/authelia-stack/firewall-bouncer/ the build kit
```

## What it needs, and why

| | |
|---|---|
| `network_mode: host` | it changes the **host's** firewall, not a container's |
| `cap_add: [NET_ADMIN, NET_RAW]` | iptables rules and IP sets; not `privileged`, nothing else |
| CrowdSec's API at `127.0.0.1:8080` | a host-network container reaches published ports on loopback only |
| a bouncer key | reads decisions only; cannot create bans or send alerts |
| the host's iptables backend in the image | `nf_tables` vs `legacy`: rules in the other one are ignored |

A container does not isolate a firewall bouncer: whoever controls it controls the host's firewall,
exactly like the host package. The image is for portability and pinning, not for confinement.

## 1. Build the image

```sh
cp -r examples/firewall-bouncer /opt/authelia-stack/firewall-bouncer
sudo /opt/authelia-stack/firewall-bouncer/build.bash
```

The script picks the binary for the CPU (`x86_64` or `aarch64`), verifies the archive's SHA256,
builds `local/crowdsec-firewall-bouncer:v0.0.38`, and compares iptables in the image with the host:

```
image:    local/crowdsec-firewall-bouncer:v0.0.38
bouncer:  version: v0.0.38-...
iptables: image iptables v1.8.9 (nf_tables) | host iptables v1.8.10 (nf_tables)
```

It stops with an error when the backends differ (a host still on `iptables-legacy`). Then either
switch the host (`update-alternatives --set iptables /usr/sbin/iptables-nft`, reboot) or install
`iptables-legacy` in the image and point `/usr/sbin/iptables` at it.

## 2. Connect it to CrowdSec

1. **Key.** One value, used twice: CrowdSec registers the bouncer with it at start
   (`BOUNCER_KEY_firewall`), and the bouncer sends it. The config file reads it from the
   environment (`api_key: ${CROWDSEC_FIREWALL_BOUNCER_KEY}`; the bouncer expands `${...}`):

   ```sh
   echo "CROWDSEC_FIREWALL_BOUNCER_KEY=$(openssl rand -hex 32)" >> .env
   ```

   A bouncer created by hand (`cscli bouncers add <name> -o raw`) works too: put that key in
   `.env` instead and drop `BOUNCER_KEY_firewall` from the overlay.

2. **API port.** The overlay publishes CrowdSec's API on `127.0.0.1:8080` only. Check the port is
   free first: `ss -tlnp | grep ':8080 '` prints nothing.

3. **Start.** Add the overlay to `COMPOSE_FILE` in `.env` (or pass `-f`), then:

   ```sh
   docker compose up -d
   ```

4. **Check, before you log out.** Make sure your own address is not banned:

   ```sh
   docker compose exec crowdsec cscli decisions list -i "${SSH_CLIENT%% *}"   # No active decisions
   docker compose logs crowdsec-firewall-bouncer | tail      # "N decisions added", no errors
   docker compose exec crowdsec cscli bouncers list          # firewall: last API pull = now
   iptables -L INPUT -n --line-numbers | head -4             # 1  CROWDSEC_CHAIN
   iptables -L DOCKER-USER -n --line-numbers | head -4       # 1  CROWDSEC_CHAIN
   iptables -S CROWDSEC_CHAIN                                # one DROP rule per IP set
   ```

   `CROWDSEC_CHAIN` must be **line 1** in both chains: an `ACCEPT` above it would let banned
   addresses through. The chain name is upper case (`grep -i`), and `ipset` exists in the image,
   not necessarily on the host (`docker compose exec crowdsec-firewall-bouncer ipset list -n`).

5. **Test ban** with a documentation address, which belongs to nobody:

   ```sh
   docker compose exec crowdsec cscli decisions add --ip 192.0.2.123 --duration 5m --reason test
   sleep 15
   docker compose exec crowdsec-firewall-bouncer sh -c \
     'for s in $(ipset list -n); do ipset test $s 192.0.2.123 2>&1; done' | grep 'is in set'
   docker compose exec crowdsec cscli decisions delete --ip 192.0.2.123
   ```

   Decisions land in one set per origin: `crowdsec-blacklists-0` for the community blocklist,
   another for your own bans; each set gets its own `DROP` rule when it first appears.

## 3. What gets dropped, and what never does

- Only the sender addresses in the sets. Established connections of a banned address stop too.
- Web visitors behind a CDN reach the server from the CDN's addresses, which CrowdSec never bans
  (`crowdsecurity/whitelist-good-actors`); they keep getting the Traefik bouncer's 403 instead.
- Private ranges are whitelisted (`crowdsecurity/whitelists`): the VPN and the LAN are never dropped.
- Bans expire (4 h by default) and leave the set by themselves.

## 4. SSH and OpenVPN: give CrowdSec their logs

A ban needs a detection first. Traefik's and Authelia's logs say nothing about SSH or a VPN
server, so add their logs (`examples/firewall-bouncer/acquis.non-http.yaml`).

**SSH.** `crowdsecurity/linux` (installed by the image by default) parses `auth.log`. Mount the
host's `/var/log` folder read-only in the `crowdsec` service (`/var/log:/var/log/host:ro`, commented
in the overlay) and add the SSH section to `crowdsec/acquis.yaml`.

**OpenVPN.** The community collection `pserranoa/openvpn` (CrowdSec hub) bans after
3 failures within about a minute: failed passwords, certificate errors, failed TLS. Before relying
on it, check it reads **your** log format:

1. Add it to `COLLECTIONS` of the `crowdsec` service (so a rebuild reinstalls it), recreate CrowdSec.
2. Where does OpenVPN log? `grep -E '^\s*(log|log-append)\b' server.conf` names the file inside its
   container; `docker inspect <openvpn> --format '{{range .Mounts}}{{.Source}} -> {{.Destination}}{{"\n"}}{{end}}'`
   gives the host path.
3. Test lines in your log's format (dates as `YYYY-MM-DD HH:MM:SS` work):

   ```sh
   docker compose exec crowdsec cscli explain --type openvpn \
     --log "2026-10-20 18:50:01 192.0.2.9:51234 TLS Auth Error: Auth Username/Password verification failed for peer"
   docker compose exec crowdsec cscli explain --type openvpn \
     --log "2026-10-20 18:50:02 192.0.2.9:51234 VERIFY ERROR: depth=0, error=unable to get local issuer certificate: CN=x"
   # both end with: 🟢 pserranoa/openvpn-bf
   ```

4. Mount **only the log file** read-only (its folder holds the server's keys), e.g.
   `/srv/openvpn/conf/openvpn.log:/var/log/openvpn/openvpn.log:ro`, and add the OpenVPN section to
   `crowdsec/acquis.yaml`. Recreate CrowdSec.
5. `docker compose exec crowdsec cscli metrics show acquisition` lists
   `file:/var/log/openvpn/openvpn.log` with lines read. Most lines are "unparsed": only failures
   are parsed.

Limits of that parser: IPv4 clients only, and its "TLS handshake failed" pattern needs `from …`
after the message; OpenVPN versions that log it without `from` (plain scanners) are not counted.
Failed logins and certificate errors are.

**WireGuard** needs nothing: it does not answer packets without a valid key, so there is no failure
to detect.

## Day to day

- **Logs:** `docker compose logs -f crowdsec-firewall-bouncer`.
- **Unban:** `docker compose exec crowdsec cscli decisions delete --ip <address>`; the set follows
  within `update_frequency`.
- **Stop:** `docker compose stop crowdsec-firewall-bouncer` removes its chain and rules; nothing to
  clean up. If you lock yourself out, stop it from the provider's console.
- **CrowdSec down:** the bouncer keeps the sets it has and retries; bans that expire meanwhile are
  removed when it reconnects.
- **fail2ban side by side:** both can run; `CROWDSEC_CHAIN` sits above fail2ban's chains. Compare
  `cscli alerts list` with fail2ban's bans for a week before removing jails that overlap
  (`sshd`, `openvpn`, `traefik`).

## Updating

1. Find the new version on the release page
   (`https://github.com/crowdsecurity/cs-firewall-bouncer/releases`) and record its checksums:

   ```sh
   V=v0.0.39
   for a in amd64 arm64; do
     curl -fsSL "https://github.com/crowdsecurity/cs-firewall-bouncer/releases/download/$V/crowdsec-firewall-bouncer-linux-$a.tgz" | sha256sum
   done
   ```

2. Put `VERSION` and both values in `build.bash`, run it.
3. Change the image tag in `compose.firewall-bouncer.yml`, `docker compose up -d`. The old image
   stays until `docker image rm` for a quick rollback (old tag back in compose, `up -d`).

## Pitfalls

| Symptom | Cause | Fix |
|---|---|---|
| CrowdSec restarts after an `acquis.yaml` edit, `type: authelia---` | the file had no final newline, the appended `---` stuck to its last line | split the line; check with `tail -c1 acquis.yaml \| od -c` before appending |
| `cannot assign requested address` for CrowdSec's port; afterwards CrowdSec has no network | a published address that does not exist on the host (a VPN address inside a container) | publish `127.0.0.1` only |
| rules exist but nothing is dropped | iptables backend differs between image and host | `build.bash` checks it; switch one side |
| Docker-published ports (a VPN server in a container) not covered | only `INPUT` listed | keep `DOCKER-USER` in `iptables_chains` |
| `grep crowdsec` finds no rule | the chain is `CROWDSEC_CHAIN` | `grep -i` |
| `ipset: command not found` on the host | it is installed in the image | `docker compose exec crowdsec-firewall-bouncer ipset list -n` |
| `pull access denied for local/crowdsec-firewall-bouncer` | the image was not built on this host | run `build.bash` (the overlay sets `pull_policy: never`) |
