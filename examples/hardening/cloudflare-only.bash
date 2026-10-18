#!/usr/bin/env bash
# Accept new connections to ports 80/443 on the public interface only from Cloudflare.
# Docker's published ports bypass ufw/INPUT, so the rules go in Docker's DOCKER-USER chain.
# Only 80/443 on the public interface are touched: SSH, the VPN, any other published port and
# everything arriving over the VPN interface keep working as before. Guide: docs/hardening.md.
#
#   sudo ./cloudflare-only.bash show       # what it would do (default)
#   sudo ./cloudflare-only.bash apply      # load Cloudflare's ranges and add the rule
#   sudo ./cloudflare-only.bash remove     # undo
#   sudo ./cloudflare-only.bash status
#
# Needs: iptables, ipset (apt install ipset), curl. Re-run `apply` after a reboot or let the
# systemd unit at the bottom do it.
set -euo pipefail

IFACE="${IFACE:-$(ip route show default | awk '{print $5; exit}')}"
SET=cloudflare4
TAG="cloudflare-only"
RANGES_URL="https://www.cloudflare.com/ips-v4"

# the one rule, as iptables arguments
RULE=(-i "$IFACE" -p tcp -m multiport --dports "80,443" -m conntrack --ctstate NEW
      -m set ! --match-set "$SET" src -m comment --comment "$TAG" -j DROP)

load_set() {
  local ranges
  ranges="$(curl -fsS --max-time 15 "$RANGES_URL")"
  # refuse to continue on an empty or odd answer: an empty set would drop all web traffic
  [ "$(grep -cE '^[0-9.]+/[0-9]+$' <<<"$ranges")" -ge 10 ] || { echo "unexpected answer from $RANGES_URL" >&2; exit 1; }
  ipset create -exist "$SET" hash:net
  ipset create -exist "$SET-new" hash:net
  ipset flush "$SET-new"
  while read -r net; do [ -n "$net" ] && ipset add "$SET-new" "$net"; done <<<"$ranges"
  ipset swap "$SET-new" "$SET" && ipset destroy "$SET-new"
}

has_rule() { iptables -C DOCKER-USER "${RULE[@]}" 2>/dev/null; }

case "${1:-show}" in
  show)
    echo "public interface: $IFACE   (override: IFACE=eth0 $0 apply)"
    echo "would add:  iptables -I DOCKER-USER ${RULE[*]}"
    echo "Cloudflare ranges:"; curl -fsS --max-time 15 "$RANGES_URL" | sed 's/^/  /'
    echo "Before applying: every hostname on 80/443 must be proxied (orange cloud) in Cloudflare."
    ;;
  apply)
    [ -n "$IFACE" ] || { echo "no default-route interface found; set IFACE=" >&2; exit 1; }
    iptables -L DOCKER-USER -n >/dev/null 2>&1 || { echo "DOCKER-USER chain missing (is Docker running?)" >&2; exit 1; }
    load_set
    has_rule || iptables -I DOCKER-USER "${RULE[@]}"
    echo "applied on $IFACE: $(ipset list $SET | grep -c '/') Cloudflare ranges allowed on 80/443"
    ;;
  remove)
    while has_rule; do iptables -D DOCKER-USER "${RULE[@]}"; done
    ipset destroy "$SET" 2>/dev/null || true
    echo "removed"
    ;;
  status)
    iptables -L DOCKER-USER -n -v --line-numbers | grep -E "Chain|$TAG" || true
    ipset list "$SET" 2>/dev/null | sed -n '1,8p' || echo "set $SET not loaded"
    ;;
  *) echo "usage: $0 show|apply|remove|status" >&2; exit 2 ;;
esac

# Keep it across reboots (and refresh the ranges weekly):
#   sudo cp cloudflare-only.bash /usr/local/sbin/ && sudo chmod 755 /usr/local/sbin/cloudflare-only.bash
#   /etc/systemd/system/cloudflare-only.service:
#     [Unit]
#     Description=Ports 80/443 from Cloudflare only
#     After=docker.service network-online.target
#     Requires=docker.service
#     [Service]
#     Type=oneshot
#     ExecStart=/usr/local/sbin/cloudflare-only.bash apply
#     RemainAfterExit=yes
#     [Install]
#     WantedBy=multi-user.target
#   /etc/systemd/system/cloudflare-only.timer:  [Timer] OnCalendar=weekly  Persistent=true
#                                               [Install] WantedBy=timers.target
#   sudo systemctl daemon-reload && sudo systemctl enable --now cloudflare-only.service cloudflare-only.timer
