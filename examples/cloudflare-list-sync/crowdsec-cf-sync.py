#!/usr/bin/env python3
"""Mirror CrowdSec's own bans into a Cloudflare IP list (used by a WAF rule: ip.src in $list).
Guide: docs/cloudflare-list-sync.md.

Every INTERVAL seconds:
  wanted  = active CrowdSec decisions of type ban, from ORIGINS (default: crowdsec, cscli;
            NOT the community blocklist: it is larger than a free plan's list)
  current = list items whose comment starts with "crowdsec" (items you added by hand are
            never touched)
  then adds what is missing and removes what expired.

IPv6 addresses are listed as their /64 (one host usually owns the whole /64).
If CrowdSec cannot be reached, the cycle is skipped: nothing is removed from the list.
Only the Python standard library: no pip, nothing downloaded at run time.

Environment:
  LAPI_URL       http://crowdsec:8080
  LAPI_KEY       a bouncer key (cscli bouncers add cloudflare-list -o raw)
  CF_API_TOKEN   API token with Account > Account Filter Lists > Edit
  CF_ACCOUNT_ID  account id (32 hex)
  CF_LIST_ID     list id (32 hex)
  ORIGINS        crowdsec,cscli
  INTERVAL       60
  MAX_ITEMS      5000   cap for items owned by this tool (free plan: 10000 in total)
  DRY_RUN        1 = only log what would change
"""

from __future__ import annotations

import ipaddress
import json
import os
import sys
import time
import urllib.error
import urllib.request

TAG = "crowdsec"
CF_API = os.environ.get("CF_API", "https://api.cloudflare.com/client/v4").rstrip("/")


def env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if not value:
        sys.exit(f"missing environment variable {name}")
    return value


def log(msg: str) -> None:
    print(time.strftime("%Y-%m-%dT%H:%M:%S"), msg, flush=True)


def call(method: str, url: str, headers: dict[str, str], body: object = None) -> object:
    if not url.startswith(("http://", "https://")):  # never file: or other schemes
        raise ValueError(f"refusing URL {url!r}")
    data = json.dumps(body).encode() if body is not None else None
    hdrs = dict(headers)
    if data is not None:
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)  # noqa: S310
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (scheme checked above)
        raw = resp.read()
    return json.loads(raw) if raw else None


def normalise(value: str) -> str | None:
    """'203.0.113.9' -> '203.0.113.9'; a range stays a range; IPv6 becomes its /64."""
    try:
        net = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return None
    if net.version == 6 and net.prefixlen > 64:
        net = net.supernet(new_prefix=64)
    if net.num_addresses == 1:
        return str(net.network_address)
    return str(net)


class Sync:
    def __init__(self) -> None:
        self.lapi = env("LAPI_URL", "http://crowdsec:8080").rstrip("/")
        self.lapi_headers = {"X-Api-Key": env("LAPI_KEY"), "User-Agent": "crowdsec-cf-sync"}
        account = env("CF_ACCOUNT_ID")
        self.items_url = f"{CF_API}/accounts/{account}/rules/lists/{env('CF_LIST_ID')}/items"
        self.ops_url = f"{CF_API}/accounts/{account}/rules/lists/bulk_operations"
        self.cf_headers = {"Authorization": f"Bearer {env('CF_API_TOKEN')}"}
        self.origins = {o.strip() for o in env("ORIGINS", "crowdsec,cscli").split(",") if o.strip()}
        self.max_items = int(env("MAX_ITEMS", "5000"))
        self.dry_run = os.environ.get("DRY_RUN") == "1"

    def wanted(self) -> dict[str, str]:
        decisions = call("GET", f"{self.lapi}/v1/decisions", self.lapi_headers) or []
        out: dict[str, str] = {}
        for d in decisions:  # type: ignore[union-attr]
            if d.get("type") != "ban" or d.get("origin") not in self.origins:
                continue
            if str(d.get("scope", "")).lower() not in ("ip", "range"):
                continue
            item = normalise(str(d.get("value", "")))
            if item:
                out[item] = str(d.get("scenario") or "manual")
        return out

    def current(self) -> tuple[dict[str, str], set[str]]:
        owned: dict[str, str] = {}
        present: set[str] = set()
        cursor = ""
        while True:
            url = f"{self.items_url}?per_page=500" + (f"&cursor={cursor}" if cursor else "")
            page = call("GET", url, self.cf_headers)
            for item in page["result"]:  # type: ignore[index]
                ip = normalise(item.get("ip", ""))
                if not ip:
                    continue
                present.add(ip)
                if str(item.get("comment") or "").startswith(TAG):
                    owned[ip] = item["id"]
            cursor = ((page.get("result_info") or {}).get("cursors") or {}).get("after", "")  # type: ignore[union-attr]
            if not cursor:
                return owned, present

    def wait(self, response: object) -> None:
        op = ((response or {}).get("result") or {}).get("operation_id")  # type: ignore[union-attr]
        if not op:
            return
        for _ in range(60):
            status = call("GET", f"{self.ops_url}/{op}", self.cf_headers)
            state = (status.get("result") or {}).get("status")  # type: ignore[union-attr]
            if state == "completed":
                return
            if state == "failed":
                raise RuntimeError(f"bulk operation failed: {status}")
            time.sleep(2)
        raise RuntimeError(f"bulk operation {op} still pending")

    def run_once(self) -> None:
        try:
            wanted = self.wanted()
        except (urllib.error.URLError, OSError, ValueError) as err:
            log(f"CrowdSec unreachable ({err}); list left as it is")
            return
        owned, present = self.current()
        add = [ip for ip in wanted if ip not in present]
        remove = [ip for ip in owned if ip not in wanted]
        room = self.max_items - (len(owned) - len(remove))
        if len(add) > room:
            log(f"cap MAX_ITEMS={self.max_items}: adding {max(room, 0)} of {len(add)}")
            add = add[: max(room, 0)]
        if not add and not remove:
            return
        for verb, ips in (("add", add), ("remove", remove)):
            if ips:
                log(f"{verb} {len(ips)}: {' '.join(ips[:10])}{' ...' if len(ips) > 10 else ''}")
        if self.dry_run:
            return
        for i in range(0, len(remove), 1000):
            ids = [{"id": owned[ip]} for ip in remove[i : i + 1000]]
            self.wait(call("DELETE", self.items_url, self.cf_headers, {"items": ids}))
        for i in range(0, len(add), 1000):
            body = [{"ip": ip, "comment": f"{TAG}: {wanted[ip]}"[:100]} for ip in add[i : i + 1000]]
            self.wait(call("POST", self.items_url, self.cf_headers, body))


def main() -> None:
    sync = Sync()
    interval = int(env("INTERVAL", "60"))
    once = "--once" in sys.argv
    mode = " (dry run)" if sync.dry_run else ""
    log(f"syncing origins {sorted(sync.origins)} every {interval}s{mode}")
    while True:
        try:
            sync.run_once()
        except urllib.error.HTTPError as err:
            log(f"HTTP {err.code} from {err.url}: {err.read()[:300]!r}")
        except Exception as err:  # keep running; the next cycle retries
            log(f"error: {err}")
        if once:
            return
        time.sleep(interval)


if __name__ == "__main__":
    main()
