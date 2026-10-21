#!/usr/bin/env python3
"""Keep CrowdSec's bans in step with a text file: one IP or CIDR per line, `#` starts a comment.
Guide: docs/static-blocklist.md.

Watches LIST_FILE; within CHECK seconds of a change it adds a ban for every new line and removes
the ban of every deleted line. It also re-checks every RECHECK seconds, so a ban deleted by hand
(cscli) comes back while its line is in the file. The bans carry origin and reason
"static-blocklist", so every bouncer enforces them and they are told apart from other bans.

It talks to CrowdSec's API with a machine login (no Docker socket, no cscli):
  cscli machines add static-blocklist --password <password> -f -

If the file is missing or unreadable, nothing is changed. An empty file removes all its bans.
Only the Python standard library.

Environment:
  LAPI_URL          http://crowdsec:8080
  MACHINE_ID        static-blocklist
  MACHINE_PASSWORD  the machine's password
  LIST_FILE         /data/static-blocklist.txt
  DURATION          87600h  (10 years; the file decides when a ban ends)
  CHECK             5       seconds between looks at the file
  RECHECK           600     seconds between full comparisons with CrowdSec
"""

from __future__ import annotations

import ipaddress
import json
import os
import sys
import time
import urllib.error
import urllib.request

NAME = "static-blocklist"


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
    # CrowdSec refuses a machine login whose User-Agent is not "name/version"
    hdrs = {"User-Agent": "crowdsec-static-blocklist/1.0", **headers}
    if data is not None:
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)  # noqa: S310
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (scheme checked above)
        raw = resp.read()
    return json.loads(raw) if raw else None


def parse(text: str) -> tuple[dict[str, str], list[str]]:
    """Lines -> {value: scope}; invalid lines are returned separately (and skipped)."""
    wanted: dict[str, str] = {}
    bad: list[str] = []
    for line in text.splitlines():
        entry = line.split("#", 1)[0].strip()
        if not entry:
            continue
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            bad.append(entry)
            continue
        if net.num_addresses == 1:
            wanted[str(net.network_address)] = "Ip"
        else:
            wanted[str(net)] = "Range"
    return wanted, bad


def active(duration: str) -> bool:
    return bool(duration) and duration != "0s" and not duration.startswith("-")


class Blocklist:
    def __init__(self) -> None:
        self.lapi = env("LAPI_URL", "http://crowdsec:8080").rstrip("/")
        self.machine = env("MACHINE_ID", NAME)
        self.password = env("MACHINE_PASSWORD")
        self.path = env("LIST_FILE", "/data/static-blocklist.txt")
        self.duration = env("DURATION", "87600h")

    def headers(self) -> dict[str, str]:
        body = {"machine_id": self.machine, "password": self.password, "scenarios": []}
        token = call("POST", f"{self.lapi}/v1/watchers/login", {}, body)["token"]  # type: ignore[index]
        return {"Authorization": f"Bearer {token}"}

    def current(self, headers: dict[str, str]) -> dict[str, int]:
        url = f"{self.lapi}/v1/alerts?scenario={NAME}&has_active_decision=true&limit=0"
        out: dict[str, int] = {}
        for alert in call("GET", url, headers) or []:  # type: ignore[union-attr]
            for d in alert.get("decisions") or []:
                if d.get("origin") == NAME and active(str(d.get("duration", ""))):
                    out[str(d["value"])] = int(d["id"])
        return out

    def apply(self) -> None:
        try:
            with open(self.path, encoding="utf-8") as fh:
                wanted, bad = parse(fh.read())
        except OSError as err:
            log(f"cannot read {self.path} ({err}); nothing changed")
            return
        for entry in bad:
            log(f"skipped, not an IP or CIDR: {entry!r}")
        headers = self.headers()
        current = self.current(headers)
        add = [v for v in wanted if v not in current]
        remove = [v for v in current if v not in wanted]
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        for i in range(0, len(add), 500):
            chunk = add[i : i + 500]
            decisions = [
                {"duration": self.duration, "origin": NAME, "scenario": NAME, "type": "ban",
                 "scope": wanted[v], "value": v}
                for v in chunk
            ]  # fmt: skip
            first = chunk[0]
            source = {"scope": wanted[first], "value": first}
            source["ip" if wanted[first] == "Ip" else "range"] = first
            alert = {
                "scenario": NAME, "scenario_hash": "", "scenario_version": "", "message": NAME,
                "events_count": len(chunk), "start_at": now, "stop_at": now, "capacity": 0,
                "leakspeed": "0", "simulated": False, "events": [], "source": source,
                "decisions": decisions,
            }  # fmt: skip
            call("POST", f"{self.lapi}/v1/alerts", headers, [alert])
        for v in remove:
            call("DELETE", f"{self.lapi}/v1/decisions/{current[v]}", headers)
        for verb, values in (("added", add), ("removed", remove)):
            if values:
                more = " ..." if len(values) > 10 else ""
                shown = " ".join(values[:10])
                log(f"{verb} {len(values)}: {shown}{more} ({len(wanted)} in the file)")


def main() -> None:
    blocklist = Blocklist()
    check = int(env("CHECK", "5"))
    recheck = int(env("RECHECK", "600"))
    once = "--once" in sys.argv
    log(f"watching {blocklist.path} (every {check}s, full check every {recheck}s)")
    seen: tuple[float, int] | None = None
    last_full = 0.0
    while True:
        try:
            st = os.stat(blocklist.path)
            stamp: tuple[float, int] | None = (st.st_mtime, st.st_size)
        except OSError:
            stamp = None
        if stamp != seen or time.monotonic() - last_full >= recheck:
            try:
                blocklist.apply()
                seen = stamp
                last_full = time.monotonic()
            except urllib.error.HTTPError as err:
                log(f"HTTP {err.code} from {err.url}: {err.read()[:300]!r}")
            except Exception as err:  # keep watching; the next look retries
                log(f"error: {err}")
        if once:
            return
        time.sleep(check)


if __name__ == "__main__":
    main()
