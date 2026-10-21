"""examples/cloudflare-list-sync: the sync against fake CrowdSec and Cloudflare APIs; its overlay.

The fakes behave like the real APIs where it matters: the list is paged (per_page <= 500), writes
are asynchronous bulk operations, and only one operation per account may be pending.
"""

from __future__ import annotations

import importlib.util
import json
import threading
import uuid
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import ModuleType
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from ruamel.yaml import YAML

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "examples" / "cloudflare-list-sync" / "crowdsec-cf-sync.py"
OVERLAY = ROOT / "examples" / "production" / "compose.cloudflare-list-sync.yml"


class Fake:
    def __init__(self) -> None:
        self.decisions: list[dict[str, str]] = []
        self.items: list[dict[str, str]] = []
        self.ops: dict[str, int] = {}
        self.pending: str | None = None
        self.lapi_up = True
        self.log: list[str] = []


def _handler(fake: Fake, lapi_port: list[int]) -> type[BaseHTTPRequestHandler]:
    class H(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def _send(self, code: int, obj: object) -> None:
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body(self) -> Any:
            n = int(self.headers.get("Content-Length") or 0)
            return json.loads(self.rfile.read(n)) if n else None

        def do_GET(self) -> None:
            url = urlparse(self.path)
            if self.server.server_address[1] == lapi_port[0]:
                if self.headers.get("X-Api-Key") != "lapi-key":
                    return self._send(403, {"message": "forbidden"})
                if not fake.lapi_up:
                    return self._send(500, {"message": "down"})
                return self._send(200, fake.decisions)
            assert self.headers.get("Authorization") == "Bearer cf-token"
            if "/bulk_operations/" in url.path:
                op = url.path.rsplit("/", 1)[1]
                fake.ops[op] += 1
                done = fake.ops[op] >= 2  # pending on the first poll
                if done:
                    fake.pending = None
                return self._send(200, {"result": {"status": "completed" if done else "pending"}})
            query = parse_qs(url.query)
            per = int(query.get("per_page", ["25"])[0])
            assert 1 <= per <= 500
            start = int(query.get("cursor", ["0"])[0])
            more = start + per < len(fake.items)
            info = {"cursors": {"after": str(start + per)}} if more else {"cursors": {}}
            page = fake.items[start : start + per]
            return self._send(200, {"success": True, "result": page, "result_info": info})

        def _op(self) -> str | None:
            if fake.pending:
                fake.log.append("REJECTED: operation pending")
                return None
            op = uuid.uuid4().hex
            fake.ops[op] = 0
            fake.pending = op
            return op

        def do_POST(self) -> None:
            op = self._op()
            if not op:
                return self._send(400, {"success": False})
            for item in self._body():
                fake.items.append({"id": uuid.uuid4().hex[:8], **item})
                fake.log.append(f"ADD {item['ip']} [{item['comment']}]")
            self._send(200, {"success": True, "result": {"operation_id": op}})

        def do_DELETE(self) -> None:
            op = self._op()
            if not op:
                return self._send(400, {"success": False})
            ids = {i["id"] for i in self._body()["items"]}
            fake.log += [f"DEL {i['ip']}" for i in fake.items if i["id"] in ids]
            fake.items[:] = [i for i in fake.items if i["id"] not in ids]
            self._send(200, {"success": True, "result": {"operation_id": op}})

    return H


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[Fake, Any]]:
    fake = Fake()
    lapi_port: list[int] = [0]
    handler = _handler(fake, lapi_port)
    lapi = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    cf = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    lapi_port[0] = lapi.server_address[1]
    for server in (lapi, cf):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setenv("LAPI_URL", f"http://127.0.0.1:{lapi.server_address[1]}")
    monkeypatch.setenv("LAPI_KEY", "lapi-key")
    monkeypatch.setenv("CF_API", f"http://127.0.0.1:{cf.server_address[1]}")
    monkeypatch.setenv("CF_API_TOKEN", "cf-token")
    monkeypatch.setenv("CF_ACCOUNT_ID", "a" * 32)
    monkeypatch.setenv("CF_LIST_ID", "b" * 32)
    monkeypatch.delenv("DRY_RUN", raising=False)
    spec = importlib.util.spec_from_file_location("crowdsec_cf_sync", SCRIPT)
    assert spec and spec.loader
    module: ModuleType = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module.time, "sleep", lambda _s: None)
    yield fake, module
    lapi.shutdown()
    cf.shutdown()


def _ban(
    value: str, origin: str = "crowdsec", type_: str = "ban", scope: str = "Ip"
) -> dict[str, str]:
    return {"origin": origin, "type": type_, "scope": scope, "value": value, "scenario": "s/x"}


def _listed(fake: Fake) -> set[str]:
    return {i["ip"] for i in fake.items if i["comment"] != "filler"}


def test_mirrors_own_bans_keeps_manual_items_and_follows_pages(world: tuple[Fake, Any]) -> None:
    fake, module = world
    fake.items = [
        {"id": "m1", "ip": "198.51.100.1", "comment": "added by hand"},
        {"id": "o1", "ip": "192.0.2.50", "comment": "crowdsec: old"},
        *(
            {"id": f"f{n}", "ip": f"10.9.{n // 250}.{n % 250}", "comment": "filler"}
            for n in range(600)
        ),
    ]
    fake.decisions = [
        _ban("203.0.113.9"),
        _ban("2001:db8:1:2::5", origin="cscli"),  # -> its /64
        _ban("192.0.2.0/28", origin="cscli", scope="Range"),
        _ban("198.51.100.1"),  # already listed by hand: not added twice
        _ban("203.0.113.77", origin="CAPI"),  # community blocklist: never mirrored
        _ban("203.0.113.88", type_="captcha"),  # not a ban
    ]
    sync = module.Sync()
    sync.run_once()
    assert _listed(fake) == {"198.51.100.1", "203.0.113.9", "2001:db8:1:2::/64", "192.0.2.0/28"}
    assert "REJECTED: operation pending" not in fake.log  # waits for each bulk operation
    assert any(e.startswith("ADD 203.0.113.9 [crowdsec: s/x]") for e in fake.log)

    fake.log.clear()
    sync.run_once()
    assert fake.log == []  # nothing to do: own items are recognised on later pages too

    fake.decisions = [d for d in fake.decisions if d["value"] != "203.0.113.9"]  # ban expired
    sync.run_once()
    assert fake.log == ["DEL 203.0.113.9"]


def test_crowdsec_down_or_empty_never_removes_manual_items(world: tuple[Fake, Any]) -> None:
    fake, module = world
    fake.items = [{"id": "m1", "ip": "198.51.100.1", "comment": "added by hand"}]
    fake.decisions = [_ban("203.0.113.9")]
    sync = module.Sync()
    sync.run_once()
    fake.lapi_up = False
    fake.log.clear()
    sync.run_once()
    assert fake.log == []  # unreachable: list left as it is
    assert _listed(fake) == {"198.51.100.1", "203.0.113.9"}

    fake.lapi_up = True
    fake.decisions = []
    sync.run_once()
    assert _listed(fake) == {"198.51.100.1"}  # only its own items go


def test_dry_run_and_cap(world: tuple[Fake, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    fake, module = world
    fake.decisions = [_ban(f"203.0.113.{n}") for n in range(1, 11)]
    monkeypatch.setenv("DRY_RUN", "1")
    module.Sync().run_once()
    assert fake.items == []
    monkeypatch.delenv("DRY_RUN")
    monkeypatch.setenv("MAX_ITEMS", "4")
    module.Sync().run_once()
    assert len(fake.items) == 4


def test_refuses_non_http_urls(world: tuple[Fake, Any]) -> None:
    _fake, module = world
    with pytest.raises(ValueError, match="refusing URL"):
        module.call("GET", "file:///etc/passwd", {})


def test_overlay_runs_unprivileged_with_a_token_and_reads_only_decisions() -> None:
    services = YAML(typ="safe").load(OVERLAY.read_text())["services"]
    svc = services["crowdsec-cf-sync"]
    assert svc["user"] == "65534:65534" and svc["read_only"] is True
    assert svc["cap_drop"] == ["ALL"] and "cap_add" not in svc
    assert "ports" not in svc and all(str(v).endswith(":ro") for v in svc["volumes"])
    env = svc["environment"]
    assert set(env["ORIGINS"].split(",")) == {"crowdsec", "cscli", "static-blocklist"}  # no CAPI
    assert env["DRY_RUN"] == "1"  # first start logs only
    assert env["CF_API_TOKEN"].startswith("${CF_API_TOKEN")
    assert env["LAPI_KEY"].startswith("${CROWDSEC_CF_SYNC_KEY")
    registered = services["crowdsec"]["environment"]["BOUNCER_KEY_cloudflare_list"]
    assert registered.startswith("${CROWDSEC_CF_SYNC_KEY")
    assert "X-Auth-Key" not in SCRIPT.read_text()  # no Global API Key support at all
