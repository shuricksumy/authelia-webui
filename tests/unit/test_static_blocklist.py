"""examples/static-blocklist: the watcher against a fake CrowdSec API, and its overlay.

The fake mirrors what CrowdSec 1.8.1 does (checked against a real instance): machine logins with a
User-Agent that is not "name/version" are refused, alerts carry their decisions, and a deleted
decision stays listed with duration "0s" until cleanup.
"""

from __future__ import annotations

import importlib.util
import json
import re
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import ModuleType
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from ruamel.yaml import YAML

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "examples" / "static-blocklist" / "crowdsec-static-blocklist.py"
EXAMPLE = ROOT / "examples" / "static-blocklist" / "static-blocklist.example.txt"
OVERLAY = ROOT / "examples" / "production" / "compose.static-blocklist.yml"
CF_OVERLAY = ROOT / "examples" / "production" / "compose.cloudflare-list-sync.yml"


class FakeLapi:
    def __init__(self) -> None:
        # each decision: id, origin, scenario, scope, value, deleted
        self.decisions: list[dict[str, Any]] = []
        self.next_id = 1

    def active(self) -> list[tuple[str, str, str]]:
        live = [d for d in self.decisions if not d["deleted"]]
        return sorted((d["origin"], d["scope"], d["value"]) for d in live)


def _handler(fake: FakeLapi) -> type[BaseHTTPRequestHandler]:
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

        def _authorised(self) -> bool:
            return self.headers.get("Authorization") == "Bearer jwt"

        def do_POST(self) -> None:
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if self.path == "/v1/watchers/login":
                ua_ok = re.fullmatch(r"[\w.-]+/[\w.-]+", self.headers.get("User-Agent", ""))
                creds_ok = (body["machine_id"], body["password"]) == ("static-blocklist", "pw")
                if not (ua_ok and creds_ok):
                    return self._send(401, {"message": "incorrect Username or Password"})
                return self._send(200, {"code": 200, "token": "jwt"})
            assert self.path == "/v1/alerts" and self._authorised()
            for alert in body:
                assert alert["source"]["value"] and alert["scenario"] == "static-blocklist"
                for d in alert["decisions"]:
                    fake.decisions.append({**d, "id": fake.next_id, "deleted": False})
                    fake.next_id += 1
            return self._send(201, [str(fake.next_id)])

        def do_GET(self) -> None:
            assert self._authorised()
            url = urlparse(self.path)
            assert url.path == "/v1/alerts"
            scenario = parse_qs(url.query)["scenario"][0]
            decisions = [
                {**d, "duration": "0s" if d["deleted"] else "87599h59m50s"}
                for d in fake.decisions if d["scenario"] == scenario
            ]  # fmt: skip
            return self._send(200, [{"id": 1, "decisions": decisions}] if decisions else [])

        def do_DELETE(self) -> None:
            assert self._authorised()
            ident = int(self.path.rsplit("/", 1)[1])
            for d in fake.decisions:
                if d["id"] == ident:
                    d["deleted"] = True  # stays listed with "0s", like CrowdSec
            return self._send(200, {"nbDeleted": "1"})

    return H


@pytest.fixture
def world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[FakeLapi, Any, Path]]:
    fake = FakeLapi()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(fake))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    list_file = tmp_path / "static-blocklist.txt"
    monkeypatch.setenv("LAPI_URL", f"http://127.0.0.1:{server.server_address[1]}")
    monkeypatch.setenv("MACHINE_ID", "static-blocklist")
    monkeypatch.setenv("MACHINE_PASSWORD", "pw")
    monkeypatch.setenv("LIST_FILE", str(list_file))
    spec = importlib.util.spec_from_file_location("crowdsec_static_blocklist", SCRIPT)
    assert spec and spec.loader
    module: ModuleType = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    yield fake, module, list_file
    server.shutdown()


def test_file_lines_become_bans_and_deleted_lines_lift_them(
    world: tuple[FakeLapi, Any, Path],
) -> None:
    fake, module, list_file = world
    blocklist = module.Blocklist()
    list_file.write_text(
        "192.0.2.200   # single\n198.51.100.0/24 # range\nnot-an-ip\n"
        "2001:db8::7\n203.0.113.5/32\n\n# comment only\n"
    )
    blocklist.apply()
    assert fake.active() == [
        ("static-blocklist", "Ip", "192.0.2.200"),
        ("static-blocklist", "Ip", "2001:db8::7"),
        ("static-blocklist", "Ip", "203.0.113.5"),  # a /32 is a single address
        ("static-blocklist", "Range", "198.51.100.0/24"),
    ]
    count = len(fake.decisions)
    blocklist.apply()
    assert len(fake.decisions) == count  # nothing added twice

    list_file.write_text("192.0.2.200\n2001:db8::7\n203.0.113.5\n")
    blocklist.apply()
    assert ("static-blocklist", "Range", "198.51.100.0/24") not in fake.active()

    list_file.write_text("192.0.2.200\n2001:db8::7\n203.0.113.5\n198.51.100.0/24\n")
    blocklist.apply()  # re-added right after removal: the "0s" leftover does not hide it
    assert ("static-blocklist", "Range", "198.51.100.0/24") in fake.active()


def test_restores_hand_deleted_bans_and_never_acts_on_a_missing_file(
    world: tuple[FakeLapi, Any, Path],
) -> None:
    fake, module, list_file = world
    blocklist = module.Blocklist()
    list_file.write_text("192.0.2.200\n")
    blocklist.apply()
    fake.decisions[0]["deleted"] = True  # someone ran cscli decisions delete
    blocklist.apply()
    assert fake.active() == [("static-blocklist", "Ip", "192.0.2.200")]

    list_file.unlink()
    blocklist.apply()  # missing file: nothing changes
    assert fake.active() == [("static-blocklist", "Ip", "192.0.2.200")]

    list_file.write_text("# nothing left\n")
    blocklist.apply()  # an empty list lifts every ban it owns
    assert fake.active() == []


def test_watch_loop_applies_a_saved_change(
    world: tuple[FakeLapi, Any, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    fake, module, list_file = world
    list_file.write_text("")
    monkeypatch.setenv("CHECK", "1")
    loop = threading.Thread(target=module.main, daemon=True)
    loop.start()
    time.sleep(0.5)
    list_file.write_text("192.0.2.201  # saved while watching\n")
    for _ in range(40):
        if fake.active():
            break
        time.sleep(0.1)
    assert fake.active() == [("static-blocklist", "Ip", "192.0.2.201")]


def test_login_user_agent_has_the_form_crowdsec_requires() -> None:
    assert re.search(r'"User-Agent": "crowdsec-static-blocklist/[\d.]+"', SCRIPT.read_text())


def test_parse_skips_invalid_lines_and_normalises() -> None:
    spec = importlib.util.spec_from_file_location("sb_parse", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    wanted, bad = module.parse("10.0.0.1/24\nfoo\n2001:db8::1/128 # x\n")
    assert wanted == {"10.0.0.0/24": "Range", "2001:db8::1": "Ip"} and bad == ["foo"]
    example, _ = module.parse(EXAMPLE.read_text())
    assert example == {}  # the example file only holds commented-out samples


def test_overlay_mounts_the_list_folder_read_only_and_runs_unprivileged() -> None:
    svc = YAML(typ="safe").load(OVERLAY.read_text())["services"]["crowdsec-static-blocklist"]
    assert svc["user"] == "65534:65534" and svc["read_only"] is True
    assert svc["cap_drop"] == ["ALL"] and "cap_add" not in svc and "ports" not in svc
    volumes = [str(v) for v in svc["volumes"]]
    assert all(v.endswith(":ro") for v in volumes)
    assert any(v.endswith(":/data:ro") for v in volumes)  # the folder, not the file
    assert not any("docker.sock" in v for v in volumes)
    assert svc["environment"]["LIST_FILE"].startswith("/data/")
    assert svc["environment"]["MACHINE_PASSWORD"].startswith("${CROWDSEC_BLOCKLIST_PASSWORD")
    cf = YAML(typ="safe").load(CF_OVERLAY.read_text())["services"]["crowdsec-cf-sync"]
    assert "static-blocklist" in cf["environment"]["ORIGINS"].split(",")
