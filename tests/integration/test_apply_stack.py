"""Apply against the real stack: socket proxy, Authelia restart, health check, rollback.

The proxy only accepts the configurator containers, so the engine runs *inside* them
(`docker compose exec`); the host only observes the effects.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from tests.e2e.conftest import compose, stack_env
from tests.fixtures.stack import STACK, prepare

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[2]
AUTHELIA = "authelia-webui-authelia-1"
FORWARD_AUTH = "http://127.0.0.1:19091/api/authz/forward-auth"

APPLY_SCRIPT = """
import json, os
from app.settings import load_settings
from app.apply.engine import ApplyEngine, ApplyRequest
from app.apply.jobs import JobBoard
from app.apply.runtime import AutheliaRuntime
from app.apply.validate import validate_candidate
from app.rules.store import DraftStore, sha256

s = load_settings()
store = DraftStore(s.CONFIG_MANAGED_DIR)
doc = store.current()
domain, old, new = os.environ["T_DOMAIN"], os.environ["T_FROM"], os.environ["T_TO"]
idx = next(i for i, r in enumerate(doc.rules())
           if r.get("domain") == domain and r.get("policy") == old)
node = doc.blocks[idx].node()
node["policy"] = new
store.save(doc.replace_rule(idx, node, note=os.environ.get("T_NOTE") or None))
rev = sha256(store.current().render())[:16]
engine = ApplyEngine(s, AutheliaRuntime(s.DOCKER_PROXY_URL, s.AUTHELIA_CONTAINER),
                     JobBoard(s.CONFIG_MANAGED_DIR), validate_candidate)
job = engine.board.new("alice")
engine.apply(ApplyRequest("alice", "10.8.0.5", rev), job)
print(json.dumps({"result": job.result, "message": job.message, "details": job.details,
                  "steps": [[x.name, x.status] for x in job.steps]}))
"""


@pytest.fixture(scope="module")
def stack() -> Iterator[dict[str, str]]:
    if subprocess.run(["docker", "info"], capture_output=True, check=False).returncode != 0:
        pytest.skip("docker daemon not running")
    prepare()
    env = stack_env()
    up = compose("up", "-d", "--build", "--wait", "--wait-timeout", "240", env=env)
    try:
        assert up.returncode == 0, up.stderr[-2000:]
        yield env
    finally:
        compose("down", "-v", "--remove-orphans", env=env)


def exec_python(
    env: dict[str, str], service: str, script: str, variables: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    flags = [arg for k, v in (variables or {}).items() for arg in ("-e", f"{k}={v}")]
    return subprocess.run(
        ["docker", "compose", "-f", str(ROOT / "compose.test.yml"), "exec", "-T", *flags, service,
         "python", "-"],
        input=script, capture_output=True, text=True, check=False, env=env, cwd=ROOT, timeout=180,
    )  # fmt: skip


def started_at() -> str:
    return subprocess.run(["docker", "inspect", "-f", "{{.State.StartedAt}}", AUTHELIA],
                          capture_output=True, text=True, check=True).stdout.strip()  # fmt: skip


def anonymous_notes_status() -> int:
    headers = {"X-Forwarded-Method": "GET", "X-Forwarded-Proto": "https",
               "X-Forwarded-Host": "notes.example.test", "X-Forwarded-URI": "/",
               "X-Forwarded-For": "10.8.0.5"}  # fmt: skip
    return httpx.get(FORWARD_AUTH, headers=headers, timeout=10).status_code


PROXY_PROBE = """
import httpx
P, A = "http://socket-proxy:2375", "authelia-webui-authelia-1"
for method, path in [("GET", f"/v1.41/containers/{A}/json"), ("GET", "/v1.41/containers/json"),
                     ("POST", "/v1.41/containers/create"), ("POST", f"/v1.41/containers/{A}/exec"),
                     ("POST", "/v1.41/containers/authelia-webui-traefik-1/restart"),
                     ("GET", "/v1.41/images/json"), ("GET", "/version")]:
    print(method, path, httpx.request(method, P + path, timeout=10).status_code)
"""


def test_socket_proxy_allows_only_inspect_and_restart_of_authelia(stack: dict[str, str]) -> None:
    out = exec_python(stack, "configurator", PROXY_PROBE).stdout.splitlines()
    codes = {" ".join(line.split()[:2]): int(line.split()[-1]) for line in out}
    assert codes[f"GET /v1.41/containers/{AUTHELIA}/json"] == 200
    denied = {k: v for k, v in codes.items() if k != f"GET /v1.41/containers/{AUTHELIA}/json"}
    assert denied and all(v == 403 for v in denied.values()), denied


def test_instances_without_the_proxy_network_cannot_reach_it(stack: dict[str, str]) -> None:
    probe = "import httpx\ntry:\n    httpx.get('http://socket-proxy:2375/v1.41/containers/json', timeout=5)\n    print('reached')\nexcept httpx.HTTPError:\n    print('unreachable')\n"  # noqa: E501
    assert exec_python(stack, "configurator-locked", probe).stdout.strip() == "unreachable"


def test_apply_restarts_authelia_and_changes_real_behaviour(stack: dict[str, str]) -> None:
    assert anonymous_notes_status() in (302, 401)  # two_factor: sent to log in
    before = started_at()
    change = {"T_DOMAIN": "notes.example.test", "T_FROM": "two_factor", "T_TO": "deny"}
    proc = exec_python(stack, "configurator", APPLY_SCRIPT, change)
    assert proc.returncode == 0, proc.stderr[-1500:]
    job = json.loads(proc.stdout.strip().splitlines()[-1])
    assert job["result"] == "applied", job
    assert started_at() != before  # really restarted, through the proxy
    assert anonymous_notes_status() == 403  # the new rule is live in Authelia
    live = (STACK / "managed" / "access_control.yml").read_text()
    log = subprocess.run(["git", "-C", str(STACK / "managed"), "log", "--format=%an %s"],
                         capture_output=True, text=True, check=True).stdout  # fmt: skip
    assert "alice Rules: 1 edited" in log and "Initial import" in log
    assert "policy: deny" in live


def test_unhealthy_apply_is_rolled_back_for_real(stack: dict[str, str]) -> None:
    """configurator-broken checks health via health-switch, which reports unhealthy while the
    live rules contain "break-health" - exactly what this change adds."""
    live_before = (STACK / "managed" / "access_control.yml").read_text()
    change = {"T_DOMAIN": "cloud.example.test", "T_FROM": "bypass", "T_TO": "bypass",
              "T_NOTE": "break-health (test marker)"}  # fmt: skip
    proc = exec_python(stack, "configurator-broken", APPLY_SCRIPT, change)
    assert proc.returncode == 0, proc.stderr[-1500:]
    job = json.loads(proc.stdout.strip().splitlines()[-1])
    assert job["result"] == "rolled-back", job
    assert (STACK / "managed" / "access_control.yml").read_text() == live_before
    assert httpx.get("http://127.0.0.1:19091/api/health", timeout=10).status_code == 200
    assert "break-health" not in (STACK / "managed" / "access_control.yml").read_text()
    subjects = subprocess.run(
        ["git", "-C", str(STACK / "managed"), "log", "--format=%s", "-n2"],
        capture_output=True, text=True, check=True,
    ).stdout.split("\n")  # fmt: skip
    assert subjects[0].startswith("Rollback:")
    # the failed change waits in the draft for the user to fix
    assert (STACK / "managed" / ".draft" / "access_control.yml").is_file()
