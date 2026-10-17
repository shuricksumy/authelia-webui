"""Apply against the real stack: socket proxy, Authelia restart, health check, rollback.

The proxy only accepts the configurator containers, so the engine runs *inside* them
(`docker compose exec`); the host only observes the effects.
"""

from __future__ import annotations

import json
import os
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
from app.rules.store import DraftStore

s = load_settings()
store = DraftStore(s.CONFIG_MANAGED_DIR)
doc = store.current()
domain, old, new = os.environ["T_DOMAIN"], os.environ["T_FROM"], os.environ["T_TO"]
idx = next(i for i, r in enumerate(doc.rules())
           if r.get("domain") == domain and r.get("policy") == old)
node = doc.blocks[idx].node()
node["policy"] = new
store.save(doc.replace_rule(idx, node, note=os.environ.get("T_NOTE") or None))
rev = store.current_sha()[:16]
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
    from app.rules.store import DraftStore

    DraftStore(STACK / "managed").discard()  # leave no draft behind for the next test


def test_verify_step_checks_seeded_access_tests_against_real_authelia(
    stack: dict[str, str],
) -> None:
    """The stack seeds anonymous access tests; after a real apply they are probed live."""
    change = {"T_DOMAIN": "cloud.example.test", "T_FROM": "bypass", "T_TO": "bypass",
              "T_NOTE": "verify step integration test"}  # fmt: skip
    proc = exec_python(stack, "configurator", APPLY_SCRIPT, change)
    assert proc.returncode == 0, proc.stderr[-1500:]
    job = json.loads(proc.stdout.strip().splitlines()[-1])
    assert job["result"] == "applied", job
    assert ["verify", "done"] in job["steps"], job["steps"]


def test_migration_script_runs_inside_the_image(stack: dict[str, str], tmp_path: Path) -> None:
    """docs/migration.md runs the split script from the image, validated by its own Authelia."""
    from tests.fixtures.generate import GENERATED

    work = tmp_path / "work"
    work.mkdir()
    (work / "configuration.yml").write_text((GENERATED / "configuration.yml").read_text())
    proc = subprocess.run(
        ["docker", "run", "--rm", "--user", f"{os.getuid()}:{os.getgid()}",
         "-v", f"{work}:/work", "authelia-configurator:stack",
         "python", "-m", "scripts.split_config", "--config", "/work/configuration.yml",
         "--out", "/work/out"],
        capture_output=True, text=True, check=False, timeout=180,
    )  # fmt: skip
    assert proc.returncode == 0, proc.stderr[-1500:]
    assert "authelia validate split   : ok" in proc.stdout
    assert (work / "out" / "managed" / "access_control.yml").is_file()


# --------------------------------------------------------------------- OIDC clients (Phase 2)

CLIENT_SCRIPT = """
import json, os
from ruamel.yaml.comments import CommentedMap
from app.authelia_cli import AutheliaCLI
from app.settings import load_settings
from app.apply.engine import ApplyEngine, ApplyRequest
from app.apply.jobs import JobBoard
from app.apply.runtime import AutheliaRuntime
from app.apply.validate import validate_candidate
from app.rules.store import DraftStore

s = load_settings()
store = DraftStore(s.CONFIG_MANAGED_DIR)
clients = store.current_clients()
secret, digest = AutheliaCLI.local(s.AUTHELIA_BINARY).hash_random_pbkdf2()
cid = os.environ["T_CLIENT"]
idx = clients.index_of(cid)
if idx is None:
    node = CommentedMap()
    node["client_id"] = cid
    node["client_name"] = "Integration machine client"
    node["client_secret"] = digest
    node["public"] = False
    node["authorization_policy"] = "one_factor"
    node["scopes"] = ["groups"]
    node["grant_types"] = ["client_credentials"]
    node["response_types"] = []
    node["token_endpoint_auth_method"] = "client_secret_basic"
    clients = clients.insert(len(clients.blocks), node)
else:
    clients = clients.with_secret(idx, digest)
store.save(store.current(), clients=clients)
rev = store.current_sha()[:16]
engine = ApplyEngine(s, AutheliaRuntime(s.DOCKER_PROXY_URL, s.AUTHELIA_CONTAINER),
                     JobBoard(s.CONFIG_MANAGED_DIR), validate_candidate)
job = engine.board.new("alice")
engine.apply(ApplyRequest("alice", "10.8.0.5", rev), job)
print(json.dumps({"result": job.result, "message": job.message, "details": job.details,
                  "steps": [[x.name, x.status, x.detail] for x in job.steps], "secret": secret}))
"""
TOKEN = "http://127.0.0.1:19091/api/oidc/token"


def token_status(client_id: str, secret: str) -> int:
    # Authelia answers OIDC only for its configured portal URL, port included.
    headers = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "auth.example.test:8443"}
    data = {"grant_type": "client_credentials", "scope": "groups"}
    return httpx.post(TOKEN, data=data, auth=(client_id, secret), headers=headers,
                      timeout=10).status_code  # fmt: skip


def test_generated_client_secret_works_at_the_real_token_endpoint(stack: dict[str, str]) -> None:
    """The secret shown once is the one Authelia accepts: generated by the bundled binary, only
    its hash stored, applied through the engine (verify step checks OIDC discovery)."""
    run_ = exec_python(stack, "configurator", CLIENT_SCRIPT, {"T_CLIENT": "machine-e2e"})
    assert run_.returncode == 0, run_.stderr[-1500:]
    first = json.loads(run_.stdout.strip().splitlines()[-1])
    assert first["result"] == "applied", first
    assert any(s[0] == "verify" and s[1] == "done" for s in first["steps"]), first["steps"]
    clients_file = (STACK / "managed" / "oidc_clients.yml").read_text()
    assert first["secret"] not in clients_file and "machine-e2e" in clients_file
    assert token_status("machine-e2e", first["secret"]) == 200
    # the issuer the setup info shows is the one Authelia really announces
    from app.apply.probe import portal_url

    headers = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "auth.example.test:8443"}
    discovery = httpx.get("http://127.0.0.1:19091/.well-known/openid-configuration",
                          headers=headers, timeout=10).json()  # fmt: skip
    assert discovery["issuer"].rstrip("/") == portal_url(
        STACK / "configuration.yml", "auth.example.test"
    )
    assert token_status("machine-e2e", first["secret"] + "x") == 401

    run_ = exec_python(stack, "configurator", CLIENT_SCRIPT, {"T_CLIENT": "machine-e2e"})
    second = json.loads(run_.stdout.strip().splitlines()[-1])
    assert second["result"] == "applied", second
    assert token_status("machine-e2e", first["secret"]) == 401  # rotated: the old one is dead
    assert token_status("machine-e2e", second["secret"]) == 200


# --------------------------------------------------------------------- emergency access

EMERGENCY = "http://127.0.0.1:8090"
CHECK_SCRIPT = """
import json, os
from app.authelia_cli import AutheliaCLI
cli = AutheliaCLI.local()
digest = os.environ["EMERGENCY_PASSWORD_HASH"]
right = os.environ["T_PASSWORD"]
print(json.dumps([
    cli.validate_password(right, digest),
    cli.validate_password(right + "x", digest),
    cli.validate_password("", digest),
    cli.validate_password("a\\rb", digest),
    cli.validate_password(right, digest + " --config /etc/passwd"),
    cli.validate_password(right, "plaintext"),
]))
"""


def test_the_bundled_binary_checks_the_emergency_password(stack: dict[str, str]) -> None:
    from tests.fixtures.stack import EMERGENCY_PASSWORD

    out = exec_python(stack, "configurator", CHECK_SCRIPT, {"T_PASSWORD": EMERGENCY_PASSWORD})
    assert out.returncode == 0, out.stderr[-1500:]
    assert json.loads(out.stdout.strip().splitlines()[-1]) == [
        True,
        False,
        False,
        False,
        False,
        False,
    ]


def emergency_login(password: str) -> httpx.Response:
    return httpx.post(
        f"{EMERGENCY}/emergency/login", data={"password": password},
        headers={"Origin": EMERGENCY}, follow_redirects=False, timeout=30,
    )  # fmt: skip


def test_the_emergency_port_is_loopback_only_and_checks_the_password(
    stack: dict[str, str],
) -> None:
    from tests.fixtures.stack import EMERGENCY_PASSWORD

    published = subprocess.run(
        ["docker", "compose", "-f", str(ROOT / "compose.test.yml"), "port", "configurator", "8090"],
        capture_output=True, text=True, check=True, env=stack, cwd=ROOT,
    ).stdout.strip()  # fmt: skip
    assert published.startswith("127.0.0.1:"), published  # never 0.0.0.0
    assert httpx.get(f"{EMERGENCY}/emergency/login", timeout=10).status_code == 200
    assert httpx.get(f"{EMERGENCY}/emergency/login", headers={"Host": "evil.example.com"},
                     timeout=10).status_code == 403  # fmt: skip
    assert emergency_login("not-the-password").status_code == 401
    good = emergency_login(EMERGENCY_PASSWORD)
    assert good.status_code == 303 and "HttpOnly" in good.headers["set-cookie"]


def test_the_configurator_is_reachable_while_authelia_is_down(stack: dict[str, str]) -> None:
    """The reason the door exists: with Authelia stopped the normal URL fails (Traefik cannot ask
    Authelia), the emergency port still serves the whole UI."""
    import time

    from tests.fixtures.stack import EMERGENCY_PASSWORD

    cookie = emergency_login(EMERGENCY_PASSWORD).headers["set-cookie"].split(";")[0]
    normal = "https://127.0.0.1:8444/rules"
    subprocess.run(["docker", "stop", "-t", "5", AUTHELIA], check=True, capture_output=True)
    try:
        down = httpx.get(normal, headers={"Host": "authcfg.example.test:8444"}, verify=False,  # noqa: S501
                         follow_redirects=False, timeout=15)  # fmt: skip
        assert down.status_code >= 500, down.status_code
        page = httpx.get(f"{EMERGENCY}/rules", headers={"Cookie": cookie}, timeout=30)
        assert page.status_code == 200 and "Emergency access." in page.text
        assert "not healthy" in page.text or "cannot be determined" in page.text
        logs = httpx.get(f"{EMERGENCY}/logs", headers={"Cookie": cookie}, timeout=30)
        assert logs.status_code == 200
    finally:
        subprocess.run(["docker", "start", AUTHELIA], check=True, capture_output=True)
        deadline = time.time() + 90
        while time.time() < deadline:
            try:
                if httpx.get("http://127.0.0.1:19091/api/health", timeout=3).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(1)
