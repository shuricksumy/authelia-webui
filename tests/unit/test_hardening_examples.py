"""examples/hardening (docs/hardening.md): the security properties the guide relies on."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest
from ruamel.yaml import YAML

ROOT = Path(__file__).resolve().parents[2]
HARDENING = ROOT / "examples" / "hardening"
PRODUCTION = ROOT / "examples" / "production"
CROWDSEC_COMPOSE = PRODUCTION / "compose.crowdsec.yml"


def _load(path: Path) -> object:
    return YAML(typ="safe").load(path.read_text())


@pytest.mark.parametrize(
    "path", sorted([*HARDENING.glob("*.yml"), *HARDENING.glob("*.yaml")]), ids=lambda p: p.name
)
def test_hardening_files_are_valid_yaml(path: Path) -> None:
    docs = list(YAML(typ="safe").load_all(path.read_text()))
    assert docs and all(d is not None for d in docs)


def _socket_proxy_rule(path: Path, method: str) -> re.Pattern[str]:
    command = _load(path)["services"]["traefik-socket-proxy"]["command"]  # type: ignore[index]
    rule = next(c.split("=", 1)[1] for c in command if c.startswith(f"-allow{method}="))
    return re.compile("^(?:" + rule + ")$")  # the proxy anchors rules the same way


def test_traefik_socket_proxy_allows_only_the_docker_provider_calls() -> None:
    get = _socket_proxy_rule(HARDENING / "compose.socket-proxy.yml", "GET")
    needed = ["/_ping", "/v1.51/_ping", "/version", "/v1.51/version", "/v1.51/events",
              "/v1.51/containers/json", "/v1.51/containers/3f9a2c1b7e/json"]  # fmt: skip
    forbidden = ["/v1.51/containers/abc/logs", "/v1.51/containers/abc/archive",
                 "/v1.51/containers/abc/export", "/v1.51/containers/create", "/v1.51/exec/x/json",
                 "/v1.51/images/json", "/v1.51/containers/../../secrets/json"]  # fmt: skip
    assert [p for p in needed if not get.match(p)] == []
    assert [p for p in forbidden if get.match(p)] == []
    command = _load(HARDENING / "compose.socket-proxy.yml")["services"]["traefik-socket-proxy"][  # type: ignore[index]
        "command"
    ]
    assert not any(c.startswith(("-allowPOST", "-allowPUT", "-allowDELETE")) for c in command)


def test_realip_runs_before_the_bouncer_and_cdn_trust_is_paired_with_it() -> None:
    static = _load(HARDENING / "traefik-static.snippet.yml")
    websecure = static["entryPoints"]["websecure"]  # type: ignore[index]
    assert websecure["http"]["middlewares"] == ["realip@file", "crowdsec@file"]
    assert "forwardedHeaders" in websecure  # documented as "only together with realip"
    assert set(static["experimental"]["plugins"]) == {"bouncer", "realip"}  # type: ignore[index]
    assert static["accessLog"] == {"filePath": "/var/log/traefik/access.log", "format": "json"}  # type: ignore[index]


def test_security_middlewares_fail_open_share_the_cdn_list_and_keep_the_key_in_a_file() -> None:
    mws = _load(HARDENING / "security.yml")["http"]["middlewares"]  # type: ignore[index]
    realip = mws["realip"]["plugin"]["realip"]
    bouncer = mws["crowdsec"]["plugin"]["bouncer"]
    assert bouncer["forwardedHeadersTrustedIPs"] == realip["trustedIPs"]
    assert realip["trustedIPs"] == ["192.0.2.0/24"]  # placeholder: a documentation range
    assert bouncer["updateMaxFailure"] == -1
    assert bouncer["crowdsecMode"] == "stream"
    assert "crowdsecLapiKey" not in bouncer and bouncer["crowdsecLapiKeyFile"].endswith(".key")
    for net in bouncer["clientTrustedIPs"]:
        assert net.startswith(("127.", "10.", "172.", "192.168.")), net  # private only


def test_crowdsec_addon_is_read_only_on_logs_and_never_sees_the_socket() -> None:
    services = _load(CROWDSEC_COMPOSE)["services"]  # type: ignore[index]
    cs = services["crowdsec"]
    assert cs["cap_drop"] == ["ALL"] and cs["cap_add"] == ["DAC_READ_SEARCH"]
    assert "no-new-privileges:true" in cs["security_opt"]
    assert "ports" not in cs
    volumes = [str(v) for v in cs["volumes"]]
    assert not any("docker.sock" in v for v in volumes)
    assert all(v.endswith(":ro") for v in volumes if "/var/log/" in v)
    assert ":latest" not in cs["image"]
    env = cs["environment"]
    assert "crowdsecurity/whitelists" in env["PARSERS"]
    assert "crowdsecurity/whitelist-good-actors" in env["COLLECTIONS"]
    assert services["traefik"]["tmpfs"] == ["/plugins-storage"]  # read-only Traefik, plugins


def test_noauth_scenario_is_a_local_leaky_bucket() -> None:
    scenario = _load(HARDENING / "noauth-probing.yaml")
    assert scenario["type"] == "leaky" and scenario["name"].startswith("local/")  # type: ignore[index]
    assert "RouterName" in scenario["filter"]  # type: ignore[index]


def test_cloudflare_lockdown_refuses_an_empty_range_list() -> None:
    script = (HARDENING / "cloudflare-only.bash").read_text()
    assert "set -euo pipefail" in script
    assert "-ge 10 ]" in script  # an empty or odd answer would otherwise drop all web traffic
    assert '"80,443"' in script and "DOCKER-USER" in script
    if shutil.which("bash"):
        subprocess.run(["bash", "-n", str(HARDENING / "cloudflare-only.bash")], check=True)


def test_traefik_manager_calls_the_api_by_traefiks_fixed_address() -> None:
    """By name, a second shared network (crowdsec) can make the call come from another address."""
    compose = _load(PRODUCTION / "compose.yml")
    traefik_ip = compose["services"]["traefik"]["networks"]["edge"]["ipv4_address"]  # type: ignore[index]
    tm = _load(PRODUCTION / "compose.traefik-manager.yml")["services"]["traefik-manager"]  # type: ignore[index]
    assert tm["environment"]["TRAEFIK_API_URL"] == f"http://{traefik_ip}:8081"
    both = _load(PRODUCTION / "compose.traefik-manager.crowdsec.yml")["services"]  # type: ignore[index]
    assert both["traefik-manager"]["networks"] == {"crowdsec": {}}  # map form: keeps edge's IP


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker is not installed")
def test_all_four_compose_files_merge_and_keep_fixed_addresses() -> None:
    env = {"AUTHELIA_VERSION": "4.39.28", "DOCKER_GID": "999", "APP_SECRET_KEY": "x" * 40,
           "DOMAIN": "example.com", "VPN_ADDRESS": "10.8.0.1", "VPN_CIDR": "10.8.0.0/24",
           "REDIS_PASSWORD": "y" * 32, "CROWDSEC_BOUNCER_KEY": "z" * 64,
           "PATH": "/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin"}  # fmt: skip
    files = ["compose.yml", "compose.traefik-manager.yml", "compose.crowdsec.yml",
             "compose.traefik-manager.crowdsec.yml"]  # fmt: skip
    args = [a for f in files for a in ("-f", str(PRODUCTION / f))]
    proc = subprocess.run(
        ["docker", "compose", *args, "config", "--format", "json"],
        capture_output=True, text=True, env=env, check=False, timeout=60,
    )  # fmt: skip
    if "Cannot connect to the Docker daemon" in proc.stderr:
        pytest.skip("docker daemon is not running")
    assert proc.returncode == 0, proc.stderr[-800:]
    import json

    tm = json.loads(proc.stdout)["services"]["traefik-manager"]["networks"]
    assert tm["edge"]["ipv4_address"] == "172.30.0.20" and "crowdsec" in tm


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker is not installed")
def test_production_compose_with_crowdsec_resolves() -> None:
    env = {"AUTHELIA_VERSION": "4.39.28", "DOCKER_GID": "999", "APP_SECRET_KEY": "x" * 40,
           "DOMAIN": "example.com", "VPN_ADDRESS": "10.8.0.1", "VPN_CIDR": "10.8.0.0/24",
           "REDIS_PASSWORD": "y" * 32, "CROWDSEC_BOUNCER_KEY": "z" * 64,
           "PATH": "/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin"}  # fmt: skip
    proc = subprocess.run(
        ["docker", "compose", "-f", str(PRODUCTION / "compose.yml"), "-f", str(CROWDSEC_COMPOSE),
         "config", "--format", "json"],
        capture_output=True, text=True, env=env, check=False, timeout=60,
    )  # fmt: skip
    if "Cannot connect to the Docker daemon" in proc.stderr:
        pytest.skip("docker daemon is not running")
    assert proc.returncode == 0, proc.stderr[-800:]
    import json

    traefik = json.loads(proc.stdout)["services"]["traefik"]
    assert {"edge", "crowdsec"} <= set(traefik["networks"])  # the overlay adds, never replaces
    assert traefik["networks"]["edge"]["ipv4_address"] == "172.30.0.2"


@pytest.mark.parametrize("path", sorted((PRODUCTION / "logrotate").iterdir()), ids=lambda p: p.name)
def test_logrotate_files_have_no_comment_after_a_directive(path: Path) -> None:
    """logrotate reads `directive  # text` as extra arguments and skips the whole block."""
    inside = False
    for n, line in enumerate(path.read_text().splitlines(), 1):
        code = line.strip()
        if code.endswith("{"):
            inside = True
        elif code == "}":
            inside = False
        elif inside and code and not code.startswith("#"):
            assert "#" not in code, f"{path.name}:{n}: comment after a directive"
