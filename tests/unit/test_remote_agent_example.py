"""examples/remote-agent: the properties its README relies on."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from ruamel.yaml import YAML

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "remote-agent"
EDGE = EXAMPLE / "edge"
HOME = EXAMPLE / "home"


def _load_all(path: Path) -> list[object]:
    return [d for d in YAML(typ="safe").load_all(path.read_text()) if d is not None]


@pytest.mark.parametrize(
    "path", sorted([*EXAMPLE.rglob("*.yml"), *EXAMPLE.rglob("*.yaml")]), ids=lambda p: p.name
)
def test_example_files_are_valid_yaml(path: Path) -> None:
    assert _load_all(path)


def _entrypoint_port() -> str:
    static = _load_all(EDGE / "traefik-static.snippet.yml")[0]
    address = static["entryPoints"]["cslapi"]["address"]  # type: ignore[index]
    assert re.fullmatch(r":\d+", address)
    return str(address[1:])


def test_lapi_router_is_bound_to_its_entrypoint_and_allow_listed() -> None:
    http = _load_all(EDGE / "crowdsec-lapi.yml")[0]["http"]  # type: ignore[index]
    router = http["routers"]["crowdsec-lapi"]
    assert router["entryPoints"] == ["cslapi"]  # without it: attached to every entry point
    mw = http["middlewares"][router["middlewares"][0]]["ipAllowList"]["sourceRange"]
    assert len(mw) == 1 and mw[0].endswith("/32")  # one address, not a range
    url = http["services"][router["service"]]["loadBalancer"]["servers"][0]["url"]
    assert url == "http://crowdsec:8080"


def test_agent_talks_to_the_edge_entrypoint_and_is_agent_only() -> None:
    svc = _load_all(HOME / "compose.yml")[0]["services"]["crowdsec-agent"]  # type: ignore[index]
    env = svc["environment"]
    assert env["DISABLE_LOCAL_API"] == "true"
    assert env["LOCAL_API_URL"].endswith(f":{_entrypoint_port()}")
    host = re.match(r"http://([\d.]+):", env["LOCAL_API_URL"]).group(1)  # type: ignore[union-attr]
    # the client tunnel routes exactly this address
    allowed = next(
        line for line in (HOME / "wireguard-client.snippet.conf").read_text().splitlines()
        if line.startswith("AllowedIPs")
    )  # fmt: skip
    assert f"{host}/32" in allowed
    assert "${" in env["AGENT_PASSWORD"]  # from .env, never inline
    assert "crowdsecurity/whitelists" in env["PARSERS"]


def test_agent_is_read_only_on_logs_and_has_no_socket_or_ports() -> None:
    svc = _load_all(HOME / "compose.yml")[0]["services"]["crowdsec-agent"]  # type: ignore[index]
    assert "ports" not in svc
    assert svc["cap_drop"] == ["ALL"] and svc["cap_add"] == ["DAC_READ_SEARCH"]
    assert "no-new-privileges:true" in svc["security_opt"]
    volumes = [str(v) for v in svc["volumes"]]
    assert not any("docker.sock" in v for v in volumes)
    host_logs = [v for v in volumes if not v.startswith("./crowdsec-agent/config")
                 and not v.startswith("./crowdsec-agent/data")]  # fmt: skip
    assert all(v.endswith(":ro") for v in host_logs), host_logs
    image = svc["image"]
    assert image.endswith("-debian") and ":latest" not in image  # journalctl is Debian-only


def test_home_assistant_source_strips_colour_codes_with_supported_functions() -> None:
    docs = _load_all(HOME / "acquis.yaml")
    ha = next(d for d in docs if d.get("labels", {}).get("type") == "home-assistant")  # type: ignore[union-attr]
    assert ha["source"] == "journalctl"  # type: ignore[index]
    transform = ha["transform"]  # type: ignore[index]
    assert "ReplaceRegexp" not in transform  # does not exist: the agent stops at start
    for code in ("0", "32", "33", "31", "36", "1;31"):
        assert f'"\\x1b[{code}m"' in transform, code
    assert any(d.get("labels", {}).get("type") == "Nextcloud" for d in docs)  # type: ignore[union-attr]


def test_webdav_scenario_is_local_counts_app_rejections_and_names_routers() -> None:
    scenario = _load_all(EDGE / "webdav-auth-bf.yaml")[0]
    assert scenario["type"] == "leaky" and scenario["name"].startswith("local/")  # type: ignore[index]
    flt = scenario["filter"]  # type: ignore[index]
    assert "'401'" in flt and "RouterName in [" in flt
    assert scenario["groupby"] == "evt.Meta.source_ip"  # type: ignore[index]


def test_readme_names_every_file() -> None:
    readme = (EXAMPLE / "README.md").read_text()
    for path in sorted(p for p in EXAMPLE.rglob("*") if p.is_file() and p.name != "README.md"):
        assert str(path.relative_to(EXAMPLE)) in readme, path.name
