"""examples/firewall-bouncer + compose.firewall-bouncer.yml (docs/firewall-bouncer.md)."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest
from ruamel.yaml import YAML

ROOT = Path(__file__).resolve().parents[2]
KIT = ROOT / "examples" / "firewall-bouncer"
PRODUCTION = ROOT / "examples" / "production"
OVERLAY = PRODUCTION / "compose.firewall-bouncer.yml"
CONFIG = PRODUCTION / "crowdsec" / "firewall-bouncer.yaml"


def _load(path: Path) -> object:
    return YAML(typ="safe").load(path.read_text())


def _services() -> dict:  # type: ignore[type-arg]
    return _load(OVERLAY)["services"]  # type: ignore[index,no-any-return]


def _build_version() -> str:
    match = re.search(r'^VERSION="(v[\d.]+)"$', (KIT / "build.bash").read_text(), re.M)
    assert match
    return match.group(1)


def test_image_tag_in_compose_matches_the_built_version() -> None:
    bouncer = _services()["crowdsec-firewall-bouncer"]
    assert bouncer["image"] == f"local/crowdsec-firewall-bouncer:{_build_version()}"
    assert bouncer["pull_policy"] == "never"  # a local image: never fetched from a registry
    assert _build_version() in (ROOT / "docs" / "firewall-bouncer.md").read_text()


def test_build_pins_a_checksum_per_cpu_and_checks_the_iptables_backend() -> None:
    script = (KIT / "build.bash").read_text()
    assert "set -euo pipefail" in script
    sums = re.findall(r'SHA256="([0-9a-f]+)"', script)
    assert len(sums) == 2 and all(len(s) == 64 for s in sums)
    assert "nf_tables|legacy" in script
    dockerfile = (KIT / "Dockerfile").read_text()
    assert "sha256sum -c" in dockerfile and "releases/download/${VERSION}/" in dockerfile
    if shutil.which("bash"):
        subprocess.run(["bash", "-n", str(KIT / "build.bash")], check=True)


def test_build_context_holds_the_dockerfile_only() -> None:
    lines = [ln for ln in (KIT / ".dockerignore").read_text().splitlines() if ln and ln[0] != "#"]
    assert lines == ["*", "!Dockerfile"]


def test_bouncer_has_host_networking_and_only_firewall_capabilities() -> None:
    bouncer = _services()["crowdsec-firewall-bouncer"]
    assert bouncer["network_mode"] == "host"
    assert bouncer["cap_drop"] == ["ALL"] and sorted(bouncer["cap_add"]) == ["NET_ADMIN", "NET_RAW"]
    assert not bouncer.get("privileged")
    assert bouncer["read_only"] is True and "no-new-privileges:true" in bouncer["security_opt"]
    assert all(str(v).endswith(":ro") for v in bouncer["volumes"])
    assert not any("docker.sock" in str(v) for v in bouncer["volumes"])


def test_crowdsec_api_is_published_on_loopback_only_and_matches_the_config() -> None:
    ports = [str(p) for p in _services()["crowdsec"]["ports"]]
    assert ports == ["127.0.0.1:8080:8080"]
    config = _load(CONFIG)
    assert config["api_url"].startswith("http://127.0.0.1:8080")  # type: ignore[index]


def test_one_key_from_env_registers_and_authenticates_the_bouncer() -> None:
    services = _services()
    config = _load(CONFIG)
    assert config["api_key"] == "${CROWDSEC_FIREWALL_BOUNCER_KEY}"  # type: ignore[index]
    reg = services["crowdsec"]["environment"]["BOUNCER_KEY_firewall"]
    sent = services["crowdsec-firewall-bouncer"]["environment"]["CROWDSEC_FIREWALL_BOUNCER_KEY"]
    assert reg.startswith("${CROWDSEC_FIREWALL_BOUNCER_KEY") and sent.startswith(
        "${CROWDSEC_FIREWALL_BOUNCER_KEY"
    )


def test_rules_cover_host_services_and_docker_ports_and_drop_silently() -> None:
    config = _load(CONFIG)
    assert config["iptables_chains"] == ["INPUT", "DOCKER-USER"]  # type: ignore[index]
    assert config["mode"] == "iptables" and config["deny_action"] == "DROP"  # type: ignore[index]
    assert config["supported_decisions_types"] == ["ban"]  # type: ignore[index]


def test_non_http_sources_start_a_new_document_and_label_openvpn() -> None:
    text = (KIT / "acquis.non-http.yaml").read_text()
    first = next(ln for ln in text.splitlines() if ln and not ln.startswith("#"))
    assert first == "---"  # appended to acquis.yaml, it must open a new document
    docs = [d for d in YAML(typ="safe").load_all(text) if d is not None]
    labels = {d["labels"]["type"]: d["filenames"] for d in docs}
    assert labels["openvpn"] == ["/var/log/openvpn/openvpn.log"]
    assert labels["syslog"] == ["/var/log/host/auth.log"]


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker is not installed")
def test_overlay_merges_with_the_crowdsec_add_on() -> None:
    env = {"AUTHELIA_VERSION": "4.39.28", "DOCKER_GID": "999", "APP_SECRET_KEY": "x" * 40,
           "DOMAIN": "example.com", "VPN_ADDRESS": "10.8.0.1", "VPN_CIDR": "10.8.0.0/24",
           "REDIS_PASSWORD": "y" * 32, "CROWDSEC_BOUNCER_KEY": "z" * 64,
           "CROWDSEC_FIREWALL_BOUNCER_KEY": "w" * 64,
           "PATH": "/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin"}  # fmt: skip
    files = ["compose.yml", "compose.crowdsec.yml", "compose.firewall-bouncer.yml"]
    args = [a for f in files for a in ("-f", str(PRODUCTION / f))]
    proc = subprocess.run(
        ["docker", "compose", *args, "config", "--format", "json"],
        capture_output=True, text=True, env=env, check=False, timeout=60,
    )  # fmt: skip
    if "Cannot connect to the Docker daemon" in proc.stderr:
        pytest.skip("docker daemon is not running")
    assert proc.returncode == 0, proc.stderr[-800:]
    import json

    services = json.loads(proc.stdout)["services"]
    crowdsec = services["crowdsec"]
    assert "BOUNCER_KEY_traefik" in crowdsec["environment"]  # the overlay adds, never replaces
    assert "BOUNCER_KEY_firewall" in crowdsec["environment"]
    assert crowdsec["ports"][0]["host_ip"] == "127.0.0.1"
