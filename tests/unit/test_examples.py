"""The production examples stay valid YAML, mention no real data and the compose file resolves."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from ruamel.yaml import YAML

EXAMPLES = Path(__file__).resolve().parents[2] / "examples"


@pytest.mark.parametrize("path", sorted(EXAMPLES.glob("*.example.yml")), ids=lambda p: p.name)
def test_example_is_valid_yaml(path: Path) -> None:
    assert YAML(typ="safe").load(path.read_text()) is not None


def test_compose_example_never_mounts_the_socket_in_the_configurator() -> None:
    compose = YAML(typ="safe").load((EXAMPLES / "compose.example.yml").read_text())
    for name, service in compose["services"].items():
        mounts = [str(v) for v in service.get("volumes", [])]
        has_socket = any("docker.sock" in m for m in mounts)
        assert has_socket == (name == "socket-proxy"), name
        if has_socket:
            assert all(m.endswith(":ro") for m in mounts if "docker.sock" in m)


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker is not installed")
def test_compose_example_resolves_with_sample_values() -> None:
    env = {"AUTHELIA_VERSION": "4.39.28", "DOCKER_GID": "999", "APP_SECRET_KEY": "x" * 40,
           "PATH": "/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin"}  # fmt: skip
    proc = subprocess.run(
        ["docker", "compose", "-f", str(EXAMPLES / "compose.example.yml"), "config", "-q"],
        capture_output=True, text=True, env=env, check=False, timeout=60,
    )  # fmt: skip
    if "Cannot connect to the Docker daemon" in proc.stderr:
        pytest.skip("docker daemon is not running")
    assert proc.returncode == 0, proc.stderr[-800:]


def test_dev_and_test_compose_files_are_valid_and_keep_users_in_managed() -> None:
    root = EXAMPLES.parent
    for name in ("compose.test.yml", "compose.dev.yml"):
        data = YAML(typ="safe").load((root / name).read_text())
        for service in data["services"].values():
            for volume in service.get("volumes", []):
                assert str(volume).count(":") <= 2, (name, volume)
                assert "stack/users.yml" not in str(volume), (name, volume)
    test = YAML(typ="safe").load((root / "compose.test.yml").read_text())
    assert test["x-configurator-env"]["USERS_FILE"] == "/config/managed/users.yml"


PRODUCTION = EXAMPLES / "production"


@pytest.mark.parametrize("path", sorted(PRODUCTION.rglob("*.yml")), ids=lambda p: str(p.name))
def test_production_example_files_are_valid_yaml(path: Path) -> None:
    if path.name == "oidc_jwks.example.yml":  # a template-filter file: read as the app reads it
        from app.oidc.jwks import JwksDocument

        assert JwksDocument.parse(path.read_text()).kids() == ["main"]
        return
    assert YAML(typ="safe").load(path.read_text()) is not None


def test_production_compose_mounts_the_socket_only_in_the_proxy_and_hardens_services() -> None:
    compose = YAML(typ="safe").load((PRODUCTION / "compose.yml").read_text())
    for name, service in compose["services"].items():
        socket = [v for v in service.get("volumes", []) if "docker.sock" in str(v)]
        assert bool(socket) == (name == "socket-proxy"), name
        assert all(str(v).endswith(":ro") for v in socket)
        if (
            name != "authelia"
        ):  # Authelia writes its db and the users file reload needs nothing else
            assert service.get("read_only") is True or "<<" in service, name
    env = compose["services"]["configurator"]["environment"]
    assert env["TRUSTED_PROXY_CIDRS"] == "172.30.0.2/32"
    assert compose["services"]["traefik"]["networks"]["edge"]["ipv4_address"] == "172.30.0.2"
    assert env["USERS_FILE"] == "/config/managed/users.yml"
    config_mount = [
        v for v in compose["services"]["configurator"]["volumes"] if "configuration.yml" in v
    ]
    assert config_mount and all(v.endswith(":ro") for v in config_mount)


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker is not installed")
def test_production_compose_resolves_with_sample_values() -> None:
    env = {"AUTHELIA_VERSION": "4.39.28", "DOCKER_GID": "999", "APP_SECRET_KEY": "x" * 40,
           "DOMAIN": "example.com", "VPN_ADDRESS": "10.8.0.1", "VPN_CIDR": "10.8.0.0/24",
           "REDIS_PASSWORD": "y" * 32,
           "PATH": "/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin"}  # fmt: skip
    proc = subprocess.run(
        ["docker", "compose", "-f", str(PRODUCTION / "compose.yml"), "config", "-q"],
        capture_output=True, text=True, env=env, check=False, timeout=60,
    )  # fmt: skip
    if "Cannot connect to the Docker daemon" in proc.stderr:
        pytest.skip("docker daemon is not running")
    assert proc.returncode == 0, proc.stderr[-800:]


def test_production_example_files_are_in_git() -> None:
    """The root .gitignore excludes managed/ folders (real data). The synthetic examples are
    re-included; this fails locally when one is not tracked, instead of only in CI."""
    tracked = subprocess.run(
        ["git", "ls-files", "examples/production"], capture_output=True, text=True,
        check=True, cwd=EXAMPLES.parent,
    ).stdout.split()  # fmt: skip
    for name in ("access_control", "oidc_clients", "users", "oidc_jwks"):
        assert f"examples/production/authelia/managed/{name}.example.yml" in tracked


# The optional Traefik Manager add-on (docs/traefik-manager.md).
TM_COMPOSE = PRODUCTION / "compose.traefik-manager.yml"
TM_DYNAMIC = PRODUCTION / "traefik-manager" / "traefik-manager.yml"


def test_production_traefik_loads_a_folder_and_keeps_the_api_unpublished() -> None:
    static = YAML(typ="safe").load((PRODUCTION / "traefik" / "traefik.yml").read_text())
    assert static["providers"]["file"]["directory"] == "/etc/traefik/dynamic"
    assert "filename" not in static["providers"]["file"]
    assert static["api"] == {"dashboard": False}  # no insecure mode, no dashboard
    port = static["entryPoints"]["tmapi"]["address"].lstrip(":")
    compose = YAML(typ="safe").load((PRODUCTION / "compose.yml").read_text())
    assert not any(port in str(p).split(":")[-1] for p in compose["services"]["traefik"]["ports"])
    assert (PRODUCTION / "traefik" / "dynamic" / "dynamic.yml").is_file()
    assert not (PRODUCTION / "traefik" / "dynamic" / "traefik-manager.yml").exists()  # opt-in


def test_traefik_manager_addon_is_hardened_and_never_sees_the_socket() -> None:
    tm = YAML(typ="safe").load(TM_COMPOSE.read_text())["services"]["traefik-manager"]
    assert ":" in tm["image"] and not tm["image"].endswith(":latest")
    assert tm["read_only"] is True and tm["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in tm["security_opt"]
    assert not any("docker.sock" in str(v) for v in tm["volumes"])
    env = tm["environment"]
    for unset in ("STATIC_CONFIG_PATH", "RESTART_METHOD", "DOCKER_HOST", "AUTH_ENABLED"):
        assert unset not in env, unset
    assert env["CONFIG_PATH"] == "/app/dynamic/dynamic.yml" and "CONFIG_DIR" not in env
    assert env["TRUSTED_PROXIES"] == "172.30.0.2/32"  # Traefik's fixed address
    assert "./traefik/dynamic:/app/dynamic" in tm["volumes"]  # the folder: atomic saves
    assert "ports" not in tm


def test_traefik_manager_addon_routes_vpn_only_and_allows_only_its_own_address() -> None:
    tm = YAML(typ="safe").load(TM_COMPOSE.read_text())["services"]["traefik-manager"]
    address = tm["networks"]["edge"]["ipv4_address"]
    http = YAML(typ="safe").load(TM_DYNAMIC.read_text())["http"]
    ui = http["routers"]["traefik-manager"]
    assert ui["entryPoints"] == ["internal"] and "authelia" in ui["middlewares"]
    api = http["routers"]["traefik-manager-api"]
    assert api["entryPoints"] == ["tmapi"] and api["service"] == "api@internal"
    allow = http["middlewares"][api["middlewares"][0]]["ipAllowList"]["sourceRange"]
    assert allow == [f"{address}/32"]
    for router in http["routers"].values():  # without entryPoints a router joins every entrypoint
        assert router.get("entryPoints"), router


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker is not installed")
def test_production_compose_with_traefik_manager_resolves() -> None:
    env = {"AUTHELIA_VERSION": "4.39.28", "DOCKER_GID": "999", "APP_SECRET_KEY": "x" * 40,
           "DOMAIN": "example.com", "VPN_ADDRESS": "10.8.0.1", "VPN_CIDR": "10.8.0.0/24",
           "REDIS_PASSWORD": "y" * 32,
           "PATH": "/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin"}  # fmt: skip
    proc = subprocess.run(
        ["docker", "compose", "-f", str(PRODUCTION / "compose.yml"), "-f", str(TM_COMPOSE),
         "config", "-q"],
        capture_output=True, text=True, env=env, check=False, timeout=60,
    )  # fmt: skip
    if "Cannot connect to the Docker daemon" in proc.stderr:
        pytest.skip("docker daemon is not running")
    assert proc.returncode == 0, proc.stderr[-800:]
