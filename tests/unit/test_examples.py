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
