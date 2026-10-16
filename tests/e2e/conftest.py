"""Compose test stack for e2e: real Authelia (split config) + the configurator image."""

from __future__ import annotations

import os
import secrets
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from scripts.split_config import _dockerfile_version
from tests.fixtures.stack import prepare

ROOT = Path(__file__).resolve().parents[2]
PORTAL_HOST = "auth.example.com"  # must sit under the session cookie domain or Authelia 403s
PORTAL_URL = f"http://{PORTAL_HOST}:19091"


def compose(*args: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", "-f", str(ROOT / "compose.test.yml"), *args],
        capture_output=True, text=True, check=False, env=env, cwd=ROOT,
    )  # fmt: skip


@pytest.fixture(scope="session")
def browser_type_launch_args(browser_type_launch_args: dict[str, object]) -> dict[str, object]:
    """Resolve the synthetic portal host to the local test port without touching /etc/hosts."""
    rule = f"--host-resolver-rules=MAP {PORTAL_HOST} 127.0.0.1"
    return {**browser_type_launch_args, "args": [rule]}


@pytest.fixture(scope="session")
def stack() -> Iterator[dict[str, str]]:
    if subprocess.run(["docker", "info"], capture_output=True, check=False).returncode != 0:
        pytest.skip("docker daemon not running")
    prepare()
    env = {
        **os.environ,
        "AUTHELIA_VERSION": _dockerfile_version(),
        "TEST_APP_SECRET_KEY": secrets.token_urlsafe(48),
    }
    up = compose("up", "-d", "--build", "--wait", "--wait-timeout", "180", env=env)
    try:
        assert up.returncode == 0, up.stderr[-2000:]
        yield env
    finally:
        compose("down", "-v", "--remove-orphans", env=env)
