"""The Redis user in examples/production/compose.sessions.yml, run for real.

The guide promises that the configurator's Redis user can scan, read and delete session keys and
nothing else. This starts Redis with the add-on's own command line and checks it.
"""

from __future__ import annotations

import re
import secrets
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
import redis
from ruamel.yaml import YAML

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[2]
OVERLAY = ROOT / "examples" / "production" / "compose.sessions.yml"
PORT = 16392
NAME = "sessions-example-redis"


@pytest.fixture(scope="module")
def server(cli: object) -> Iterator[tuple[redis.Redis, redis.Redis]]:
    admin_password, user_password = secrets.token_hex(12), secrets.token_hex(12)
    values = {"REDIS_PASSWORD": admin_password, "CONFIGURATOR_REDIS_PASSWORD": user_password}
    command = [
        str(x) for x in YAML(typ="safe").load(OVERLAY.read_text())["services"]["redis"]["command"]
    ]
    # what compose does with ${NAME} and ${NAME:?message}
    command = [
        re.sub(r"\$\{(\w+)(?::\?[^}]*)?\}", lambda m: values[m.group(1)], part) for part in command
    ]
    assert command[0] == "redis-server"
    subprocess.run(["docker", "rm", "-f", NAME], capture_output=True, check=False)
    run = subprocess.run(
        ["docker", "run", "-d", "--name", NAME, "-p", f"127.0.0.1:{PORT}:6379",
         "redis:8-alpine", *command],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    try:
        assert run.returncode == 0, run.stderr[-1000:]
        admin = redis.Redis(host="127.0.0.1", port=PORT, password=admin_password)
        for _ in range(40):
            try:
                admin.ping()
                break
            except redis.exceptions.ConnectionError:
                time.sleep(0.25)
        user = redis.Redis(
            host="127.0.0.1", port=PORT, username="configurator", password=user_password
        )
        yield admin, user
    finally:
        subprocess.run(["docker", "rm", "-f", NAME], capture_output=True, check=False)


def test_the_user_can_scan_read_and_delete_session_keys(
    server: tuple[redis.Redis, redis.Redis],
) -> None:
    admin, user = server
    admin.set("authelia-session:abc", b"value")
    assert user.ping()
    assert list(user.scan_iter(match="authelia-session:*")) == [b"authelia-session:abc"]
    assert user.get("authelia-session:abc") == b"value"
    assert user.pttl("authelia-session:abc") == -1
    assert user.delete("authelia-session:abc") == 1


def test_the_user_cannot_create_a_session_or_touch_anything_else(
    server: tuple[redis.Redis, redis.Redis],
) -> None:
    admin, user = server
    admin.set("other", b"1")
    with pytest.raises(redis.exceptions.NoPermissionError):
        user.set("authelia-session:forged", b"x")  # no way to sign anyone in
    with pytest.raises(redis.exceptions.NoPermissionError):
        user.get("other")
    with pytest.raises(redis.exceptions.NoPermissionError):
        user.delete("other")
    with pytest.raises(redis.exceptions.NoPermissionError):
        user.flushall()
    with pytest.raises(redis.exceptions.NoPermissionError):
        user.config_get("*")


def test_the_default_user_still_needs_its_password(server: tuple[redis.Redis, redis.Redis]) -> None:
    with pytest.raises(redis.exceptions.AuthenticationError):
        redis.Redis(host="127.0.0.1", port=PORT).ping()
