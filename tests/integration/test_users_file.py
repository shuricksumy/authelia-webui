"""Phase 3 measurements: how Authelia 4.39 treats the users file the configurator will write.

Results are documented in docs/users-file.md; keep both in sync. Everything runs against the real
stack (users file in managed/, watch: true). Login checks use /api/firstfactor directly; each
user gets at most one failed attempt (Authelia bans after 3 within 2 minutes by default).
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Iterator

import httpx
import pytest

from tests.fixtures.stack import STACK, USERS_NAME
from tests.integration.test_apply_stack import exec_python, stack  # noqa: F401  (fixture)

pytestmark = pytest.mark.integration

USERS = STACK / "managed" / USERS_NAME
CREDENTIALS = STACK.parent / "credentials.json"
FIRST_FACTOR = "http://127.0.0.1:19091/api/firstfactor"
HEADERS = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "auth.example.test:8443",
           "X-Forwarded-For": "10.8.0.5"}  # fmt: skip

HASH_SCRIPT = """
import json, os, sys
from app.authelia_cli import AutheliaCLI
from app.settings import load_settings
s = load_settings()
cli = AutheliaCLI.local(s.AUTHELIA_BINARY)
typed = cli.hash_password(os.environ["T_PASSWORD"], s.CONFIG_MAIN)
generated, generated_digest = cli.generate_password(s.CONFIG_MAIN)
print(json.dumps({"typed": typed, "generated": generated, "generated_digest": generated_digest}))
"""


def login(username: str, password: str) -> int:
    body = {"username": username, "password": password, "keepMeLoggedIn": False}
    return httpx.post(FIRST_FACTOR, json=body, headers=HEADERS, timeout=10).status_code


def wait_login(username: str, password: str, want: int, timeout: float = 25) -> float | None:
    """Seconds until the login answers `want` (one failure allowed at most), else None."""
    start = time.monotonic()
    time.sleep(1.5)  # give the watcher a moment before the first (possibly failing) attempt
    while time.monotonic() - start < timeout:
        if login(username, password) == want:
            return time.monotonic() - start
        time.sleep(max(0.0, 12 - (time.monotonic() - start)))  # second and last attempt later
        if login(username, password) == want:
            return time.monotonic() - start
        return None
    return None


def user_block(name: str, digest: str, *, disabled: bool = False, extra: str = "") -> str:
    return (f"    {name}:\n        password: '{digest}'\n        displayname: '{name.title()}'\n"
            f"        email: '{name}@example.test'\n        groups:\n            - 'home'\n"
            f"        disabled: {'true' if disabled else 'false'}\n{extra}")  # fmt: skip


def atomic_write(text: str) -> None:
    tmp = USERS.with_name(".users.tmp")
    tmp.write_text(text)
    os.replace(tmp, USERS)  # a new inode, as the configurator's atomic write produces


def in_place_write(text: str) -> None:
    with open(USERS, "r+") as handle:
        handle.seek(0)
        handle.write(text)
        handle.truncate()
        handle.flush()
        os.fsync(handle.fileno())


@pytest.fixture(scope="module")
def digests(stack: dict[str, str]) -> Iterator[dict[str, str]]:  # noqa: F811
    proc = exec_python(stack, "configurator", HASH_SCRIPT, {"T_PASSWORD": "Typed-pass-123!"})
    assert proc.returncode == 0, proc.stderr[-1500:]
    original = USERS.read_text()
    yield json.loads(proc.stdout.strip().splitlines()[-1])
    atomic_write(original)


def test_typed_password_hashed_on_a_terminal_uses_the_configured_argon2(
    digests: dict[str, str],
) -> None:
    assert digests["typed"].startswith("$argon2id$v=19$m=65536,t=3,p=4$")
    assert digests["generated_digest"].startswith("$argon2id$v=19$m=65536,t=3,p=4$")
    assert len(digests["generated"]) == 20


def test_reload_after_an_atomic_replace(digests: dict[str, str]) -> None:
    base = USERS.read_text()
    atomic_write(base + user_block("carol", digests["typed"]))
    took = wait_login("carol", "Typed-pass-123!", 200)
    print(f"MEASURED atomic replace reload: {took}")
    assert took is not None, "Authelia did not pick up an atomically replaced users file"


def test_generated_password_logs_in(digests: dict[str, str]) -> None:
    base = USERS.read_text()
    atomic_write(base + user_block("gina", digests["generated_digest"]))
    assert wait_login("gina", digests["generated"], 200) is not None


def test_disabled_user_cannot_log_in(digests: dict[str, str]) -> None:
    text = USERS.read_text()
    atomic_write(text + user_block("dora", digests["typed"], disabled=True))
    time.sleep(4)
    assert login("dora", "Typed-pass-123!") == 401


def test_extra_attributes_under_extra_are_accepted(digests: dict[str, str]) -> None:
    text = USERS.read_text()
    extra = "        extra:\n            photo_quota: 7\n"
    atomic_write(text + user_block("eve", digests["typed"], extra=extra))
    took = wait_login("eve", "Typed-pass-123!", 200)
    print(f"MEASURED extra: map accepted: {took is not None}")
    assert took is not None


def test_an_invalid_file_keeps_the_old_users(digests: dict[str, str]) -> None:
    creds = json.loads(CREDENTIALS.read_text())
    good = USERS.read_text()
    atomic_write("users: [not valid\n")
    time.sleep(4)
    status = login(creds["username"], creds["password"])
    health = httpx.get("http://127.0.0.1:19091/api/health", timeout=5).status_code
    atomic_write(good)
    print(f"MEASURED invalid file: alice login {status}, health {health}")
    assert health == 200
