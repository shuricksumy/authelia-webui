"""Open sessions against the real thing: Authelia (the pinned version) with its sessions in Redis.

app/sessions.py reads Authelia's internal session format (see its docstring and docs/sessions.md).
This test signs real users in, then lists and deletes their sessions through SessionStore. If it
fails after an Authelia bump, the format changed: update app/sessions.py before releasing.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest
import redis

from app.sessions import SessionStore
from tests.fixtures.stack import STACK, prepare

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[2]
AUTHELIA = "http://127.0.0.1:19091"
AUTHZ = f"{AUTHELIA}/api/authz/forward-auth"
REDIS_PORT = 16390
PORTAL_HOST = "auth.example.test:8443"  # what Traefik would forward as the original host


@dataclass
class Env:
    store: SessionStore
    admin: redis.Redis
    restricted: redis.Redis
    password: str  # every test user shares the generated password
    secret_file: Path
    restricted_password: str


def _compose(*args: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    files = [
        "-f",
        str(ROOT / "compose.test.yml"),
        "-f",
        str(ROOT / "tests/integration/compose.sessions.yml"),
    ]
    return subprocess.run(
        ["docker", "compose", *files, *args],
        capture_output=True, text=True, check=False, env=env, cwd=ROOT,
    )  # fmt: skip


@pytest.fixture(scope="module")
def env(
    authelia_version: str, cli: object, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[Env]:
    prepare()
    session_secret = secrets.token_hex(32)
    admin_password = secrets.token_hex(16)
    restricted_password = secrets.token_hex(16)
    environment = {
        **os.environ,
        "AUTHELIA_VERSION": authelia_version, "TEST_APP_SECRET_KEY": secrets.token_urlsafe(48),
        "DEV_UID": str(os.getuid()), "DEV_GID": str(os.getgid()),
        "SESSIONS_TEST_SECRET": session_secret, "SESSIONS_TEST_REDIS_PASSWORD": admin_password,
    }  # fmt: skip
    secret_file = tmp_path_factory.mktemp("sessions") / "session-secret"
    secret_file.write_text(session_secret + "\n")
    up = _compose(
        "up", "-d", "--wait", "--wait-timeout", "120", "redis", "authelia", env=environment
    )
    try:
        assert up.returncode == 0, up.stderr[-2000:]
        admin = redis.Redis(host="127.0.0.1", port=REDIS_PORT, password=admin_password)
        # What docs/sessions.md tells the owner to create: scan, read and delete session keys only.
        admin.acl_setuser(
            "configurator", enabled=True, passwords=[f"+{restricted_password}"], reset_keys=True,
            keys=["authelia-session:*"], reset_channels=True,
            commands=["-@all", "+scan", "+get", "+del", "+pttl", "+ping"],
        )  # fmt: skip
        restricted = redis.Redis(
            host="127.0.0.1", port=REDIS_PORT, username="configurator", password=restricted_password
        )
        credentials = json.loads((STACK.parent / "credentials.json").read_text())
        yield Env(
            SessionStore(restricted, secret_file),
            admin,
            restricted,
            credentials["password"],
            secret_file,
            restricted_password,
        )
    finally:
        _compose("down", "-v", env=environment)


def sign_in(env: Env, user: str) -> str:
    """First-factor login; returns the session cookie as the browser would send it."""
    response = httpx.post(
        f"{AUTHELIA}/api/firstfactor", timeout=15,
        headers={"X-Forwarded-Proto": "https", "X-Forwarded-Host": PORTAL_HOST},
        json={"username": user, "password": env.password, "keepMeLoggedIn": False, "targetURL": ""},
    )  # fmt: skip
    cookies = response.headers.get_list("set-cookie")
    assert response.status_code == 200 and cookies, (
        f"{user}: {response.status_code} {response.text[:200]}"
    )
    return cookies[0].split(";", 1)[0]  # "authelia_session=<id>"


def still_signed_in(cookie: str) -> bool:
    """A 1FA page (the portal's settings) answers 200 with a live session and a redirect without."""
    response = httpx.get(
        AUTHZ, timeout=15, follow_redirects=False,
        headers={"X-Forwarded-Proto": "https", "X-Forwarded-Host": "auth.example.test",
                 "X-Forwarded-URI": "/settings", "X-Forwarded-Method": "GET", "Cookie": cookie},
    )  # fmt: skip
    return response.status_code == 200


def test_real_sessions_are_listed_and_the_cookie_is_the_session_key(env: Env) -> None:
    before = len(env.store.snapshot(fresh=True).for_user("alice"))
    first, second, bobs = sign_in(env, "alice"), sign_in(env, "alice"), sign_in(env, "bob")
    snap = env.store.snapshot(fresh=True)
    assert snap.unreadable == 0 and not snap.looks_like_wrong_secret  # the format is what we read
    assert len(snap.for_user("alice")) == before + 2 and len(snap.for_user("bob")) >= 1
    keys = {s.key for s in snap.sessions}
    for cookie in (first, second, bobs):  # the value Authelia sets IS the Redis key's id
        assert env.store.current_key(cookie) in keys
    mine = next(s for s in snap.sessions if s.key == env.store.current_key(first))
    assert mine.username == "alice" and mine.second_factor is False  # password only so far
    assert mine.last_activity is not None and mine.expires_in is not None and mine.expires_in > 0


def test_revoke_signs_the_user_out_everywhere_but_the_account_still_works(env: Env) -> None:
    first, second, bobs = sign_in(env, "alice"), sign_in(env, "alice"), sign_in(env, "bob")
    assert all(still_signed_in(c) for c in (first, second, bobs))
    result = env.store.revoke("alice")
    assert result.deleted >= 2 and result.complete
    assert not still_signed_in(first) and not still_signed_in(second)  # signed out at once
    assert still_signed_in(bobs)  # nobody else was touched
    assert env.store.snapshot(fresh=True).for_user("alice") == []
    again = sign_in(env, "alice")  # the account is still enabled
    assert still_signed_in(again)
    assert len(env.store.snapshot(fresh=True).for_user("alice")) == 1


def test_revoke_can_keep_the_callers_current_session(env: Env) -> None:
    mine, other = sign_in(env, "alice"), sign_in(env, "alice")
    result = env.store.revoke("alice", keep=env.store.current_key(mine))
    assert result.kept == 1 and result.deleted >= 1
    assert still_signed_in(mine) and not still_signed_in(other)


def test_the_restricted_redis_user_can_read_and_delete_but_never_write(env: Env) -> None:
    sign_in(env, "bob")
    assert env.restricted.ping()
    with pytest.raises(redis.exceptions.NoPermissionError):
        env.restricted.set("authelia-session:forged", b"x")  # it cannot create a session
    with pytest.raises(redis.exceptions.NoPermissionError):
        env.restricted.get("some-other-key")  # nor read outside the session keys
    assert next(env.restricted.scan_iter(match="authelia-session:*"), None) is not None


def test_a_wrong_secret_reads_nothing_and_deletes_nothing(env: Env, tmp_path: Path) -> None:
    cookie = sign_in(env, "alice")
    wrong = tmp_path / "wrong-secret"
    wrong.write_text(secrets.token_hex(32))
    store = SessionStore(env.restricted, wrong)
    snap = store.snapshot(fresh=True)
    assert snap.sessions == () and snap.looks_like_wrong_secret
    assert store.revoke("alice").deleted == 0
    assert still_signed_in(cookie)


def test_one_session_can_be_ended_by_its_handle_and_only_that_one(env: Env) -> None:
    first, second = sign_in(env, "alice"), sign_in(env, "alice")
    handle = env.store.handle_of(env.store.current_key(first) or "")
    result = env.store.revoke_one("alice", handle)
    assert result.deleted == 1
    assert not still_signed_in(first) and still_signed_in(second)


def test_a_handle_does_not_work_across_users(env: Env) -> None:
    alice, bobs = sign_in(env, "alice"), sign_in(env, "bob")
    bobs_handle = env.store.handle_of(env.store.current_key(bobs) or "")
    assert env.store.revoke_one("alice", bobs_handle).deleted == 0  # alice's page, bob's handle
    assert still_signed_in(bobs) and still_signed_in(alice)


def test_everyone_can_be_signed_out_except_the_session_kept(env: Env) -> None:
    mine, other, bobs = sign_in(env, "alice"), sign_in(env, "alice"), sign_in(env, "bob")
    result = env.store.revoke_everyone(keep=env.store.current_key(mine))
    assert result.kept == 1 and result.deleted >= 2 and result.users >= 2
    assert still_signed_in(mine)  # the administrator pressing the button stays signed in
    assert not still_signed_in(other) and not still_signed_in(bobs)


def test_the_app_connects_through_its_own_settings_as_the_restricted_user(env: Env) -> None:
    """The path production takes: SessionStore.from_settings, logging in as the restricted Redis
    user. Building the client by hand (as the other tests do) once hid that the app asked Redis to
    name its connection, which that user may not do, so Redis refused the whole connection."""
    from app.settings import Settings

    settings = Settings(
        AUTH_DOMAIN="auth.example.test",
        CONFIGURATOR_DOMAIN="authcfg.example.test",
        ADMIN_GROUP="admin",
        ALLOWED_CLIENT_CIDRS="10.8.0.0/24",  # type: ignore[arg-type]
        TRUSTED_PROXY_CIDRS="172.20.0.0/16",  # type: ignore[arg-type]
        AUTHELIA_CONTAINER="authelia",
        AUTHELIA_HEALTH_URL="http://authelia:9091/api/health",
        APP_SECRET_KEY="k" * 40,  # type: ignore[arg-type]
        SESSIONS_REDIS_URL=f"redis://127.0.0.1:{REDIS_PORT}/0",
        SESSIONS_REDIS_USERNAME="configurator",
        SESSIONS_REDIS_PASSWORD=env.restricted_password,  # type: ignore[arg-type]
        SESSIONS_SECRET_FILE=env.secret_file,
    )
    store = SessionStore.from_settings(settings)
    assert store is not None
    first, second = sign_in(env, "alice"), sign_in(env, "alice")
    snap = store.snapshot(fresh=True)  # a refused connection would raise SessionsUnavailable here
    assert snap.unreadable == 0 and len(snap.for_user("alice")) >= 2
    handle = store.handle_of(store.current_key(first) or "")
    assert store.revoke_one("alice", handle).deleted == 1
    assert not still_signed_in(first) and still_signed_in(second)
