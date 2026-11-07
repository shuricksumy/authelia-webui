"""Open sessions in Redis: read, count and delete per user (app/sessions.py), against a fake Redis.

The blobs are built exactly like Authelia builds them (docs/sessions.md): AES-256-GCM with
SHA-256(secret) as the key, nonce first, around a MessagePack map holding the session as JSON.
tests/integration/test_sessions_redis.py checks the same against the real Authelia and Redis.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import time
from pathlib import Path
from typing import Any

import msgpack
import pytest
import redis
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.sessions import PREFIX, SessionStore, SessionsUnavailable

SECRET = secrets.token_hex(16)  # per run: no secret-looking literal in the source
PENDING_TOTP = "PENDING-TOTP-MARKER"  # must never show up anywhere
NOW = int(time.time())


def encrypt(secret: str, plain: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(hashlib.sha256(secret.encode()).digest()).encrypt(nonce, plain, None)


def blob(user: dict[str, Any] | None, secret: str = SECRET) -> bytes:
    values: dict[str, Any] = {} if user is None else {"UserSession": json.dumps(user).encode()}
    return encrypt(secret, msgpack.packb({"KV": values}, use_bin_type=True))


def user_session(
    name: str, *, second: bool = False, remember: bool = False, ago: int = 30
) -> dict[str, Any]:
    return {
        "Username": name, "DisplayName": name.title(), "Groups": ["dev"],
        "Emails": [f"{name}@example.com"], "KeepMeLoggedIn": remember,
        "LastActivity": NOW - ago, "FirstFactorAuthnTimestamp": NOW - 600,
        "SecondFactorAuthnTimestamp": NOW - 590 if second else 0,
        "TOTP": {"Secret": PENDING_TOTP, "Issuer": "Authelia"}, "WebAuthn": None,
    }  # fmt: skip


class FakePipeline:
    def __init__(self, server: FakeRedis) -> None:
        self.server, self.calls = server, []

    def get(self, key: bytes) -> None:
        self.calls.append(("get", key))

    def pttl(self, key: bytes) -> None:
        self.calls.append(("pttl", key))

    def execute(self) -> list[Any]:
        if self.server.fail:
            raise self.server.fail
        return [
            self.server.data.get(k) if op == "get" else self.server.ttl.get(k, -1)
            for op, k in self.calls
        ]


class FakeRedis:
    def __init__(self) -> None:
        self.data: dict[bytes, bytes] = {}
        self.ttl: dict[bytes, int] = {}
        self.fail: Exception | None = None
        self.scans = 0
        self.deleted: list[bytes] = []

    def add(self, sid: str, value: bytes, ttl_ms: int = 3_000_000) -> bytes:
        key = f"{PREFIX}{sid}".encode()
        self.data[key], self.ttl[key] = value, ttl_ms
        return key

    def scan_iter(self, match: str | None = None, count: int | None = None) -> Any:
        if self.fail:
            raise self.fail
        self.scans += 1
        prefix = (match or "").rstrip("*").encode()
        yield from [k for k in list(self.data) if k.startswith(prefix)]

    def pipeline(self, transaction: bool = True) -> FakePipeline:
        return FakePipeline(self)

    def delete(self, *keys: bytes) -> int:
        if self.fail:
            raise self.fail
        gone = [k for k in keys if k in self.data]
        for key in gone:
            del self.data[key]
        self.deleted += gone
        return len(gone)


@pytest.fixture
def secret_file(tmp_path: Path) -> Path:
    path = tmp_path / "session-secret"
    path.write_bytes(SECRET.encode() + b"\n")  # `echo` leaves a newline: it must not matter
    return path


@pytest.fixture
def server() -> FakeRedis:
    fake = FakeRedis()
    fake.add("a1", blob(user_session("alice", second=True, remember=True, ago=5)), ttl_ms=90_000)
    fake.add("a2", blob(user_session("alice", ago=400)))
    fake.add("b1", blob(user_session("bob")))
    fake.add("anon", blob(None))  # a visitor nobody has signed in yet
    fake.add("authelia-startup-probe", b"probe")
    return fake


def store(server: FakeRedis, secret_file: Path, **kw: Any) -> SessionStore:
    return SessionStore(server, secret_file, **kw)


def test_lists_sessions_per_user_with_the_useful_fields(
    server: FakeRedis, secret_file: Path
) -> None:
    snap = store(server, secret_file).snapshot()
    assert [(s.username, s.second_factor) for s in snap.sessions] == [
        ("alice", True), ("alice", False), ("bob", False),
    ]  # fmt: skip
    first = snap.for_user("alice")[0]
    assert first.remember_me is True and first.expires_in == 90
    assert first.last_activity is not None and abs(first.last_activity.timestamp() - (NOW - 5)) < 2
    assert first.second_factor_at is not None and snap.for_user("alice")[1].second_factor_at is None
    assert dict(snap.counts()) == {"alice": 2, "bob": 1}
    assert snap.unreadable == 0 and not snap.truncated and not snap.looks_like_wrong_secret


def test_anonymous_sessions_and_the_startup_probe_are_not_counted(
    server: FakeRedis, secret_file: Path
) -> None:
    snap = store(server, secret_file).snapshot()
    assert len(snap.sessions) == 3  # not 5
    assert snap.unreadable == 0  # a session without a user is valid, not "unreadable"


def test_username_lookup_ignores_case(server: FakeRedis, secret_file: Path) -> None:
    snap = store(server, secret_file).snapshot()
    assert len(snap.for_user("ALICE")) == 2 and len(snap.for_user("nobody")) == 0


def test_a_session_key_is_not_in_any_repr_or_log(
    server: FakeRedis, secret_file: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    sessions = store(server, secret_file)
    snap = sessions.snapshot()
    sessions.revoke("alice")
    text = repr(snap) + caplog.text
    assert PREFIX not in text and PENDING_TOTP not in text and SECRET not in text


def test_nothing_from_a_pending_totp_setup_is_kept(server: FakeRedis, secret_file: Path) -> None:
    snap = store(server, secret_file).snapshot()
    for s in snap.sessions:
        assert PENDING_TOTP not in repr(s) and PENDING_TOTP not in str(vars(s))


def test_unreadable_keys_are_counted_not_listed_and_never_deleted(
    server: FakeRedis, secret_file: Path
) -> None:
    server.add("other-secret", blob(user_session("alice"), secret=secrets.token_hex(16)))
    server.add("garbage", b"definitely not a session")
    server.add("short", b"x")
    sessions = store(server, secret_file)
    snap = sessions.snapshot()
    assert snap.unreadable == 3 and len(snap.sessions) == 3
    result = sessions.revoke("alice")
    assert result.deleted == 2 and result.unreadable == 3  # the two proven ones only
    assert f"{PREFIX}other-secret".encode() in server.data  # never guessed at
    assert f"{PREFIX}garbage".encode() in server.data


def test_all_keys_failing_looks_like_the_wrong_secret(server: FakeRedis, tmp_path: Path) -> None:
    wrong = tmp_path / "wrong"
    wrong.write_text("not the session secret")
    snap = SessionStore(server, wrong).snapshot()
    assert snap.sessions == () and snap.unreadable == 4 and snap.looks_like_wrong_secret


def test_revoke_deletes_only_that_users_sessions(server: FakeRedis, secret_file: Path) -> None:
    sessions = store(server, secret_file)
    result = sessions.revoke("Alice")
    assert (result.deleted, result.kept, result.complete) == (2, 0, True)
    left = sessions.snapshot(fresh=True)
    assert [s.username for s in left.sessions] == ["bob"]
    assert f"{PREFIX}anon".encode() in server.data  # nobody else's key was touched


def test_revoke_can_keep_the_callers_own_session(server: FakeRedis, secret_file: Path) -> None:
    sessions = store(server, secret_file)
    mine = sessions.current_key("theme=dark; authelia_session=a2; other=1")
    result = sessions.revoke("alice", keep=mine)
    assert (result.deleted, result.kept) == (1, 1)
    assert [s.username for s in sessions.snapshot(fresh=True).for_user("alice")] == ["alice"]
    assert f"{PREFIX}a2".encode() in server.data and f"{PREFIX}a1".encode() not in server.data


def test_revoke_for_a_user_without_sessions_deletes_nothing(
    server: FakeRedis, secret_file: Path
) -> None:
    assert store(server, secret_file).revoke("nobody").deleted == 0 and server.deleted == []


def test_revoke_needs_a_username(server: FakeRedis, secret_file: Path) -> None:
    with pytest.raises(ValueError):
        store(server, secret_file).revoke("  ")


def test_a_cut_short_read_says_so_and_revoke_reports_it_is_incomplete(
    server: FakeRedis, secret_file: Path
) -> None:
    sessions = store(server, secret_file, max_keys=2)
    assert sessions.snapshot().truncated is True
    assert sessions.revoke("alice").complete is False


def test_the_time_budget_stops_the_read(server: FakeRedis, secret_file: Path) -> None:
    ticks = iter(range(0, 1000, 5))  # every look at the clock is five "seconds" later
    snap = store(server, secret_file, budget_s=3.0, clock=lambda: float(next(ticks))).snapshot()
    assert snap.truncated is True


def test_reads_are_cached_briefly_and_revoke_clears_the_cache(
    server: FakeRedis, secret_file: Path
) -> None:
    now = [100.0]
    sessions = store(server, secret_file, cache_s=5.0, clock=lambda: now[0])
    sessions.snapshot()
    sessions.snapshot()
    assert server.scans == 1  # the Users page and the Overview share one read
    sessions.snapshot(fresh=True)
    assert server.scans == 2
    now[0] += 6
    sessions.snapshot()
    assert server.scans == 3
    sessions.revoke("bob")  # scans once itself, then forgets the cache
    assert server.scans == 4
    assert [s.username for s in sessions.snapshot().sessions] == ["alice", "alice"]


@pytest.mark.parametrize(
    ("error", "shown"),
    [
        (
            redis.exceptions.ConnectionError("cannot connect to redis.internal:6379"),
            "cannot be reached",
        ),
        (redis.exceptions.TimeoutError("timed out"), "cannot be reached"),
        (redis.exceptions.AuthenticationError("WRONGPASS password=hunter2"), "refused"),
        (
            redis.exceptions.NoPermissionError("NOPERM user cfg has no permissions"),
            "may not read or delete",
        ),
        (redis.exceptions.ResponseError("ERR something"), "returned an error"),
    ],
)
def test_redis_trouble_is_unavailable_with_a_safe_message_and_deletes_nothing(
    server: FakeRedis,
    secret_file: Path,
    error: Exception,
    shown: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    server.fail = error
    sessions = store(server, secret_file)
    with pytest.raises(SessionsUnavailable) as raised:
        sessions.snapshot()
    assert shown in str(raised.value)
    assert "hunter2" not in str(raised.value) and "hunter2" not in caplog.text
    with pytest.raises(SessionsUnavailable):
        sessions.revoke("alice")
    assert server.deleted == []


def test_a_failing_delete_is_unavailable_too(server: FakeRedis, secret_file: Path) -> None:
    sessions = store(server, secret_file)
    sessions.snapshot()

    def boom(*keys: bytes) -> int:
        raise redis.exceptions.ConnectionError("down")

    server.delete = boom  # type: ignore[method-assign]
    with pytest.raises(SessionsUnavailable, match="cannot be reached"):
        sessions.revoke("alice")


def test_a_missing_or_empty_secret_file_is_unavailable(server: FakeRedis, tmp_path: Path) -> None:
    with pytest.raises(SessionsUnavailable, match="does not exist"):
        SessionStore(server, tmp_path / "missing").snapshot()
    empty = tmp_path / "empty"
    empty.write_text("\n")
    with pytest.raises(SessionsUnavailable, match="empty"):
        SessionStore(server, empty).snapshot()


def test_the_secret_is_read_each_time_so_a_rotation_needs_no_restart(
    server: FakeRedis, secret_file: Path
) -> None:
    sessions = store(server, secret_file, cache_s=0)
    assert len(sessions.snapshot().sessions) == 3
    secret_file.write_text("a different secret")
    assert sessions.snapshot().looks_like_wrong_secret


@pytest.mark.parametrize(
    ("header", "name", "expected"),
    [
        ("authelia_session=abc123", "authelia_session", "abc123"),
        ("a=1; authelia_session=x-y_z!#$%^*; b=2", "authelia_session", "x-y_z!#$%^*"),
        ("authelia_session=; other=1", "authelia_session", None),
        ("other=1", "authelia_session", None),
        (None, "authelia_session", None),
        ("my_cookie=zzz; authelia_session=no", "my_cookie", "zzz"),
    ],
)
def test_current_session_comes_from_the_cookie_header(
    server: FakeRedis, secret_file: Path, header: str | None, name: str, expected: str | None
) -> None:
    key = SessionStore(server, secret_file, cookie_name=name).current_key(header)
    assert key == (None if expected is None else PREFIX + expected)


def test_after_a_redis_failure_later_reads_fail_at_once_until_the_pause_ends(
    server: FakeRedis, secret_file: Path
) -> None:
    now = [100.0]
    sessions = store(server, secret_file, cache_s=0, clock=lambda: now[0])
    server.fail = redis.exceptions.ConnectionError("down")
    with pytest.raises(SessionsUnavailable):
        sessions.snapshot()  # waits out the timeout once...
    server.fail = None
    with pytest.raises(SessionsUnavailable, match="cannot be reached"):
        sessions.snapshot()  # ...but pages after it do not wait again
    assert server.scans == 0  # Redis was not even asked
    now[0] += 20  # the pause is over: Redis is back
    assert len(sessions.snapshot().sessions) == 3


def test_an_explicit_action_always_tries_even_during_the_pause(
    server: FakeRedis, secret_file: Path
) -> None:
    sessions = store(server, secret_file, cache_s=0)
    server.fail = redis.exceptions.ConnectionError("down")
    with pytest.raises(SessionsUnavailable):
        sessions.snapshot()
    server.fail = None
    assert sessions.revoke("bob").deleted == 1  # revoke reads fresh: it is not held back


# ------------------------------------------------------------------ handles, one session, everyone


def handles(sessions: SessionStore, user: str) -> list[str]:
    return [s.handle for s in sessions.snapshot(fresh=True).for_user(user)]


def test_a_handle_stands_in_for_the_key_without_revealing_it(
    server: FakeRedis, secret_file: Path
) -> None:
    real_id = "Zq9#x!K2m%L7$wP4-_nR8^cT3*vB5yD6"  # as long and as odd as Authelia's own ids
    server.add(real_id, blob(user_session("dave")))
    sessions = store(server, secret_file, handle_key=b"k" * 32)
    snap = sessions.snapshot()
    seen = [s.handle for s in snap.sessions]
    assert len(set(seen)) == 4 and all(
        len(h) == 20 and set(h) <= set("0123456789abcdef") for h in seen
    )
    dave = snap.for_user("dave")[0]
    assert real_id not in dave.handle and real_id not in repr(dave)  # a key is never in a repr
    assert dave.handle in repr(dave)  # a handle may be shown
    same = store(server, secret_file, handle_key=b"k" * 32)
    other = store(server, secret_file, handle_key=b"x" * 32)
    assert handles(sessions, "alice") == handles(same, "alice")
    assert handles(sessions, "alice") != handles(other, "alice")


def test_revoke_one_ends_exactly_that_session(server: FakeRedis, secret_file: Path) -> None:
    sessions = store(server, secret_file)
    first, second = handles(sessions, "alice")
    result = sessions.revoke_one("alice", first)
    assert (result.deleted, result.users) == (1, 1)
    assert handles(sessions, "alice") == [second]
    assert f"{PREFIX}b1".encode() in server.data  # bob untouched


def test_a_handle_cannot_end_another_users_session(server: FakeRedis, secret_file: Path) -> None:
    sessions = store(server, secret_file)
    (bobs,) = handles(sessions, "bob")
    result = sessions.revoke_one("alice", bobs)  # alice's page, bob's handle
    assert result.deleted == 0 and server.deleted == []
    assert handles(sessions, "bob") == [bobs]


def test_revoke_one_with_an_unknown_or_forged_handle_does_nothing(
    server: FakeRedis, secret_file: Path
) -> None:
    sessions = store(server, secret_file)
    for forged in ("0" * 20, "", "a1", PREFIX + "a1", "../../etc"):
        assert sessions.revoke_one("alice", forged).deleted == 0
    assert server.deleted == []


def test_revoke_one_reports_redis_trouble_and_deletes_nothing(
    server: FakeRedis, secret_file: Path
) -> None:
    sessions = store(server, secret_file)
    first = handles(sessions, "alice")[0]
    server.fail = redis.exceptions.ConnectionError("down")
    with pytest.raises(SessionsUnavailable):
        sessions.revoke_one("alice", first)
    assert server.deleted == []


def test_revoke_everyone_signs_all_users_out_but_not_the_one_kept(
    server: FakeRedis, secret_file: Path
) -> None:
    sessions = store(server, secret_file)
    result = sessions.revoke_everyone(keep=f"{PREFIX}a2")
    assert (result.deleted, result.kept, result.users, result.complete) == (2, 1, 2, True)
    assert [s.key for s in sessions.snapshot(fresh=True).sessions] == [f"{PREFIX}a2"]
    assert f"{PREFIX}anon".encode() in server.data  # a visitor session nobody signed in to


def test_revoke_everyone_never_touches_unreadable_keys(
    server: FakeRedis, secret_file: Path
) -> None:
    server.add("garbage", b"not a session")
    sessions = store(server, secret_file)
    result = sessions.revoke_everyone()
    assert (result.deleted, result.unreadable) == (3, 1)
    assert f"{PREFIX}garbage".encode() in server.data


def test_handles_survive_a_restart_when_they_come_from_the_app_secret(
    server: FakeRedis, secret_file: Path, tmp_path: Path
) -> None:
    from app.settings import Settings

    def settings(app_secret: str) -> Settings:
        return Settings(
            AUTH_DOMAIN="auth.example.com", CONFIGURATOR_DOMAIN="authcfg.example.com",
            ADMIN_GROUP="admin", ALLOWED_CLIENT_CIDRS="10.8.0.0/24",  # type: ignore[arg-type]
            TRUSTED_PROXY_CIDRS="172.20.0.0/16",  # type: ignore[arg-type]
            AUTHELIA_CONTAINER="authelia", AUTHELIA_HEALTH_URL="http://authelia:9091/api/health",
            APP_SECRET_KEY=app_secret,  # type: ignore[arg-type]
            SESSIONS_REDIS_URL="redis://redis:6379/0", SESSIONS_SECRET_FILE=secret_file,
        )  # fmt: skip

    def handle_with(app_secret: str) -> str:
        made = SessionStore.from_settings(settings(app_secret))
        assert made is not None
        return made.handle_of(f"{PREFIX}a1")

    assert handle_with("a" * 40) == handle_with("a" * 40)  # the same after a restart
    assert handle_with("a" * 40) != handle_with("b" * 40)


def test_the_secret_file_message_says_why_it_cannot_be_used(
    server: FakeRedis, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = tmp_path / "made-by-docker"
    folder.mkdir()  # what a bind mount creates when the host file did not exist
    with pytest.raises(SessionsUnavailable, match="is a folder"):
        SessionStore(server, folder).snapshot()

    unreadable = tmp_path / "root-only"
    unreadable.write_text("secret")

    def deny(self: Path) -> bytes:
        raise PermissionError(13, "Permission denied", str(self))

    monkeypatch.setattr(Path, "read_bytes", deny)  # chmod would not stop a test run as root
    with pytest.raises(
        SessionsUnavailable, match="not readable by the configurator's user"
    ) as raised:
        SessionStore(server, unreadable).snapshot()
    assert "check its owner and mode" in str(raised.value)
    assert str(unreadable) not in str(raised.value)  # the message never echoes a path or an error
