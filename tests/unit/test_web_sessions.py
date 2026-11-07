"""Open sessions in the UI: the user editor's block, sign out everywhere, the Users page column and
the Overview card (app/web_sessions.py), through the ASGI app with a fake Redis."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import redis

from app.apply import audit
from app.sessions import PREFIX, SessionStore
from app.ui import ago, duration
from tests.unit.test_sessions import SECRET, FakeRedis, blob, user_session
from tests.unit.test_web import UI, env  # noqa: F401  (fixture)

ALICE_1, ALICE_2, BOB_1 = "sid-alice-one", "sid-alice-two", "sid-bob-one"


def fake() -> FakeRedis:
    server = FakeRedis()
    server.add(ALICE_1, blob(user_session("alice", second=True, remember=True, ago=5)))
    server.add(ALICE_2, blob(user_session("alice", ago=400)))
    server.add(BOB_1, blob(user_session("bob", ago=90)))
    server.add("sid-anon", blob(None))
    return server


@pytest.fixture
def server() -> FakeRedis:
    return fake()


def attach(page: UI, server: FakeRedis, secret: Path) -> UI:
    page.client.app.state.sessions = SessionStore(server, secret, cache_s=0)  # type: ignore[attr-defined]
    return page


@pytest.fixture
def secret_file(tmp_path: Path) -> Path:
    path = tmp_path / "session-secret"
    path.write_text(SECRET)
    return path


@pytest.fixture
def ui(env: dict[str, Path], server: FakeRedis, secret_file: Path) -> UI:  # noqa: F811
    """Another administrator looking at alice's and bob's sessions."""
    return attach(UI(env, user="root", groups="admin"), server, secret_file)


@pytest.fixture
def me(env: dict[str, Path], server: FakeRedis, secret_file: Path) -> UI:  # noqa: F811
    """Alice herself: her own sessions, one of which is the browser she is using."""
    return attach(UI(env, user="alice", groups="admin"), server, secret_file)


def with_cookie(page: UI, path: str, cookie: str, method: str = "get") -> Any:
    headers = {**page.headers, "Cookie": cookie}
    if method == "get":
        return page.client.get(path, headers=headers, follow_redirects=False)
    token = page.token()
    return page.client.post(
        path, headers={**headers, "X-CSRF-Token": token}, data={"rev": page.rev()}
    )


# ------------------------------------------------------------------ switched off


def test_everything_looks_as_before_when_the_feature_is_off(env: dict[str, Path]) -> None:  # noqa: F811
    page = UI(env)
    assert "<th>Sessions</th>" not in page.get("/users").text
    assert "Open sessions" not in page.get("/").text
    block = page.get("/users/bob/sessions", htmx=True).text
    assert "not set up" in block and "docs/sessions.md" in block
    assert page.post("/users/bob/sessions/revoke").status_code == 404
    assert page.get("/users/bob/sessions/confirm", htmx=True).status_code == 404


def test_the_editor_loads_the_block_after_itself(ui: UI) -> None:
    editor = ui.get("/users/bob/edit").text
    assert 'hx-get="/users/bob/sessions"' in editor and 'hx-trigger="load"' in editor
    assert "sessions-block" not in ui.get("/users/new").text  # a user that does not exist yet


# ------------------------------------------------------------------ the block


def test_the_block_lists_a_users_sessions_without_any_key(ui: UI) -> None:
    text = ui.get("/users/alice/sessions", htmx=True).text
    assert "<strong>2</strong> open" in text and "1 with 2FA" in text
    assert "2FA</span>" in text and "1FA</span>" in text and "stays signed in" in text
    assert "Sign out everywhere" in text
    for hidden in (PREFIX, ALICE_1, ALICE_2, BOB_1, "PENDING-TOTP-MARKER"):
        assert hidden not in text  # a key is a live session id; a pending TOTP secret is secret


def test_a_user_without_sessions_shows_none_and_no_button(ui: UI) -> None:
    text = ui.get("/users/carol/sessions", htmx=True).text
    assert "No open sessions" in text and "Sign out" not in text


def test_the_confirmation_says_what_will_happen(ui: UI) -> None:
    text = ui.get("/users/alice/sessions/confirm", htmx=True).text
    assert "Sign out everywhere?" in text and "ends 2 open sessions" in text
    assert 'hx-post="/users/alice/sessions/revoke"' in text
    assert "stays enabled" in text and "OpenID Connect" in text


# ------------------------------------------------------------------ signing a user out


def test_sign_out_everywhere_deletes_only_that_users_sessions_and_is_audited(
    ui: UI,
    server: FakeRedis,
    env: dict[str, Path],  # noqa: F811
) -> None:
    r = ui.post("/users/alice/sessions/revoke")
    assert r.status_code == 200
    assert "alice: 2 sessions signed out." in r.text and 'id="modal" hx-swap-oob="true"' in r.text
    assert "No open sessions" in r.text
    assert [k.decode() for k in server.data] == [PREFIX + BOB_1, PREFIX + "sid-anon"]
    entry = audit.recent(env["managed"])[-1]
    assert (entry.action, entry.result, entry.user) == ("sessions", "revoked", "root")
    assert "alice" in entry.summary and "2 session" in entry.summary
    assert PREFIX not in entry.summary and ALICE_1 not in entry.summary  # never a key


def test_signing_out_a_user_with_no_sessions_says_so_and_writes_no_audit_entry(
    ui: UI,
    env: dict[str, Path],  # noqa: F811
) -> None:
    r = ui.post("/users/carol/sessions/revoke")
    assert "carol has no open sessions" in r.text
    assert audit.recent(env["managed"]) == []


def test_signing_yourself_out_keeps_the_session_you_are_using(me: UI, server: FakeRedis) -> None:
    block = with_cookie(me, "/users/alice/sessions", f"theme=dark; authelia_session={ALICE_2}")
    assert "this browser" in block.text and "Sign out my other sessions" in block.text
    r = with_cookie(me, "/users/alice/sessions/revoke", f"authelia_session={ALICE_2}", "post")
    assert r.status_code == 200 and "your current one kept" in r.text
    assert PREFIX + ALICE_2 in {k.decode() for k in server.data}
    assert PREFIX + ALICE_1 not in {k.decode() for k in server.data}


def test_signing_yourself_out_without_a_cookie_does_nothing(me: UI, server: FakeRedis) -> None:
    r = me.post("/users/alice/sessions/revoke")  # no Authelia cookie: which session is mine?
    assert r.status_code == 422 and "Cannot tell which session is yours" in r.text
    assert len(server.data) == 4  # nothing deleted


def test_your_only_session_is_not_offered_for_sign_out(me: UI, server: FakeRedis) -> None:
    del server.data[(PREFIX + ALICE_2).encode()]
    text = with_cookie(me, "/users/alice/sessions", f"authelia_session={ALICE_1}").text
    assert "This is your only session" in text and "Sign out" not in text


def test_the_new_routes_are_admin_only_and_need_the_csrf_token(
    ui: UI,
    env: dict[str, Path],  # noqa: F811
) -> None:
    outsider = UI(env, user="bob", groups="home")
    assert outsider.get("/users/alice/sessions").status_code == 403
    revoke = outsider.client.post("/users/alice/sessions/revoke", headers=outsider.headers)
    assert revoke.status_code == 403
    forged = ui.client.post("/users/bob/sessions/revoke", headers=ui.headers)  # no CSRF header
    assert forged.status_code == 403


# ------------------------------------------------------------------ the Users page and Overview


def test_the_users_page_gets_a_sessions_column(ui: UI) -> None:
    text = ui.get("/users").text
    assert "<th>Sessions</th>" in text
    assert 'title="1 with 2FA">2</span>' in text  # alice: two sessions, one with 2FA
    assert 'title="0 with 2FA">1</span>' in text  # bob: one session
    assert "Open sessions are unavailable" not in text


def test_the_overview_shows_how_many_are_signed_in(ui: UI) -> None:
    text = ui.get("/").text
    assert "Open sessions" in text and "3</span>" in text and "2 users" in text


# ------------------------------------------------------------------ when it goes wrong


@pytest.mark.parametrize(
    ("error", "shown"),
    [
        (redis.exceptions.ConnectionError("down"), "cannot be reached"),
        (redis.exceptions.AuthenticationError("WRONGPASS"), "refused"),
        (redis.exceptions.NoPermissionError("NOPERM"), "may not read or delete"),
    ],
)
def test_redis_trouble_is_a_message_never_a_broken_page(
    ui: UI, server: FakeRedis, error: Exception, shown: str
) -> None:
    server.fail = error
    assert shown in ui.get("/users/alice/sessions", htmx=True).text
    users = ui.get("/users")
    assert users.status_code == 200 and "Open sessions are unavailable" in users.text
    assert "alice" in users.text  # the list itself is unaffected
    overview = ui.get("/")
    assert overview.status_code == 200 and "Open sessions are unavailable" in overview.text
    r = ui.post("/users/bob/sessions/revoke")
    assert r.status_code == 422 and shown in r.text
    assert server.deleted == []


def test_a_wrong_secret_is_explained_and_deletes_nothing(
    ui: UI, server: FakeRedis, tmp_path: Path
) -> None:
    wrong = tmp_path / "wrong"
    wrong.write_text("not the session secret")
    attach(ui, server, wrong)
    block = ui.get("/users/alice/sessions", htmx=True).text
    assert "SESSIONS_SECRET_FILE" in block and "No open sessions" in block
    assert "SESSIONS_SECRET_FILE" in ui.get("/users").text
    assert "deleted" not in ui.post("/users/bob/sessions/revoke").text
    assert server.deleted == []


# ------------------------------------------------------------------ small helpers


def test_ago_and_duration_read_naturally() -> None:
    now = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)
    assert ago(None, now) == "unknown" and ago(now - timedelta(seconds=10), now) == "just now"
    assert ago(now - timedelta(minutes=4), now) == "4 min ago"
    assert ago(now - timedelta(hours=3), now) == "3 h ago"
    assert ago(now - timedelta(days=2, hours=5), now) == "2 d ago"
    assert ago(now + timedelta(minutes=5), now) == "just now"  # a clock a little ahead
    assert duration(None) == "unknown" and duration(20) == "under a minute"
    assert duration(52 * 60) == "52 min" and duration(3600 + 5 * 60) == "1 h 5 min"
    assert duration(2 * 3600) == "2 h" and duration(3 * 86400) == "3 d"
    assert duration(86400 + 3 * 3600) == "1 d 3 h"
