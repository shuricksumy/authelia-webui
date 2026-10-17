"""Users and groups pages through HTTP (Phase 3b), with the password-hygiene guarantees."""

from __future__ import annotations

import logging
import re
from pathlib import Path

import pytest

from app.authelia_cli import AutheliaCLI
from app.users.document import UsersDocument
from tests.unit.conftest import FIXTURES, fill_placeholders
from tests.unit.test_users import HASH, HASH_2
from tests.unit.test_web import UI, env  # noqa: F401  (fixture)

MAIN = """authentication_backend:
  file:
    path: /config/managed/users.yml
    watch: true
    extra_attributes:
      photo_quota:
        multi_valued: false
        value_type: 'integer'
password_policy:
  standard:
    enabled: true
    min_length: 8
    require_uppercase: true
    require_lowercase: true
    require_number: true
    require_special: true
"""
PLAINTEXT = "Generated-Plain-123!"


@pytest.fixture
def uenv(env: dict[str, Path], monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:  # noqa: F811
    managed = env["managed"]
    text = fill_placeholders((FIXTURES / "users.example.yml").read_text())
    (managed / "users.yml").write_text(text.replace("dummy-002", HASH))
    env["main"].write_text(MAIN)
    env["users"] = managed / "users.yml"
    monkeypatch.setattr(
        AutheliaCLI,
        "generate_password",
        lambda self, main, length=20, charset="ascii": (PLAINTEXT, HASH_2),
    )
    monkeypatch.setattr(AutheliaCLI, "hash_password", lambda self, pw, main: HASH_2)
    return env


@pytest.fixture
def ui(uenv: dict[str, Path]) -> UI:
    u = UI(uenv)
    u.settings.USERS_FILE = uenv["users"]  # the app reads settings.USERS_FILE
    return u


def rev(ui: UI) -> str:
    page = ui.get("/users/new").text
    return re.search(r'name="users_rev" value="([0-9a-f]+)"', page).group(1)  # type: ignore[union-attr]


def post(ui: UI, path: str, data: dict[str, object] | None = None):  # type: ignore[no-untyped-def]
    return ui.post(path, {**(data or {}), "users_rev": rev(ui)})  # type: ignore[arg-type]


def doc(uenv: dict[str, Path]) -> UsersDocument:
    return UsersDocument.parse(uenv["users"].read_text())


def test_list_never_shows_a_hash_and_marks_you(ui: UI) -> None:
    page = ui.get("/users").text
    assert "alice" in page and "bob" in page and "you" in page
    assert "dummy-hash" not in page and "argon2" not in page and HASH not in page
    assert ui.get("/users?q=nobody").text.count("<tr") <= 2


def test_edit_a_user_changes_only_that_user(ui: UI, uenv: dict[str, Path]) -> None:
    before = uenv["users"].read_text()
    r = post(
        ui,
        "/users/save",
        {
            "original": "bob",
            "displayname": "Bobby",
            "email": "bob@example.com",
            "l_groups": ["home", "family"],
            "x_photo_quota": "42",
        },
    )
    assert r.status_code == 204, r.text
    d = doc(uenv)
    assert d.users()["bob"]["displayname"] == "Bobby" and d.users()["bob"]["groups"] == [
        "home",
        "family",
    ]
    assert d.users()["bob"]["extra"] == {"photo_quota": 42}
    old = UsersDocument.parse(before)
    assert all(d.blocks[i] == b for i, b in enumerate(old.blocks) if b.name != "bob")


def test_new_user_with_a_generated_password_shows_it_once(
    ui: UI, uenv: dict[str, Path], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    r = post(
        ui,
        "/users/save",
        {
            "username": "carol",
            "displayname": "Carol",
            "email": "carol@example.com",
            "l_groups": ["home"],
            "new_groups": "guests",
            "pw_mode": "generate",
        },
    )
    assert r.status_code == 200 and PLAINTEXT in r.text and 'type="password"' in r.text
    assert "no-store" in r.headers["cache-control"] and r.headers["hx-retarget"] == "#modal"
    d = doc(uenv)
    assert d.users()["carol"]["groups"] == ["home", "guests"] and d.has_password("carol")
    everything = "\n".join(
        p.read_text(errors="replace")
        for p in uenv["managed"].rglob("*")
        if p.is_file() and ".git" not in p.parts
    )
    assert PLAINTEXT not in everything and PLAINTEXT not in caplog.text
    assert HASH_2 in uenv["users"].read_text()
    for page in ("/users", "/users/carol/edit", "/groups", "/history"):
        text = ui.get(page).text
        assert PLAINTEXT not in text and HASH_2 not in text and "other-hash" not in text


def test_typed_password_is_checked_against_the_policy(ui: UI, uenv: dict[str, Path]) -> None:
    from app.users import passwords

    r = post(
        ui,
        "/users/save",
        {"username": "dave", "displayname": "Dave", "pw_mode": "typed", "password": "weak"},
    )
    assert (
        r.status_code == 422
        and "The password needs" in r.text
        and "weak" not in r.text.replace("weak ", "")
    )
    assert "dave" not in doc(uenv).names()
    ok = post(
        ui,
        "/users/save",
        {
            "username": "dave",
            "displayname": "Dave",
            "pw_mode": "typed",
            "password": "Typed-Pass-123!",
        },
    )
    assert ok.status_code == 204 and doc(uenv).raw("dave")["password"] == HASH_2
    assert passwords.PasswordError  # the policy lives in app.users.schema, covered in test_users


def test_set_a_new_password_for_a_user(ui: UI, uenv: dict[str, Path]) -> None:
    assert "New password for bob" in ui.get("/users/bob/password", htmx=True).text
    r = post(ui, "/users/bob/password", {"pw_mode": "generate"})
    assert r.status_code == 200 and PLAINTEXT in r.text and "already works" in r.text
    assert doc(uenv).raw("bob")["password"] == HASH_2
    bad = post(ui, "/users/bob/password", {"pw_mode": "typed", "password": "x"})
    assert bad.status_code == 422 and doc(uenv).raw("bob")["password"] == HASH_2


def test_lockout_guards_in_the_ui(ui: UI, uenv: dict[str, Path]) -> None:
    r = post(
        ui,
        "/users/save",
        {
            "original": "alice",
            "displayname": "Alice Example",
            "email": "alice@example.com",
            "l_groups": ["dev"],
        },
    )
    assert r.status_code == 422 and "cannot remove, disable or demote yourself" in r.text
    r = post(
        ui,
        "/users/save",
        {
            "original": "alice",
            "displayname": "Alice Example",
            "email": "alice@example.com",
            "l_groups": ["admin"],
            "disabled": "1",
        },
    )
    assert r.status_code == 422
    assert post(ui, "/users/alice/delete").status_code == 422
    assert "alice" in doc(uenv).names() and doc(uenv).users()["alice"]["groups"] == ["admin", "dev"]


def test_delete_asks_first(ui: UI, uenv: dict[str, Path]) -> None:
    assert "Delete user?" in ui.get("/users/device/delete", htmx=True).text
    assert post(ui, "/users/device/delete").status_code == 204
    assert "device" not in doc(uenv).names()


def test_invalid_input_is_refused_with_reasons(ui: UI, uenv: dict[str, Path]) -> None:
    r = post(ui, "/users/save", {"username": "bad name", "displayname": "X", "pw_mode": "generate"})
    assert r.status_code == 422 and "Usernames may use" in r.text
    r = post(ui, "/users/save", {"original": "bob", "displayname": "Bob", "email": "nope"})
    assert r.status_code == 422 and "not an email" in r.text
    r = post(
        ui,
        "/users/save",
        {
            "original": "bob",
            "displayname": "Bob",
            "email": "bob@example.com",
            "x_photo_quota": "lots",
        },
    )
    assert r.status_code == 422 and "whole number" in r.text


def test_a_stale_page_is_refused(ui: UI, uenv: dict[str, Path]) -> None:
    old = rev(ui)
    post(
        ui,
        "/users/save",
        {
            "original": "bob",
            "displayname": "Bobby",
            "email": "bob@example.com",
            "l_groups": ["home"],
        },
    )
    r = ui.post(
        "/users/save",
        {
            "original": "bob",
            "displayname": "Other",
            "email": "bob@example.com",
            "l_groups": ["home"],
            "users_rev": old,
        },
    )
    assert r.status_code == 422 and "changed in the meantime" in r.text
    assert doc(uenv).users()["bob"]["displayname"] == "Bobby"


def test_groups_page_members_rename_and_rule_references(ui: UI, uenv: dict[str, Path]) -> None:
    page = ui.get("/groups").text
    assert "admin" in page and "family" in page and "Used by rule" in page
    assert post(ui, "/groups/home/members", {"user": "alice", "action": "add"}).status_code == 204
    assert "home" in doc(uenv).users()["alice"]["groups"]
    assert (
        post(ui, "/groups/home/members", {"user": "alice", "action": "remove"}).status_code == 204
    )
    assert post(ui, "/groups/home/rename", {"new_name": "household"}).status_code == 204
    assert "household" in doc(uenv).users()["bob"]["groups"]
    assert post(ui, "/groups/admin/rename", {"new_name": "root"}).status_code == 422  # lockout
    assert post(ui, "/groups/x/rename", {"new_name": "a b"}).status_code == 422


def test_history_labels_users_commits_without_hashes(ui: UI, uenv: dict[str, Path]) -> None:
    post(
        ui,
        "/users/save",
        {
            "original": "bob",
            "displayname": "Bobby",
            "email": "bob@example.com",
            "l_groups": ["home"],
        },
    )
    post(ui, "/users/bob/password", {"pw_mode": "generate"})
    page = ui.get("/history").text
    assert "users (no restart)" in page and "Users: new password for bob" in page
    sha = re.search(r"/history/([0-9a-f]{40})/diff", page).group(1)  # type: ignore[union-attr]
    diff = ui.get(f"/history/{sha}/diff", htmx=True).text
    assert "other-hash" not in diff and "dummy-hash" not in diff and "&lt;hash&gt;" in diff
    assert "Revert to this" not in page.split("Users: new password")[1].split("</tr>")[0]


def test_read_only_when_the_file_is_outside_managed(
    env: dict[str, Path],  # noqa: F811
    tmp_path: Path,
) -> None:
    outside = tmp_path / "users.yml"
    outside.write_text(fill_placeholders((FIXTURES / "users.example.yml").read_text()))
    ui = UI(env)
    ui.settings.USERS_FILE = outside
    page = ui.get("/users").text
    assert "read-only here" in page and "+ New user" not in page and "alice" in page
    r = ui.post("/users/save", {"original": "bob", "displayname": "X", "users_rev": "0" * 16})
    assert r.status_code == 422 and "read-only" in r.text
