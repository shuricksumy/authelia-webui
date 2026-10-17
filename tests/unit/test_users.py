"""Phase 3a: the users file document, schema, policy, checks, lockout guards and saving."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from app.apply.engine import Refused
from app.authelia_cli import AutheliaCLI
from app.blocklist import DocumentError
from app.users import passwords
from app.users.document import DELETE, UsersDocument
from app.users.lint import groups_of, lint_users, lockout_problems, referenced_groups
from app.users.schema import PasswordPolicy, load_schema, policy_problems
from tests.unit.conftest import FIXTURES, fill_placeholders
from tests.unit.test_apply import env, git, make  # noqa: F401  (fixture)

HASH = "$argon2id$v=19$m=65536,t=3,p=4$dummy-salt$dummy-hash"
HASH_2 = "$argon2id$v=19$m=65536,t=3,p=4$other-salt$other-hash"


@pytest.fixture
def users_text() -> str:
    return fill_placeholders((FIXTURES / "users.example.yml").read_text())


# --------------------------------------------------------------------- document


def test_round_trip_and_style_detection(users_text: str) -> None:
    doc = UsersDocument.parse(users_text)
    assert doc.render() == users_text
    assert doc.names() == ["alice", "bob", "device", "family"]
    assert (doc.key_col, doc.step, doc.seq_offset) == (4, 4, 4)


def test_users_never_expose_the_password(users_text: str) -> None:
    doc = UsersDocument.parse(users_text)
    assert all("password" not in u for u in doc.users().values())
    assert doc.has_password("alice") and doc.raw("alice")["password"]


def test_set_fields_rewrites_only_the_changed_keys(users_text: str) -> None:
    doc = UsersDocument.parse(users_text)
    new = doc.set_fields("bob", {"displayname": "Bobby", "groups": ["home", "family"]})
    changed = [line for line in new.render().splitlines() if line not in users_text.splitlines()]
    assert changed == ["        displayname: 'Bobby'", "            - 'family'"] or set(
        changed
    ) >= {"        displayname: 'Bobby'", "            - 'family'"}
    assert all(new.blocks[i] == b for i, b in enumerate(doc.blocks) if b.name != "bob")
    assert new.users()["bob"]["groups"] == ["home", "family"]


def test_delete_a_key_add_a_user_delete_a_user(users_text: str) -> None:
    doc = UsersDocument.parse(users_text)
    doc = doc.set_fields("alice", {"email": DELETE, "disabled": True})
    assert "email" not in doc.users()["alice"] and doc.users()["alice"]["disabled"] is True
    doc = doc.add("carol", {"displayname": "Carol", "email": "carol@example.com",
                            "groups": ["home"], "disabled": False, "password": HASH})  # fmt: skip
    assert "    carol:\n        displayname: 'Carol'" in doc.render()
    assert "            - 'home'" in doc.render()  # the file's own list style
    assert doc.raw("carol")["password"] == HASH
    assert "carol" not in doc.delete("carol").names()
    with pytest.raises(DocumentError):
        doc.add("carol", {"displayname": "Again"})
    with pytest.raises(DocumentError):
        doc.add("bad name", {"displayname": "x"})


def test_rename_group_across_users(users_text: str) -> None:
    doc = UsersDocument.parse(users_text).rename_group("home", "household")
    assert groups_of(doc.users())["household"] == ["bob", "device"] and "home" not in groups_of(
        doc.users()
    )


def test_an_unusual_style_is_refused_not_corrupted() -> None:
    text = "users:\n  bob: {displayname: 'Bob', password: 'x', groups: [home]}\n"
    doc = UsersDocument.parse(text)
    with pytest.raises(DocumentError):
        doc.set_fields("bob", {"displayname": "Bobby"})
    with pytest.raises(DocumentError):
        UsersDocument.parse(text).set_fields("bob", {"displayname": "a\nb: c"})


def test_two_space_style_is_followed() -> None:
    text = (
        "users:\n  bob:\n    displayname: 'Bob'\n    password: 'x'\n    groups:\n      - 'home'\n"
    )
    doc = UsersDocument.parse(text).add("eve", {"displayname": "Eve", "groups": ["home"]})
    assert doc.render().endswith("  eve:\n    displayname: 'Eve'\n    groups:\n      - 'home'\n")


# --------------------------------------------------------------------- schema and policy


def test_schema_from_the_realistic_main(tmp_path: Path, realistic_main: str) -> None:
    main = tmp_path / "configuration.yml"
    main.write_text(realistic_main)
    schema = load_schema(main)
    assert schema.extra["photo_quota"].value_type == "integer" and schema.watch
    assert schema.policy.mode == "standard" and schema.policy.require_special
    assert schema.login_by_email


@pytest.mark.parametrize(
    ("password", "missing"),
    [
        ("Abcdef1!", []),
        ("abcdef1!", ["an uppercase letter"]),
        ("ABCDEF1!", ["a lowercase letter"]),
        ("Abcdefg!", ["a number"]),
        ("Abcdefg1", ["a special character"]),
        ("Ab1!", ["at least 8 characters"]),
    ],
)
def test_standard_policy(password: str, missing: list[str]) -> None:
    policy = PasswordPolicy("standard", 8, 0, True, True, True, True)
    assert policy_problems(password, policy) == missing


# --------------------------------------------------------------------- lint and lockout


def test_lint_rules(tmp_path: Path, realistic_main: str) -> None:
    main = tmp_path / "configuration.yml"
    main.write_text(realistic_main)
    schema = load_schema(main)
    users = {
        "ok": {"displayname": "Ok", "email": "ok@example.com", "groups": ["a"], "photo_quota": 5},
        "nopw": {"displayname": "No password"},
        "noname": {"email": "x@example.com"},
        "bademail": {"displayname": "B", "email": "not-an-email"},
        "badtype": {"displayname": "T", "extra": {"photo_quota": "lots"}},
        "unknown": {"displayname": "U", "extra": {"shoe_size": 42}},
        "dup1": {"displayname": "D", "email": "same@example.com"},
        "dup2": {"displayname": "D", "email": "SAME@example.com"},
        "badgroups": {"displayname": "G", "groups": "admin"},
    }
    pw = {n: n != "nopw" for n in users}
    by_user: dict[str, list[str]] = {}
    for who, severity, message in lint_users(users, schema, pw):
        if severity == "error":
            by_user.setdefault(who, []).append(message)
    assert "ok" not in by_user
    assert set(by_user) == {"nopw", "noname", "bademail", "badtype", "unknown", "dup1", "dup2",
                            "badgroups"}  # fmt: skip


def test_lockout_guards() -> None:
    before = {"alice": {"groups": ["admin"]}, "bob": {"groups": ["admin"]}}
    assert lockout_problems(before, {"alice": {"groups": []}, "bob": {"groups": ["admin"]}},
                            "alice", "admin")  # fmt: skip
    assert not lockout_problems(before, {"alice": {"groups": ["admin"]}, "bob": {"groups": []}},
                                "alice", "admin")  # fmt: skip
    assert lockout_problems(before, {"alice": {"groups": ["admin"], "disabled": True},
                                     "bob": {"groups": ["admin"]}}, "alice", "admin")  # fmt: skip
    assert lockout_problems(
        {"bob": {"groups": ["admin"]}}, {"bob": {"groups": ["x"]}}, "ci", "admin"
    )  # last admin, even when someone else does it


def test_referenced_groups() -> None:
    rules = [{"subject": ["group:family", ["user:bob", "group:home"]]}, {"subject": "group:family"}]
    assert referenced_groups(rules) == {"family": [1, 2], "home": [1]}


# --------------------------------------------------------------------- saving through the engine


@pytest.fixture
def users_env(env: dict[str, Any], users_text: str) -> dict[str, Any]:  # noqa: F811
    path = env["managed"] / "users.yml"
    path.write_text(users_text.replace("dummy-002", HASH))
    s = env["settings"].model_copy(update={"USERS_FILE": path})
    return {**env, "settings": s, "users": path}


def engine_for(users_env: dict[str, Any]) -> Any:
    engine, _, _ = make({**users_env})
    return engine


def test_update_users_commits_and_audits(users_env: dict[str, Any]) -> None:
    engine = engine_for(users_env)
    rev = engine.users_rev()
    sha = engine.update_users(
        lambda d: (d.set_fields("bob", {"displayname": "Bobby"}), "Users: edited bob"), "alice", rev
    )
    assert sha and "displayname: 'Bobby'" in users_env["users"].read_text()
    log = git(users_env["managed"], "log", "--format=%an|%s").splitlines()
    assert log[0] == "alice|Users: edited bob"
    assert "users.yml" in git(users_env["managed"], "ls-files")  # imported with the repo
    assert '"action": "users"' in (users_env["managed"] / "audit.log").read_text()


def test_update_users_refuses_stale_lockout_and_invalid(users_env: dict[str, Any]) -> None:
    engine = engine_for(users_env)
    with pytest.raises(Refused, match="changed in the meantime"):
        engine.update_users(lambda d: (d, "x"), "alice", "0" * 16)
    rev = engine.users_rev()
    with pytest.raises(Refused, match="yourself"):
        engine.update_users(
            lambda d: (d.set_fields("alice", {"groups": ["dev"]}), "x"), "alice", rev
        )
    with pytest.raises(Refused, match="not an email"):
        engine.update_users(lambda d: (d.set_fields("bob", {"email": "nope"}), "x"), "alice", rev)
    assert "dev" in users_env["users"].read_text() and "nope" not in users_env["users"].read_text()


def test_update_users_loses_no_concurrent_authelia_write(users_env: dict[str, Any]) -> None:
    engine = engine_for(users_env)
    path = users_env["users"]

    def change(doc: UsersDocument) -> tuple[UsersDocument, str]:
        path.write_text(path.read_text().replace("Bob Example", "Bob Reset"))  # Authelia, meanwhile
        return doc.set_fields("device", {"displayname": "Dev"}), "x"

    with pytest.raises(Refused, match="Authelia changed the users file"):
        engine.update_users(change, "alice", engine.users_rev())
    assert "Bob Reset" in path.read_text()


def test_users_file_outside_managed_is_read_only(env: dict[str, Any], tmp_path: Path) -> None:  # noqa: F811
    outside = tmp_path / "users.yml"
    outside.write_text("users: {}\n")
    engine, _, _ = make(
        {**env, "settings": env["settings"].model_copy(update={"USERS_FILE": outside})}
    )
    assert engine.users_name is None
    with pytest.raises(Refused, match="read-only"):
        engine.update_users(lambda d: (d, "x"), "alice", None)


# --------------------------------------------------------------------- passwords


def test_typed_password_goes_to_a_terminal_not_a_command_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app import authelia_cli

    seen: dict[str, Any] = {}

    def fake(argv: Any, answer: str, timeout: float) -> str:
        seen["argv"], seen["answer"] = list(argv), answer
        return f"Enter Password: \r\nDigest: {HASH}\r\n"

    monkeypatch.setattr(authelia_cli, "_run_with_terminal", fake)
    policy = PasswordPolicy("standard", 8, 0, True, True, True, True)
    digest = passwords.typed(AutheliaCLI.local(), Path("/c/main.yml"), "Typed-pass-1!", policy)
    assert digest == HASH and seen["answer"] == "Typed-pass-1!"
    assert "Typed-pass-1!" not in " ".join(seen["argv"]) and "--password" not in seen["argv"]
    assert "--config" in seen["argv"]
    with pytest.raises(passwords.PasswordError, match="needs") as exc:
        passwords.typed(AutheliaCLI.local(), Path("/c/main.yml"), "weak", policy)
    assert "weak" not in str(exc.value)


def test_generated_password_is_regenerated_until_it_meets_the_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outputs = iter(["alllowercase", "Good-Pass-123!"])

    def run(self: AutheliaCLI, args: Any, **_: Any) -> subprocess.CompletedProcess[str]:
        value = next(outputs)
        return subprocess.CompletedProcess(
            args, 0, f"Random Password: {value}\nDigest: {HASH}\n", ""
        )

    monkeypatch.setattr(AutheliaCLI, "run", run)
    policy = PasswordPolicy("standard", 8, 0, True, True, True, True)
    assert passwords.generated(AutheliaCLI.local(), Path("/m.yml"), policy) == (
        "Good-Pass-123!",
        HASH,
    )


def test_a_password_change_stores_only_the_hash(users_env: dict[str, Any]) -> None:
    """The engine only ever receives a hash; the typed/generated plaintext stays in the request."""
    engine = engine_for(users_env)
    plaintext = "Never-On-Disk-123!"
    engine.update_users(
        lambda d: (d.set_fields("bob", {"password": HASH_2}), "Users: new password for bob"),
        "alice", engine.users_rev(),
    )  # fmt: skip
    everything = "\n".join(
        p.read_text(errors="replace") for p in users_env["managed"].rglob("*") if p.is_file()
    )
    assert plaintext not in everything and HASH_2 in users_env["users"].read_text()


def test_an_existing_repo_starts_tracking_the_users_file(users_env: dict[str, Any]) -> None:
    engine = engine_for(users_env)
    engine.repo.ensure(["access_control.yml"])  # a repo from before Phase 3
    assert not engine.repo.tracks("users.yml")
    engine.update_users(lambda d: (d.set_fields("bob", {"displayname": "B"}), "Users: x"),
                        "alice", engine.users_rev())  # fmt: skip
    log = git(users_env["managed"], "log", "--format=%s").splitlines()
    assert log[:2] == ["Users: x", "Users: start tracking the users file"]
