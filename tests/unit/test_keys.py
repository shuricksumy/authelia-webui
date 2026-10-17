# ruff: noqa: F811  (the `env` fixture is imported from test_apply)
"""OIDC key rotation (prepare -> promote -> retire) through the apply engine, with fakes for the
container and for Authelia's key set, real git, and no real key material."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

import pytest

from app.apply import audit, keys
from app.apply import state as apply_state
from app.apply.engine import ApplyEngine
from app.apply.jobs import JobBoard
from app.authelia_cli import AutheliaCLI, ValidationResult
from app.oidc.jwks import JwksDocument, entry_lines, key_path, new_document
from tests.unit.test_apply import FakeRuntime, ScriptedHealth, env, git, ok_validator  # noqa: F401

FAKE_KEY = b"fake-private-key-material-for-tests"


class Authelia:
    """Stands in for Authelia: what it 'publishes' is whatever the live keys file lists."""

    def __init__(self, managed: Path) -> None:
        self.managed = managed
        self.broken = False
        self.validate_ok = True

    def published(self, _url: str, _host: str) -> list[str] | str:
        if self.broken:
            return ["somebody-else"]
        return JwksDocument.parse((self.managed / "oidc_jwks.yml").read_text()).kids()

    def validate(self, _settings: Any, text: str) -> ValidationResult:
        # like Authelia: every key the candidate names must exist as a file
        doc = JwksDocument.parse(text)
        missing = [k.kid for k in doc.entries() if not Path(k.secret_path).is_file()]
        ok = self.validate_ok and not missing
        return ValidationResult(ok, [] if ok else ["rejected"], [], "")


@pytest.fixture(autouse=True)
def fake_generator(monkeypatch: pytest.MonkeyPatch) -> None:
    def generate(self: AutheliaCLI, directory: Path, algorithm: str, bits: int = 4096) -> Path:
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "private.pem").write_bytes(FAKE_KEY)
        (directory / "public.pem").write_bytes(b"public")
        return directory / "private.pem"

    monkeypatch.setattr(AutheliaCLI, "generate_key_pair", generate)


def setup(
    env: dict[str, Any], health: list[bool] | None = None, kids: tuple[str, ...] = ("old",)
) -> tuple[ApplyEngine, Authelia, FakeRuntime]:
    managed: Path = env["managed"]
    settings = env["settings"]
    settings.CONFIG_FILTERS = "template"
    entries = []
    for kid in kids:
        path = key_path(managed, kid)
        path.parent.parent.mkdir(mode=0o700, exist_ok=True)
        path.parent.mkdir(mode=0o700, exist_ok=True)
        path.write_bytes(FAKE_KEY)
        entries.append(entry_lines(kid, "RS256", path))
    (managed / "oidc_jwks.yml").write_text(new_document(entries).render())
    authelia = Authelia(managed)
    runtime = FakeRuntime()
    engine = ApplyEngine(
        settings, runtime, JobBoard(managed), ok_validator,  # type: ignore[arg-type]
        ScriptedHealth(list(health or [True])),  # type: ignore[arg-type]
        discovery=lambda *a: None, keys_validator=authelia.validate, jwks_probe=authelia.published,
    )  # fmt: skip
    engine.repo.ensure(("access_control.yml", "oidc_clients.yml", "oidc_jwks.yml"))
    engine.repo.exclude("secrets/")
    return engine, authelia, runtime


def op(engine: ApplyEngine, action: str, kid: str = "", rev: str | None = None) -> keys.KeyOp:
    return keys.KeyOp(action, kid, rev or keys.keys_state(engine).rev, "alice", "10.8.0.5")


def go(engine: ApplyEngine, operation: keys.KeyOp):  # type: ignore[no-untyped-def]
    return keys.run(engine, operation, engine.board.new("alice"))


def kids(env: dict[str, Any]) -> list[str]:
    return JwksDocument.parse((env["managed"] / "oidc_jwks.yml").read_text()).kids()


def test_a_full_rotation_prepare_promote_retire(env: dict[str, Any]) -> None:
    engine, _, runtime = setup(env, [True, True, True])
    managed: Path = env["managed"]
    job = go(engine, op(engine, "prepare"))
    assert job.result == "applied", job.message
    [old, new] = kids(env)
    assert old == "old" and new.startswith("key-")
    pem = key_path(managed, new)
    assert pem.read_bytes() == FAKE_KEY and stat.S_IMODE(pem.stat().st_mode) == 0o600
    assert stat.S_IMODE(pem.parent.stat().st_mode) == 0o700
    assert apply_state.load(managed)["jwks_prepared_at"] > 0
    assert "OIDC keys: prepared new key" in git(managed, "log", "-1", "--format=%s")

    job = go(engine, op(engine, "promote", new))
    assert job.result == "applied", job.message
    assert kids(env) == [new, "old"]

    job = go(engine, op(engine, "retire", "old"))
    assert job.result == "applied", job.message
    assert kids(env) == [new]
    assert not key_path(managed, "old").exists()  # deleted only after the retire succeeded
    assert pem.exists() and runtime.restarts == 3


def test_private_keys_never_reach_git_the_audit_log_or_the_job(env: dict[str, Any]) -> None:
    engine, _, _ = setup(env)
    managed: Path = env["managed"]
    job = go(engine, op(engine, "prepare"))
    assert job.result == "applied"
    tracked = git(managed, "ls-files")
    assert "secrets" not in tracked and "oidc_jwks.yml" in tracked
    assert "secrets" not in git(managed, "status", "--porcelain", "--untracked-files=all")
    everything = git(managed, "log", "-p", "--all")
    everything += (managed / ".apply" / "last.json").read_text()
    everything += audit.AuditEntry.__name__ + (managed / "audit.log").read_text()
    assert FAKE_KEY.decode() not in everything
    # a repository created before secrets/ existed is protected by the local exclude too
    assert "secrets/" in (managed / ".git" / "info" / "exclude").read_text()


def test_a_wrong_key_set_after_restart_rolls_back_and_drops_the_new_file(
    env: dict[str, Any],
) -> None:
    engine, authelia, runtime = setup(env, [True, True])
    before = (env["managed"] / "oidc_jwks.yml").read_text()
    authelia.broken = True
    job = go(engine, op(engine, "prepare"))
    assert job.result == "rolled-back", job.message
    assert (env["managed"] / "oidc_jwks.yml").read_text() == before
    assert sorted(p.name for p in key_path(env["managed"], "x").parent.iterdir()) == ["old.pem"]
    assert runtime.restarts == 2  # the change and the rollback


def test_a_failed_retire_keeps_the_old_file_for_the_rollback(env: dict[str, Any]) -> None:
    engine, authelia, _ = setup(env, [True, True], kids=("new", "old"))
    authelia.broken = True
    job = go(engine, op(engine, "retire", "old"))
    assert job.result == "rolled-back"
    assert kids(env) == ["new", "old"] and key_path(env["managed"], "old").exists()


def test_an_unhealthy_authelia_rolls_back(env: dict[str, Any]) -> None:
    engine, _, _ = setup(env, [False, True], kids=("a", "b"))
    job = go(engine, op(engine, "promote", "b"))
    assert job.result == "rolled-back"
    assert kids(env) == ["a", "b"]


def test_validation_failure_changes_nothing(env: dict[str, Any]) -> None:
    engine, authelia, runtime = setup(env)
    authelia.validate_ok = False
    head = engine.repo.head()
    job = go(engine, op(engine, "prepare"))
    assert job.result == "refused" and engine.repo.head() == head and runtime.restarts == 0
    assert [p.name for p in key_path(env["managed"], "x").parent.iterdir()] == ["old.pem"]
    assert kids(env) == ["old"]


def test_steps_are_refused_out_of_order(env: dict[str, Any]) -> None:
    engine, _, _ = setup(env)
    state = keys.keys_state(engine)
    assert keys.preconditions(engine, op(engine, "promote", "old")) != []  # the first key signs
    assert keys.preconditions(engine, op(engine, "retire", "nope")) != []
    assert keys.preconditions(engine, op(engine, "explode")) != []
    assert keys.preconditions(engine, keys.KeyOp("prepare", "", "0" * 16, "a", "-"))[0].startswith(
        "The keys changed"
    )
    assert keys.preconditions(engine, op(engine, "prepare", rev=state.rev)) == []
    go(engine, op(engine, "prepare"))
    assert any("second key" in r for r in keys.preconditions(engine, op(engine, "prepare")))


def test_the_template_filter_must_be_configured(env: dict[str, Any]) -> None:
    engine, _, _ = setup(env)
    env["settings"].CONFIG_FILTERS = ""
    assert any("CONFIG_FILTERS" in r for r in keys.preconditions(engine, op(engine, "prepare")))
    assert any("CONFIG_FILTERS" in r for r in engine.preconditions())


def test_an_unmigrated_setup_is_reported_not_broken(env: dict[str, Any]) -> None:
    engine, _, _ = setup(env)
    (env["managed"] / "oidc_jwks.yml").unlink()
    state = keys.keys_state(engine)
    assert not state.migrated and not state.manageable
    assert keys.preconditions(engine, keys.KeyOp("prepare", "", "", "a", "-"))
    (env["managed"] / "oidc_jwks.yml").write_text("garbage: [")
    assert keys.keys_state(engine).problem and not keys.keys_state(engine).manageable


def test_inline_private_keys_block_rotation(env: dict[str, Any]) -> None:
    engine, _, _ = setup(env)
    (env["managed"] / "oidc_jwks.yml").write_text(
        "identity_providers:\n  oidc:\n    jwks:\n      - key_id: 'x'\n"
        "        algorithm: 'RS256'\n        key: |\n          inline\n"
    )
    assert "still written into the file" in keys.keys_state(engine).problem
    assert not keys.keys_state(engine).can_prepare()


def test_a_crash_before_the_commit_restores_the_keys_file(env: dict[str, Any]) -> None:
    engine, _, _ = setup(env)
    managed: Path = env["managed"]
    before = (managed / "oidc_jwks.yml").read_text()
    engine._write_marker({"old_head": engine.repo.head(), "started_at": "start-0", "user": "a"})
    (managed / "oidc_jwks.yml").write_text(before + "# half written\n")
    assert "undone" in (engine.recover() or "")
    assert (managed / "oidc_jwks.yml").read_text() == before and os.path.exists(managed)


def test_a_cleanup_problem_after_success_keeps_the_step_applied(
    env: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    engine, _, _ = setup(env, kids=("new", "old"))

    def fail(path: Path | None) -> None:
        raise PermissionError("read-only")

    monkeypatch.setattr(keys, "_drop", fail)
    job = go(engine, op(engine, "retire", "old"))
    assert job.result == "applied", job.message
    assert kids(env) == ["new"]


def test_template_text_in_a_draft_is_refused_when_the_filter_is_on(env: dict[str, Any]) -> None:
    engine, _, _ = setup(env)
    store = env["store"]
    doc = store.current()
    node = doc.blocks[0].node()
    store.save(doc.replace_rule(0, node, note='{{ env "APP_SECRET_KEY" }}'))
    reasons = engine.preconditions()
    assert any("evaluate it as a template" in r for r in reasons)
    env["settings"].CONFIG_FILTERS = ""
    assert not any("evaluate it as a template" in r for r in engine.preconditions())
