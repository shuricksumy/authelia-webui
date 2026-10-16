"""Apply engine (SPEC §6) with a fake container runtime and health results, real git repos."""

from __future__ import annotations

import fcntl
import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from app.apply import audit
from app.apply.engine import ApplyEngine, ApplyRequest
from app.apply.health import HealthResult, wait_restarted_and_healthy
from app.apply.jobs import JobBoard
from app.apply.repo import ManagedRepo, RepoError
from app.apply.runtime import ContainerState, RuntimeUnavailable
from app.authelia_cli import ValidationResult
from app.rules.store import DraftStore, sha256
from app.settings import Settings
from tests.unit.test_web import ACCESS_CONTROL

# --------------------------------------------------------------------- fakes


@dataclass
class FakeRuntime:
    version: str = "4.39.28"
    starts: int = 0
    restarts: int = 0
    fail_restart: bool = False
    unavailable: bool = False

    def inspect(self, timeout_s: float | None = None) -> ContainerState:
        if self.unavailable:
            raise RuntimeUnavailable("socket proxy unreachable (ConnectError)")
        return ContainerState(f"start-{self.starts}", True, self.version)

    def restart(self, grace_s: int = 10) -> None:
        if self.fail_restart:
            raise RuntimeUnavailable("restarting Authelia failed (HTTP 403)")
        self.restarts += 1
        self.starts += 1


@dataclass
class ScriptedHealth:
    """Returns the scripted results in order (True = healthy)."""

    script: list[bool]
    calls: list[str] = field(default_factory=list)

    def __call__(
        self, runtime: Any, url: str, previous: str, timeout_s: float = 30
    ) -> HealthResult:
        self.calls.append(previous)
        ok = self.script.pop(0)
        return HealthResult(ok, "healthy" if ok else "Authelia did not come back up within 30 s.")


def ok_validator(settings: Settings, text: str) -> ValidationResult:
    return ValidationResult(True, [], [], "")


# --------------------------------------------------------------------- fixture


@pytest.fixture
def env(tmp_path: Path) -> dict[str, Any]:
    managed = tmp_path / "managed"
    managed.mkdir()
    (managed / "access_control.yml").write_text(ACCESS_CONTROL)
    (managed / "oidc_clients.yml").write_text("identity_providers:\n  oidc:\n    clients: []\n")
    users = tmp_path / "users.yml"
    users.write_text("users:\n  alice:\n    groups: [admin]\n  bob:\n    groups: [family]\n")
    main = tmp_path / "configuration.yml"
    main.write_text("theme: light\n")
    log = tmp_path / "authelia.log"
    log.write_text(json.dumps({"level": "error", "msg": "error loading rule 3: bad thing"}) + "\n")
    settings = Settings(
        AUTH_DOMAIN="auth.example.com", CONFIGURATOR_DOMAIN="authcfg.example.com",
        ADMIN_GROUP="admin", ALLOWED_CLIENT_CIDRS="10.8.0.0/24",  # type: ignore[arg-type]
        TRUSTED_PROXY_CIDRS="172.20.0.0/16",  # type: ignore[arg-type]
        AUTHELIA_CONTAINER="authelia", AUTHELIA_HEALTH_URL="http://authelia:9091/api/health",
        APP_SECRET_KEY="k" * 40,  # type: ignore[arg-type]
        CONFIG_MANAGED_DIR=managed, USERS_FILE=users, CONFIG_MAIN=main,
        AUTHELIA_VERSION="4.39.28", AUTHELIA_LOG_FILE=log,
    )  # fmt: skip
    return {"settings": settings, "managed": managed, "store": DraftStore(managed)}


def make(
    env: dict[str, Any],
    health: list[bool] | None = None,
    validator: Any = ok_validator,
    runtime: FakeRuntime | None = None,
) -> tuple[ApplyEngine, FakeRuntime, ScriptedHealth]:
    runtime = runtime or FakeRuntime()
    waiter = ScriptedHealth(list(health or [True]))
    engine = ApplyEngine(env["settings"], runtime, JobBoard(env["managed"]), validator, waiter)  # type: ignore[arg-type]
    return engine, runtime, waiter


def draft_move(env: dict[str, Any]) -> str:
    """Create a valid draft (move rule 4 below rule 5) and return its revision."""
    store: DraftStore = env["store"]
    store.save(store.current().move(3, 4))
    return sha256(store.current().render())[:16]


def run(engine: ApplyEngine, rev: str):  # type: ignore[no-untyped-def]
    job = engine.board.new("alice")
    return engine.apply(ApplyRequest("alice", "10.8.0.5", rev), job)


def git(managed: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(managed), *args], capture_output=True, text=True,
                          check=True).stdout  # fmt: skip


def live(env: dict[str, Any]) -> str:
    return (env["managed"] / "access_control.yml").read_text()


# --------------------------------------------------------------------- happy path


def test_successful_apply_writes_commits_restarts_and_clears_the_draft(env: dict[str, Any]) -> None:
    rev = draft_move(env)
    draft_text = env["store"].current().render()
    engine, runtime, waiter = make(env, [True])
    job = run(engine, rev)
    assert job.result == "applied", job.message
    assert live(env) == draft_text and not env["store"].has_draft()
    assert runtime.restarts == 1 and waiter.calls == ["start-0"]  # waited for a *new* start
    log = git(env["managed"], "log", "--format=%an|%s|%b").strip().split("\n")
    assert log[0].startswith("alice|Rules: order changed|Applied-by: alice")
    assert "Initial import" in git(env["managed"], "log", "--format=%s")
    assert git(env["managed"], "status", "--porcelain").strip() == ""  # runtime files ignored
    assert not (env["managed"] / ".apply" / "in-progress.json").exists()
    assert [s.status for s in job.steps] == ["done", "done", "done", "done", "skipped"]
    entries = audit.recent(env["managed"])
    assert entries[-1].result == "applied" and entries[-1].user == "alice"
    assert entries[-1].client_ip == "10.8.0.5" and job.commit.startswith(entries[-1].commit[:7])


def test_audit_log_holds_no_configuration_content(env: dict[str, Any]) -> None:
    engine, _, _ = make(env, [True])
    run(engine, draft_move(env))
    text = (env["managed"] / "audit.log").read_text()
    assert "photos.example.com" not in text and "resources" not in text
    assert oct((env["managed"] / "audit.log").stat().st_mode & 0o777) == "0o600"


# --------------------------------------------------------------------- rollback


def test_unhealthy_after_restart_rolls_back_and_keeps_the_change_in_the_draft(
    env: dict[str, Any],
) -> None:
    original = live(env)
    rev = draft_move(env)
    failed = env["store"].current().render()
    engine, runtime, _ = make(env, [False, True])
    job = run(engine, rev)
    assert job.result == "rolled-back", job.message
    assert live(env) == original  # previous version is live again
    assert runtime.restarts == 2
    subjects = git(env["managed"], "log", "--format=%s").split("\n")
    assert subjects[0].startswith("Rollback:") and subjects[1] == "Rules: order changed"
    assert env["store"].current().render() == failed  # the user can fix and retry
    assert job.step("rollback").status == "done"
    assert "error loading rule 3" in " ".join(job.details)  # Authelia log excerpt (SPEC §16.4)
    assert audit.recent(env["managed"])[-1].result == "rolled-back"


def test_rollback_that_also_fails_reports_manual_action_and_keeps_the_marker(
    env: dict[str, Any],
) -> None:
    engine, _, _ = make(env, [False, False])
    job = run(engine, draft_move(env))
    assert job.result == "failed" and "Manual action needed" in job.message
    assert (env["managed"] / ".apply" / "in-progress.json").exists()


def test_failed_restart_call_undoes_the_commit_without_waiting(env: dict[str, Any]) -> None:
    original = live(env)
    engine, _, waiter = make(env, [], runtime=FakeRuntime(fail_restart=True))
    job = run(engine, draft_move(env))
    assert job.result == "rolled-back" and "could not be restarted" in job.message
    assert live(env) == original and waiter.calls == [] and env["store"].has_draft()
    assert not (env["managed"] / ".apply" / "in-progress.json").exists()


# --------------------------------------------------------------------- refusals (nothing changes)


def refused(env: dict[str, Any], engine: ApplyEngine, rev: str, fragment: str) -> None:
    before = live(env)
    runtime = engine.runtime
    job = run(engine, rev)
    assert job.result == "refused", job.message
    assert fragment in job.message, job.message
    assert live(env) == before
    assert runtime.restarts == 0  # type: ignore[attr-defined]


def test_validator_rejection_changes_nothing(env: dict[str, Any]) -> None:
    def reject(settings: Settings, text: str) -> ValidationResult:
        return ValidationResult(False, ["access_control: rule #2: bad"], [], "")

    engine, _, _ = make(env, validator=reject)
    rev = draft_move(env)
    refused(env, engine, rev, "Authelia rejected the draft")
    assert env["store"].has_draft()
    assert engine.board.current().details == ["access_control: rule #2: bad"]  # type: ignore[union-attr]


def test_missing_validator_changes_nothing(env: dict[str, Any]) -> None:
    engine, _, _ = make(env, validator=lambda s, t: None)
    refused(env, engine, draft_move(env), "validator could not run")


def test_no_draft(env: dict[str, Any]) -> None:
    engine, _, _ = make(env)
    refused(env, engine, "", "no unapplied changes")


def test_wrong_revision(env: dict[str, Any]) -> None:
    draft_move(env)
    engine, _, _ = make(env)
    refused(env, engine, "0" * 16, "changed since you reviewed it")


def test_stale_draft(env: dict[str, Any]) -> None:
    rev = draft_move(env)
    path = env["managed"] / "access_control.yml"
    path.write_text(path.read_text() + "# edited by hand\n")
    engine, _, _ = make(env)
    refused(env, engine, rev, "live file changed")


def test_hand_edited_tracked_file_blocks_apply(env: dict[str, Any]) -> None:
    engine, _, _ = make(env, [True])
    engine.repo.ensure(["access_control.yml", "oidc_clients.yml"])
    (env["managed"] / "oidc_clients.yml").write_text("identity_providers: {}\n")
    refused(env, engine, draft_move(env), "changed outside the configurator")


def test_blocking_lint_and_protected_violations(env: dict[str, Any]) -> None:
    store: DraftStore = env["store"]
    from app.rules.document import RulesDocument

    bad = ACCESS_CONTROL.replace("'^/api/ping$'", "'^(?!/x).*$'")
    store.save(RulesDocument.parse(bad))
    engine, _, _ = make(env)
    refused(env, engine, sha256(store.current().render())[:16], "blocking lint")
    store.discard()
    store.save(store.current().delete(2))  # removes the explicit deny for the configurator
    refused(env, engine, sha256(store.current().render())[:16], "Protected rules")


def test_version_mismatch_blocks_by_default_and_warn_allows(env: dict[str, Any]) -> None:
    engine, _, _ = make(env, runtime=FakeRuntime(version="4.40.0"))
    rev = draft_move(env)
    refused(env, engine, rev, "4.40.0 is running")
    env["settings"].VERSION_MISMATCH = "warn"
    engine2, _, _ = make(env, [True], runtime=FakeRuntime(version="4.40.0"))
    assert run(engine2, rev).result == "applied"


def test_unreachable_proxy_blocks_apply(env: dict[str, Any]) -> None:
    engine, _, _ = make(env, runtime=FakeRuntime(unavailable=True))
    refused(env, engine, draft_move(env), "Cannot check the running Authelia")


def test_only_one_apply_at_a_time(env: dict[str, Any]) -> None:
    engine, _, _ = make(env, [True])
    rev = draft_move(env)
    lock = env["managed"] / ".apply"
    lock.mkdir(exist_ok=True)
    with open(lock / "lock", "w") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        refused(env, engine, rev, "Another apply is already running")


# --------------------------------------------------------------------- recovery and job state


def test_recovery_after_crash_keeps_a_healthy_apply(env: dict[str, Any]) -> None:
    engine, _, _ = make(env, [True])
    engine.repo.ensure(["access_control.yml"])
    old = engine.repo.head()
    path = env["managed"] / "access_control.yml"
    path.write_text(path.read_text() + "# applied\n")
    engine.repo.commit(["access_control.yml"], "Rules: updated", "", "alice")
    (env["managed"] / ".apply").mkdir(exist_ok=True)
    (env["managed"] / ".apply" / "in-progress.json").write_text(
        json.dumps({"old_head": old, "started_at": "start-0", "user": "alice"})
    )
    assert "completed" in (engine.recover() or "")
    assert not (env["managed"] / ".apply" / "in-progress.json").exists()


def test_recovery_after_crash_rolls_back_an_unhealthy_apply(env: dict[str, Any]) -> None:
    original = live(env)
    engine, runtime, _ = make(env, [False, True])
    engine.repo.ensure(["access_control.yml"])
    old = engine.repo.head()
    path = env["managed"] / "access_control.yml"
    path.write_text(original.replace("policy: deny\n", "policy: one_factor\n", 1))
    engine.repo.commit(["access_control.yml"], "Rules: updated", "", "alice")
    (env["managed"] / ".apply").mkdir(exist_ok=True)
    (env["managed"] / ".apply" / "in-progress.json").write_text(
        json.dumps({"old_head": old, "started_at": "start-0", "user": "alice"})
    )
    assert "previous version is live again" in (engine.recover() or "")
    assert live(env) == original and runtime.restarts == 1
    assert engine.board.current().result == "rolled-back"  # type: ignore[union-attr]


def test_no_marker_no_recovery(env: dict[str, Any]) -> None:
    engine, _, _ = make(env)
    assert engine.recover() is None


def test_job_result_survives_a_new_board(env: dict[str, Any]) -> None:
    engine, _, _ = make(env, [True])
    run(engine, draft_move(env))
    reloaded = JobBoard(env["managed"]).current()
    assert reloaded is not None and reloaded.result == "applied" and reloaded.user == "alice"
    assert oct((env["managed"] / ".apply" / "last.json").stat().st_mode & 0o777) == "0o600"


# --------------------------------------------------------------------- health and repo


def test_health_waits_for_a_real_restart() -> None:
    runtime = FakeRuntime()
    now = [0.0]
    result = wait_restarted_and_healthy(
        runtime, "http://x", "start-0", timeout_s=5, check=lambda url: True,  # type: ignore[arg-type]
        clock=lambda: now[0], sleep=lambda s: now.__setitem__(0, now[0] + s),
    )  # fmt: skip
    assert not result.healthy and "did not come back" in result.reason  # same instance: no
    runtime.starts = 1
    result = wait_restarted_and_healthy(
        runtime, "http://x", "start-0", timeout_s=5, check=lambda url: True,  # type: ignore[arg-type]
        clock=lambda: now[0], sleep=lambda s: now.__setitem__(0, now[0] + s),
    )  # fmt: skip
    assert result.healthy


def test_repo_basics(tmp_path: Path) -> None:
    (tmp_path / "access_control.yml").write_text("a: 1\n")
    repo = ManagedRepo(tmp_path, "authcfg.example.com")
    assert repo.ensure(["access_control.yml", "missing.yml"]) is True
    assert repo.ensure(["access_control.yml"]) is False
    (tmp_path / "access_control.yml").write_text("a: 2\n")
    assert repo.is_dirty()
    sha = repo.commit(["access_control.yml"], "Rules: updated", "Applied-by: bob", "bob")
    assert not repo.is_dirty()
    top = repo.log()[0]
    assert (top.sha, top.author, top.subject, top.body) == (sha, "bob", "Rules: updated",
                                                             "Applied-by: bob")  # fmt: skip
    assert "+a: 2" in repo.diff(sha, "access_control.yml")
    assert repo.file_at(repo.log()[1].sha, "access_control.yml") == "a: 1\n"
    repo.revert_head("test")
    assert (tmp_path / "access_control.yml").read_text() == "a: 1\n"
    for bad in ("HEAD; rm -rf /", "zzzzzzz", "--output=/tmp/x"):
        with pytest.raises(RepoError):
            repo.diff(bad, "access_control.yml")


def test_job_board_sees_a_result_written_by_another_instance(env: dict[str, Any]) -> None:
    """Two instances (or workers) share the managed dir; each must show the same latest job."""
    first, second = JobBoard(env["managed"]), JobBoard(env["managed"])
    assert first.current() is None and second.current() is None
    job = first.new("alice")
    first.update(job, result="applied", message="done")
    seen = second.current()
    assert seen is not None and seen.id == job.id and seen.result == "applied"
    other = second.new("bob")
    assert first.current() is not None and first.current().id == other.id  # type: ignore[union-attr]
