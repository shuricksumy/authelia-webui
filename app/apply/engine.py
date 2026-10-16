"""Apply a reviewed draft safely (SPEC §6):

    validate -> atomic write -> git commit -> restart -> health check -> rollback if unhealthy

Guarantees:
- nothing is written unless the draft is current, reviewed (same revision), lint-clean,
  keeps protected rules intact, matches the running Authelia version and validates;
- one apply at a time (exclusive flock), and a draft edited meanwhile is never applied;
- the live file always matches a git commit; a failed restart or health check reverts the
  commit (a new "Rollback" commit), restarts again and reports why;
- a crash mid-apply leaves a marker that startup recovery resolves (app/apply/engine.recover).
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import tempfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.apply import audit
from app.apply.health import HealthResult, wait_restarted_and_healthy
from app.apply.jobs import Job, JobBoard
from app.apply.repo import ManagedRepo, RepoError
from app.apply.runtime import AutheliaRuntime, RuntimeUnavailable
from app.authelia_cli import ValidationResult, redact
from app.rules.document import DocumentError, RulesDocument
from app.rules.lint import blocking, lint
from app.rules.protected import check_protected
from app.rules.store import (
    LIVE_NAME,
    DraftStore,
    StaleDraftError,
    load_main_definitions,
    load_users,
    sha256,
)
from app.settings import Settings, VersionMismatch

TRACKED = (LIVE_NAME, "oidc_clients.yml", "disabled_rules.yml", "protected_rules.yml")
MARKER = "in-progress.json"
RECOVERY_HINT = (
    "Manual action needed. On the Docker host run: "
    "git -C <CONFIG_MANAGED_DIR> log -3, then git -C <CONFIG_MANAGED_DIR> revert HEAD "
    "and docker restart <authelia container>."
)

Validator = Callable[[Settings, str], ValidationResult | None]
HealthWaiter = Callable[..., HealthResult]


class Refused(Exception):
    """A precondition failed; nothing was changed. Message is plain language."""


@dataclass(frozen=True)
class ApplyRequest:
    user: str
    client_ip: str
    rev: str  # revision of the draft the user reviewed (first 16 hex of its sha256)


class ApplyEngine:
    def __init__(
        self,
        settings: Settings,
        runtime: AutheliaRuntime,
        board: JobBoard,
        validator: Validator,
        health_waiter: HealthWaiter = wait_restarted_and_healthy,
    ) -> None:
        self.settings = settings
        self.runtime = runtime
        self.board = board
        self.validator = validator
        self.health_waiter = health_waiter
        self.managed = settings.CONFIG_MANAGED_DIR
        self.store = DraftStore(self.managed)
        self.repo = ManagedRepo(self.managed, settings.CONFIGURATOR_DOMAIN)
        self.state_dir = self.managed / ".apply"

    # ------------------------------------------------------------------ locking / marker

    @contextlib.contextmanager
    def _exclusive(self) -> Iterator[None]:
        self.state_dir.mkdir(mode=0o700, exist_ok=True)
        with open(self.state_dir / "lock", "w") as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Refused("Another apply is already running.") from None
            try:
                yield
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)

    def _marker(self) -> Path:
        return self.state_dir / MARKER

    def _write_marker(self, data: dict[str, Any]) -> None:
        self.state_dir.mkdir(mode=0o700, exist_ok=True)
        self._marker().write_text(json.dumps(data))

    # ------------------------------------------------------------------ preconditions

    def version_problem(self) -> str | None:
        """None when the running Authelia matches the bundled one (or the policy is `warn`)."""
        try:
            running = self.runtime.inspect(timeout_s=3).version
        except RuntimeUnavailable as exc:
            return f"Cannot check the running Authelia: {exc}."
        bundled = self.settings.AUTHELIA_VERSION
        if running != bundled and self.settings.VERSION_MISMATCH == VersionMismatch.BLOCK:
            return (
                f"Authelia {running or 'unknown'} is running, but this configurator bundles "
                f"{bundled}. Deploy the image tagged authelia-{running} (or update Authelia to "
                f"{bundled}) before applying."
            )
        return None

    def preconditions(self, rev: str | None = None) -> list[str]:
        """Plain-language reasons why apply is not possible right now (empty: ready)."""
        reasons: list[str] = []
        if self.board.running():
            reasons.append("Another apply is running.")
        if not self.store.has_draft():
            return [*reasons, "There are no unapplied changes."]
        if self.store.is_stale():
            reasons.append(
                "The live file changed after this draft was started. Discard it and redo the edits."
            )
        try:
            doc = self.store.current()
        except DocumentError as exc:
            return [*reasons, str(exc)]
        if rev is not None and rev != sha256(doc.render())[:16]:
            reasons.append("The draft changed since you reviewed it. Review it again.")
        if self.repo.is_repo() and self.repo.is_dirty():
            reasons.append(
                "Managed files were changed outside the configurator (git shows uncommitted "
                "changes). Commit or revert them on the host first."
            )
        users = load_users(self.settings.USERS_FILE)
        definitions = load_main_definitions(self.settings.CONFIG_MAIN)
        known = frozenset(((definitions.get("definitions") or {}).get("network") or {}).keys())
        issues = lint(doc.rules(), users=users, default_policy=doc.default_policy(),
                      known_networks=known)  # fmt: skip
        if blocking(issues):
            reasons.append(f"{len(blocking(issues))} blocking lint problem(s) must be fixed first.")
        report = check_protected({**definitions, **doc.effective()}, self.settings)
        if not report.ok:
            reasons.append("Protected rules are not satisfied: " + " ".join(report.violations))
        problem = self.version_problem()
        if problem:
            reasons.append(problem)
        return reasons

    # ------------------------------------------------------------------ apply

    def apply(self, request: ApplyRequest, job: Job) -> Job:
        """Run the whole flow for `job`; always returns with job.result set."""
        try:
            with self._exclusive():
                self._apply(request, job)
        except Refused as exc:
            self._finish(job, request, "refused", str(exc), action="apply")
        except Exception:
            self._finish(job, request, "failed", "Unexpected error. " + RECOVERY_HINT, "apply")
        return job

    def _apply(self, request: ApplyRequest, job: Job) -> None:
        board = self.board
        reasons = self.preconditions(rev=request.rev)
        reasons = [r for r in reasons if r != "Another apply is running."]  # that is us
        if reasons:
            raise Refused(" ".join(reasons))
        self.repo.ensure(TRACKED)
        doc = self.store.current()
        text = doc.render()
        changes = self.store.changes()

        board.update(job, "validate", "running")
        result = self.validator(self.settings, text)
        if result is None:
            board.update(job, "validate", "failed", "The Authelia validator is not available.")
            raise Refused("Authelia's validator could not run, so nothing was applied.")
        if not result.ok:
            board.update(job, "validate", "failed", "Authelia rejected the draft.",
                         details=[*result.errors][:10])  # fmt: skip
            raise Refused("Authelia rejected the draft; nothing was applied.")
        board.update(job, "validate", "done",
                     f"{len(result.warnings)} warning(s)" if result.warnings else "OK")  # fmt: skip

        board.update(job, "save", "running")
        try:
            before = self.runtime.inspect(timeout_s=5).started_at
        except RuntimeUnavailable as exc:
            raise Refused(f"Cannot reach Authelia's container: {exc}.") from None
        old_head = self.repo.head()
        try:
            with self.store.locked():
                if sha256(self.store.current().render()) != sha256(text):
                    raise Refused("The draft changed while applying. Review it again.")
                self._write_marker({"old_head": old_head, "started_at": before,
                                    "user": request.user})  # fmt: skip
                self._atomic_write(self.managed / LIVE_NAME, text)
                try:
                    commit = self.repo.commit(
                        [LIVE_NAME], _subject(changes), _body(request), author=request.user
                    )
                except RepoError:
                    self.repo.restore(LIVE_NAME)  # put the committed file back
                    self._marker().unlink(missing_ok=True)
                    raise Refused("Saving to git failed; the live file was restored.") from None
                self.store.discard_unlocked()
        except StaleDraftError:
            self._marker().unlink(missing_ok=True)
            raise Refused("The draft changed while applying. Review it again.") from None
        board.update(job, "save", "done", f"commit {commit[:7]}", commit=commit)

        board.update(job, "restart", "running")
        try:
            self.runtime.restart()
        except RuntimeUnavailable as exc:
            # Authelia never loaded the new file: undo the commit so file == running config.
            self.repo.revert_head(f"could not restart Authelia ({exc})")
            self._marker().unlink(missing_ok=True)
            board.update(job, "restart", "failed", str(exc))
            self._restore_draft(text)
            self._finish(job, request, "rolled-back",
                         f"Authelia could not be restarted ({exc}); the change was undone and "
                         "is back in your draft.", "apply", commit)  # fmt: skip
            return
        board.update(job, "restart", "done")

        board.update(job, "health", "running")
        health = self._wait(before)
        if health.healthy:
            board.update(job, "health", "done", health.reason)
            board.update(job, "rollback", "skipped")
            self._marker().unlink(missing_ok=True)
            self._finish(job, request, "applied", "Applied. Authelia is healthy.", "apply", commit)
            return
        board.update(job, "health", "failed", health.reason)
        self._rollback(job, request, text, health.reason, commit)

    def _rollback(self, job: Job, request: ApplyRequest, failed_text: str, reason: str,
                  commit: str) -> None:  # fmt: skip
        board = self.board
        board.update(job, "rollback", "running")
        details = self._authelia_errors()
        try:
            before = self.runtime.inspect(timeout_s=5).started_at
            revert = self.repo.revert_head(reason)
            self.runtime.restart()
            health = self._wait(before)
        except (RuntimeUnavailable, RepoError) as exc:
            board.update(job, "rollback", "failed", str(exc), details=details)
            self._finish(job, request, "failed",
                         f"The change made Authelia unhealthy and rolling back failed ({exc}). "
                         + RECOVERY_HINT, "rollback", commit)  # fmt: skip
            return
        if not health.healthy:
            board.update(job, "rollback", "failed", health.reason, details=details)
            self._finish(job, request, "failed",
                         "The change made Authelia unhealthy and it is still unhealthy after "
                         "rolling back. " + RECOVERY_HINT, "rollback", revert)  # fmt: skip
            return
        self._marker().unlink(missing_ok=True)
        self._restore_draft(failed_text)
        board.update(job, "rollback", "done", "previous version restored", details=details)
        self._finish(job, request, "rolled-back",
                     f"Rolled back: {reason} The previous version is live again; your change is "
                     "back in the draft so you can fix it.", "rollback", revert)  # fmt: skip

    def _wait(self, previous_started_at: str) -> HealthResult:
        return self.health_waiter(
            self.runtime, self.settings.AUTHELIA_HEALTH_URL, previous_started_at,
            timeout_s=float(self.settings.APPLY_HEALTH_TIMEOUT_S),
        )  # fmt: skip

    # ------------------------------------------------------------------ recovery

    def recover(self) -> str | None:
        """Called at startup: resolve an apply interrupted by a crash. Returns a summary."""
        marker = self._marker()
        if not marker.exists():
            return None
        try:
            data = json.loads(marker.read_text())
            before = str(data["started_at"])
            old_head = str(data["old_head"])
        except (OSError, ValueError, KeyError):
            return "An interrupted apply left an unreadable marker; check the history."
        job = self.board.new("recovery")
        request = ApplyRequest(user="recovery", client_ip="-", rev="")
        if self.repo.head() == old_head:  # crashed before the commit: nothing changed
            marker.unlink(missing_ok=True)
            self._finish(job, request, "refused", "An interrupted apply had not changed anything.",
                         "recovery")  # fmt: skip
            return job.message
        health = self.health_waiter(
            self.runtime, self.settings.AUTHELIA_HEALTH_URL, before,
            timeout_s=float(self.settings.APPLY_HEALTH_TIMEOUT_S),
        )  # fmt: skip
        if health.healthy:
            marker.unlink(missing_ok=True)
            self._finish(job, request, "applied",
                         "An interrupted apply had completed; Authelia is healthy.", "recovery",
                         self.repo.head())  # fmt: skip
            return job.message
        self._rollback(job, request, self.repo.file_at(self.repo.head(), LIVE_NAME),
                       "interrupted apply left Authelia unhealthy.", self.repo.head())  # fmt: skip
        return job.message

    # ------------------------------------------------------------------ helpers

    def _finish(self, job: Job, request: ApplyRequest, result: str, message: str, action: str,
                commit: str = "") -> None:  # fmt: skip
        self.board.update(job, result=result, message=message, commit=commit or job.commit)
        audit.append(self.managed, audit.AuditEntry(
            ts=audit.now(), user=request.user, client_ip=request.client_ip, action=action,
            result=result, commit=(commit or job.commit)[:12], summary=message[:200],
        ))  # fmt: skip

    def _restore_draft(self, text: str) -> None:
        with contextlib.suppress(DocumentError, StaleDraftError, OSError):
            self.store.save(RulesDocument.parse(text))

    def _atomic_write(self, path: Path, text: str) -> None:
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".apply-")
        try:
            with os.fdopen(fd, "w") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
            os.chmod(tmp, mode)
            os.replace(tmp, path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def _authelia_errors(self, limit: int = 5) -> list[str]:
        """Last error messages from Authelia's JSON log, if configured (SPEC §16.4)."""
        path = self.settings.AUTHELIA_LOG_FILE
        if path is None:
            return []
        try:
            lines = path.read_text(errors="replace").splitlines()[-200:]
        except OSError:
            return []
        out = []
        for line in lines:
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if entry.get("level") in ("error", "fatal", "panic"):
                out.append(redact(str(entry.get("msg", "")))[:300])
        return out[-limit:]


def _subject(changes: Any) -> str:
    parts = []
    if changes.added:
        parts.append(f"{changes.added} added")
    if changes.edited:
        parts.append(f"{changes.edited} edited")
    if changes.removed:
        parts.append(f"{changes.removed} removed")
    if changes.order_changed:
        parts.append("order changed")
    if changes.default_policy_changed:
        parts.append("default policy changed")
    return "Rules: " + (", ".join(parts) if parts else "updated")


def _body(request: ApplyRequest) -> str:
    return f"Applied-by: {request.user}\nClient-IP: {request.client_ip}"
