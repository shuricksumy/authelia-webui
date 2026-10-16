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

from app.apply import audit, notify, probe
from app.apply import state as apply_state
from app.apply.health import HealthResult, wait_restarted_and_healthy
from app.apply.jobs import Job, JobBoard
from app.apply.repo import ManagedRepo, RepoError
from app.apply.runtime import AutheliaRuntime, RuntimeUnavailable
from app.authelia_cli import ValidationResult, redact
from app.rules import access_tests
from app.rules.disabled import DISABLED_NAME, DisabledRules
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

TRACKED = (LIVE_NAME, "oidc_clients.yml", "disabled_rules.yml", "access_tests.yml")
EXTERNAL_SUBJECT = "External change: edited outside the configurator"
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
    accept_tests: bool = False  # the admin ticked "I accept these changes" for failing tests


class ApplyEngine:
    def __init__(
        self,
        settings: Settings,
        runtime: AutheliaRuntime,
        board: JobBoard,
        validator: Validator,
        health_waiter: HealthWaiter = wait_restarted_and_healthy,
        prober: probe.Prober = probe.forward_auth,
    ) -> None:
        self.prober = prober
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

    def exclusive(self) -> contextlib.AbstractContextManager[None]:
        """The apply lock (non-blocking: Refused when another apply holds it)."""
        return self._exclusive()

    # ------------------------------------------------------------------ external changes

    def commit_external_changes(self) -> str | None:
        """Commit hand edits of tracked managed files (SPEC §16.8). Returns the commit, or None
        when there was nothing to commit or an apply is running (it will be done later)."""
        if not self.repo.has_commits():
            return None
        try:
            with self._exclusive():
                return self._commit_external_unlocked()
        except Refused:
            return None

    def _commit_external_unlocked(self) -> str | None:
        if not self.repo.has_commits() or not self.repo.is_dirty():
            return None
        sha = self.repo.commit_tracked_changes(
            EXTERNAL_SUBJECT,
            "Found uncommitted changes to managed files and recorded them as they were.",
            author="external",
        )
        apply_state.update(self.managed, external={"commit": sha, "ts": audit.now()})
        audit.append(self.managed, audit.AuditEntry(
            ts=audit.now(), user="external", client_ip="-", action="external-change",
            result="committed", commit=sha[:12], summary="Managed files were edited by hand.",
        ))  # fmt: skip
        return sha

    def main_config_sha(self) -> str:
        try:
            return sha256(self.settings.CONFIG_MAIN.read_text())
        except OSError:
            return ""

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

    def test_results(self) -> list[access_tests.CaseResult]:
        """Access tests evaluated on the live rules and on the draft (when there is one)."""
        definitions = load_main_definitions(self.settings.CONFIG_MAIN)
        cases = access_tests.load(self.managed)
        live_config = {**definitions, **self.store.live().effective()}
        draft_config = (
            {**definitions, **self.store.current().effective()} if self.store.has_draft() else None
        )
        return access_tests.evaluate(cases, live_config, draft_config,
                                     self.settings.default_client_ip)  # fmt: skip

    def preconditions(self, rev: str | None = None, accept_tests: bool = False) -> list[str]:
        """Plain-language reasons why apply is not possible right now (empty: ready)."""
        reasons: list[str] = []
        if self.board.running():
            reasons.append("Another apply is running.")
        elif self._marker().exists():
            reasons.append(
                "An earlier apply did not finish cleanly. Restart the configurator so it can "
                "resolve it (it checks Authelia and rolls back if needed), then review again."
            )
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
        if rev is not None and rev != self.store.current_sha()[:16]:
            reasons.append("The draft changed since you reviewed it. Review it again.")
        try:
            failing = access_tests.failing(self.test_results())
        except DocumentError as exc:
            failing = []
            reasons.append(f"The access tests file cannot be read: {exc}.")
        if failing and not accept_tests:
            reasons.append(
                f"{len(failing)} access test(s) would not get the expected result. Check them "
                'and tick "I accept these changes" if that is intended.'
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
        if self.repo.ensure(TRACKED) or "main_sha" not in apply_state.load(self.managed):
            apply_state.update(self.managed, main_sha=self.main_config_sha())
        self._commit_external_unlocked()  # hand edits become history first (may stale the draft)
        reasons = self.preconditions(rev=request.rev, accept_tests=request.accept_tests)
        reasons = [r for r in reasons if r != "Another apply is running."]  # that is us
        if reasons:
            raise Refused(" ".join(reasons))
        doc = self.store.current()
        text = doc.render()
        disabled_text = self.store.current_disabled().render()
        expected_state = self.store.current_sha()
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
                if self.store.current_sha() != expected_state:
                    raise Refused("The draft changed while applying. Review it again.")
                self._write_marker({"old_head": old_head, "started_at": before,
                                    "user": request.user})  # fmt: skip
                paths = [LIVE_NAME]
                if disabled_text != self.store.live_disabled_text():
                    # Authelia never reads this file; written first, committed together.
                    disabled_path = self.managed / DISABLED_NAME
                    if disabled_text:
                        self._atomic_write(disabled_path, disabled_text)
                    else:
                        disabled_path.unlink(missing_ok=True)
                    paths.append(DISABLED_NAME)
                self._atomic_write(self.managed / LIVE_NAME, text)
                try:
                    commit = self.repo.commit(
                        paths, _subject(changes), _body(request), author=request.user
                    )
                except RepoError:
                    for path in paths:  # put the committed files back
                        self.repo.restore(path)
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
            if self._restarted_since(before):
                # The call failed (e.g. timed out) but Docker did restart it: the new file is
                # what Authelia loaded, so carry on with the health check instead of reverting.
                board.update(job, "restart", "done", f"restarted (the call reported: {exc})")
                return self._health_or_rollback(job, request, text, before, commit, disabled_text)
            # Authelia never loaded the new file: undo the commit so file == running config.
            self.repo.revert_head(f"could not restart Authelia ({exc})", author=request.user)
            self._marker().unlink(missing_ok=True)
            board.update(job, "restart", "failed", str(exc))
            self._restore_draft(text, disabled_text)
            self._finish(job, request, "rolled-back",
                         f"Authelia could not be restarted ({exc}); the change was undone and "
                         "is back in your draft.", "apply", commit)  # fmt: skip
            return
        board.update(job, "restart", "done")
        self._health_or_rollback(job, request, text, before, commit, disabled_text)

    def _restarted_since(self, previous_started_at: str) -> bool:
        try:
            return self.runtime.inspect(timeout_s=5).started_at != previous_started_at
        except RuntimeUnavailable:
            return False  # cannot tell: treat as not restarted (the file is reverted)

    def _health_or_rollback(self, job: Job, request: ApplyRequest, text: str, before: str,
                            commit: str, disabled_text: str | None = None) -> None:  # fmt: skip
        board = self.board
        board.update(job, "health", "running")
        health = self._wait(before)
        if health.healthy:
            board.update(job, "health", "done", health.reason)
            mismatch = self._verify(job, text)
            if mismatch:
                self._rollback(job, request, text, mismatch, commit, disabled_text)
                return
            board.update(job, "rollback", "skipped")
            self._marker().unlink(missing_ok=True)
            apply_state.update(self.managed, main_sha=self.main_config_sha())
            self._finish(job, request, "applied", "Applied. Authelia is healthy.", "apply", commit)
            return
        board.update(job, "health", "failed", health.reason)
        self._rollback(job, request, text, health.reason, commit, disabled_text)

    def _rollback(self, job: Job, request: ApplyRequest, failed_text: str, reason: str,
                  commit: str, failed_disabled: str | None = None) -> None:  # fmt: skip
        board = self.board
        board.update(job, "rollback", "running")
        details = [*job.details, *self._authelia_errors()]
        try:
            before = self.runtime.inspect(timeout_s=5).started_at
            revert = self.repo.revert_head(reason, author=request.user)
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
        self._restore_draft(failed_text, failed_disabled)
        board.update(job, "rollback", "done", "previous version restored", details=details)
        self._finish(job, request, "rolled-back",
                     f"{reason} The previous version is live again; your change is back in the "
                     "draft so you can fix it.", "rollback", revert)  # fmt: skip

    def _verify(self, job: Job, text: str) -> str | None:
        """Probe anonymous access tests against the real Authelia; a reason string on mismatch."""
        board = self.board
        try:
            cases = access_tests.load(self.managed)
        except DocumentError:
            cases = []
        if not any(c.anonymous for c in cases):
            board.update(job, "verify", "skipped", "no anonymous access tests")
            return None
        board.update(job, "verify", "running")
        definitions = load_main_definitions(self.settings.CONFIG_MAIN)
        config = {**definitions, **RulesDocument.parse(text).effective()}
        results = probe.verify(cases, config, self.settings.authelia_base_url,
                               self.settings.default_client_ip, self.prober)  # fmt: skip
        bad = [r for r in results if r.mismatch]
        untestable = [r for r in results if r.actual == "untestable"]
        if bad:
            details = [f"{r.case.method} {r.case.url}: previewed {r.expected}, Authelia says "
                       f"{r.actual}" for r in bad]  # fmt: skip
            board.update(job, "verify", "failed", f"{len(bad)} mismatch(es)", details=details)
            return f"Authelia does not behave as previewed for {len(bad)} access test(s)."
        note = f"{len(results) - len(untestable)} checked"
        if untestable:
            note += f", {len(untestable)} not testable"
        board.update(job, "verify", "done", note)
        return None

    def _wait(self, previous_started_at: str) -> HealthResult:
        return self.health_waiter(
            self.runtime, self.settings.AUTHELIA_HEALTH_URL, previous_started_at,
            timeout_s=float(self.settings.APPLY_HEALTH_TIMEOUT_S),
        )  # fmt: skip

    # ------------------------------------------------------------------ recovery

    def recover(self) -> str | None:
        """Called at startup: resolve an apply interrupted by a crash. Returns a summary.

        Holds the apply lock: if another live process (a second instance, or this app before a
        reload) is still applying, its marker is not a crash and must not be touched. A process
        that died has released its flock, so a real crash is always recoverable.
        """
        if not self._marker().exists():
            return None
        try:
            with self._exclusive():
                return self._recover()
        except Refused:
            return None  # another apply is in progress; it will finish its own work

    def _recover(self) -> str | None:
        marker = self._marker()
        if not marker.exists():  # finished while we waited for nothing (non-blocking lock)
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
        if result in ("applied", "rolled-back", "failed"):
            notify.send(self.settings, action, result, request.user, message[:300],
                        commit or job.commit)  # fmt: skip
        audit.append(self.managed, audit.AuditEntry(
            ts=audit.now(), user=request.user, client_ip=request.client_ip, action=action,
            result=result, commit=(commit or job.commit)[:12], summary=message[:200],
        ))  # fmt: skip

    def _restore_draft(self, text: str, disabled_text: str | None = None) -> None:
        with contextlib.suppress(DocumentError, StaleDraftError, OSError):
            disabled = DisabledRules.parse(disabled_text) if disabled_text is not None else None
            self.store.save(RulesDocument.parse(text), disabled=disabled)

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
            with path.open("rb") as handle:
                handle.seek(0, os.SEEK_END)
                size = handle.tell()
                start = max(0, size - 65536)  # only the tail: logs can be gigabytes
                handle.seek(start)
                lines = handle.read().decode("utf-8", errors="replace").splitlines()
                if start > 0:
                    lines = lines[1:]  # the first line was cut in the middle by the seek
                lines = lines[-200:]
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
    if changes.disabled:
        parts.append(f"{changes.disabled} disabled")
    if changes.enabled:
        parts.append(f"{changes.enabled} enabled")
    if changes.deleted_disabled:
        parts.append(f"{changes.deleted_disabled} disabled rule(s) deleted")
    return "Rules: " + (", ".join(parts) if parts else "updated")


def _body(request: ApplyRequest) -> str:
    return f"Applied-by: {request.user}\nClient-IP: {request.client_ip}"
