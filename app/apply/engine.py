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
import logging
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
from app.oidc.document import CLIENTS_NAME
from app.oidc.lint import lint_clients
from app.oidc.names import load_oidc_names
from app.rules import access_tests
from app.rules.disabled import DISABLED_NAME
from app.rules.document import DocumentError, RulesDocument
from app.rules.lint import blocking, lint
from app.rules.protected import check_protected
from app.rules.store import (
    LIVE_NAME,
    DraftStore,
    Snapshot,
    StaleDraftError,
    load_main_definitions,
    load_users,
    sha256,
)
from app.settings import Settings, VersionMismatch
from app.users.document import UsersDocument
from app.users.lint import lint_users, lockout_problems
from app.users.schema import load_schema

log = logging.getLogger("app.apply")

TRACKED = (LIVE_NAME, CLIENTS_NAME, "disabled_rules.yml", "access_tests.yml")
EXTERNAL_SUBJECT = "External change: edited outside the configurator"
MARKER = "in-progress.json"
RECOVERY_HINT = (
    "Manual action needed. On the Docker host run: "
    "git -C <CONFIG_MANAGED_DIR> log -3, then git -C <CONFIG_MANAGED_DIR> revert HEAD "
    "and docker restart <authelia container>."
)

# (settings, candidate access_control text, candidate oidc_clients text or None) -> result
Validator = Callable[[Settings, str, str | None], ValidationResult | None]
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
        discovery: probe.Discovery = probe.oidc_discovery,
    ) -> None:
        self.prober = prober
        self.discovery = discovery
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
        if self._marker().exists():
            # An interrupted apply's own write is not a hand edit: recovery resolves it.
            return None
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

    # ------------------------------------------------------------------ users (SPEC §9)

    @property
    def users_name(self) -> str | None:
        """The users file's name when it lives in the managed dir (else it is read-only here)."""
        path = self.settings.USERS_FILE
        return path.name if path.parent.resolve() == self.managed.resolve() else None

    def users_rev(self) -> str:
        try:
            return sha256(self.settings.USERS_FILE.read_text())[:16]
        except FileNotFoundError:
            return sha256("")[:16]

    def update_users(
        self,
        change: Callable[[UsersDocument], tuple[UsersDocument, str]],
        user: str,
        expected_rev: str | None,
    ) -> str:
        """Change the users file at once (Authelia reloads it: no restart). Under the apply lock:
        hand edits (and Authelia's own writes, e.g. password resets) are committed first, the
        revision is checked, the result is validated, lockouts are refused, and the write is a
        compare-and-swap against the file on disk."""
        name = self.users_name
        if name is None:
            raise Refused("The users file is outside the managed folder, so it is read-only here.")
        path = self.settings.USERS_FILE
        with self._exclusive():
            self.repo.ensure((*TRACKED, name))
            if not self.repo.tracks(name):
                self.repo.commit([name], "Users: start tracking the users file", "", "configurator")
            self._commit_external_unlocked()
            text = path.read_text()
            if expected_rev is not None and expected_rev != sha256(text)[:16]:
                raise Refused("The users changed in the meantime. Reload the page and retry.")
            before = UsersDocument.parse(text)
            after, subject = change(before)
            old, new = before.users(), after.users()
            touched = {n for n in new if old.get(n) != new.get(n)}
            touched |= {n for n in after.names() if before.names().count(n) == 0}
            touched |= {n for n in new if n in old and before.raw(n).get("password")
                        != after.raw(n).get("password")}  # fmt: skip
            schema = load_schema(self.settings.CONFIG_MAIN)
            has_pw = {n: after.has_password(n) for n in after.names()}
            errors = [m for who, sev, m in lint_users(new, schema, has_pw)
                      if sev == "error" and who in touched]  # fmt: skip
            errors += lockout_problems(old, new, user, self.settings.ADMIN_GROUP)
            if errors:
                raise Refused(" ".join(errors[:5]))
            if path.read_text() != text:  # Authelia wrote it while we were working
                raise Refused(
                    "Authelia changed the users file just now. Reload the page and retry."
                )
            self._atomic_write(path, after.render())
            sha = self.repo.commit([name], " ".join(subject.split())[:120], "", author=user)
            audit.append(self.managed, audit.AuditEntry(
                ts=audit.now(), user=user, client_ip="-", action="users", result="saved",
                commit=sha[:12], summary=" ".join(subject.split())[:200],
            ))  # fmt: skip
            return sha

    def tests_rev(self) -> str:
        """Revision of access_tests.yml as the page saw it (edits by index check it)."""
        try:
            return sha256((self.managed / access_tests.TESTS_NAME).read_text())[:16]
        except FileNotFoundError:
            return sha256("")[:16]

    def update_tests(
        self,
        change: Callable[
            [list[access_tests.AccessCase]], tuple[list[access_tests.AccessCase], str]
        ],
        user: str,
        expected_rev: str | None = None,
    ) -> str:
        """Read, change and commit access_tests.yml under the apply lock. Authelia never reads the
        file, so there is no draft, no restart and nothing to roll back. `change` returns the new
        list and the commit subject. Refused while an apply runs or when the file changed since
        `expected_rev`."""
        with self._exclusive():
            self.repo.ensure(TRACKED)
            self._commit_external_unlocked()
            if expected_rev is not None and expected_rev != self.tests_rev():
                raise Refused("The tests changed in the meantime. Reload the page and retry.")
            cases, subject = change(access_tests.load(self.managed))
            subject = " ".join(subject.split())[:120]  # one line, bounded
            self._atomic_write(self.managed / access_tests.TESTS_NAME, access_tests.render(cases))
            sha = self.repo.commit([access_tests.TESTS_NAME], subject, "", author=user)
            audit.append(self.managed, audit.AuditEntry(
                ts=audit.now(), user=user, client_ip="-", action="tests", result="saved",
                commit=sha[:12], summary=subject,
            ))  # fmt: skip
            return sha

    def notices(self) -> dict[str, Any]:
        """Banners for the page shell: hand edits found (and committed), main config changed."""
        with contextlib.suppress(RepoError, OSError):  # a banner must never break a page
            self.commit_external_changes()
        data = apply_state.load(self.managed)
        external = data.get("external") if isinstance(data.get("external"), dict) else None
        if external and external.get("commit") == data.get("external_seen"):
            external = None
        baseline = data.get("main_sha")
        main_changed = bool(baseline) and baseline != self.main_config_sha()
        return {"external": external, "main_changed": main_changed}

    def acknowledge(self, what: str) -> None:
        """Dismiss a banner: the hand edit is recorded as seen, or the main config becomes the
        new baseline."""
        data = apply_state.load(self.managed)
        if what == "external":
            external = data.get("external")
            if isinstance(external, dict):
                apply_state.update(self.managed, external_seen=external.get("commit"))
        elif what == "main":
            apply_state.update(self.managed, main_sha=self.main_config_sha())

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
        try:
            clients = self.store.current_clients()
        except DocumentError as exc:
            clients = None
            reasons.append(f"The OIDC clients file cannot be read: {exc}.")
        if clients is not None:
            names = load_oidc_names(self.settings.CONFIG_MAIN)
            client_errors = blocking(lint_clients(clients.clients(), names))
            if client_errors:
                reasons.append(f"{len(client_errors)} blocking OIDC client problem(s) must be "
                               "fixed first.")  # fmt: skip
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
            log.exception("apply failed unexpectedly")  # messages only; never file contents
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
        snap = self.store.snapshot()
        text = snap.rules
        expected_state = self.store.current_sha()
        changes = self.store.changes()

        board.update(job, "validate", "running")
        result = self.validator(self.settings, text, snap.clients or None)
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
                if snap.disabled != self.store.live_disabled_text():
                    # Authelia never reads this file; written first, committed together.
                    disabled_path = self.managed / DISABLED_NAME
                    if snap.disabled:
                        self._atomic_write(disabled_path, snap.disabled)
                    else:
                        disabled_path.unlink(missing_ok=True)
                    paths.append(DISABLED_NAME)
                if snap.clients and snap.clients != self.store.live_clients_text():
                    self._atomic_write(self.managed / CLIENTS_NAME, snap.clients)
                    paths.append(CLIENTS_NAME)
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
                return self._health_or_rollback(job, request, snap, before, commit)
            # Authelia never loaded the new file: undo the commit so file == running config.
            self.repo.revert_head(f"could not restart Authelia ({exc})", author=request.user)
            self._marker().unlink(missing_ok=True)
            board.update(job, "restart", "failed", str(exc))
            self._restore_draft(snap)
            self._finish(job, request, "rolled-back",
                         f"Authelia could not be restarted ({exc}); the change was undone and "
                         "is back in your draft.", "apply", commit)  # fmt: skip
            return
        board.update(job, "restart", "done")
        self._health_or_rollback(job, request, snap, before, commit)

    def _restarted_since(self, previous_started_at: str) -> bool:
        try:
            return self.runtime.inspect(timeout_s=5).started_at != previous_started_at
        except RuntimeUnavailable:
            return False  # cannot tell: treat as not restarted (the file is reverted)

    def _health_or_rollback(self, job: Job, request: ApplyRequest, snap: Snapshot, before: str,
                            commit: str) -> None:  # fmt: skip
        board = self.board
        board.update(job, "health", "running")
        health = self._wait(before)
        if health.healthy:
            board.update(job, "health", "done", health.reason)
            mismatch = self._verify(job, snap)
            if mismatch:
                self._rollback(job, request, snap, mismatch, commit)
                return
            board.update(job, "rollback", "skipped")
            self._marker().unlink(missing_ok=True)
            apply_state.update(self.managed, main_sha=self.main_config_sha())
            self._finish(job, request, "applied", "Applied. Authelia is healthy.", "apply", commit)
            return
        board.update(job, "health", "failed", health.reason)
        self._rollback(job, request, snap, health.reason, commit)

    def _rollback(self, job: Job, request: ApplyRequest, failed: Snapshot | None, reason: str,
                  commit: str) -> None:  # fmt: skip
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
        if failed is not None:
            self._restore_draft(failed)
        board.update(job, "rollback", "done", "previous version restored", details=details)
        self._finish(job, request, "rolled-back",
                     f"{reason} The previous version is live again; your change is back in the "
                     "draft so you can fix it.", "rollback", revert)  # fmt: skip

    def _verify(self, job: Job, snap: Snapshot) -> str | None:
        """Probe the real Authelia after the restart; a reason string when it disagrees.

        - OIDC (when this deployment has clients): the discovery document must be served.
        - Anonymous access tests: Authelia must answer what the rule tester predicted.
        """
        board = self.board
        if snap.clients:
            board.update(job, "verify", "running")
            host = probe.portal_host(self.settings.CONFIG_MAIN, self.settings.AUTH_DOMAIN)
            problem = self.discovery(self.settings.authelia_base_url, host)
            if problem:
                board.update(job, "verify", "failed", "OIDC discovery failed", details=[problem])
                return f"Authelia's OpenID Connect provider is not answering: {problem}."
        text = snap.rules
        try:
            cases = access_tests.load(self.managed)
        except DocumentError:
            cases = []
        if not any(c.anonymous for c in cases):
            if snap.clients:
                board.update(job, "verify", "done", "OIDC discovery answers")
            else:
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
        if self.repo.head() == old_head:
            # Crashed before the commit: the live files may already hold the new text, which
            # Authelia never loaded. Put the committed version back so file == running config;
            # the draft is still there (it is discarded only after the commit).
            # Only the files an apply writes: the users file (or access tests) may hold newer
            # changes Authelia made meanwhile (password resets) that must not be undone.
            for path in (LIVE_NAME, DISABLED_NAME, CLIENTS_NAME):
                if self.repo.tracks(path):
                    self.repo.restore(path)
            marker.unlink(missing_ok=True)
            self._finish(job, request, "refused",
                         "An interrupted apply was undone before it took effect; your change is "
                         "still in the draft.", "recovery")  # fmt: skip
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
        self._rollback(job, request, self._snapshot_at(self.repo.head()),
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

    def _snapshot_at(self, sha: str) -> Snapshot | None:
        """The drafted files as committed in `sha` (a missing file is "")."""

        def text(name: str) -> str:
            try:
                return self.repo.file_at(sha, name)
            except RepoError:
                return ""

        rules = text(LIVE_NAME)
        return Snapshot(rules, text(DISABLED_NAME), text(CLIENTS_NAME)) if rules else None

    def _restore_draft(self, snap: Snapshot) -> None:
        """Put the failed change back into the draft (the live files are the old ones again)."""
        with contextlib.suppress(DocumentError, StaleDraftError, OSError):
            self.store.save_snapshot(snap)

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
    clients = getattr(changes, "clients", None)
    client_parts = []
    if clients is not None:
        for count, word in ((clients.added, "added"), (clients.edited, "edited"),
                            (clients.removed, "removed")):  # fmt: skip
            if count:
                client_parts.append(f"{count} {word}")
        if clients.secrets_rotated:
            client_parts.append(f"{clients.secrets_rotated} secret(s) rotated")
    sections = []
    if parts or not client_parts:
        sections.append("Rules: " + (", ".join(parts) if parts else "updated"))
    if client_parts:
        sections.append("OIDC clients: " + ", ".join(client_parts))
    return "; ".join(sections)


def _body(request: ApplyRequest) -> str:
    return f"Applied-by: {request.user}\nClient-IP: {request.client_ip}"
