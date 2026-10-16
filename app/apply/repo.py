"""The managed directory as a local git repository (SPEC §6: every apply is a commit).

The repository is local only and never pushed: it contains password hashes (oidc_clients.yml).
Runtime state (.draft/, .apply/, locks) and the audit log are not tracked, so a revert can never
rewrite the audit trail.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

GITIGNORE = """# Managed by the Authelia Configurator. Runtime state is never committed.
.draft/
.apply/
.lock
audit.log
"""
GIT_TIMEOUT_S = 30


class RepoError(RuntimeError):
    """A git operation failed; message is safe to show (no file contents)."""


@dataclass(frozen=True)
class Commit:
    sha: str
    author: str
    timestamp: int  # unix seconds
    subject: str
    body: str

    @property
    def short(self) -> str:
        return self.sha[:7]


class ManagedRepo:
    def __init__(self, path: Path, email_domain: str) -> None:
        self.path = path
        self.email_domain = email_domain

    # ------------------------------------------------------------------ plumbing

    def _git(self, *args: str, author: str | None = None, check: bool = True) -> str:
        env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "LANG": "C.UTF-8",
            "HOME": str(self.path),  # git refuses to run without one; nothing is read from it
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
        }
        identity = author or "authelia-configurator"
        email = f"noreply@{self.email_domain}"
        argv = [
            "git", "-C", str(self.path),
            "-c", f"user.name={identity}", "-c", f"user.email={email}",
            "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
            "-c", "core.fsmonitor=false",
            "-c", f"safe.directory={self.path}",
            *args,
        ]  # fmt: skip
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, env=env, timeout=GIT_TIMEOUT_S, check=False
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RepoError(f"git {args[0]} could not run ({type(exc).__name__})") from None
        if check and proc.returncode != 0:
            raise RepoError(f"git {args[0]} failed")
        return proc.stdout

    # ------------------------------------------------------------------ setup

    def is_repo(self) -> bool:
        return (self.path / ".git").is_dir()

    def has_commits(self) -> bool:
        return self.is_repo() and bool(self._git("rev-parse", "--verify", "-q", "HEAD",
                                                 check=False).strip())  # fmt: skip

    def ensure(self, files: Sequence[str]) -> bool:
        """Create the repository and commit `files` as the initial import. True if created.
        Also completes a repository whose first commit never happened (e.g. a crash)."""
        if self.has_commits():
            return False
        if not self.is_repo():
            self._git("init", "-q", "-b", "main")
        (self.path / ".gitignore").write_text(GITIGNORE)
        present = [f for f in files if (self.path / f).is_file()]
        self._git("add", "--", ".gitignore", *present)
        self._git("commit", "-q", "-m", "Initial import of the managed configuration")
        return True

    # ------------------------------------------------------------------ state

    def is_dirty(self) -> bool:
        """Tracked files changed or staged outside the configurator (e.g. edited over SSH)."""
        return bool(self._git("status", "--porcelain", "--untracked-files=no").strip())

    def head(self) -> str:
        return self._git("rev-parse", "HEAD").strip()

    # ------------------------------------------------------------------ writes

    def commit(self, paths: Sequence[str], subject: str, body: str, author: str) -> str:
        self._git("add", "--", *paths)
        message = subject if not body else f"{subject}\n\n{body}"
        self._git("commit", "-q", "-m", message, author=author)
        return self.head()

    def commit_tracked_changes(self, subject: str, body: str, author: str) -> str:
        """Commit every change to tracked files (hand edits); untracked files stay untracked."""
        self._git("add", "--update")
        message = subject if not body else f"{subject}\n\n{body}"
        self._git("commit", "-q", "-m", message, author=author)
        return self.head()

    def restore(self, path: str) -> None:
        """Put the committed version of `path` back into the working tree."""
        self._git("checkout", "--", path)

    def restore_all(self) -> None:
        """Put every tracked file back to HEAD (untracked and ignored files are left alone)."""
        self._git("checkout", "HEAD", "--", ".")

    def revert_head(self, reason: str, author: str | None = None) -> str:
        """Undo the last commit with a new commit (history keeps both)."""
        self._git("revert", "--no-edit", "--no-commit", "HEAD", author=author)
        self._git("commit", "-q", "-m", f"Rollback: {reason}", author=author)
        return self.head()

    # ------------------------------------------------------------------ reads

    def log(self, limit: int = 50) -> list[Commit]:
        sep, end = "\x1f", "\x1e"
        out = self._git("log", f"-n{limit}", f"--format=%H{sep}%an{sep}%at{sep}%s{sep}%b{end}")
        commits = []
        for record in out.split(end):
            record = record.strip("\n")
            if not record:
                continue
            sha, author, ts, subject, body = record.split(sep, 4)
            commits.append(Commit(sha, author, int(ts), subject, body.strip()))
        return commits

    def diff(self, sha: str, path: str) -> str:
        """Diff of one file in one commit (no other file contents are ever read)."""
        self._check_sha(sha)
        # no external diff drivers or textconv filters: .gitattributes is a tracked file
        return self._git("show", "--format=", "--no-color", "--no-ext-diff", "--no-textconv",
                         sha, "--", path)  # fmt: skip

    def file_at(self, sha: str, path: str) -> str:
        self._check_sha(sha)
        return self._git("show", "--no-textconv", f"{sha}:{path}")

    def _check_sha(self, sha: str) -> None:
        if not (7 <= len(sha) <= 40 and all(c in "0123456789abcdef" for c in sha)):
            raise RepoError("not a commit id")
        if self._git("cat-file", "-t", sha, check=False).strip() != "commit":
            raise RepoError("unknown commit")
