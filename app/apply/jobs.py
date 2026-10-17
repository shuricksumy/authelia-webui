"""State of the current / last apply, shown by the progress panel and the result banner.

Kept in memory (one apply at a time) and mirrored to CONFIG_MANAGED_DIR/.apply/last.json, so the
result is still there after Authelia's restart signs everyone out and they log in again.
"""

from __future__ import annotations

import copy
import json
import os
import secrets
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

STEPS = ("validate", "save", "restart", "health", "verify", "rollback")
STEP_LABELS = {
    "validate": "Validating",
    "save": "Saving",
    "restart": "Restarting Authelia",
    "health": "Health check",
    "verify": "Checking the live Authelia",
    "rollback": "Rolling back",
}


@dataclass
class Step:
    name: str
    status: str = "pending"  # pending | running | done | failed | skipped
    detail: str = ""

    @property
    def label(self) -> str:
        return STEP_LABELS[self.name]


@dataclass
class Job:
    id: str
    user: str
    started: int
    steps: list[Step] = field(default_factory=lambda: [Step(n) for n in STEPS])
    result: str | None = None  # applied | rolled-back | failed | refused
    message: str = ""
    details: list[str] = field(default_factory=list)
    commit: str = ""
    finished: int | None = None

    @property
    def done(self) -> bool:
        return self.result is not None

    def step(self, name: str) -> Step:
        return next(s for s in self.steps if s.name == name)


class JobBoard:
    def __init__(self, managed_dir: Path) -> None:
        self.path = managed_dir / ".apply" / "last.json"
        self._lock = threading.Lock()
        self._mtime: int | None = None
        self._job: Job | None = self._load()

    def _stamp(self) -> int | None:
        try:
            return self.path.stat().st_mtime_ns
        except OSError:
            return None

    def _load(self) -> Job | None:
        self._mtime = self._stamp()
        try:
            raw = json.loads(self.path.read_text())
            raw["steps"] = [Step(**s) for s in raw["steps"]]
            return Job(**raw)
        except (OSError, ValueError, TypeError, KeyError):
            return None

    def _save(self, job: Job) -> None:
        self.path.parent.mkdir(mode=0o700, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(asdict(job), handle)
        os.replace(tmp, self.path)
        self._mtime = self._stamp()

    def new(self, user: str) -> Job:
        job = Job(id=secrets.token_hex(6), user=user, started=int(time.time()))
        with self._lock:
            self._job = job
            self._save(job)
        return job

    def update(self, job: Job, step: str | None = None, status: str = "", detail: str = "",
               **fields: Any) -> None:  # fmt: skip
        with self._lock:
            if step:
                s = job.step(step)
                s.status = status or s.status
                s.detail = detail or s.detail
            for key, value in fields.items():
                setattr(job, key, value)
            if job.result and job.finished is None:
                job.finished = int(time.time())
            self._job = job
            self._save(job)

    def current(self) -> Job | None:
        """The latest job. Re-read when the file changed, so several instances or processes
        sharing the managed directory (and a restarted app) all see the same result."""
        with self._lock:
            if self._stamp() != self._mtime:
                self._job = self._load()
            return self._job

    def snapshot(self) -> Job | None:
        """An independent copy for rendering: the apply thread keeps mutating the live job, and a
        page built from it could otherwise mix two moments (e.g. "done" yet still polling)."""
        with self._lock:
            if self._stamp() != self._mtime:
                self._job = self._load()
            return copy.deepcopy(self._job)

    def running(self) -> bool:
        job = self.current()
        return job is not None and not job.done
