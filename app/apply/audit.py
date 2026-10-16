"""Append-only audit log (SPEC §6): who, when, from where, what, result.

JSON lines in CONFIG_MANAGED_DIR/audit.log, mode 0600, not tracked by git. Entries never hold
diffs or configuration values - only a short summary and the commit id.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path

AUDIT_NAME = "audit.log"


@dataclass(frozen=True)
class AuditEntry:
    ts: int
    user: str
    client_ip: str
    action: str  # apply | rollback | recovery | revert-to-draft
    result: str  # applied | rolled-back | failed | refused | started
    commit: str
    summary: str


def append(managed_dir: Path, entry: AuditEntry) -> None:
    path = managed_dir / AUDIT_NAME
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a") as handle:
        handle.write(json.dumps(asdict(entry), sort_keys=True) + "\n")


def now() -> int:
    return int(time.time())


def recent(managed_dir: Path, limit: int = 200) -> list[AuditEntry]:
    path = managed_dir / AUDIT_NAME
    try:
        lines = path.read_text().splitlines()[-limit:]
    except OSError:
        return []
    entries = []
    for line in lines:
        try:
            entries.append(AuditEntry(**json.loads(line)))
        except (ValueError, TypeError):
            continue  # a damaged line never breaks the history page
    return entries
