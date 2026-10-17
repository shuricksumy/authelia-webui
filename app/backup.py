"""The managed folder as one downloadable archive (SPEC §16.6).

It is a complete restore point: the tracked files, the whole git history, the audit log and the
OIDC private keys (`secrets/`, which are deliberately not in git). So the archive holds password
hashes and private keys: the page that offers it asks for a confirmation and every download is
audited. Runtime state (`.draft/`, `.apply/`, lock files) is not part of it, and symlinks and
special files are never archived, so nothing outside the folder can be pulled in through a link.
"""

from __future__ import annotations

import os
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import IO

from itsdangerous import BadSignature, URLSafeTimedSerializer

EXCLUDED_TOP = frozenset({".draft", ".apply"})  # runtime state: a restore must not resurrect it
EXCLUDED_FILES = frozenset({".lock"})
MAX_BYTES = 256 * 1024 * 1024  # a managed folder is a few MB; more means something is wrong
TOKEN_MAX_AGE_S = 60
ARC_ROOT = "managed"


class BackupError(RuntimeError):
    """The archive could not be made; the message is safe to show."""


@dataclass(frozen=True)
class BackupInfo:
    files: int
    size: int  # compressed bytes
    has_keys: bool


def filename(now: datetime | None = None) -> str:
    return f"authelia-managed-{(now or datetime.now(UTC)):%Y%m%d-%H%M}.tar.gz"


def _included(relative: Path, is_dir: bool) -> bool:
    parts = relative.parts
    if parts and parts[0] in EXCLUDED_TOP:
        return False
    return not (not is_dir and relative.name in EXCLUDED_FILES)


def build(managed: Path, out: IO[bytes]) -> BackupInfo:
    """Write a .tar.gz of `managed` to `out`. The caller holds the apply lock, so the files do not
    change underneath it."""
    files = 0
    has_keys = False
    total = 0
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        for current, dirs, names in os.walk(managed, followlinks=False):
            here = Path(current)
            relative_dir = here.relative_to(managed)
            dirs[:] = sorted(d for d in dirs if _included(relative_dir / d, True))
            if relative_dir.parts:  # the folder itself, so permissions (700 on secrets/) survive
                tar.add(here, arcname=f"{ARC_ROOT}/{relative_dir}", recursive=False)
            for name in sorted(names):
                path = here / name
                relative = relative_dir / name
                if not _included(relative, False) or path.is_symlink() or not path.is_file():
                    continue
                total += path.stat().st_size
                if total > MAX_BYTES:
                    raise BackupError("The managed folder is unexpectedly large; not archived.")
                tar.add(path, arcname=f"{ARC_ROOT}/{relative}", recursive=False)
                files += 1
                has_keys = has_keys or relative.parts[:1] == ("secrets",)
    return BackupInfo(files, out.tell(), has_keys)


def make_archive(managed: Path) -> tuple[IO[bytes], BackupInfo]:
    """The archive in an anonymous temporary file, rewound and ready to stream."""
    handle = tempfile.TemporaryFile()  # noqa: SIM115  (the caller streams and closes it)
    try:
        info = build(managed, handle)
    except BaseException:
        handle.close()
        raise
    handle.seek(0)
    return handle, info


# ---------------------------------------------------------------- the download link


class Tokens:
    """A one-minute link for one user: the download is a GET (a browser saves it), so it carries
    a signed token instead of the CSRF header a POST needs."""

    def __init__(self, secret_key: str) -> None:
        self._serializer = URLSafeTimedSerializer(secret_key, salt="backup-v1")

    def issue(self, username: str) -> str:
        return self._serializer.dumps({"u": username})

    def verify(self, token: str | None, username: str) -> bool:
        if not token:
            return False
        try:
            data = self._serializer.loads(token, max_age=TOKEN_MAX_AGE_S)
        except BadSignature:
            return False
        return isinstance(data, dict) and data.get("u") == username
