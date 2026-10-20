"""Counts next to the sidebar links (rules, access tests, clients, users, groups).

Shown on every page, so they are cached until one of the files they come from changes (a stat per
file per request). They count the live files, never the draft. A count that cannot be read is
left out: the sidebar must never break a page.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path

from app.rules import access_tests
from app.rules.store import DraftStore
from app.settings import Settings
from app.users.document import UsersDocument

log = logging.getLogger("app.navcounts")

_lock = threading.Lock()
_cache: dict[str, tuple[tuple[tuple[str, int, int], ...], dict[str, int]]] = {}


def _stamp(paths: list[Path]) -> tuple[tuple[str, int, int], ...]:
    out = []
    for path in paths:
        try:
            st = path.stat()
            out.append((str(path), st.st_mtime_ns, st.st_size))
        except OSError:
            out.append((str(path), 0, -1))
    return tuple(out)


def _compute(settings: Settings) -> dict[str, int]:
    counts: dict[str, int] = {}
    managed = settings.CONFIG_MANAGED_DIR
    store = DraftStore(managed)
    try:
        counts["rules"] = len(store.live().blocks)
    except Exception:  # a count is optional
        log.debug("rule count unavailable", exc_info=True)
    try:
        clients = store.live_clients()
        if clients is not None:
            counts["clients"] = len(clients.clients())
    except Exception:
        log.debug("client count unavailable", exc_info=True)
    try:
        counts["tests"] = len(access_tests.load(managed))
    except Exception:
        log.debug("test count unavailable", exc_info=True)
    try:
        users = UsersDocument.parse(settings.USERS_FILE.read_text()).users()
        counts["users"] = len(users)
        counts["groups"] = len({g for u in users.values() for g in (u.get("groups") or [])})
    except Exception:
        log.debug("user count unavailable", exc_info=True)
    return counts


def nav_counts(settings: Settings) -> dict[str, int]:
    managed = settings.CONFIG_MANAGED_DIR
    files = sorted(managed.glob("*.yml")) if managed.is_dir() else []
    stamp = _stamp([*files, settings.USERS_FILE])
    key = str(managed)
    with _lock:
        hit = _cache.get(key)
        if hit and hit[0] == stamp:
            return hit[1]
    counts = _compute(settings)
    with _lock:
        _cache[key] = (stamp, counts)
    return counts
