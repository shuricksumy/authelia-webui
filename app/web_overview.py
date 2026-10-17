"""Overview dashboard (`/`) and the log viewer (`/logs`).

The dashboard only gathers what other modules already know (lint, protected rules, access tests,
client and user checks, runtime status, the Authelia log). Each check is isolated: one that
cannot run becomes a line saying so, never a failed page.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, Response

from app import certs, logs
from app.apply.runtime import RuntimeUnavailable
from app.oidc.lint import lint_clients
from app.oidc.names import load_oidc_names
from app.rules import access_tests
from app.rules.lint import blocking
from app.users.document import UsersDocument
from app.users.lint import lint_users
from app.users.schema import load_schema
from app.web import View, load_view, render, services_of

router = APIRouter()
log = logging.getLogger("app.overview")


@dataclass(frozen=True)
class Attention:
    severity: str  # error | warning | info
    text: str
    href: str = ""


@dataclass
class Overview:
    items: list[Attention] = field(default_factory=list)
    counts: dict[str, str] = field(default_factory=dict)
    up_since: str = ""
    log_counts: dict[str, int] | None = None


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def collect(v: View) -> Overview:
    """Everything the dashboard shows, computed from the live files."""
    out = Overview()
    services = services_of(v.request)

    def check(label: str, fn: Callable[[], None]) -> None:
        try:
            fn()
        except Exception:  # a broken check must not take the page down
            log.exception("overview check '%s' failed", label)
            out.items.append(Attention("info", f"Could not check {label}."))

    def runtime() -> None:
        status = services.status.get()
        if status.bad or status.mismatch_warns:
            out.items.append(
                Attention(
                    "error" if status.bad else "warning",
                    status.explanation or "Authelia needs a look.",
                )
            )
        try:
            out.up_since = _up_since(services.runtime.inspect(timeout_s=1.0).started_at)
        except RuntimeUnavailable:
            out.up_since = ""

    def rules() -> None:
        issues, report = v.analyse(v.live)
        errors = blocking(issues)
        warnings = [i for i in issues if i.severity == "warning"]
        out.counts["Rules"] = str(len(v.live.blocks))
        out.counts["Disabled rules"] = str(len(v.disabled.entries))
        if report.violations:
            out.items.append(
                Attention("error", f"Protected rule problem: {report.violations[0]}", "/rules")
            )
        if errors:
            out.items.append(
                Attention(
                    "error", f"{_plural(len(errors), 'rule error')}: {errors[0].message}", "/rules"
                )
            )
        if warnings:
            out.items.append(
                Attention(
                    "warning",
                    f"{_plural(len(warnings), 'rule warning')}, for example: {warnings[0].message}",
                    "/rules",
                )
            )

    def tests() -> None:
        cases = access_tests.load(v.settings.CONFIG_MANAGED_DIR)
        out.counts["Access tests"] = str(len(cases))
        failing = [r for r in services.engine.test_results() if r.live.policy != r.case.expect]
        if failing:
            out.items.append(
                Attention(
                    "error",
                    f"{_plural(len(failing), 'access test')} failing on the live rules.",
                    "/tests",
                )
            )

    def clients() -> None:
        live = v.store.live_clients()
        if live is None:
            return
        found = live.clients()
        out.counts["OIDC clients"] = str(len(found))
        issues = lint_clients(found, load_oidc_names(v.settings.CONFIG_MAIN))
        errors = [i for i in issues if i.severity == "error"]
        plain = [i for i in issues if i.code == "plaintext-secret"]
        other = [i for i in issues if i.severity == "warning" and i.code != "plaintext-secret"]
        if errors:
            out.items.append(
                Attention(
                    "error",
                    f"{_plural(len(errors), 'OIDC client error')}: {errors[0].message}",
                    "/clients",
                )
            )
        if plain:
            out.items.append(
                Attention(
                    "warning",
                    f"{_plural(len(plain), 'OIDC client')} keep a plain-text secret.",
                    "/clients",
                )
            )
        if other:
            out.items.append(
                Attention(
                    "warning",
                    f"{_plural(len(other), 'OIDC client warning')}: {other[0].message}",
                    "/clients",
                )
            )

    def users() -> None:
        try:
            doc = UsersDocument.parse(v.settings.USERS_FILE.read_text())
        except (OSError, ValueError):
            out.items.append(Attention("warning", "The users file could not be read.", "/users"))
            return
        data = doc.users()
        enabled = {n: u for n, u in data.items() if not u.get("disabled")}
        admins = [
            n for n, u in enabled.items() if v.settings.ADMIN_GROUP in (u.get("groups") or [])
        ]
        out.counts["Users"] = f"{len(enabled)}" + (
            f" + {len(data) - len(enabled)} disabled" if len(data) != len(enabled) else ""
        )
        groups = {g for u in data.values() for g in (u.get("groups") or [])}
        out.counts["Groups"] = str(len(groups))
        if len(admins) < 2:
            out.items.append(
                Attention(
                    "warning",
                    f"Only {_plural(len(admins), 'enabled administrator')} in "
                    f"'{v.settings.ADMIN_GROUP}': one mistake locks everyone out.",
                    "/users",
                )
            )
        problems = lint_users(
            data, load_schema(v.settings.CONFIG_MAIN), {n: doc.has_password(n) for n in doc.names()}
        )
        errors = [p for p in problems if p[1] == "error"]
        if errors:
            out.items.append(
                Attention(
                    "error", f"{_plural(len(errors), 'user problem')}: {errors[0][2]}", "/users"
                )
            )

    def logs_check() -> None:
        path = v.settings.AUTHELIA_LOG_FILE
        if path is None:
            return
        found = _log_counts(path)
        out.log_counts = found
        if found and found["error"]:
            out.items.append(
                Attention(
                    "warning",
                    f"{_plural(found['error'], 'error')} in Authelia's log in the last 24 hours.",
                    "/logs?level=error&window=24h",
                )
            )

    def certificates() -> None:
        watcher = services.certs
        for info in (watcher.expiring() if watcher else [])[:3]:
            days = info.days_left()
            out.items.append(Attention(
                "error" if days is not None and days < 0 else "warning",
                f"Certificate {info.source} ({info.subject or 'unknown'}) "
                f"{certs.describe_days(days or 0)}.", "/keys",
            ))  # fmt: skip

    check("Authelia", runtime)
    check("the rules", rules)
    check("the access tests", tests)
    check("the OIDC clients", clients)
    check("the users", users)
    check("the log", logs_check)
    check("the certificates", certificates)
    order = {"error": 0, "warning": 1, "info": 2}
    out.items.sort(key=lambda item: order[item.severity])
    return out


_COUNTS_TTL_S = 60.0
_counts_cache: dict[str, tuple[float, dict[str, int] | None]] = {}
_counts_lock = threading.Lock()


def _log_counts(path: Path) -> dict[str, int] | None:
    """Errors/warnings of the last 24 h, cached for a minute: a large log takes a moment to scan
    and the dashboard is the landing page."""
    key = str(path)
    with _counts_lock:
        hit = _counts_cache.get(key)
        if hit and time.monotonic() - hit[0] < _COUNTS_TTL_S:
            return hit[1]
    value = logs.counts(path, datetime.now(UTC) - logs.WINDOWS["24h"])
    with _counts_lock:
        _counts_cache[key] = (time.monotonic(), value)
    return value


def _up_since(started_at: str) -> str:
    try:
        moment = datetime.fromisoformat(started_at.replace("Z", "+00:00").split(".")[0])
    except ValueError:
        return ""
    return (
        moment.replace(tzinfo=moment.tzinfo or UTC).astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
    )


# Plain `def` routes: FastAPI runs them in a worker thread. render() does blocking work (status
# probe, git for the notices), which must never run on the event loop.
@router.get("/", response_class=HTMLResponse)
def overview(request: Request) -> Response:
    v = load_view(request)
    data = collect(v)
    return render(v, "overview.html", active="overview", data=data,
                  draft=v.store.changes() if v.store.has_draft() else None,
                  log_configured=v.settings.AUTHELIA_LOG_FILE is not None)  # fmt: skip


# --------------------------------------------------------------------------- logs

LEVEL_CHOICES = (("error", "Errors"), ("warn", "Warnings and errors"), ("info", "Info and above"),
                 ("debug", "Everything"))  # fmt: skip
WINDOW_CHOICES = (("1h", "Last hour"), ("24h", "Last 24 hours"), ("7d", "Last 7 days"),
                  ("all", "All available"))  # fmt: skip
PAGE = 200
DOWNLOAD = 5000


def _query(level: str, window: str, q: str, ip: str) -> tuple[logs.Query, str, str]:
    level = level if level in logs.LEVELS else "warn"
    window = window if window in (*logs.WINDOWS, "all") else "24h"
    return (
        logs.Query(level, logs.window_start(window), q.strip()[:200], ip.strip()[:64]),
        level,
        window,
    )


@router.get("/logs", response_class=HTMLResponse)
def logs_page(request: Request, level: str = "warn", window: str = "24h", q: str = "",
              ip: str = "", older: str = "") -> Response:  # fmt: skip
    v = load_view(request)
    path = v.settings.AUTHELIA_LOG_FILE
    query, level, window = _query(level, window, q, ip)
    ctx: dict[str, Any] = {
        "active": "logs",
        "configured": path is not None,
        "level": level,
        "window": window,
        "q": query.text,
        "ip": query.ip,
        "levels": LEVEL_CHOICES,
        "windows": WINDOW_CHOICES,
        "page": logs.Page(),
        "problems": [],
        "problems_limited": False,
        "older": older,
    }
    if path is not None:
        ctx["page"] = logs.read(path, query, PAGE, older)
        if not older:
            found, limited = logs.problems(path, query.since)
            ctx["problems"], ctx["problems_limited"] = found[:15], limited
    return render(v, "logs.html", **ctx)


@router.get("/logs/download")
async def logs_download(request: Request, level: str = "warn", window: str = "24h", q: str = "",
                        ip: str = "") -> Response:  # fmt: skip
    path = request.app.state.settings.AUTHELIA_LOG_FILE
    if path is None:
        return Response("No log file is configured.", status_code=404, media_type="text/plain")
    query, _, _ = _query(level, window, q, ip)
    page = await run_in_threadpool(logs.read, path, query, DOWNLOAD)
    body = "\n".join(e.raw for e in reversed(page.entries)) + "\n"
    return Response(
        body, media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="authelia-log-excerpt.txt"'},
    )  # fmt: skip
