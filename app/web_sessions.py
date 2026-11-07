"""Open sessions in the UI (docs/sessions.md): the Sessions block of the user editor, the
"sign out everywhere" action, and the counts the Users page and the Overview show.

Everything is optional. Without SESSIONS_REDIS_URL the store is None, the block says the feature is
not set up, and the Users page and Overview look as before. A Redis problem is shown as a short
message in place of the numbers; it never takes a page down.

Plain `def` routes (worker threads): they wait on Redis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, Response

from app.apply import audit, notify
from app.security import identity_of
from app.sessions import SessionStore, SessionsUnavailable, Snapshot
from app.web import Conflict, conflict_response, load_view, render, sessions_of

router = APIRouter()


@dataclass
class SessionCounts:
    """What the Users page and the Overview show, from one read."""

    on: bool = False  # the feature is switched on
    problem: str = ""  # why the numbers are missing (Redis down, wrong secret, ...)
    total: dict[str, int] = field(default_factory=dict)  # per lower-cased username
    two_factor: dict[str, int] = field(default_factory=dict)

    @property
    def usable(self) -> bool:
        return self.on and not self.problem

    @property
    def sessions(self) -> int:
        return sum(self.total.values())

    @property
    def users(self) -> int:
        return len(self.total)


def counts_of(request: Request) -> SessionCounts:
    store = sessions_of(request)
    if store is None:
        return SessionCounts()
    try:
        snap = store.snapshot()
    except SessionsUnavailable as exc:
        return SessionCounts(on=True, problem=str(exc))
    out = SessionCounts(on=True)
    for s in snap.sessions:
        key = s.username.casefold()
        out.total[key] = out.total.get(key, 0) + 1
        out.two_factor[key] = out.two_factor.get(key, 0) + (1 if s.second_factor else 0)
    if snap.looks_like_wrong_secret:
        out.problem = "none could be read (is SESSIONS_SECRET_FILE the session secret?)"
    return out


def _is_me(request: Request, name: str) -> bool:
    return identity_of(request.state).username.casefold() == name.casefold()


def block_context(
    request: Request, name: str, snap: Snapshot | None = None, **extra: Any
) -> dict[str, Any]:
    """The values partials/user_sessions.html needs. Session keys never go into a template."""
    store = sessions_of(request)
    ctx: dict[str, Any] = {
        "active": "users", "uname": name, "enabled": store is not None, "problem": "",
        "is_me": _is_me(request, name), "sessions": [], "flash": "", "error": "",
        "clear_modal": False, "truncated": False, "wrong_secret": False, "with_2fa": 0,
        "last_activity": None, **extra,
    }  # fmt: skip
    if store is None:
        return ctx
    try:
        snap = snap or store.snapshot()
    except SessionsUnavailable as exc:
        ctx["problem"] = str(exc)
        return ctx
    mine = snap.for_user(name)
    current = store.current_key(request.headers.get("cookie")) if ctx["is_me"] else None
    ctx.update(
        sessions=[
            {
                "second_factor": s.second_factor, "last_activity": s.last_activity,
                "first_factor_at": s.first_factor_at, "remember_me": s.remember_me,
                "expires_in": s.expires_in, "current": s.key == current,
            }
            for s in mine
        ],
        truncated=snap.truncated, wrong_secret=snap.looks_like_wrong_secret,
        with_2fa=sum(1 for s in mine if s.second_factor),
        last_activity=max((s.last_activity for s in mine if s.last_activity), default=None),
    )  # fmt: skip
    return ctx


@router.get("/users/{name}/sessions", response_class=HTMLResponse)
def sessions_block(request: Request, name: str) -> Response:
    v = load_view(request)
    return render(v, "partials/user_sessions.html", **block_context(request, name))


@router.get("/users/{name}/sessions/confirm", response_class=HTMLResponse)
def sessions_confirm(request: Request, name: str) -> Response:
    store = sessions_of(request)
    if store is None:
        return conflict_response(Conflict("Open sessions are not set up.", 404))
    v = load_view(request)
    ctx = block_context(request, name)
    if ctx["problem"]:
        return conflict_response(Conflict(f"Open sessions are unavailable: {ctx['problem']}.", 503))
    return render(v, "partials/sessions_revoke_confirm.html", **ctx)


@router.post("/users/{name}/sessions/revoke", response_class=HTMLResponse)
def sessions_revoke(request: Request, name: str) -> Response:
    store: SessionStore | None = sessions_of(request)
    if store is None:
        return conflict_response(Conflict("Open sessions are not set up.", 404))
    v = load_view(request)
    identity = identity_of(request.state)
    keep = None
    if _is_me(request, name):
        # Signing yourself out of the configurator mid-action helps nobody: your own session stays.
        keep = store.current_key(request.headers.get("cookie"))
        if keep is None:
            return render(
                v, "partials/user_sessions.html", status=422,
                **block_context(
                    request, name, clear_modal=True,
                    error="Cannot tell which session is yours (no Authelia cookie in this "
                    "request), so nothing was signed out.",
                ),
            )  # fmt: skip
    try:
        result = store.revoke(name, keep=keep)
    except SessionsUnavailable as exc:
        return render(
            v, "partials/user_sessions.html", status=422,
            **block_context(request, name, clear_modal=True,
                            error=f"Open sessions are unavailable: {exc}."),
        )  # fmt: skip
    notes = [f"{result.deleted} session{'' if result.deleted == 1 else 's'} signed out"]
    if result.kept:
        notes.append("your current one kept")
    if not result.complete:
        notes.append("the list was cut short, so some may remain")
    if result.deleted:
        detail = ", ".join(notes[1:]) or "all of them"
        summary = f"Signed out {result.deleted} session(s) of {name[:80]} ({detail})"
        audit.append(
            v.settings.CONFIG_MANAGED_DIR,
            audit.AuditEntry(
                ts=audit.now(), user=identity.username, client_ip=str(identity.client_ip),
                action="sessions", result="revoked", commit="", summary=summary,
            ),
        )  # fmt: skip
        notify.send(v.settings, "sessions", "revoked", identity.username, summary)
    flash = f"{name}: {notes[0]}" + (f" ({', '.join(notes[1:])})" if notes[1:] else "") + "."
    if not result.deleted:
        flash = f"{name} has no open sessions to sign out."
    return render(
        v, "partials/user_sessions.html",
        **block_context(request, name, flash=flash, clear_modal=True),  # re-reads (cache cleared)
    )  # fmt: skip
