"""Apply, progress, result and history pages (SPEC §6, §15.6, §15.8).

An apply runs in a background thread. Authelia's restart signs everyone out (memory sessions),
so the browser may lose its session mid-apply: the outcome is persisted (JobBoard) and shown by
/apply/result after the next login, and the progress panel's script sends the browser there.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, Response, StreamingResponse

from app import backup
from app.apply import audit, notify
from app.apply.engine import ApplyRequest, Refused
from app.apply.jobs import Job
from app.apply.repo import Commit, RepoError
from app.authelia_cli import redact
from app.oidc.document import CLIENTS_NAME, ClientsDocument
from app.oidc.jwks import JWKS_NAME
from app.rules.disabled import DISABLED_NAME, DisabledRules
from app.rules.document import DocumentError, RulesDocument
from app.rules.store import LIVE_NAME, Snapshot, StaleDraftError
from app.security import identity_of
from app.ui import diff_lines
from app.users.document import USERS_NAME
from app.web import (
    STALE,
    Conflict,
    conflict_response,
    load_view,
    render,
    require_rev,
    services_of,
    shell_context,
    templates,
)

router = APIRouter()
DRAFTED = (LIVE_NAME, DISABLED_NAME, CLIENTS_NAME)
SHOWN = (*DRAFTED, USERS_NAME, JWKS_NAME)  # files whose changes History can show (hashes redacted)


# --------------------------------------------------------------------------- apply


@router.post("/apply", response_class=HTMLResponse)
async def start_apply(request: Request) -> Response:
    data = await request.form()  # before load_view: no await between reading and starting
    v = load_view(request)
    services = services_of(request)
    try:
        require_rev(v, str(data.get("rev", "")))
    except Conflict as exc:
        return conflict_response(exc)
    identity = identity_of(request.state)
    accept_tests = str(data.get("accept_tests", "")) == "1"
    apply_request = ApplyRequest(identity.username, str(identity.client_ip), v.rev, accept_tests)

    def check_and_start() -> list[str]:
        # Blocking (container inspect, lint, file I/O): runs in a worker thread, not on the loop.
        with services.start_lock:
            reasons = services.engine.preconditions(rev=v.rev, accept_tests=accept_tests)
            if not reasons:
                job = services.board.new(identity.username)
                threading.Thread(
                    target=services.engine.apply, args=(apply_request, job), name="apply",
                    daemon=True,
                ).start()  # fmt: skip
            return reasons

    reasons = await run_in_threadpool(check_and_start)
    if reasons:
        return render(v, "partials/apply_refused.html", status=422, reasons=reasons)
    return render(v, "partials/apply_progress.html", **_progress_context(services.board.snapshot()))


def _progress_context(job: Job | None) -> dict[str, Any]:
    return {"job": job, "polling": job is not None and not job.done}


@router.get("/apply/status", response_class=HTMLResponse)
def apply_status(request: Request) -> Response:
    services = services_of(request)
    job = services.board.snapshot()
    if job is not None and job.done:
        services.status.invalidate()  # the footer should reflect the restart that just happened
    return templates(request).TemplateResponse(
        request,
        "partials/apply_progress.html",
        {**shell_context(request), **_progress_context(job)},
    )


@router.get("/apply/result", response_class=HTMLResponse)
def apply_result(request: Request) -> Response:
    job = services_of(request).board.snapshot()
    ctx = {**shell_context(request), **_progress_context(job), "has_draft": False,
           "change_count": 0, "stale": False}  # fmt: skip
    return templates(request).TemplateResponse(request, "apply_result.html", ctx)


# --------------------------------------------------------------------------- notices


@router.post("/notices/{what}/seen", response_class=HTMLResponse)
def notice_seen(request: Request, what: str) -> Response:
    if what not in ("external", "main"):
        return Response("Unknown notice.", status_code=404)
    services_of(request).engine.acknowledge(what)
    return HTMLResponse("")


@router.post("/notices/main/revalidate", response_class=HTMLResponse)
def revalidate_main(request: Request) -> Response:
    """Validate the live rules together with the (changed) main configuration."""
    services = services_of(request)
    store = services.engine.store
    result = services.engine.validator(
        services.engine.settings, store.live_text(), store.live_clients_text() or None
    )
    return templates(request).TemplateResponse(
        request, "partials/main_revalidated.html", {"request": request, "result": result}
    )


# --------------------------------------------------------------------------- history


@dataclass
class HistoryRow:
    commit: Commit
    kind: str  # applied | rolled-back | rollback | initial | other
    label: str
    when: str
    current: bool


def _when(timestamp: int) -> str:
    return datetime.fromtimestamp(timestamp, UTC).strftime("%Y-%m-%d %H:%M")


def history_rows(request: Request) -> list[HistoryRow]:
    services = services_of(request)
    if not services.repo.is_repo():
        return []
    commits = services.repo.log(100)
    rows = []
    for i, commit in enumerate(commits):
        newer = commits[i - 1] if i > 0 else None
        if commit.author == "external" or commit.subject.startswith("External change"):
            kind, label = "external", "edited outside the configurator"
        elif commit.subject.startswith("Users:"):
            kind, label = "users", "users (no restart)"
        elif commit.subject.startswith("OIDC keys:"):
            kind, label = "keys", "OIDC keys (restarts Authelia)"
        elif commit.subject.startswith("Tests:"):
            kind, label = "tests", "access tests (no restart)"
        elif commit.subject.startswith("Rollback:"):
            kind, label = "rollback", "automatic rollback"
        elif commit.subject.startswith("Initial import"):
            kind, label = "initial", "initial import"
        elif newer is not None and newer.subject.startswith("Rollback:"):
            kind, label = "rolled-back", "rolled back (Authelia was unhealthy)"
        else:
            kind, label = "applied", "applied"
        rows.append(HistoryRow(commit, kind, label, _when(commit.timestamp), current=(i == 0)))
    return rows


@router.get("/history", response_class=HTMLResponse)
def history(request: Request) -> Response:
    try:
        v = load_view(request)
    except (OSError, DocumentError):
        return templates(request).TemplateResponse(
            request, "error.html",
            {**shell_context(request), "message": "The managed files could not be read.",
             "has_draft": False, "change_count": 0, "stale": False},
            status_code=503,
        )  # fmt: skip
    entries = audit.recent(v.settings.CONFIG_MANAGED_DIR, 50)
    return render(v, "history.html", rows=history_rows(request), audit=list(reversed(entries)),
                  active="history")  # fmt: skip


# --------------------------------------------------------------------------- backup


@router.get("/backup", response_class=HTMLResponse)
def backup_page(request: Request) -> Response:
    v = load_view(request)
    return render(v, "backup.html", active="history",
                  has_keys=(v.settings.CONFIG_MANAGED_DIR / "secrets").is_dir())  # fmt: skip


@router.post("/backup/prepare", response_class=HTMLResponse)
async def backup_prepare(request: Request) -> Response:
    """The confirmation: only after it does the page get a one-minute download link."""
    data = await request.form()
    v = await run_in_threadpool(load_view, request)
    if str(data.get("confirm", "")) != "1":
        return await run_in_threadpool(
            lambda: render(v, "partials/backup_link.html", status=422, link="", error=True)
        )
    token = _backup_tokens(request).issue(identity_of(request.state).username)
    return await run_in_threadpool(
        lambda: render(
            v, "partials/backup_link.html", link=f"/backup/download?token={token}", error=False
        )
    )


@router.get("/backup/download")
def backup_download(request: Request, token: str = "") -> Response:
    identity = identity_of(request.state)
    settings = request.app.state.settings
    if not _backup_tokens(request).verify(token, identity.username):
        return Response("This download link has expired. Open the backup page again.",
                        status_code=403, media_type="text/plain")  # fmt: skip
    engine = services_of(request).engine
    try:
        with engine.exclusive():  # no apply may change the files while they are archived
            handle, info = backup.make_archive(settings.CONFIG_MANAGED_DIR)
    except Refused as exc:
        return Response(str(exc), status_code=409, media_type="text/plain")
    except (backup.BackupError, OSError) as exc:
        return Response(f"The backup could not be made ({type(exc).__name__}).", status_code=500,
                        media_type="text/plain")  # fmt: skip
    summary = f"{info.files} files, {info.size} bytes" + (", with keys" if info.has_keys else "")
    audit.append(settings.CONFIG_MANAGED_DIR, audit.AuditEntry(
        ts=audit.now(), user=identity.username, client_ip=str(identity.client_ip), action="backup",
        result="downloaded", commit="", summary=summary,
    ))  # fmt: skip
    notify.send(settings, "backup", "downloaded", identity.username, summary)

    def stream() -> Iterator[bytes]:
        try:
            while chunk := handle.read(64 * 1024):
                yield chunk
        finally:
            handle.close()

    return StreamingResponse(
        stream(), media_type="application/gzip",
        headers={"Content-Disposition": f'attachment; filename="{backup.filename()}"',
                 "Content-Length": str(info.size)},
    )  # fmt: skip


def _backup_tokens(request: Request) -> backup.Tokens:
    return backup.Tokens(request.app.state.settings.APP_SECRET_KEY.get_secret_value())


@router.get("/history/{sha}/diff", response_class=HTMLResponse)
def history_diff(request: Request, sha: str) -> Response:
    services = services_of(request)
    try:
        text = "".join(services.repo.diff(sha, name) for name in SHOWN)
    except RepoError:
        return Response("Unknown commit.", status_code=404)
    text = redact(text)  # client secret hashes never reach a page
    return templates(request).TemplateResponse(
        request, "partials/history_diff.html", {"request": request, "diff": diff_lines(text)}
    )


@router.post("/history/{sha}/revert", response_class=HTMLResponse)
async def revert_to(request: Request, sha: str) -> Response:
    """Load an old version into the draft; it still goes through review and the safe apply."""
    data = await request.form()  # before load_view: no await between reading and saving
    v = load_view(request)
    try:
        require_rev(v, str(data.get("rev", "")))
        if v.store.has_draft():
            raise Conflict("There are unapplied changes. Apply or discard them first.", 422)
        repo = services_of(request).repo

        def at(name: str) -> str:
            try:
                return repo.file_at(sha, name)
            except RepoError:
                return ""

        snap = Snapshot(at(LIVE_NAME), at(DISABLED_NAME), at(CLIENTS_NAME))
        try:
            RulesDocument.parse(snap.rules)
            DisabledRules.parse(snap.disabled)
            if snap.clients:
                ClientsDocument.parse(snap.clients)
        except DocumentError:
            raise Conflict("That version could not be loaded.", 422) from None
        live = (v.store.live_text(), v.store.live_disabled_text(), v.store.live_clients_text())
        if (snap.rules, snap.disabled, snap.clients) == live:
            raise Conflict("That version is already live.", 422)
        if bool(snap.clients) != bool(live[2]):
            raise Conflict("That version has a different OIDC setup; revert it by hand.", 422)
        v.store.save_snapshot(snap, expected_sha=v.sha)
    except Conflict as exc:
        return conflict_response(exc)
    except (StaleDraftError, OSError):
        return conflict_response(Conflict(STALE))
    identity = identity_of(request.state)
    audit.append(
        v.settings.CONFIG_MANAGED_DIR,
        audit.AuditEntry(
            ts=audit.now(), user=identity.username, client_ip=str(identity.client_ip),
            action="revert-to-draft", result="started", commit=sha[:12],
            summary="Loaded an earlier version into the draft.",
        ),
    )  # fmt: skip
    return Response(status_code=204, headers={"HX-Redirect": "/review"})
