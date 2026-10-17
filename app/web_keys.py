"""Keys and certificates page: OIDC signing-key rotation and certificate expiry (Phase 4c).

Each rotation step is a normal safe apply (app/apply/keys.py) run in a background thread, with the
same progress panel as the rules apply. No private key material ever reaches a page: only key
ids, algorithms and certificate dates.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, Response

from app.apply import keys
from app.security import identity_of
from app.web import load_view, render, services_of
from app.web_apply import _progress_context

router = APIRouter()


def _certificate_rows(request: Request) -> list[dict[str, Any]]:
    watcher = services_of(request).certs
    settings = request.app.state.settings
    rows = []
    for info in watcher.report() if watcher else []:
        days = info.days_left()
        if days is None:
            status = "unknown"
        elif days < 0:
            status = "expired"
        elif days <= settings.CERT_WARN_DAYS:
            status = "soon"
        else:
            status = "ok"
        rows.append({"cert": info, "days": days, "status": status})
    return rows


@router.get("/keys", response_class=HTMLResponse)
async def keys_page(request: Request, flash: str = "") -> Response:
    v = await run_in_threadpool(load_view, request)
    engine = services_of(request).engine
    state = await run_in_threadpool(keys.keys_state, engine)
    waited = None
    if state.prepared_at and state.doc and len(state.doc.blocks) > 1:
        waited = max(0, int(time.time()) - state.prepared_at)
    return render(
        v, "keys.html", active="keys", state=state, certificates=_certificate_rows(request),
        waited_hours=None if waited is None else waited // 3600,
        wait_enough=waited is not None and waited >= keys.SUGGESTED_WAIT_S,
        warn_days=v.settings.CERT_WARN_DAYS, flash=flash,
        progress=_progress_context(services_of(request).board.snapshot()),
    )  # fmt: skip


@router.post("/keys/{action}", response_class=HTMLResponse)
async def keys_step(request: Request, action: str) -> Response:
    data = await request.form()
    v = load_view(request)
    services = services_of(request)
    identity = identity_of(request.state)
    operation = keys.KeyOp(
        action=action, kid=str(data.get("kid", "")), rev=str(data.get("keys_rev", "")),
        user=identity.username, client_ip=str(identity.client_ip),
    )  # fmt: skip

    def check_and_start() -> list[str]:
        with services.start_lock:
            reasons = keys.preconditions(services.engine, operation)
            if not reasons:
                job = services.board.new(identity.username)
                threading.Thread(
                    target=keys.run, args=(services.engine, operation, job), name="keys",
                    daemon=True,
                ).start()  # fmt: skip
            return reasons

    reasons = await run_in_threadpool(check_and_start)
    if reasons:
        return render(v, "partials/apply_refused.html", status=422, reasons=reasons)
    return render(v, "partials/apply_progress.html", **_progress_context(services.board.snapshot()))
