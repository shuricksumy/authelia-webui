"""Login and logout for the break-glass port (app/emergency.py). Both routes exist only on that
port: on the normal port they are a 404, so nobody can guess passwords through the proxy."""

from __future__ import annotations

import time

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from app.emergency import COOKIE, Emergency
from app.web import templates

router = APIRouter()


def _emergency(request: Request) -> Emergency | None:
    em: Emergency = request.app.state.emergency
    server = request.scope.get("server")
    return em if em.enabled and server and server[1] == em.port else None


def _page(request: Request, message: str = "", status: int = 200) -> Response:
    return templates(request).TemplateResponse(
        request, "emergency_login.html", {"message": message}, status_code=status
    )


@router.get("/emergency/login", response_class=HTMLResponse)
def login_page(request: Request) -> Response:
    em = _emergency(request)
    if em is None:
        return Response("Not found", status_code=404, media_type="text/plain")
    client = request.scope.get("client") or ("?", 0)
    remaining = em.locked_for(str(client[0]))
    return _page(request, _locked(remaining) if remaining else "")


@router.post("/emergency/login", response_class=HTMLResponse)
async def login(request: Request) -> Response:
    em = _emergency(request)
    if em is None:
        return Response("Not found", status_code=404, media_type="text/plain")
    data = await request.form()
    password = str(data.get("password", ""))
    client = request.scope.get("client") or ("?", 0)
    outcome = await run_in_threadpool(em.attempt, password, str(client[0]))
    if outcome.result == "ok":
        response = RedirectResponse("/", status_code=303)
        response.headers.append("set-cookie", em.cookie_header(time.time()).decode())
        return response
    if outcome.result == "locked":
        return _page(request, _locked(outcome.locked_for_s), status=429)
    if outcome.result == "error":
        return _page(request, "The password could not be checked right now.", status=503)
    return _page(request, "Wrong password.", status=401)


@router.post("/emergency/logout")
def logout(request: Request) -> Response:
    em = _emergency(request)
    if em is None:
        return Response("Not found", status_code=404, media_type="text/plain")
    em.end_all_sessions()  # the cookie alone could be replayed until it expired
    response = Response(status_code=204, headers={"HX-Redirect": "/emergency/login"})
    response.headers.append("set-cookie", Emergency.clear_cookie_header().decode())
    return response


def _locked(seconds: int) -> str:
    minutes = max(1, (seconds + 59) // 60)
    return f"Too many wrong passwords. Try again in {minutes} minute{'s' if minutes != 1 else ''}."


__all__ = ["COOKIE", "router"]
