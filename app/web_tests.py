"""Access tests page (SPEC §16.2): saved "this request must get this policy" checks.

Unlike rules, tests are not drafted: Authelia never reads them, so an edit is committed to the
managed repo at once (author = the admin) with no restart.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, Response

from app.apply.engine import Refused
from app.apply.repo import RepoError
from app.rules import access_tests
from app.rules.access_tests import AccessCase
from app.rules.document import DocumentError
from app.rules.tester import POLICIES
from app.security import identity_of
from app.ui import POLICY_LABEL
from app.web import (
    METHODS,
    Conflict,
    View,
    conflict_response,
    load_view,
    render,
    services_of,
)

router = APIRouter()


def _outcome(policy: str) -> str:
    return POLICY_LABEL.get(policy, policy.upper())


def form_context(
    v: View, case: AccessCase | None, index: int | None, errors: list[str]
) -> dict[str, Any]:
    case = case or AccessCase(url="", expect="one_factor")
    return {
        "case": case, "index": index, "errors": errors, "policies": POLICIES,
        "policy_labels": POLICY_LABEL, "methods": METHODS,
        "usernames": sorted(v.users.usernames), "groups_text": ", ".join(case.groups),
    }  # fmt: skip


@router.get("/tests", response_class=HTMLResponse)
def tests_page(request: Request) -> Response:
    v = load_view(request)
    try:
        results = services_of(request).engine.test_results()
    except DocumentError as exc:
        return render(v, "tests.html", results=[], broken=str(exc), active="tests",
                      labels=POLICY_LABEL)  # fmt: skip
    return render(v, "tests.html", results=results, broken="", active="tests", labels=POLICY_LABEL)


@router.get("/tests/new", response_class=HTMLResponse)
def new_test(request: Request, url: str = "", method: str = "GET", user: str = "",
             groups: str = "", ip: str = "", expect: str = "one_factor") -> Response:  # fmt: skip
    v = load_view(request)
    case = AccessCase(
        url=url, method=method if method in METHODS else "GET", user=user, ip=ip,
        groups=tuple(g.strip() for g in groups.split(",") if g.strip()),
        expect=expect if expect in POLICIES else "one_factor",
    )  # fmt: skip
    return render(v, "partials/test_form.html", **form_context(v, case, None, []))


@router.get("/tests/{index}/edit", response_class=HTMLResponse)
def edit_test(request: Request, index: int) -> Response:
    v = load_view(request)
    cases = access_tests.load(v.settings.CONFIG_MANAGED_DIR)
    if not 0 <= index < len(cases):
        return conflict_response(Conflict("That test no longer exists. Reload the page.", 404))
    return render(v, "partials/test_form.html", **form_context(v, cases[index], index, []))


def _save(request: Request, cases: list[AccessCase], subject: str) -> str | None:
    """Commit the new list. Returns a plain-language problem, or None."""
    identity = identity_of(request.state)
    try:
        services_of(request).engine.save_tests(cases, identity.username, subject)
    except Refused as exc:
        return str(exc)
    except (OSError, RepoError):
        return "The tests could not be saved."
    return None


@router.post("/tests/save", response_class=HTMLResponse)
async def save_test(request: Request) -> Response:
    data = await request.form()
    v = load_view(request)
    raw_index = str(data.get("index", "")).strip()
    index = int(raw_index) if raw_index.isdigit() else None
    values = {
        k: str(data.get(k, "")) for k in ("name", "url", "method", "user", "groups", "ip", "expect")
    }
    try:
        case = access_tests.case_from(values)
        if case.method not in METHODS:
            raise DocumentError("unknown HTTP method")
        cases = access_tests.load(v.settings.CONFIG_MANAGED_DIR)
    except DocumentError as exc:
        draft = AccessCase(url=values["url"], expect="one_factor", name=values["name"])
        return render(v, "partials/test_form.html", status=422,
                      **form_context(v, draft, index, [str(exc)]))  # fmt: skip
    if index is not None and 0 <= index < len(cases):
        cases[index] = case
        subject = f"Tests: edited {case.name or case.url}"
    else:
        cases.append(case)
        subject = f"Tests: added {case.name or case.url}"
    problem = await run_in_threadpool(_save, request, cases, subject)
    if problem:
        return render(v, "partials/test_form.html", status=422,
                      **form_context(v, case, index, [problem]))  # fmt: skip
    return Response(status_code=204, headers={"HX-Redirect": "/tests"})


@router.post("/tests/{index}/delete", response_class=HTMLResponse)
async def delete_test(request: Request, index: int) -> Response:
    v = load_view(request)
    cases = access_tests.load(v.settings.CONFIG_MANAGED_DIR)
    if not 0 <= index < len(cases):
        return conflict_response(Conflict("That test no longer exists. Reload the page.", 404))
    gone = cases.pop(index)
    problem = await run_in_threadpool(
        _save, request, cases, f"Tests: removed {gone.name or gone.url}"
    )
    if problem:
        return conflict_response(Conflict(problem, 422))
    return Response(status_code=204, headers={"HX-Redirect": "/tests"})
