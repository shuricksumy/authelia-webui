"""Access tests page (SPEC §16.2): saved "this request must get this policy" checks.

Unlike rules, tests are not drafted: Authelia never reads them, so an edit is committed to the
managed repo at once (author = the admin) with no restart.
"""

from __future__ import annotations

from collections.abc import Callable
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
    is_htmx,
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
        "tests_rev": services_of(v.request).engine.tests_rev(),
    }  # fmt: skip


def list_context(v: View) -> dict[str, Any]:
    """The tests table; the form opens as a drawer over it."""
    engine = services_of(v.request).engine
    try:
        results = engine.test_results()
    except DocumentError as exc:
        return {"results": [], "broken": str(exc), "active": "tests", "labels": POLICY_LABEL,
                "tests_rev": ""}  # fmt: skip
    return {"results": results, "broken": "", "active": "tests", "labels": POLICY_LABEL,
            "tests_rev": engine.tests_rev()}  # fmt: skip


def form_response(v: View, form: dict[str, Any], status: int = 200) -> Response:
    """The form alone for the drawer (htmx), or the whole page with the drawer open (a link)."""
    if is_htmx(v.request):
        return render(v, "partials/test_form.html", status=status, **form)
    return render(v, "tests.html", status=status, **{**list_context(v), **form, "panel": True})


@router.get("/tests", response_class=HTMLResponse)
def tests_page(request: Request) -> Response:
    v = load_view(request)
    return render(v, "tests.html", **list_context(v))


@router.get("/tests/new", response_class=HTMLResponse)
def new_test(request: Request, url: str = "", method: str = "GET", user: str = "",
             groups: str = "", ip: str = "", expect: str = "one_factor") -> Response:  # fmt: skip
    v = load_view(request)
    case = AccessCase(
        url=url, method=method if method in METHODS else "GET", user=user, ip=ip,
        groups=tuple(g.strip() for g in groups.split(",") if g.strip()),
        expect=expect if expect in POLICIES else "one_factor",
    )  # fmt: skip
    return form_response(v, form_context(v, case, None, []))


@router.get("/tests/{index}/edit", response_class=HTMLResponse)
def edit_test(request: Request, index: int) -> Response:
    v = load_view(request)
    cases = access_tests.load(v.settings.CONFIG_MANAGED_DIR)
    if not 0 <= index < len(cases):
        return conflict_response(Conflict("That test no longer exists. Reload the page.", 404))
    return form_response(v, form_context(v, cases[index], index, []))


Change = Callable[[list[AccessCase]], tuple[list[AccessCase], str]]


def _commit(request: Request, change: Change, expected_rev: str) -> str | None:
    """Apply `change` to the tests file under the apply lock. Returns a problem, or None."""
    identity = identity_of(request.state)
    try:
        services_of(request).engine.update_tests(change, identity.username, expected_rev)
    except Refused as exc:
        return str(exc)
    except LookupError:
        return "That test no longer exists. Reload the page."
    except (OSError, RepoError, DocumentError):
        return "The tests could not be saved."
    return None


@router.post("/tests/save", response_class=HTMLResponse)
async def save_test(request: Request) -> Response:
    data = await request.form()
    v = load_view(request)
    raw_index = str(data.get("index", "")).strip()
    index = int(raw_index) if raw_index.isdigit() else None
    fields = ("name", "url", "method", "user", "groups", "ip", "expect")
    values = {k: str(data.get(k, "")) for k in fields}
    try:
        case = access_tests.case_from(values)
        if case.method not in METHODS:
            raise DocumentError("unknown HTTP method")
    except DocumentError as exc:
        draft = AccessCase(url=values["url"][:2048], expect="one_factor", name=values["name"][:200])
        return form_response(v, form_context(v, draft, index, [str(exc)]), 422)

    def change(cases: list[AccessCase]) -> tuple[list[AccessCase], str]:
        if index is None:
            return [*cases, case], f"Tests: added {case.name or case.url}"
        if not 0 <= index < len(cases):
            raise LookupError(index)
        return [*cases[:index], case, *cases[index + 1 :]], f"Tests: edited {case.name or case.url}"

    problem = await run_in_threadpool(_commit, request, change, str(data.get("tests_rev", "")))
    if problem:
        return form_response(v, form_context(v, case, index, [problem]), 422)
    return Response(status_code=204, headers={"HX-Redirect": "/tests"})


@router.post("/tests/{index}/delete", response_class=HTMLResponse)
async def delete_test(request: Request, index: int) -> Response:
    data = await request.form()

    def change(cases: list[AccessCase]) -> tuple[list[AccessCase], str]:
        if not 0 <= index < len(cases):
            raise LookupError(index)
        gone = cases[index]
        return [*cases[:index], *cases[index + 1 :]], f"Tests: removed {gone.name or gone.url}"

    problem = await run_in_threadpool(_commit, request, change, str(data.get("tests_rev", "")))
    if problem:
        return conflict_response(Conflict(problem, 422))
    return Response(status_code=204, headers={"HX-Redirect": "/tests"})
