"""Pages and HTMX partials (SPEC §15). Phase 1a: everything edits the draft, nothing is applied.

Conventions:
- every mutation carries `rev`, a short hash of the draft it was rendered from; a mismatch
  (another tab changed the draft) answers 409 and only updates the flash message;
- a change that would weaken a protected rule (app/rules/protected.py) is refused;
- GET routes that return an HTMX partial redirect to the full page for normal navigation.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap
from ruamel.yaml.error import YAMLError

from app.apply.services import ApplyServices
from app.apply.validate import validate_candidate
from app.authelia_cli import ValidationResult
from app.navcounts import nav_counts
from app.rules.disabled import DisabledRules
from app.rules.document import DocumentError, RulesDocument
from app.rules.form import FormError, RuleForm, apply_form
from app.rules.lint import Issue, UsersInfo, blocking, lint
from app.rules.protected import ProtectedReport, check_protected
from app.rules.store import (
    DraftStore,
    StaleDraftError,
    load_main_definitions,
    load_users,
    state_sha,
)
from app.rules.tester import POLICIES, RequestObject, RuleTester, Subject
from app.security import Identity, identity_of
from app.settings import Settings
from app.ui import (
    POLICY_LABEL,
    build_disabled_rows,
    build_rows,
    diff_lines,
    filter_rows,
    format_subject_lines,
    group_by_domain,
    lines_of,
    parse_subject_lines,
    skipped_summary,
)

router = APIRouter()
METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")


class Conflict(Exception):
    """The draft changed since the page was rendered, or the change is refused."""

    def __init__(self, message: str, status: int = 409) -> None:
        super().__init__(message)
        self.message = message
        self.status = status


@dataclass
class View:
    request: Request
    settings: Settings
    store: DraftStore
    users: UsersInfo
    definitions: dict[str, Any]
    identity: Identity
    live: RulesDocument
    doc: RulesDocument
    disabled: DisabledRules
    clients_text: str = ""  # "" when the deployment has no oidc_clients.yml

    @property
    def sha(self) -> str:
        """Revision of the whole draft state (rules, disabled rules, OIDC clients)."""
        return state_sha(self.doc, self.disabled, self.clients_text)

    @property
    def rev(self) -> str:
        return self.sha[:16]

    @property
    def known_networks(self) -> frozenset[str]:
        network = (self.definitions.get("definitions") or {}).get("network") or {}
        return frozenset(str(k) for k in network)

    def effective(self, doc: RulesDocument | None = None) -> dict[str, Any]:
        return {**self.definitions, **(doc or self.doc).effective()}

    def analyse(self, doc: RulesDocument | None = None) -> tuple[list[Issue], ProtectedReport]:
        doc = doc or self.doc
        issues = lint(
            doc.rules(),
            users=self.users,
            default_policy=doc.default_policy(),
            known_networks=self.known_networks,
        )
        return issues, check_protected(self.effective(doc), self.settings)


def services_of(request: Request) -> ApplyServices:
    services: ApplyServices = request.app.state.services
    return services


def templates(request: Request) -> Jinja2Templates:
    t: Jinja2Templates = request.app.state.templates
    return t


def load_view(request: Request) -> View:
    settings: Settings = request.app.state.settings
    store = DraftStore(settings.CONFIG_MANAGED_DIR)
    live = store.live()
    doc = store.current()
    return View(
        request=request,
        settings=settings,
        store=store,
        users=load_users(settings.USERS_FILE),
        definitions=load_main_definitions(settings.CONFIG_MAIN),
        identity=identity_of(request.state),
        live=live,
        doc=doc,
        disabled=store.current_disabled(),
        clients_text=store.current_clients_text(),
    )


def is_htmx(request: Request) -> bool:
    return request.headers.get("hx-request") == "true"


def shell_context(request: Request) -> dict[str, Any]:
    """What every page shows around its content: identity, footer status, last apply result."""
    services = services_of(request)
    return {
        "request": request,
        "identity": identity_of(request.state),
        "csrf_token": request.state.csrf_token,
        "bundled_version": request.app.state.settings.AUTHELIA_VERSION,
        "runtime": services.status.get(),
        "last_job": services.board.snapshot(),
        "notices": services.engine.notices(),
        "cert_warnings": services.certs.expiring() if services.certs else [],
        "emergency": bool(getattr(request.state, "emergency", False)),
        "any_network": request.app.state.settings.ALLOW_ANY_CLIENT_NETWORK,
        "admin_group": request.app.state.settings.ADMIN_GROUP,
        "nav_counts": nav_counts(request.app.state.settings),
    }


def base_context(v: View, **extra: Any) -> dict[str, Any]:
    changes = v.store.changes()
    count = changes.count
    return {
        **shell_context(v.request),
        "has_draft": v.store.has_draft(),
        "stale": v.store.is_stale(),
        "change_count": count,
        "rev": v.rev,
        **extra,
    }


def render(v: View, name: str, status: int = 200, **ctx: Any) -> HTMLResponse:
    return templates(v.request).TemplateResponse(
        v.request, name, base_context(v, **ctx), status_code=status
    )


def error_page(request: Request, message: str, status: int = 503) -> HTMLResponse:
    return templates(request).TemplateResponse(
        request,
        "error.html",
        {
            **shell_context(request),
            "message": message,
            "has_draft": False,
            "change_count": 0,
            "stale": False,
        },
        status_code=status,
    )


# --------------------------------------------------------------------------- helpers


def require_rev(v: View, rev: str | None) -> None:
    if rev != v.rev:
        raise Conflict(STALE)


STALE = "The draft changed in another tab or window. Reload the page and retry."


def commit(v: View, new_doc: RulesDocument, disabled: DisabledRules | None = None) -> None:
    """Save `new_doc` as the draft unless it introduces a protected-rule violation.

    The save is a compare-and-swap against the document this view was built from, so two
    concurrent edits can never silently overwrite each other.
    """
    _, before = v.analyse()
    _, after = v.analyse(new_doc)
    introduced = [x for x in after.violations if x not in before.violations]
    if introduced:
        raise Conflict("Refused: this would weaken a protected rule. " + " ".join(introduced), 422)
    try:
        v.store.save(new_doc, expected_sha=v.sha, disabled=disabled)
    except StaleDraftError:
        raise Conflict(STALE) from None


def refuse_locked(v: View, index: int) -> None:
    """Protected rules are read-only (SPEC §4); the UI disables them, the server enforces it."""
    _, report = v.analyse()
    if index in report.locked:
        raise Conflict("This is a protected rule and is read-only.", 422)


def conflict_response(exc: Conflict) -> HTMLResponse:
    body = (
        '<div id="flash" class="flash error" role="alert" hx-swap-oob="true">'
        f"{_esc(exc.message)}</div>"
    )
    return HTMLResponse(body, status_code=exc.status, headers={"HX-Reswap": "none"})


def _esc(text: str) -> str:
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    )


def section_response(
    v: View, flash: str = "", query: str = "", panel: bool = False
) -> HTMLResponse:
    """Re-render the rules section (and the draft bar out-of-band) after a mutation."""
    v2 = load_view(v.request)
    return render(
        v2, "partials/section_response.html", **rules_context(v2, query=query, flash=flash)
    )


def rules_context(v: View, view: str = "order", query: str = "", flash: str = "") -> dict[str, Any]:
    issues, report = v.analyse()
    rows = build_rows(v.doc, v.live, issues, report.locked)
    visible = filter_rows(rows, query)
    return {
        "rows": visible,
        "all_count": len(rows),
        "groups": group_by_domain(visible) if view == "domain" else [],
        "view": view,
        "q": query,
        "default_policy": v.doc.default_policy(),
        "policies": POLICIES,
        "protected_violations": report.violations,
        "flash": flash,
        "sortable": view == "order" and not query.strip(),
        "disabled_rows": build_disabled_rows(v.disabled),
    }


def editor_context(
    v: View,
    index: int | None,
    form: RuleForm,
    errors: list[str] | None = None,
    locked: bool = False,
) -> dict[str, Any]:
    inner = index is not None and v.doc.blocks[index].has_inner_comments
    return {
        "index": index,
        "form": form,
        "domain_text": "\n".join(form.domain),
        "domain_regex_text": "\n".join(form.domain_regex),
        "resources_text": "\n".join(form.resources),
        "subject_text": format_subject_lines(form.subject),
        "methods_text": "\n".join(form.methods),
        "networks_text": "\n".join(form.networks),
        "errors": errors or [],
        "locked": locked,
        "inner_comments": inner,
        "policies": POLICIES,
    }


def form_from_request(data: Any) -> RuleForm:
    def text(name: str) -> str:
        return str(data.get(name, "")).replace("\r\n", "\n")  # browsers send CRLF in textareas

    return RuleForm(
        domain=lines_of(text("domain")),
        domain_regex=lines_of(text("domain_regex")),
        resources=lines_of(text("resources")),
        subject=parse_subject_lines(text("subject")),
        methods=[m.upper() for m in lines_of(text("methods"))],
        networks=lines_of(text("networks")),
        query_yaml=text("query_yaml").strip("\n"),
        extra_yaml=text("extra_yaml").strip("\n"),
        policy=text("policy"),
        note=text("note").strip(),
    )


def candidate(v: View, index: int | None, form: RuleForm) -> tuple[RulesDocument, list[str]]:
    """The document with `form` applied at `index` (None = appended), plus form errors."""
    try:
        if index is None:
            return v.doc.insert(len(v.doc.blocks), apply_form(form), note=form.note), []
        block = v.doc.blocks[index]
        note = None if form.note == block.note else form.note
        return v.doc.replace_rule(index, apply_form(form, block.node()), note=note), []
    except (FormError, DocumentError) as exc:
        return v.doc, [str(exc)]


def rule_issues(issues: list[Issue], index: int) -> list[Issue]:
    return [i for i in issues if i.rule == index]


def check_index(v: View, index: int) -> None:
    if not 0 <= index < len(v.doc.blocks):
        raise Conflict("That rule no longer exists. Reload the page.", 404)


# --------------------------------------------------------------------------- pages


@router.get("/rules", response_class=HTMLResponse)
def rules_page(
    request: Request,
    view: str = "order",
    q: str = "",
    edit: int | None = None,
    new: int = 0,
    saved: str = "",
) -> Response:
    try:
        v = load_view(request)
    except (OSError, DocumentError) as exc:
        return error_page(
            request,
            "The managed access control file could not be read. Run the migration script "
            f"(scripts/split_config.py) or check CONFIG_MANAGED_DIR. ({type(exc).__name__})",
        )
    ctx = rules_context(v, view="domain" if view == "domain" else "order", query=q)
    if saved:
        ctx["flash"] = f"Rule #{saved} saved to the draft."
    panel = None
    if edit is not None and 0 <= edit < len(v.doc.blocks):
        _, report = v.analyse()
        block = v.doc.blocks[edit]
        form = RuleForm.from_data(block.data(), note=block.note)
        panel = editor_context(v, edit, form, locked=edit in report.locked)
    elif new:
        panel = editor_context(v, None, RuleForm())
    if panel:
        issues, _ = v.analyse()
        panel["issues"] = rule_issues(issues, panel["index"]) if panel["index"] is not None else []
    merged = {**ctx, "has_panel": bool(panel), **(panel or {})}
    return render(v, "rules.html", **merged)


@router.get("/rules/new", response_class=HTMLResponse)
def new_rule(request: Request) -> Response:
    if not is_htmx(request):
        return RedirectResponse("/rules?new=1", status_code=303)
    v = load_view(request)
    return render(v, "partials/editor.html", issues=[], **editor_context(v, None, RuleForm()))


@router.get("/rules/{index}/edit", response_class=HTMLResponse)
def edit_rule(request: Request, index: int) -> Response:
    if not is_htmx(request):
        return RedirectResponse(f"/rules?edit={index}", status_code=303)
    v = load_view(request)
    try:
        check_index(v, index)
    except Conflict as exc:
        return conflict_response(exc)
    issues, report = v.analyse()
    block = v.doc.blocks[index]
    form = RuleForm.from_data(block.data(), note=block.note)
    return render(
        v, "partials/editor.html", issues=rule_issues(issues, index),
        **editor_context(v, index, form, locked=index in report.locked),
    )  # fmt: skip


@router.post("/rules/validate", response_class=HTMLResponse)
async def validate_rule(request: Request) -> Response:
    data = await request.form()  # before load_view: no await between reading and saving
    v = load_view(request)
    raw = str(data.get("index", ""))
    index = int(raw) if raw.isdigit() else None
    form = form_from_request(data)
    doc, errors = candidate(v, index, form)
    issues: list[Issue] = []
    if not errors:
        all_issues, _ = v.analyse(doc)
        target = index if index is not None else len(doc.blocks) - 1
        issues = rule_issues(all_issues, target)
    return render(
        v, "partials/validation.html", errors=errors, issues=issues,
        blocked=bool(errors or blocking(issues)),
    )  # fmt: skip


@router.post("/rules/save", response_class=HTMLResponse)
async def save_rule(request: Request) -> Response:
    data = await request.form()  # before load_view: no await between reading and saving
    v = load_view(request)
    try:
        require_rev(v, str(data.get("rev", "")))
    except Conflict as exc:
        return conflict_response(exc)
    raw = str(data.get("index", ""))
    index = int(raw) if raw.isdigit() else None
    if index is not None:
        try:
            check_index(v, index)
            refuse_locked(v, index)
        except Conflict as exc:
            return conflict_response(exc)
    form = form_from_request(data)
    doc, errors = candidate(v, index, form)
    problems = list(errors)
    issues: list[Issue] = []
    if not problems:
        all_issues, _ = v.analyse(doc)
        target = index if index is not None else len(doc.blocks) - 1
        issues = rule_issues(all_issues, target)
        problems += [i.message for i in blocking(issues)]
    if not problems:
        try:
            commit(v, doc)
        except Conflict as exc:
            problems.append(exc.message)
    if problems:
        return render(
            v, "partials/editor.html", status=422, issues=issues,
            **editor_context(v, index, form, errors=problems),
        )  # fmt: skip
    number = len(doc.blocks) if index is None else index + 1
    return Response(status_code=204, headers={"HX-Redirect": f"/rules?saved={number}"})


@router.post("/rules/move", response_class=HTMLResponse)
async def move_rule(request: Request) -> Response:
    data = await request.form()  # before load_view: no await between reading and saving
    v = load_view(request)
    try:
        require_rev(v, str(data.get("rev", "")))
        src, dst = int(str(data.get("src"))), int(str(data.get("dst")))
        check_index(v, src)
        check_index(v, dst)
        commit(v, v.doc.move(src, dst))
    except (Conflict, ValueError, DocumentError) as exc:
        if isinstance(exc, Conflict):
            return conflict_response(exc)
        return conflict_response(Conflict("Could not move that rule.", 400))
    return section_response(v, flash=f"Moved rule #{src + 1} to position {dst + 1}.")


@router.post("/rules/{index}/move", response_class=HTMLResponse)
async def move_step(request: Request, index: int) -> Response:
    data = await request.form()  # before load_view: no await between reading and saving
    v = load_view(request)
    step = -1 if data.get("dir") == "up" else 1
    return await _move_to(v, index, index + step, str(data.get("rev", "")))


async def _move_to(v: View, src: int, dst: int, rev: str) -> Response:
    try:
        require_rev(v, rev)
        check_index(v, src)
        if not 0 <= dst < len(v.doc.blocks):
            return section_response(v)  # already at the edge
        commit(v, v.doc.move(src, dst))
    except Conflict as exc:
        return conflict_response(exc)
    return section_response(v, flash=f"Moved rule #{src + 1} to position {dst + 1}.")


@router.get("/rules/{index}/delete", response_class=HTMLResponse)
def delete_confirm(request: Request, index: int) -> Response:
    v = load_view(request)
    try:
        check_index(v, index)
    except Conflict as exc:
        return conflict_response(exc)
    _, report = v.analyse()
    rows = build_rows(v.doc, v.live, [], report.locked)
    return render(v, "partials/delete_confirm.html", row=rows[index])


@router.post("/rules/{index}/delete", response_class=HTMLResponse)
async def delete_rule(request: Request, index: int) -> Response:
    data = await request.form()  # before load_view: no await between reading and saving
    v = load_view(request)
    try:
        require_rev(v, str(data.get("rev", "")))
        check_index(v, index)
        refuse_locked(v, index)
        commit(v, v.doc.delete(index))
    except Conflict as exc:
        return conflict_response(exc)
    return section_response(v, flash=f"Rule #{index + 1} deleted from the draft.")


@router.post("/rules/{index}/disable", response_class=HTMLResponse)
async def disable_rule(request: Request, index: int) -> Response:
    data = await request.form()  # before load_view: no await between reading and saving
    v = load_view(request)
    try:
        require_rev(v, str(data.get("rev", "")))
        check_index(v, index)
        refuse_locked(v, index)
        commit(v, v.doc.delete(index), disabled=v.disabled.add(index, v.doc.blocks[index]))
    except Conflict as exc:
        return conflict_response(exc)
    return section_response(
        v, flash=f"Rule #{index + 1} disabled in the draft. Authelia ignores it."
    )


def check_disabled_index(v: View, index: int) -> None:
    if not 0 <= index < len(v.disabled.entries):
        raise Conflict("That disabled rule no longer exists. Reload the page.", 404)


@router.post("/disabled/{index}/enable", response_class=HTMLResponse)
async def enable_rule(request: Request, index: int) -> Response:
    data = await request.form()  # before load_view: no await between reading and saving
    v = load_view(request)
    try:
        require_rev(v, str(data.get("rev", "")))
        check_disabled_index(v, index)
        rest, entry = v.disabled.remove(index)
        position = min(entry.position, len(v.doc.blocks))
        new_doc = v.doc.insert_block(position, entry.block)
        # Belt and braces: the file must re-parse to exactly the old rules plus this one.
        rules = v.doc.rules()
        expected = [*rules[:position], entry.data(), *rules[position:]]
        if RulesDocument.parse(new_doc.render()).rules() != expected:
            raise Conflict("That disabled rule cannot be enabled safely; edit it by hand.", 422)
        commit(v, new_doc, disabled=rest)
    except (Conflict, DocumentError) as exc:
        return conflict_response(exc if isinstance(exc, Conflict) else Conflict(str(exc), 422))
    return section_response(v, flash=f"Rule enabled again at position {position + 1} in the draft.")


@router.get("/disabled/{index}/delete", response_class=HTMLResponse)
def delete_disabled_confirm(request: Request, index: int) -> Response:
    v = load_view(request)
    try:
        check_disabled_index(v, index)
    except Conflict as exc:
        return conflict_response(exc)
    return render(
        v, "partials/delete_disabled_confirm.html", row=build_disabled_rows(v.disabled)[index]
    )


@router.post("/disabled/{index}/delete", response_class=HTMLResponse)
async def delete_disabled(request: Request, index: int) -> Response:
    data = await request.form()  # before load_view: no await between reading and saving
    v = load_view(request)
    try:
        require_rev(v, str(data.get("rev", "")))
        check_disabled_index(v, index)
        rest, _ = v.disabled.remove(index)
        commit(v, v.doc, disabled=rest)
    except Conflict as exc:
        return conflict_response(exc)
    return section_response(v, flash="Disabled rule deleted permanently from the draft.")


@router.post("/rules/default-policy", response_class=HTMLResponse)
async def set_default_policy(request: Request) -> Response:
    data = await request.form()  # before load_view: no await between reading and saving
    v = load_view(request)
    policy = str(data.get("policy", ""))
    try:
        require_rev(v, str(data.get("rev", "")))
        if policy not in POLICIES:
            raise Conflict("Unknown policy.", 400)
        commit(v, v.doc.with_default_policy(policy))
    except Conflict as exc:
        return conflict_response(exc)
    return section_response(v, flash=f"Default policy set to {policy} in the draft.")


@router.get("/rules/{index}/raw", response_class=HTMLResponse)
def raw_editor(request: Request, index: int) -> Response:
    v = load_view(request)
    try:
        check_index(v, index)
    except Conflict as exc:
        return conflict_response(exc)
    _, report = v.analyse()
    return render(
        v, "partials/raw_editor.html", index=index, text=v.doc.blocks[index].rule_yaml(),
        errors=[], locked=index in report.locked,
    )  # fmt: skip


@router.post("/rules/{index}/raw", response_class=HTMLResponse)
async def save_raw(request: Request, index: int) -> Response:
    data = await request.form()  # before load_view: no await between reading and saving
    v = load_view(request)
    text = str(data.get("text", ""))
    try:
        require_rev(v, str(data.get("rev", "")))
        check_index(v, index)
        refuse_locked(v, index)
    except Conflict as exc:
        return conflict_response(exc)
    errors: list[str] = []
    try:
        node = YAML(typ="rt").load(text)
        if not isinstance(node, CommentedMap):
            errors.append("The rule must be a YAML mapping (key: value lines).")
    except YAMLError:
        errors.append("That is not valid YAML.")
        node = None
    if not errors and node is not None:
        doc = v.doc.replace_rule(index, node)
        issues, _ = v.analyse(doc)
        errors += [i.message for i in blocking(rule_issues(issues, index))]
        if not errors:
            try:
                commit(v, doc)
            except Conflict as exc:
                errors.append(exc.message)
    if errors:
        return render(
            v, "partials/raw_editor.html", status=422, index=index, text=text, errors=errors,
            locked=False,
        )  # fmt: skip
    return Response(status_code=204, headers={"HX-Redirect": f"/rules?saved={index + 1}"})


# --------------------------------------------------------------------------- tester


@router.get("/tester", response_class=HTMLResponse)
def tester_dialog(request: Request, url: str = "", user: str = "") -> Response:
    v = load_view(request)
    return render(
        v, "partials/tester.html", url=url, method="GET", user=user,
        groups=", ".join(v.users.memberships.get(user, ())), ip="", result=None, message="",
        usernames=sorted(v.users.usernames), methods=METHODS,
    )  # fmt: skip


@router.get("/tester/groups", response_class=HTMLResponse)
def tester_groups(request: Request, user: str = "") -> Response:
    v = load_view(request)
    groups = ", ".join(v.users.memberships.get(user, ()))
    return HTMLResponse(
        f'<input id="tester-groups" name="groups" value="{_esc(groups)}" '
        f'placeholder="comma separated"{" disabled" if not user else ""}>'
    )


@router.post("/tester/run", response_class=HTMLResponse)
async def tester_run(request: Request) -> Response:
    v = load_view(request)
    data = await request.form()
    url, method = str(data.get("url", "")).strip(), str(data.get("method", "GET"))
    user = str(data.get("user", ""))
    groups = tuple(g.strip() for g in str(data.get("groups", "")).split(",") if g.strip())
    ip_text = str(data.get("ip", "")).strip()
    message, result, matched = "", None, None
    try:
        obj = RequestObject.from_url(url, method if method in METHODS else "GET")
        ip = ipaddress.ip_address(ip_text) if ip_text else None
        subject = Subject(user, groups if user else (), ip)
        result = RuleTester(v.effective()).evaluate(obj, subject)
        if result.rule_index is not None:
            _, report = v.analyse()
            matched = build_rows(v.doc, v.live, [], report.locked)[result.rule_index]
    except ValueError as exc:
        message = str(exc) if "URL" in str(exc) else "That is not a valid IP address."
    return render(
        v, "partials/tester_result.html", result=result, matched=matched, message=message,
        skipped=skipped_summary(result) if result else [], user=user,
        default_policy=v.doc.default_policy(),
        test_query={"url": url, "method": method, "user": user, "groups": ", ".join(groups),
                    "ip": ip_text, "expect": result.policy if result else ""},
    )  # fmt: skip


# --------------------------------------------------------------------------- review / discard


@router.get("/review", response_class=HTMLResponse)
def review(request: Request) -> Response:
    try:
        v = load_view(request)
    except (OSError, DocumentError):
        return error_page(request, "The managed access control file could not be read.")
    issues, report = v.analyse()
    changes = v.store.changes()
    validator: ValidationResult | None = None
    reasons: list[str] = []
    if v.store.has_draft():
        validator = validate_candidate(v.settings, v.doc.render(), v.clients_text or None)
        # The tests gate is shown separately (checkbox), so it is not a reason here.
        reasons = services_of(request).engine.preconditions(rev=v.rev, accept_tests=True)
    try:
        test_results = services_of(request).engine.test_results() if v.store.has_draft() else []
    except DocumentError:
        test_results = []
    rows = build_rows(v.doc, v.live, issues, report.locked)
    return render(
        v, "review.html", changes=changes, issues=issues, errors=blocking(issues),
        warnings=[i for i in issues if i.severity == "warning"], report=report, rows=rows,
        diff=diff_lines(v.store.diff()), validator=validator, apply_reasons=reasons,
        default_policy=v.doc.default_policy(), test_results=test_results,
        tests_failing=[r for r in test_results if r.fails],
        tests_changed=[r for r in test_results if r.changed and not r.fails],
        labels=POLICY_LABEL,
    )  # fmt: skip


@router.get("/draft/discard", response_class=HTMLResponse)
def discard_confirm(request: Request) -> Response:
    v = load_view(request)
    return render(v, "partials/discard_confirm.html", changes=v.store.changes())


@router.post("/draft/discard", response_class=HTMLResponse)
async def discard(request: Request) -> Response:
    data = await request.form()  # before load_view: no await between reading and saving
    v = load_view(request)
    try:
        require_rev(v, str(data.get("rev", "")))
        v.store.discard(expected_sha=v.sha)
    except StaleDraftError:
        return conflict_response(Conflict(STALE))
    except Conflict as exc:
        return conflict_response(exc)
    return Response(status_code=204, headers={"HX-Redirect": "/rules"})
