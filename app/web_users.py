"""Users and groups pages (SPEC §9).

Unlike rules and clients there is no draft: Authelia reloads the users file by itself, so every
change is validated and saved at once (ApplyEngine.update_users). Passwords: a generated one is
shown once in the response that created it (`Cache-Control: no-store`); a typed one is checked
against the password policy. Neither is stored anywhere but as a hash; no page shows a hash.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, Response

from app.apply.engine import Refused
from app.apply.repo import RepoError
from app.authelia_cli import AutheliaCLI
from app.blocklist import DocumentError
from app.security import identity_of
from app.users import passwords
from app.users.document import DELETE, USERNAME, UsersDocument
from app.users.lint import KNOWN, groups_of, lint_users, referenced_groups
from app.users.schema import UsersSchema, load_schema
from app.web import (
    Conflict,
    View,
    conflict_response,
    load_view,
    render,
    services_of,
)

router = APIRouter()
NO_STORE = {"Cache-Control": "no-store, max-age=0", "Pragma": "no-cache"}
Change = Callable[[UsersDocument], tuple[UsersDocument, str]]


# --------------------------------------------------------------------------- helpers


def users_doc(v: View) -> UsersDocument | None:
    path = v.settings.USERS_FILE
    try:
        return UsersDocument.parse(path.read_text())
    except (OSError, DocumentError):
        return None


def users_context(v: View, **extra: Any) -> dict[str, Any]:
    engine = services_of(v.request).engine
    return {
        "active": "users", "writable": engine.users_name is not None,
        "users_rev": engine.users_rev(), "schema": load_schema(v.settings.CONFIG_MAIN),
        "admin_group": v.settings.ADMIN_GROUP, "me": v.identity.username, **extra,
    }  # fmt: skip


def run_change(request: Request, change: Change, rev: str) -> str | None:
    """Apply `change` under the lock; a plain-language problem, or None when saved."""
    me = identity_of(request.state).username
    try:
        services_of(request).engine.update_users(change, me, rev)
    except Refused as exc:
        return str(exc)
    except DocumentError as exc:
        return str(exc)
    except (OSError, RepoError):
        return "The users could not be saved."
    return None


def password_modal(v: View, password: str, username: str, created: bool) -> HTMLResponse:
    response = render(v, "partials/password_modal.html", password=password, username=username,
                      created=created)  # fmt: skip
    response.headers.update(NO_STORE)
    response.headers["HX-Retarget"] = "#modal"
    response.headers["HX-Reswap"] = "innerHTML"
    response.headers["HX-Reselect"] = "dialog"
    return response


def parse_groups(data: Any) -> list[str]:
    chosen = [str(g).strip() for g in data.getlist("l_groups") if str(g).strip()]
    extra = str(data.get("new_groups", "")).replace(",", " ").split()
    return list(dict.fromkeys([*chosen, *extra]))


def _same_members(a: list[str], b: list[str]) -> bool:
    return sorted(a) == sorted(b)


def extra_changes(user: dict[str, Any], schema: UsersSchema, data: Any) -> dict[str, Any]:
    """Field changes for the declared extra attributes, keeping each where the user has it."""
    top_level = {k: v for k, v in user.items() if k not in KNOWN}
    nested = dict(user.get("extra") or {}) if isinstance(user.get("extra"), dict) else {}
    nested_changed = False
    changes: dict[str, Any] = {}
    for name, spec in schema.extra.items():
        raw = str(data.get(f"x_{name}", "")).replace("\r\n", "\n").strip()
        if spec.multi_valued:
            parts: list[str] = [p.strip() for p in raw.split("\n") if p.strip()]
        else:
            parts = [raw] if raw else []
        values: list[Any] = []
        for part in parts:
            if spec.value_type == "integer":
                try:
                    values.append(int(part))
                except ValueError:
                    raise Conflict(f"'{name}' must be a whole number.", 422) from None
            elif spec.value_type == "boolean":
                if part not in ("true", "false"):
                    raise Conflict(f"'{name}' must be yes or no.", 422)
                values.append(part == "true")
            else:
                values.append(part)
        new: Any = DELETE if not values else (values if spec.multi_valued else values[0])
        current = top_level.get(name, nested.get(name, DELETE))
        if new == current or (new is DELETE and current is DELETE):
            continue
        if name in top_level:
            changes[name] = new
        else:
            nested_changed = True
            if new is DELETE:
                nested.pop(name, None)
            else:
                nested[name] = new
    if nested_changed:
        changes["extra"] = nested if nested else DELETE
    return changes


# --------------------------------------------------------------------------- list


def list_rows(doc: UsersDocument | None, ctx: dict[str, Any], q: str = "") -> list[dict[str, Any]]:
    """The users table; the editor opens as a drawer over it, so its pages need it too."""
    rows: list[dict[str, Any]] = []
    if doc is not None:
        schema: UsersSchema = ctx["schema"]
        users = doc.users()
        problems = lint_users(users, schema, {n: doc.has_password(n) for n in doc.names()})
        needle = q.strip().lower()
        for name, u in users.items():
            groups = [str(g) for g in u.get("groups") or []]
            hay = " ".join([name, str(u.get("displayname", "")), str(u.get("email", "")), *groups])
            if needle and needle not in hay.lower():
                continue
            rows.append({
                "name": name, "displayname": str(u.get("displayname") or ""),
                "email": str(u.get("email") or ""), "groups": groups,
                "disabled": u.get("disabled") is True,
                "admin": ctx["admin_group"] in groups,
                "issues": [m for who, sev, m in problems if who == name],
            })  # fmt: skip
    return rows


@router.get("/users", response_class=HTMLResponse)
def users_page(request: Request, q: str = "", saved: str = "") -> Response:
    v = load_view(request)
    doc = users_doc(v)
    ctx = users_context(v)
    flash = f"User {saved} saved." if saved else ""
    return render(v, "users.html", rows=list_rows(doc, ctx, q), q=q, broken=doc is None,
                  flash=flash, **ctx)  # fmt: skip


# --------------------------------------------------------------------------- editor


def editor_context(v: View, doc: UsersDocument, name: str | None, errors: list[str] | None = None,
                   form: dict[str, Any] | None = None) -> dict[str, Any]:  # fmt: skip
    ctx = users_context(v)
    user = dict(doc.users().get(name, {})) if name else {}
    top_level = {k: val for k, val in user.items() if k not in KNOWN}
    nested = user.get("extra") if isinstance(user.get("extra"), dict) else {}
    values = {**top_level, **(nested or {})}
    known_groups = sorted(groups_of(doc.users()))
    data = form or {
        "username": name or "", "displayname": user.get("displayname", ""),
        "email": user.get("email", ""), "groups": [str(g) for g in user.get("groups") or []],
        "disabled": user.get("disabled") is True,
    }  # fmt: skip
    return {
        **ctx,
        "rows": list_rows(doc, ctx),
        "q": "",
        "broken": False,
        "uname": name,
        "errors": errors or [],
        "f": data,
        "known_groups": known_groups,
        "extra_values": values,
        "has_password": bool(name and doc.has_password(name)),
    }


@router.get("/users/new", response_class=HTMLResponse)
def new_user(request: Request) -> Response:
    v = load_view(request)
    doc = users_doc(v)
    if doc is None:
        return conflict_response(Conflict("The users file could not be read.", 503))
    return render(v, "user_editor.html", **editor_context(v, doc, None))


@router.get("/users/{name}/edit", response_class=HTMLResponse)
def edit_user(request: Request, name: str) -> Response:
    v = load_view(request)
    doc = users_doc(v)
    if doc is None or name not in doc.names():
        return conflict_response(Conflict("That user no longer exists. Reload the page.", 404))
    return render(v, "user_editor.html", **editor_context(v, doc, name))


@router.post("/users/save", response_class=HTMLResponse)
async def save_user(request: Request) -> Response:
    data = await request.form()
    v = load_view(request)
    doc = users_doc(v)
    if doc is None:
        return conflict_response(Conflict("The users file could not be read.", 503))
    name = str(data.get("original", "")).strip() or None
    username = (name or str(data.get("username", ""))).strip()
    schema = load_schema(v.settings.CONFIG_MAIN)
    form: dict[str, Any] = {
        "username": username, "displayname": str(data.get("displayname", "")).strip(),
        "email": str(data.get("email", "")).strip(), "groups": parse_groups(data),
        "disabled": str(data.get("disabled", "")) == "1",
    }  # fmt: skip
    mode = str(data.get("pw_mode", "generate"))
    typed = str(data.get("password", ""))

    def fail(message: str) -> Response:
        ctx = editor_context(v, doc, name, [message], {**form, "username": username})
        return render(v, "user_editor.html", status=422, **ctx)

    if name is None and not USERNAME.match(username):
        return fail("Usernames may use letters, digits and . _ @ - (up to 64 characters).")
    if name is not None and name not in doc.names():
        return conflict_response(Conflict("That user no longer exists. Reload the page.", 404))
    if name is None and mode == "typed" and not typed:
        return fail("Type a password, or let one be generated.")

    secret = ""
    digest = ""
    if name is None:
        try:
            cli = AutheliaCLI.local(v.settings.AUTHELIA_BINARY)
            if mode == "typed":
                digest = await run_in_threadpool(
                    passwords.typed, cli, v.settings.CONFIG_MAIN, typed, schema.policy
                )
            else:
                secret, digest = await run_in_threadpool(
                    passwords.generated, cli, v.settings.CONFIG_MAIN, schema.policy
                )
        except passwords.PasswordError as exc:
            return fail(str(exc))

    try:
        extra_user = dict(doc.users().get(name, {})) if name else {}
        fields_extra = extra_changes(extra_user, schema, data)
    except Conflict as exc:
        return fail(exc.message)

    def change(current: UsersDocument) -> tuple[UsersDocument, str]:
        if name is None:
            fields: dict[str, Any] = {
                "displayname": form["displayname"], "email": form["email"],
                "groups": form["groups"], "disabled": form["disabled"], "password": digest,
            }  # fmt: skip
            for key, value in fields_extra.items():
                fields[key] = {} if value is DELETE else value
            fields = {k: v for k, v in fields.items() if v != {}}
            if not form["email"]:
                fields.pop("email")
            return current.add(username, fields), f"Users: added {username}"
        old = current.users()[name]
        changes: dict[str, Any] = {}
        if form["displayname"] != old.get("displayname"):
            changes["displayname"] = form["displayname"]
        if form["email"] != str(old.get("email") or ""):
            changes["email"] = form["email"] or DELETE
        if not _same_members(form["groups"], [str(g) for g in old.get("groups") or []]):
            changes["groups"] = form["groups"]
        if form["disabled"] != (old.get("disabled") is True):
            changes["disabled"] = form["disabled"]
        changes.update(fields_extra)
        return (current.set_fields(name, changes) if changes else current), f"Users: edited {name}"

    problem = await run_in_threadpool(run_change, request, change, str(data.get("users_rev", "")))
    if problem:
        return fail(problem)
    if secret:
        return password_modal(v, secret, username, created=True)
    return Response(status_code=204, headers={"HX-Redirect": f"/users?saved={username}"})


# --------------------------------------------------------------------------- password


@router.get("/users/{name}/password", response_class=HTMLResponse)
def password_form(request: Request, name: str) -> Response:
    v = load_view(request)
    doc = users_doc(v)
    if doc is None or name not in doc.names():
        return conflict_response(Conflict("That user no longer exists. Reload the page.", 404))
    return render(v, "partials/password_form.html", uname=name, error="", **users_context(v))


@router.post("/users/{name}/password", response_class=HTMLResponse)
async def set_password(request: Request, name: str) -> Response:
    data = await request.form()
    v = load_view(request)
    doc = users_doc(v)
    if doc is None or name not in doc.names():
        return conflict_response(Conflict("That user no longer exists. Reload the page.", 404))
    schema = load_schema(v.settings.CONFIG_MAIN)
    mode, typed = str(data.get("pw_mode", "generate")), str(data.get("password", ""))

    def fail(message: str) -> Response:
        return render(v, "partials/password_form.html", status=422, uname=name, error=message,
                      **users_context(v))  # fmt: skip

    secret = ""
    try:
        cli = AutheliaCLI.local(v.settings.AUTHELIA_BINARY)
        if mode == "typed":
            if not typed:
                return fail("Type a password, or let one be generated.")
            digest = await run_in_threadpool(passwords.typed, cli, v.settings.CONFIG_MAIN, typed,
                                             schema.policy)  # fmt: skip
        else:
            secret, digest = await run_in_threadpool(
                passwords.generated, cli, v.settings.CONFIG_MAIN, schema.policy
            )
    except passwords.PasswordError as exc:
        return fail(str(exc))
    problem = await run_in_threadpool(
        run_change, request,
        lambda d: (d.set_fields(name, {"password": digest}), f"Users: new password for {name}"),
        str(data.get("users_rev", "")),
    )  # fmt: skip
    if problem:
        return fail(problem)
    if secret:
        return password_modal(v, secret, name, created=False)
    return Response(status_code=204, headers={"HX-Redirect": f"/users?saved={name}"})


# --------------------------------------------------------------------------- delete


@router.get("/users/{name}/delete", response_class=HTMLResponse)
def delete_confirm(request: Request, name: str) -> Response:
    v = load_view(request)
    doc = users_doc(v)
    if doc is None or name not in doc.names():
        return conflict_response(Conflict("That user no longer exists. Reload the page.", 404))
    return render(v, "partials/user_delete_confirm.html", uname=name,
                  displayname=str(doc.users()[name].get("displayname") or ""),
                  **users_context(v))  # fmt: skip


@router.post("/users/{name}/delete", response_class=HTMLResponse)
async def delete_user(request: Request, name: str) -> Response:
    data = await request.form()
    problem = await run_in_threadpool(
        run_change, request, lambda d: (d.delete(name), f"Users: removed {name}"),
        str(data.get("users_rev", "")),
    )  # fmt: skip
    if problem:
        return conflict_response(Conflict(problem, 422))
    return Response(status_code=204, headers={"HX-Redirect": "/users"})


# --------------------------------------------------------------------------- groups


@router.get("/groups", response_class=HTMLResponse)
def groups_page(request: Request, saved: str = "") -> Response:
    v = load_view(request)
    doc = users_doc(v)
    ctx = users_context(v)
    ctx["active"] = "groups"
    groups: list[dict[str, Any]] = []
    if doc is not None:
        users = doc.users()
        members = groups_of(users)
        refs = referenced_groups(v.doc.rules())
        for name in sorted({*members, *refs}):
            groups.append({
                "name": name, "members": members.get(name, []), "rules": refs.get(name, []),
                "admin": name == ctx["admin_group"],
                "addable": [u for u in users if u not in members.get(name, [])],
            })  # fmt: skip
    return render(
        v,
        "groups.html",
        groups=groups,
        broken=doc is None,
        flash=f"Group {saved} saved." if saved else "",
        **ctx,
    )


def _group_change(request: Request, name: str, make: Change, rev: str) -> Response:
    problem = run_change(request, make, rev)
    if problem:
        return conflict_response(Conflict(problem, 422))
    return Response(status_code=204, headers={"HX-Redirect": f"/groups?saved={name}"})


@router.post("/groups/{name}/members", response_class=HTMLResponse)
async def group_members(request: Request, name: str) -> Response:
    data = await request.form()
    user, action = str(data.get("user", "")), str(data.get("action", ""))
    if action not in ("add", "remove"):
        return conflict_response(Conflict("Unknown action.", 400))

    def change(doc: UsersDocument) -> tuple[UsersDocument, str]:
        groups = [str(g) for g in doc.users()[user].get("groups") or []]
        if action == "add":
            groups = list(dict.fromkeys([*groups, name]))
        else:
            groups = [g for g in groups if g != name]
        return doc.set_fields(user, {"groups": groups}), f"Users: {action} {user} in group {name}"

    def guarded(doc: UsersDocument) -> tuple[UsersDocument, str]:
        if user not in doc.names():
            raise DocumentError(f"no user '{user}'")
        return change(doc)

    return await run_in_threadpool(_group_change, request, name, guarded,
                                   str(data.get("users_rev", "")))  # fmt: skip


@router.post("/groups/{name}/rename", response_class=HTMLResponse)
async def rename_group(request: Request, name: str) -> Response:
    data = await request.form()
    new = str(data.get("new_name", "")).strip()
    if not new or any(c in new for c in " ,:'\""):
        return conflict_response(
            Conflict("Group names cannot contain spaces, commas or quotes.", 422)
        )
    return await run_in_threadpool(
        _group_change, request, new,
        lambda d: (d.rename_group(name, new), f"Users: renamed group {name} to {new}"),
        str(data.get("users_rev", "")),
    )  # fmt: skip
