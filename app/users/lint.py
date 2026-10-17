"""Checks before the users file is written (SPEC §9). Authelia keeps the old users silently when a
new file is invalid (docs/users-file.md), so everything that can be checked here must be."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any

from app.users.schema import UsersSchema

EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
GROUP = re.compile(r"^[^\s,:'\"]{1,128}$")
KNOWN = (
    "password",
    "displayname",
    "email",
    "groups",
    "disabled",
    "extra",
    "given_name",
    "family_name",
    "middle_name",
    "nickname",
    "profile",
    "picture",
    "website",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
    "phone_number",
    "phone_extension",
    "address",
)


def check_value(attr_type: str, multi: bool, value: Any) -> bool:
    values = value if multi and isinstance(value, list) else [value]
    if multi and not isinstance(value, list):
        return False
    for v in values:
        if attr_type == "integer" and (isinstance(v, bool) or not isinstance(v, int)):
            return False
        if attr_type == "boolean" and not isinstance(v, bool):
            return False
        if attr_type == "string" and not isinstance(v, str):
            return False
    return True


def lint_users(
    users: Mapping[str, Mapping[str, Any]], schema: UsersSchema, password_set: Mapping[str, bool]
) -> list[tuple[str, str, str]]:
    """[(username or '', 'error'|'warning', message)]."""
    out: list[tuple[str, str, str]] = []
    emails = Counter(str(u.get("email", "")).lower() for u in users.values() if u.get("email"))
    for name, user in users.items():

        def add(severity: str, message: str, who: str = name) -> None:
            out.append((who, severity, f"User '{who}': {message}"))

        if not password_set.get(name):
            add("error", "has no password.")
        if not str(user.get("displayname") or "").strip():
            add("error", "needs a display name.")
        email = str(user.get("email") or "")
        if email and not EMAIL.match(email):
            add("error", f"'{email}' is not an email address.")
        if schema.login_by_email and email and emails[email.lower()] > 1:
            add("error", "shares its email with another user, but users log in by email.")
        groups = user.get("groups")
        if groups is not None and (
            not isinstance(groups, list)
            or not all(isinstance(g, str) and GROUP.match(g) for g in groups)
        ):
            add("error", "groups must be a list of names without spaces, commas or quotes.")
        if "disabled" in user and not isinstance(user["disabled"], bool):
            add("error", "disabled must be true or false.")
        extra = user.get("extra") or {}
        if not isinstance(extra, dict):
            add("error", "extra must be a mapping of attributes.")
            extra = {}
        top_level = {k: v for k, v in user.items() if k not in KNOWN}
        for key, value in {**top_level, **extra}.items():
            spec = schema.extra.get(str(key))
            if spec is None:
                add(
                    "warning" if key in top_level else "error",
                    f"'{key}' is not an extra attribute declared in the main configuration.",
                )
            elif not check_value(spec.value_type, spec.multi_valued, value):
                kind = (
                    f"a list of {spec.value_type}s" if spec.multi_valued else f"a {spec.value_type}"
                )
                add("error", f"'{key}' must be {kind}.")
    return out


def lockout_problems(
    before: Mapping[str, Mapping[str, Any]],
    after: Mapping[str, Mapping[str, Any]],
    me: str,
    admin_group: str,
) -> list[str]:
    """Changes that would lock the admins (or the person making them) out of this tool."""

    def admins(users: Mapping[str, Mapping[str, Any]]) -> set[str]:
        return {
            n
            for n, u in users.items()
            if admin_group in (u.get("groups") or []) and u.get("disabled") is not True
        }

    out = []
    if me in admins(before) and me not in admins(after):
        out.append("You cannot remove, disable or demote yourself; ask another admin.")
    if admins(before) and not admins(after):
        out.append(f"At least one enabled user must stay in the '{admin_group}' group.")
    return out


def groups_of(users: Mapping[str, Mapping[str, Any]]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for name, user in users.items():
        for group in user.get("groups") or []:
            out.setdefault(str(group), []).append(name)
    return dict(sorted(out.items()))


def referenced_groups(rules: Sequence[Mapping[str, Any]]) -> dict[str, list[int]]:
    """group -> rule numbers (1-based) whose subject mentions group:<name>."""
    from app.rules.tester import normalise_subjects

    out: dict[str, list[int]] = {}
    for i, rule in enumerate(rules):
        for alternative in normalise_subjects(rule.get("subject")):
            for term in alternative:
                if term.startswith("group:"):
                    out.setdefault(term.removeprefix("group:"), []).append(i + 1)
    return out
