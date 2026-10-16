from __future__ import annotations

from typing import Any

import pytest

from app.rules.document import RulesDocument
from app.rules.lint import (
    Issue,
    UsersInfo,
    blocking,
    covers,
    lint,
    literal_path,
    re2_problem,
    regex_issue,
)
from scripts.split_config import split

USERS = UsersInfo(frozenset({"alice", "bob"}), frozenset({"admin", "family"}))


def codes(issues: list[Issue]) -> list[str]:
    return [i.code for i in issues]


def rule(**kw: Any) -> dict[str, Any]:
    return {"domain": "a.example.com", "policy": "two_factor", **kw}


# --------------------------------------------------------------------- regex


@pytest.mark.parametrize(
    "pattern",
    [
        "^/api/.*$",
        "a+?",
        "a*?b",
        "[(?!]",
        r"\(?!",
        "[]a]+",
        "a{2,3}?",
        r"^/\.well-known/x$",
        "(?i)abc",
    ],
)
def test_valid_re2(pattern: str) -> None:
    assert re2_problem(pattern) is None
    assert regex_issue(pattern) is None


@pytest.mark.parametrize(
    ("pattern", "fragment"),
    [
        ("^(?!/admin).*$", "negative lookahead"),
        ("(?=x)a", "lookahead"),
        ("(?<=a)b", "lookbehind"),
        ("(?<!a)b", "negative lookbehind"),
        (r"(a)\1", "back-references"),
        ("a*+", "nested repetition"),
        ("a++", "nested repetition"),
        ("a{2}+", "nested repetition"),
        ("(?>a)", "atomic"),
    ],
)
def test_non_re2_constructs_are_blocking(pattern: str, fragment: str) -> None:
    severity, message = regex_issue(pattern) or ("", "")
    assert severity == "error" and fragment in message


def test_invalid_python_regex_is_blocking_but_re2_only_syntax_only_warns() -> None:
    assert (regex_issue("([unclosed") or ("",))[0] == "error"
    assert (regex_issue(r"^\pL+$") or ("",))[0] == "warning"  # valid RE2, Python cannot check
    assert (regex_issue("^(?<name>a)$") or ("",))[0] == "warning"  # Go >= 1.22 named group


@pytest.mark.parametrize(
    ("pattern", "path"),
    [
        ("^/api/ping$", "/api/ping"),
        (r"^/favicon\.ico$", "/favicon.ico"),
        ("^/a-b/c_d$", "/a-b/c_d"),
    ],
)
def test_literal_path(pattern: str, path: str) -> None:
    assert literal_path(pattern) == path


@pytest.mark.parametrize("pattern", ["^/api/.*$", "/api", "^/a|b$", "^/x?$"])
def test_non_literal_patterns(pattern: str) -> None:
    assert literal_path(pattern) is None


# --------------------------------------------------------------------- single-rule checks


def test_blocking_errors() -> None:
    issues = lint(
        [
            {"policy": "bypass"},  # no domain
            rule(policy="allow"),  # bad policy
            rule(resources=["^(?!/x).*$"]),  # not RE2
            rule(policy="bypass", subject="group:admin"),  # bypass + subject
            rule(subject="admin"),  # bad subject syntax
            rule(networks=["10.0.0.0/99"]),  # bad network
        ],
        users=USERS,
    )
    assert {
        "no-domain",
        "bad-policy",
        "regex",
        "bypass-subject",
        "bad-subject",
        "bad-network",
    } <= set(codes(blocking(issues)))


def test_named_networks_are_accepted() -> None:
    assert not blocking(lint([rule(networks=["vpn"])], known_networks=frozenset({"vpn"})))
    assert "bad-network" in codes(lint([rule(networks=["vpn"])]))


def test_unknown_users_and_groups_warn_only_when_users_file_is_available() -> None:
    subject = [["user:carol"], ["group:ghosts", "group:admin"]]
    issues = lint([rule(subject=subject)], users=USERS)
    assert codes(issues) == ["unknown-user", "unknown-group"]
    assert not blocking(issues)
    assert (
        lint([rule(subject=subject)], users=UsersInfo(frozenset(), frozenset(), available=False))
        == []
    )


def test_bypass_without_resources_warns_once_resources_given() -> None:
    assert codes(lint([rule(policy="bypass")])) == ["bypass-open"]
    assert lint([rule(policy="bypass", resources=["^/x$"])]) == []


# --------------------------------------------------------------------- duplicates / shadowing


def test_duplicate_rule() -> None:
    issues = lint([rule(), rule()])
    assert [(i.code, i.rule) for i in issues] == [("duplicate", 1)]


@pytest.mark.parametrize(
    ("earlier", "later", "expected"),
    [
        ({"domain": "*.example.com"}, {"domain": "a.example.com"}, True),
        ({"domain": "*.example.com"}, {"domain": "*.sub.example.com"}, True),
        ({"domain": "a.example.com"}, {"domain": "*.example.com"}, False),
        ({"domain": "*.example.com"}, {"domain": "example.com"}, False),  # apex not covered
        ({"domain": "a.example.com"}, {"domain": "A.Example.com"}, True),
        ({}, {"domain": "a.example.com", "resources": ["^/x$"]}, True),
        ({"domain": "a.example.com", "resources": ["^/x$"]}, {"domain": "a.example.com"}, False),
        ({"domain": "a.example.com", "resources": ["^/x$", "^/y$"]},
         {"domain": "a.example.com", "resources": ["^/y$"]}, True),
        ({"domain": "a.example.com", "methods": ["GET"]}, {"domain": "a.example.com"}, False),
        ({"domain": "a.example.com", "subject": "group:admin"}, {"domain": "a.example.com"}, False),
        ({"domain": "a.example.com"}, {"domain": "a.example.com", "subject": "group:admin"}, True),
        ({"domain_regex": "^a\\."}, {"domain": "a.example.com"}, False),  # cannot prove
        ({"domain": "a.example.com", "networks": ["10.0.0.0/8"]},
         {"domain": "a.example.com"}, False),
    ],
)  # fmt: skip
def test_covers(earlier: dict[str, Any], later: dict[str, Any], expected: bool) -> None:
    assert covers(earlier, later) is expected


def test_shadowed_rule_is_reported_on_the_later_rule() -> None:
    issues = lint(
        [rule(domain="*.example.com", policy="deny"), rule(policy="bypass", resources=["^/x$"])]
    )
    assert [(i.code, i.rule) for i in issues] == [("shadowed", 1)]


# --------------------------------------------------------------------- redundant paths


def test_redundant_literal_paths_are_listed_but_uncovered_ones_are_not() -> None:
    rules = [
        rule(
            domain="p.example.com", policy="bypass", resources=["^/api/ping$", r"^/favicon\.ico$"]
        ),
        rule(domain="p.example.com", policy="bypass", resources=["^/api/.*$"]),
        rule(domain="p.example.com", policy="two_factor", subject="group:family"),
    ]
    issues = [i for i in lint(rules, users=USERS) if i.code == "redundant-paths"]
    assert len(issues) == 1 and issues[0].rule == 0
    assert "^/api/ping$" in issues[0].message and "favicon" not in issues[0].message


def test_paths_with_a_different_outcome_are_not_redundant() -> None:
    rules = [
        rule(domain="p.example.com", policy="bypass", resources=["^/api/ping$"]),
        rule(domain="p.example.com", policy="deny", resources=["^/api/.*$"]),
    ]
    assert "redundant-paths" not in codes(lint(rules))


def test_realistic_config_findings(realistic_main: str) -> None:
    doc = RulesDocument.parse(split(realistic_main).access_control_text)
    users = UsersInfo(frozenset({"alice", "bob", "device", "family"}),
                      frozenset({"admin", "dev", "home", "family"}))  # fmt: skip
    issues = lint(doc.rules(), users=users)
    assert not blocking(issues)
    by_code = {c: [i for i in issues if i.code == c] for c in set(codes(issues))}
    assert {m.message.split("'")[1] for m in by_code["unknown-user"]} == {"dave", "erin"}
    redundant = by_code["redundant-paths"]
    assert len(redundant) == 1 and "favicon" not in redundant[0].message
    assert "^/api/server/ping$" in redundant[0].message
