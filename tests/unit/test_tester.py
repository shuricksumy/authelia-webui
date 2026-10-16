"""Rule tester semantics, ported from Authelia v4.39 (see app/rules/tester.py docstring)."""

from __future__ import annotations

import ipaddress

import pytest

from app.rules.tester import (
    RequestObject,
    RuleTester,
    Subject,
    go_path_clean,
    normalise_subjects,
    url_path_full_clean,
)

ALICE = Subject("alice", ("admin", "dev"))
BOB = Subject("bob", ("family",))
ANON = Subject()


def make_tester(*rules: dict[str, object], default: str = "deny", **extra: object) -> RuleTester:
    return RuleTester(
        {"access_control": {"default_policy": default, "rules": list(rules)}, **extra}
    )


def run(t: RuleTester, url: str, subject: Subject = ANON, method: str = "GET"):  # type: ignore[no-untyped-def]
    return t.evaluate(RequestObject.from_url(url, method), subject)


# --------------------------------------------------------------------- go ports


@pytest.mark.parametrize(
    ("raw", "clean"),
    [("", "."), ("/", "/"), ("//a//b/", "/a/b"), ("/a/./b/../c", "/a/c"), ("/../a", "/a"),
     ("a/../../b", "../b"), ("/a/b/..", "/a")],
)  # fmt: skip
def test_go_path_clean(raw: str, clean: str) -> None:
    assert go_path_clean(raw) == clean


@pytest.mark.parametrize(
    ("path", "query", "expected"),
    [("/", "", "/"), ("/", "x=1", "/?x=1"), ("/a/", "", "/a/"), ("/a/", "x=1", "/a/?x=1"),
     ("/a//b", "", "/a/b"), ("/a/b", "q", "/a/b?q"), ("", "", ".")],
)  # fmt: skip
def test_url_path_full_clean(path: str, query: str, expected: str) -> None:
    assert url_path_full_clean(path, query) == expected


# --------------------------------------------------------------------- ordering / default


def test_first_match_wins_and_default_applies() -> None:
    t = make_tester(
        {"domain": "app.example.com", "resources": ["^/api/"], "policy": "bypass"},
        {"domain": "app.example.com", "policy": "two_factor"},
    )
    assert run(t, "https://app.example.com/api/x").policy == "bypass"
    r = run(t, "https://app.example.com/ui")
    assert (r.rule_index, r.policy) == (1, "two_factor")
    assert [s.reason for s in r.skipped] == ["path does not match"]
    d = run(t, "https://other.example.com/")
    assert (d.rule_index, d.policy) == (None, "deny")


# --------------------------------------------------------------------- domains


@pytest.mark.parametrize(
    ("url", "matches"),
    [
        ("https://a.example.com/", True),
        ("https://a.b.example.com/", True),
        ("https://example.com/", False),
        ("https://A.EXAMPLE.COM/", True),
        ("https://notexample.com/", False),  # hygiene: ignore (suffix without the dot)
        ("https://a.example.com:8443/", True),
    ],
)
def test_wildcard_domain_is_suffix_match_without_apex(url: str, matches: bool) -> None:
    t = make_tester({"domain": "*.example.com", "policy": "bypass"})
    assert (run(t, url).rule_index == 0) is matches


def test_exact_domain_case_insensitive_and_domain_regex_search() -> None:
    t = make_tester(
        {"domain": "App.Example.com", "policy": "bypass"},
        {"domain_regex": r"^(foo|bar)\.example\.com$", "policy": "one_factor"},
    )
    assert run(t, "https://app.example.com/").rule_index == 0
    assert run(t, "https://bar.example.com/").rule_index == 1
    assert run(t, "https://baz.example.com/").rule_index is None


def test_domain_placeholders_are_reported_as_uncertain() -> None:
    t = make_tester({"domain": "{user}.example.com", "policy": "one_factor"})
    r = run(t, "https://alice.example.com/", ALICE)
    assert r.rule_index is None and r.uncertain


# --------------------------------------------------------------------- resources


def test_resources_search_path_plus_query() -> None:
    t = make_tester({"domain": "c.example.com", "resources": ["^/status.php$"], "policy": "bypass"})
    assert run(t, "https://c.example.com/status.php").rule_index == 0
    # Authelia appends ?query before matching, so an anchored regex stops matching.
    assert run(t, "https://c.example.com/status.php?x=1").rule_index is None


def test_resources_are_searched_not_full_matched() -> None:
    t = make_tester({"domain": "c.example.com", "resources": ["/api"], "policy": "bypass"})
    assert run(t, "https://c.example.com/v1/api/x").rule_index == 0


def test_path_is_cleaned_before_matching() -> None:
    t = make_tester({"domain": "c.example.com", "resources": ["^/admin"], "policy": "deny"})
    assert run(t, "https://c.example.com/public/../admin/x").rule_index == 0
    assert run(t, "https://c.example.com//admin").rule_index == 0


# --------------------------------------------------------------------- subjects


def test_subject_or_of_and() -> None:
    t = make_tester(
        {"domain": "h.example.com", "subject": [["user:bob", "group:dev"], "group:admin"],
         "policy": "two_factor"},
    )  # fmt: skip
    assert run(t, "https://h.example.com/", ALICE).rule_index == 0  # group:admin
    assert run(t, "https://h.example.com/", BOB).rule_index is None  # bob but not dev
    bob_dev = Subject("bob", ("dev",))
    assert run(t, "https://h.example.com/", bob_dev).rule_index == 0


def test_anonymous_matches_first_subject_rule_and_needs_login() -> None:
    t = make_tester(
        {"domain": "h.example.com", "subject": "group:admin", "policy": "two_factor"},
        {"domain": "h.example.com", "policy": "bypass"},
    )
    r = run(t, "https://h.example.com/")
    assert (r.rule_index, r.login_required) == (0, True)
    # A logged-in non-admin skips the subject rule and reaches the bypass rule.
    assert run(t, "https://h.example.com/", BOB).policy == "bypass"


def test_oauth2_client_subject_never_matches_a_user() -> None:
    t = make_tester(
        {"domain": "h.example.com", "subject": "oauth2:client:svc", "policy": "one_factor"}
    )
    assert run(t, "https://h.example.com/", ALICE).rule_index is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, []), ("group:a", [["group:a"]]), (["group:a", "user:b"], [["group:a"], ["user:b"]]),
     ([["group:a", "user:b"], "group:c"], [["group:a", "user:b"], ["group:c"]])],
)  # fmt: skip
def test_normalise_subjects(value: object, expected: list[list[str]]) -> None:
    assert normalise_subjects(value) == expected


# --------------------------------------------------------------------- methods / networks / query


def test_methods() -> None:
    t = make_tester({"domain": "m.example.com", "methods": ["OPTIONS"], "policy": "bypass"})
    assert run(t, "https://m.example.com/", method="options").rule_index == 0
    assert run(t, "https://m.example.com/", method="GET").rule_index is None


def test_networks_cidr_and_named_definitions() -> None:
    t = make_tester(
        {"domain": "n.example.com", "networks": ["lan"], "policy": "one_factor"},
        {"domain": "n.example.com", "networks": ["10.8.0.0/24"], "policy": "bypass"},
        definitions={"network": {"lan": ["192.168.1.0/24"]}},
    )
    lan = Subject(ip=ipaddress.ip_address("192.168.1.7"))
    vpn = Subject(ip=ipaddress.ip_address("10.8.0.3"))
    assert run(t, "https://n.example.com/", lan).rule_index == 0
    assert run(t, "https://n.example.com/", vpn).rule_index == 1
    no_ip = run(t, "https://n.example.com/", ANON)
    assert no_ip.rule_index is None and no_ip.uncertain


def test_query_operators() -> None:
    t = make_tester(
        {"domain": "q.example.com", "query": [[{"key": "secure", "value": "yes"}]],
         "policy": "two_factor"},
        {"domain": "q.example.com", "query": [[{"key": "debug", "operator": "present"}],
                                              [{"key": "t", "operator": "pattern", "value": "^a"}]],
         "policy": "deny"},
    )  # fmt: skip
    assert run(t, "https://q.example.com/?secure=yes").rule_index == 0
    assert run(t, "https://q.example.com/?debug").rule_index == 1
    assert run(t, "https://q.example.com/?t=abc").rule_index == 1
    assert run(t, "https://q.example.com/?t=b+a").rule_index is None  # '+' decodes to space
    assert run(t, "https://q.example.com/").rule_index is None


def test_relative_url_rejected() -> None:
    with pytest.raises(ValueError):
        RequestObject.from_url("/just/a/path")
