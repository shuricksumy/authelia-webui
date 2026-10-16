from __future__ import annotations

from typing import Any

import pytest

from app.rules.document import RulesDocument
from app.rules.protected import check_protected
from tests.unit.test_security import settings

PORTAL = {
    "domain": "auth.example.com",
    "policy": "bypass",
    "resources": [r"^/\.well-known/openid-configuration$", r"^/jwks\.json$", "^/api/oidc/.*"],
}
ADMIN = {
    "domain": "authcfg.example.com",
    "networks": ["10.8.0.0/24"],
    "subject": "group:admin",
    "policy": "two_factor",
}
DENY = {"domain": "authcfg.example.com", "policy": "deny"}
CATCH_ALL = {"domain": "*.example.com", "subject": "group:admin", "policy": "two_factor"}
GOOD = [PORTAL, ADMIN, DENY, CATCH_ALL]


def cfg(rules: list[dict[str, Any]], default: str = "deny") -> dict[str, Any]:
    return {"access_control": {"default_policy": default, "rules": rules}}


def test_compliant_rules_pass_and_lock_the_deciding_rules() -> None:
    report = check_protected(cfg(GOOD), settings())
    assert report.ok, report.violations
    assert report.locked == {0, 1, 2}  # portal, admin rule, explicit deny; not the catch-all


@pytest.mark.parametrize(
    ("rules", "fragment"),
    [
        ([ADMIN, DENY, CATCH_ALL], "must stay public"),  # portal bypass deleted
        ([PORTAL, DENY, CATCH_ALL], "admin on an allowed network"),  # admin rule deleted
        ([PORTAL, ADMIN, CATCH_ALL], "non-admin user"),  # explicit deny deleted
        ([PORTAL, {**ADMIN, "policy": "one_factor"}, DENY], "must get 'two_factor'"),  # weakened
        ([PORTAL, {**ADMIN, "networks": ["0.0.0.0/1"]}, DENY], "outside the allowed networks"),
        ([PORTAL, {k: v for k, v in ADMIN.items() if k != "networks"}, DENY],
         "outside the allowed networks"),  # networks dropped
        ([PORTAL, {k: v for k, v in ADMIN.items() if k != "subject"}, DENY], "non-admin user"),
        ([PORTAL, CATCH_ALL, ADMIN, DENY], "outside the allowed networks"),  # catch-all above it
        ([PORTAL, {**ADMIN, "networks": ["10.8.0.0/16"]}, DENY], "outside the allowed networks"),
        ([PORTAL, {**ADMIN, "networks": ["10.8.0.0/24", "203.0.113.0/24"]}, DENY],
         "outside the allowed networks"),
    ],
)  # fmt: skip
def test_weakening_is_detected(rules: list[dict[str, Any]], fragment: str) -> None:
    report = check_protected(cfg(rules), settings())
    assert not report.ok and any(fragment in v for v in report.violations), report.violations


@pytest.mark.parametrize(
    "rule",
    [
        # Review finding: path-limited rules used to slip through because only "/" was probed.
        {"domain": "authcfg.example.com", "policy": "bypass", "resources": ["^/api/.*$"]},
        {"domain": "authcfg.example.com", "policy": "one_factor", "resources": ["^/review$"]},
        {"domain": "authcfg.example.com", "policy": "bypass", "methods": ["POST"]},
        {"domain": "authcfg.example.com", "policy": "bypass",
         "query": [[{"key": "debug", "operator": "present"}]]},
        {"domain": "*.example.com", "policy": "one_factor"},  # broad earlier rule
    ],
)  # fmt: skip
def test_permissive_rule_for_any_path_of_the_configurator_is_detected(
    rule: dict[str, Any],
) -> None:
    report = check_protected(cfg([PORTAL, rule, ADMIN, DENY]), settings())
    assert not report.ok, rule
    assert 1 in report.locked  # the offending rule is the one deciding the probe


def test_path_limited_deny_rules_are_fine() -> None:
    """Deny only ever makes things stricter, so its limits are kept as written."""
    extra_deny = {"domain": "authcfg.example.com", "policy": "deny", "resources": ["^/api/.*$"]}
    assert check_protected(cfg([PORTAL, extra_deny, ADMIN, DENY]), settings()).ok


def test_insecure_default_policy_without_explicit_deny_is_caught() -> None:
    """default_policy deny alone is not enough: the explicit deny must exist (SPEC §8)."""
    report = check_protected(cfg([PORTAL, ADMIN], default="deny"), settings())
    assert not report.ok


def test_works_on_a_parsed_document() -> None:
    text = "access_control:\n  default_policy: deny\n  rules:\n" + "".join(
        f"    - {{domain: {r['domain']}, policy: {r['policy']}}}\n" for r in [DENY]
    )
    assert not check_protected(RulesDocument.parse(text).effective(), settings()).ok
