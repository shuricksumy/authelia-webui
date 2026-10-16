"""Access test suite (SPEC §16.2): saved "this request should get this policy" checks.

Stored in CONFIG_MANAGED_DIR/access_tests.yml (tracked in git). Before an apply every case is
evaluated with the rule tester on the live rules and on the draft; failures block the apply
unless the admin accepts them. After the restart, anonymous cases are probed against the real
Authelia (app/apply/probe.py) and compared with the tester's prediction for the new rules.
"""

from __future__ import annotations

import io
import ipaddress
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from app.rules.document import DocumentError
from app.rules.tester import POLICIES, MatchResult, RequestObject, RuleTester, Subject

TESTS_NAME = "access_tests.yml"
HEADER = "# Access tests: each request and the policy it must get (see the Access tests page).\n"

type IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


@dataclass(frozen=True)
class AccessCase:
    url: str
    expect: str
    method: str = "GET"
    user: str = ""
    groups: tuple[str, ...] = ()
    ip: str = ""
    name: str = ""

    @property
    def anonymous(self) -> bool:
        return not self.user

    def subject(self, default_ip: IPAddress | None) -> Subject:
        ip = ipaddress.ip_address(self.ip) if self.ip else default_ip
        return Subject(self.user, self.groups if self.user else (), ip)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self.name:
            out["name"] = self.name
        out["url"] = self.url
        if self.method != "GET":
            out["method"] = self.method
        if self.user:
            out["user"] = self.user
        if self.groups:
            out["groups"] = list(self.groups)
        if self.ip:
            out["ip"] = self.ip
        out["expect"] = self.expect
        return out


def case_from(data: Mapping[str, Any]) -> AccessCase:
    """Validate one case; raises DocumentError with a plain-language reason."""
    url = str(data.get("url", "")).strip()
    expect = str(data.get("expect", "")).strip()
    if expect not in POLICIES:
        raise DocumentError(f"expect must be one of {', '.join(POLICIES)}")
    try:
        RequestObject.from_url(url)
    except ValueError:
        raise DocumentError("the URL must be absolute, e.g. https://app.example.com/path") from None
    ip = str(data.get("ip") or "").strip()
    if ip:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise DocumentError("ip is not a valid IP address") from None
    groups = data.get("groups") or ()
    if isinstance(groups, str):
        groups = [g.strip() for g in groups.split(",") if g.strip()]
    return AccessCase(
        url=url,
        expect=expect,
        method=str(data.get("method") or "GET").upper(),
        user=str(data.get("user") or "").strip(),
        groups=tuple(str(g) for g in groups),
        ip=ip,
        name=str(data.get("name") or "").strip(),
    )


def parse(text: str) -> list[AccessCase]:
    if not text.strip():
        return []
    try:
        data = YAML(typ="safe", pure=True).load(text)
    except YAMLError:
        raise DocumentError("access_tests.yml is not valid YAML") from None
    if data is None:
        return []
    if not isinstance(data, list):
        raise DocumentError("access_tests.yml must be a list of test cases")
    cases = []
    for number, item in enumerate(data, start=1):
        if not isinstance(item, dict):
            raise DocumentError(f"test #{number} is not a mapping")
        try:
            cases.append(case_from(item))
        except DocumentError as exc:
            raise DocumentError(f"test #{number}: {exc}") from None
    return cases


def load(managed_dir: Path) -> list[AccessCase]:
    try:
        return parse((managed_dir / TESTS_NAME).read_text())
    except FileNotFoundError:
        return []


def render(cases: Sequence[AccessCase]) -> str:
    yaml = YAML(typ="rt")
    yaml.indent(mapping=2, sequence=4, offset=2)
    buf = io.StringIO()
    yaml.dump([c.to_dict() for c in cases], buf)
    return HEADER + buf.getvalue()


# --------------------------------------------------------------------------- evaluation


def outcome_class(result: MatchResult, anonymous: bool) -> str:
    """allow | login | deny - what Authelia's forward-auth answers (see the differential test)."""
    if result.policy == "bypass":
        return "allow"
    if result.policy == "deny":
        return "deny"
    return "login" if anonymous or result.policy == "two_factor" else "allow"


@dataclass(frozen=True)
class CaseResult:
    case: AccessCase
    live: MatchResult
    draft: MatchResult | None

    @property
    def effective(self) -> MatchResult:
        return self.draft or self.live

    @property
    def changed(self) -> bool:
        if self.draft is None:
            return False
        return (self.live.policy, self.live.login_required) != (
            self.draft.policy,
            self.draft.login_required,
        )

    @property
    def fails(self) -> bool:
        """The result the change would produce does not match `expect`."""
        return self.effective.policy != self.case.expect


def evaluate(
    cases: Sequence[AccessCase],
    live_config: Mapping[str, Any],
    draft_config: Mapping[str, Any] | None,
    default_ip: IPAddress | None,
) -> list[CaseResult]:
    live_tester = RuleTester(live_config)
    draft_tester = RuleTester(draft_config) if draft_config is not None else None
    out = []
    for case in cases:
        obj = RequestObject.from_url(case.url, case.method)
        subject = case.subject(default_ip)
        out.append(
            CaseResult(
                case,
                live_tester.evaluate(obj, subject),
                draft_tester.evaluate(obj, subject) if draft_tester else None,
            )
        )
    return out


def failing(results: Sequence[CaseResult]) -> list[CaseResult]:
    return [r for r in results if r.fails]
