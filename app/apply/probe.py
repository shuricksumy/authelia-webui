"""Ask the real Authelia how it treats anonymous test requests after a restart (SPEC §16.2).

Compared with the rule tester's prediction for the rules that were just applied: a mismatch means
Authelia does not behave as previewed (config not loaded, or the preview is wrong), and the
apply is rolled back like an unhealthy restart.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

from app.rules.access_tests import AccessCase, IPAddress, outcome_class
from app.rules.tester import RequestObject, RuleTester

# Status of /api/authz/forward-auth -> outcome class (measured, see the differential test).
STATUS_CLASS = {200: "allow", 302: "login", 303: "login", 401: "login", 403: "deny"}


@dataclass(frozen=True)
class ProbeResult:
    case: AccessCase
    expected: str  # tester prediction for the new rules
    actual: str  # allow | login | deny | untestable
    detail: str = ""

    @property
    def mismatch(self) -> bool:
        return self.actual != "untestable" and self.actual != self.expected


def forward_auth(authelia_url: str, case: AccessCase, client_ip: str) -> tuple[str, str]:
    parts = urlsplit(case.url)
    headers = {
        "X-Forwarded-Method": case.method,
        "X-Forwarded-Proto": parts.scheme or "https",
        "X-Forwarded-Host": parts.netloc,
        "X-Forwarded-URI": (parts.path or "/") + (f"?{parts.query}" if parts.query else ""),
        "X-Forwarded-For": client_ip,
    }
    try:
        status = httpx.get(
            f"{authelia_url.rstrip('/')}/api/authz/forward-auth", headers=headers, timeout=5
        ).status_code
    except httpx.HTTPError as exc:
        return "untestable", f"Authelia could not be asked ({type(exc).__name__})"
    if status == 400:
        return "untestable", "host is outside Authelia's session cookie domains"
    if status not in STATUS_CLASS:
        return "untestable", f"unexpected HTTP {status}"
    return STATUS_CLASS[status], ""


Prober = Callable[[str, AccessCase, str], tuple[str, str]]


def verify(
    cases: Sequence[AccessCase],
    new_config: Mapping[str, Any],
    authelia_url: str,
    default_ip: IPAddress | None,
    prober: Prober = forward_auth,
) -> list[ProbeResult]:
    """Probe every anonymous case; returns all results (check `.mismatch`)."""
    tester = RuleTester(new_config)
    out = []
    for case in cases:
        if not case.anonymous:
            continue  # only anonymous requests can be probed without a login
        subject = case.subject(default_ip)
        predicted = outcome_class(
            tester.evaluate(RequestObject.from_url(case.url, case.method), subject), True
        )
        client_ip = str(subject.ip) if subject.ip else "127.0.0.1"
        actual, detail = prober(authelia_url, case, client_ip)
        out.append(ProbeResult(case, predicted, actual, detail))
    return out
