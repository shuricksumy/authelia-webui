"""Ask the real Authelia how it treats anonymous test requests after a restart (SPEC §16.2).

Compared with the rule tester's prediction for the rules that were just applied: a mismatch means
Authelia does not behave as previewed (config not loaded, or the preview is wrong), and the
apply is rolled back like an unhealthy restart.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

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
# (authelia base url, portal host[:port]) -> None when fine, else a plain-language problem
Discovery = Callable[[str, str], str | None]


def portal_url(main_config: Path, auth_domain: str) -> str:
    """The portal URL as configured (session.cookies[].authelia_url for AUTH_DOMAIN), without a
    trailing slash. It is the OIDC issuer apps must use. https://AUTH_DOMAIN when not found."""
    try:
        data = YAML(typ="safe", pure=True).load(main_config.read_text())
    except (OSError, YAMLError):
        return f"https://{auth_domain}"
    session = data.get("session") if isinstance(data, dict) else None
    cookies = session.get("cookies") if isinstance(session, dict) else None
    for cookie in cookies if isinstance(cookies, list) else []:
        url = cookie.get("authelia_url") if isinstance(cookie, dict) else None
        if isinstance(url, str) and urlsplit(url).hostname == auth_domain:
            return url.rstrip("/")
    return f"https://{auth_domain}"


def portal_host(main_config: Path, auth_domain: str) -> str:
    """host[:port] of the portal. Authelia answers OIDC requests only for exactly that host."""
    return urlsplit(portal_url(main_config, auth_domain)).netloc or auth_domain


def oidc_discovery(authelia_url: str, host: str) -> str | None:
    """Fetch the OpenID Connect discovery document as a browser on the portal would see it."""
    headers = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": host}
    url = f"{authelia_url.rstrip('/')}/.well-known/openid-configuration"
    try:
        response = httpx.get(url, headers=headers, timeout=5)
    except httpx.HTTPError as exc:
        return f"discovery request failed ({type(exc).__name__})"
    if response.status_code != 200:
        return f"discovery answered HTTP {response.status_code}"
    try:
        issuer = response.json().get("issuer")
    except ValueError:
        return "discovery did not return JSON"
    return None if issuer else "discovery has no issuer"


def jwks_kids(authelia_url: str, host: str) -> list[str] | str:
    """The key ids Authelia publishes at /jwks.json (what apps verify tokens with), or a
    plain-language problem."""
    headers = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": host}
    try:
        response = httpx.get(f"{authelia_url.rstrip('/')}/jwks.json", headers=headers, timeout=5)
    except httpx.HTTPError as exc:
        return f"the key set request failed ({type(exc).__name__})"
    if response.status_code != 200:
        return f"the key set answered HTTP {response.status_code}"
    try:
        keys = response.json()["keys"]
        return [str(k["kid"]) for k in keys]
    except (ValueError, KeyError, TypeError):
        return "the key set is not in the expected format"


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
