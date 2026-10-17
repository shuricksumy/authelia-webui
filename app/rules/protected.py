"""Protected rules (SPEC §4, §8 layer 3): checked by behaviour, not by rule text.

Instead of recognising "the rule that looks like the configurator rule", we probe the rule
set with the rule tester and require the outcomes the deployment depends on:

1. Authelia portal discovery/JWKS/OIDC endpoints stay public (bypass), otherwise OIDC breaks.
2. The configurator host: an admin on an allowed network gets two_factor; anonymous requests
   from an allowed network are sent to log in (two_factor); non-admins, and anyone outside
   the allowed networks, are denied. The deny probes also run against a worst-case
   default_policy of `bypass`, which proves an explicit deny rule exists (SPEC §8).

Because it is behavioural, moving a protected rule below a wildcard catch-all, widening its
networks or dropping its deny twin is caught as well as deleting it. The rules that decide
these probes are reported as `locked` (shown read-only in the UI).

The configurator host is probed *pessimistically*: path, method and query limits of every
rule that is not `deny` are ignored, so a permissive rule that applies to some path only (for
example a bypass for `^/api/.*`) is treated as applying to every path. Probing a few sample
paths could never prove that no path is weakened; this does.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from app.rules.tester import MatchResult, RequestObject, RuleTester, Subject
from app.settings import Network, Settings

PORTAL_PROBES = (
    ("GET", "/.well-known/openid-configuration"),
    ("GET", "/jwks.json"),
    ("POST", "/api/oidc/token"),
    ("GET", "/api/oidc/authorization"),
)


def _probe_addresses() -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Outside-address probes spread over the whole IPv4 space (one per /5 block) so a widened
    network such as /1 is noticed, plus documentation addresses and one IPv6 address. Computed,
    not listed, because these are probes and must not look like real deployment addresses."""
    spread: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = [
        ipaddress.IPv4Address((octet << 24) | 0x00000063) for octet in range(1, 224, 8)
    ]
    spread += [ipaddress.ip_address(a) for a in ("192.0.2.99", "198.51.100.99", "203.0.113.99")]
    spread.append(ipaddress.ip_address("2001:db8::99"))
    return spread


@dataclass(frozen=True)
class ProtectedReport:
    violations: tuple[str, ...]
    locked: frozenset[int]

    @property
    def ok(self) -> bool:
        return not self.violations


def _inside(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, nets: Sequence[Network]) -> bool:
    return any(ip.version == n.version and ip in n for n in nets)


def _outside_ips(allowed: Sequence[Network]) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Addresses outside every allowed network, including the neighbours of each network."""
    candidates = _probe_addresses()
    for net in allowed:
        for neighbour in (int(net.network_address) - 1, int(net.broadcast_address) + 1):
            try:
                candidates.append(type(net.network_address)(neighbour))
            except ValueError:  # pragma: no cover - edge of the address space
                continue
    return [ip for ip in candidates if not _inside(ip, allowed)]


LIMITS = ("resources", "methods", "query")


def _pessimistic(config: Mapping[str, Any]) -> dict[str, Any]:
    """Every non-deny rule as if it applied to all paths, methods and queries."""
    access_control = dict(config.get("access_control") or {})
    access_control["rules"] = [
        rule if rule.get("policy") == "deny" else {k: v for k, v in rule.items() if k not in LIMITS}
        for rule in access_control.get("rules") or []
    ]
    return {**config, "access_control": access_control}


def check_protected(config: Mapping[str, Any], settings: Settings) -> ProtectedReport:
    """`config` = effective config with `access_control` (and `definitions` if any)."""
    allowed = settings.ALLOWED_CLIENT_CIDRS
    inside = next(allowed[0].hosts(), allowed[0].network_address)
    # With ALLOW_ANY_CLIENT_NETWORK there is no "outside": only identity (group + 2FA) is checked.
    outsiders = [] if settings.ALLOW_ANY_CLIENT_NETWORK else _outside_ips(allowed)
    violations: list[str] = []
    locked: set[int] = set()

    def ask(tester: RuleTester, host: str, subject: Subject, method: str = "GET") -> MatchResult:
        url = f"https://{host}/"
        return tester.evaluate(RequestObject.from_url(url, method), subject)

    def lock(result: MatchResult) -> None:
        if result.rule_index is not None:
            locked.add(result.rule_index)

    tester = RuleTester(config)
    pessimistic = _pessimistic(config)
    host_tester = RuleTester(pessimistic)
    worst = {**pessimistic, "access_control": {**pessimistic["access_control"],
                                               "default_policy": "bypass"}}  # fmt: skip
    worst_case = RuleTester(worst)

    for method, path in PORTAL_PROBES:
        obj = RequestObject.from_url(f"https://{settings.AUTH_DOMAIN}{path}", method)
        result = tester.evaluate(obj, Subject(ip=inside))
        lock(result)
        if result.policy != "bypass":
            violations.append(
                f"{settings.AUTH_DOMAIN}{path} must stay public (bypass); OIDC needs it."
            )

    host = settings.CONFIGURATOR_DOMAIN
    admin = Subject("admin-probe", (settings.ADMIN_GROUP,), inside)
    expectations = [
        ("an admin on an allowed network", host_tester, admin, "two_factor"),
        (
            "an anonymous visitor on an allowed network",
            host_tester,
            Subject(ip=inside),
            "two_factor",
        ),
        ("a non-admin user", worst_case, Subject("probe", ("no-group",), inside), "deny"),
    ]
    for ip in outsiders:
        expectations += [
            (f"an admin from outside the allowed networks ({ip})", worst_case,
             Subject("admin-probe", (settings.ADMIN_GROUP,), ip), "deny"),
            (f"an anonymous visitor from outside the allowed networks ({ip})", worst_case,
             Subject(ip=ip), "deny"),
        ]  # fmt: skip
    for label, engine, subject, expected in expectations:
        result = ask(engine, host, subject)
        lock(result)
        if result.policy != expected:
            violations.append(
                f"{host}: {label} must get '{expected}' but would get '{result.policy}'."
            )
    return ProtectedReport(tuple(violations), frozenset(locked))
