"""Preview which access_control rule applies to a request (SPEC §4 "Rule tester").

A port of Authelia v4.39.x internal/authorization (authorizer.go, access_control_rule.go,
access_control_domain.go, utils.URLPathFullClean). Differences from Authelia are covered by
tests/integration/test_tester_vs_authelia.py, which compares this module with the real
forward-auth endpoint. Keep the two in sync when Authelia changes.

Semantics that are easy to get wrong:
- first rule whose criteria all match wins, else default_policy;
- an anonymous request matches *any* subject criterion, so the first rule matching on
  everything else decides, and if it has subjects the result is "login required";
- `*.example.com` is a suffix match on ".example.com" (any depth, never the apex);
- resources are searched (not full-matched) in the cleaned path plus "?query".
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote, unquote_plus, urlsplit

POLICIES = ("bypass", "one_factor", "two_factor", "deny")

type IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
type Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass(frozen=True)
class Subject:
    username: str = ""
    groups: tuple[str, ...] = ()
    ip: IPAddress | None = None

    @property
    def anonymous(self) -> bool:
        return not self.username and not self.groups


@dataclass(frozen=True)
class RequestObject:
    host: str
    path: str  # URLPathFullClean form: cleaned path + optional "?" + raw query
    method: str
    query: Mapping[str, list[str]]

    @classmethod
    def from_url(cls, url: str, method: str = "GET") -> RequestObject:
        parts = urlsplit(url)
        if not parts.scheme or not parts.hostname:
            raise ValueError("URL must be absolute, e.g. https://app.example.com/path")
        query: dict[str, list[str]] = {}
        for pair in parts.query.split("&") if parts.query else []:
            key, _, value = pair.partition("=")
            # Go's url.Query() decodes '+' as space, like unquote_plus.
            query.setdefault(unquote_plus(key), []).append(unquote_plus(value))
        return cls(
            host=parts.hostname.lower(),
            path=url_path_full_clean(unquote(parts.path), parts.query),
            method=method.upper(),
            query=query,
        )


@dataclass(frozen=True)
class Skip:
    index: int
    reason: str


@dataclass(frozen=True)
class MatchResult:
    rule_index: int | None  # None: default_policy applied
    policy: str
    login_required: bool  # anonymous request hit a rule with subjects
    skipped: list[Skip] = field(default_factory=list)
    uncertain: list[str] = field(default_factory=list)  # criteria we cannot evaluate exactly


# --------------------------------------------------------------------------- go ports


def go_path_clean(path: str) -> str:
    """Port of Go's path.Clean."""
    if path == "":
        return "."
    rooted = path.startswith("/")
    out: list[str] = []
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if out and out[-1] != "..":
                out.pop()
            elif not rooted:
                out.append("..")
            continue
        out.append(part)
    cleaned = "/".join(out)
    if rooted:
        return "/" + cleaned
    return cleaned or "."


def url_path_full_clean(path: str, raw_query: str) -> str:
    """Port of Authelia utils.URLPathFullClean."""
    length_path = len(path)
    length_query = len(raw_query)
    append_slash = length_path > 1 and path[-1] == "/"
    if length_path == 1 and length_query == 0:
        return path
    if length_path == 1:
        return go_path_clean(path) + "?" + raw_query
    if length_query != 0 and append_slash:
        return go_path_clean(path) + "/?" + raw_query
    if length_query != 0:
        return go_path_clean(path) + "?" + raw_query
    if append_slash:
        return go_path_clean(path) + "/"
    return go_path_clean(path)


# --------------------------------------------------------------------------- normalisation


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, str | Mapping):
        return [value]
    return list(value)


def normalise_subjects(value: Any) -> list[list[str]]:
    """Outer list = OR, inner list = AND. Accepts str, [str], [[str]], mixed."""
    groups: list[list[str]] = []
    for entry in as_list(value):
        groups.append([str(s) for s in as_list(entry)])
    return groups


def named_networks(config: Mapping[str, Any]) -> dict[str, list[Network]]:
    """Named networks from definitions.network and the legacy access_control.networks."""
    out: dict[str, list[Network]] = {}
    definitions = (config.get("definitions") or {}).get("network") or {}
    for name, cidrs in definitions.items():
        out[str(name)] = [ipaddress.ip_network(str(c), strict=False) for c in as_list(cidrs)]
    for item in (config.get("access_control") or {}).get("networks") or []:
        out[str(item["name"])] = [
            ipaddress.ip_network(str(c), strict=False) for c in as_list(item.get("networks"))
        ]
    return out


# --------------------------------------------------------------------------- matching


class RuleTester:
    def __init__(self, config: Mapping[str, Any]) -> None:
        """`config` is the effective merged config (see app.config_merge)."""
        access_control = config.get("access_control") or {}
        self.default_policy = str(access_control.get("default_policy") or "deny")
        self.rules: list[Mapping[str, Any]] = list(access_control.get("rules") or [])
        self.networks = named_networks(config)

    def evaluate(self, obj: RequestObject, subject: Subject) -> MatchResult:
        skipped: list[Skip] = []
        uncertain: list[str] = []
        for index, rule in enumerate(self.rules):
            reason = self._mismatch(rule, obj, subject, uncertain, index)
            if reason is None:
                has_subjects = bool(normalise_subjects(rule.get("subject")))
                return MatchResult(
                    rule_index=index,
                    policy=str(rule.get("policy")),
                    login_required=has_subjects and subject.anonymous,
                    skipped=skipped,
                    uncertain=uncertain,
                )
            skipped.append(Skip(index, reason))
        return MatchResult(None, self.default_policy, False, skipped, uncertain)

    def _mismatch(
        self,
        rule: Mapping[str, Any],
        obj: RequestObject,
        subject: Subject,
        uncertain: list[str],
        index: int,
    ) -> str | None:
        """Reason the rule does not match, or None when it matches (Authelia's IsMatch order)."""
        if not self._domains(rule, obj, subject, uncertain, index):
            return "different domain"
        if not self._resources(rule, obj):
            return "path does not match"
        if not self._query(rule, obj, uncertain, index):
            return "query does not match"
        methods = [str(m).upper() for m in as_list(rule.get("methods"))]
        if methods and obj.method not in methods:
            return "method does not match"
        if not self._networks(rule, subject, uncertain, index):
            return "network does not match"
        if not self._subjects(rule, subject):
            return "subject does not match"
        return None

    def _domains(
        self,
        rule: Mapping[str, Any],
        obj: RequestObject,
        subject: Subject,
        uncertain: list[str],
        index: int,
    ) -> bool:
        domains = [str(d) for d in as_list(rule.get("domain"))]
        regexes = [str(d) for d in as_list(rule.get("domain_regex"))]
        if not domains and not regexes:
            return True
        for domain in domains:
            if "{user}" in domain or "{group}" in domain:
                uncertain.append(f"rule #{index + 1}: {{user}}/{{group}} domain placeholders")
                continue
            lowered = domain.lower()
            if lowered.startswith("*."):
                if obj.host.endswith(lowered[1:]):
                    return True
            elif obj.host == lowered:
                return True
        for pattern in regexes:
            if "?P<User>" in pattern or "?P<Group>" in pattern:
                uncertain.append(f"rule #{index + 1}: domain_regex with User/Group groups")
                continue
            if re.search(pattern, obj.host):
                return True
        return False

    @staticmethod
    def _resources(rule: Mapping[str, Any], obj: RequestObject) -> bool:
        resources = [str(r) for r in as_list(rule.get("resources"))]
        return not resources or any(re.search(r, obj.path) for r in resources)

    @staticmethod
    def _query(
        rule: Mapping[str, Any], obj: RequestObject, uncertain: list[str], index: int
    ) -> bool:
        """query: OR of AND groups of {key, value, operator}."""
        groups = as_list(rule.get("query"))
        if not groups:
            return True
        for group in groups:
            if all(_query_match(cond, obj, uncertain, index) for cond in as_list(group)):
                return True
        return False

    def _networks(
        self, rule: Mapping[str, Any], subject: Subject, uncertain: list[str], index: int
    ) -> bool:
        entries = [str(n) for n in as_list(rule.get("networks"))]
        if not entries:
            return True
        if subject.ip is None:
            uncertain.append(f"rule #{index + 1}: networks criterion but no client IP given")
            return False
        for entry in entries:
            nets = self.networks.get(entry)
            if nets is None:
                try:
                    nets = [ipaddress.ip_network(entry, strict=False)]
                except ValueError:
                    uncertain.append(f"rule #{index + 1}: unknown network name")
                    continue
            if any(subject.ip in net for net in nets):
                return True
        return False

    @staticmethod
    def _subjects(rule: Mapping[str, Any], subject: Subject) -> bool:
        groups = normalise_subjects(rule.get("subject"))
        if not groups or subject.anonymous:
            return True  # Authelia: anonymous matches any subject criterion
        return any(all(_subject_term(term, subject) for term in group) for group in groups)


def _subject_term(term: str, subject: Subject) -> bool:
    if term.startswith("user:"):
        return subject.username == term[len("user:") :]
    if term.startswith("group:"):
        return term[len("group:") :] in subject.groups
    return False  # oauth2:client:<id> never matches a user session


def _query_match(cond: Any, obj: RequestObject, uncertain: list[str], index: int) -> bool:
    if not isinstance(cond, Mapping):
        return False
    key = str(cond.get("key", ""))
    has_value = "value" in cond
    operator = str(cond.get("operator") or ("equal" if has_value else "present"))
    values = obj.query.get(key)
    value = str(cond.get("value", ""))
    match operator:
        case "present":
            return values is not None
        case "absent":
            return values is None
        case "equal":
            return values is not None and value in values
        case "not equal":
            return values is None or value not in values
        case "pattern":
            return values is not None and any(re.search(value, v) for v in values)
        case "not pattern":
            return values is None or not any(re.search(value, v) for v in values)
        case _:
            uncertain.append(f"rule #{index + 1}: query operator '{operator}'")
            return False
