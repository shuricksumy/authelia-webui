"""Rule lint (SPEC §4): blocking errors and non-blocking warnings.

Everything that needs a judgement about regex containment is deliberately conservative: a
warning is only raised when it can be *proven* (equal pattern strings, literal paths checked
against the real tester), never guessed.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from app.rules.tester import (
    POLICIES,
    RequestObject,
    RuleTester,
    Subject,
    as_list,
    normalise_subjects,
)

SUBJECT_PREFIXES = ("user:", "group:", "oauth2:client:")
# RE2-only syntax Python's `re` rejects: cannot be verified here, Authelia's validator decides.
RE2_ONLY = re.compile(r"\\[pPQEz]|\[\[:\^?[a-z]+:\]\]|\(\?<[A-Za-z_]")
LITERAL_PATH = re.compile(r"^\^((?:[A-Za-z0-9_/%~-]|\\[./-])+)\$$")
UNIVERSAL_RESOURCE = {".*", "^.*$", "^.*", ".*$", "^/.*", "^/.*$"}


@dataclass(frozen=True)
class Issue:
    rule: int | None  # 0-based rule index, None for document-level issues
    severity: str  # "error" blocks saving/applying, "warning" does not
    code: str
    message: str


@dataclass(frozen=True)
class UsersInfo:
    usernames: frozenset[str]
    groups: frozenset[str]
    available: bool = True
    memberships: Mapping[str, tuple[str, ...]] = field(default_factory=dict)  # user -> groups


# --------------------------------------------------------------------------- regex checks


def re2_problem(pattern: str) -> str | None:
    """Reason a pattern is not valid Go RE2 syntax, or None. Scans outside character classes."""
    i, in_class = 0, False
    after_quantifier = lazy = False
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\":
            nxt = pattern[i + 1 : i + 2]
            if nxt.isdigit() and nxt != "0" and not in_class:
                return "back-references (\\1) are not supported by RE2"
            i += 2
            after_quantifier = lazy = False
            continue
        if in_class:
            in_class = ch != "]"
            i += 1
            continue
        if ch == "[":
            in_class = True
            i += 1
            if pattern[i : i + 1] == "^":
                i += 1
            if pattern[i : i + 1] == "]":
                i += 1  # a leading ']' is a literal
            after_quantifier = lazy = False
            continue
        if ch == "(" and pattern.startswith("(?", i):
            for bad, why in (
                ("(?=", "lookahead"), ("(?!", "negative lookahead"),
                ("(?<=", "lookbehind"), ("(?<!", "negative lookbehind"), ("(?>", "atomic groups"),
            ):  # fmt: skip
                if pattern.startswith(bad, i):
                    return f"{why} '{bad}' is not supported by RE2"
        quantifier = ch in "*+?"
        width = 1
        if ch == "{":
            end = pattern.find("}", i)
            if end != -1 and re.fullmatch(r"\{\d+(,\d*)?\}", pattern[i : end + 1]):
                quantifier, width = True, end - i + 1
        if quantifier:
            if after_quantifier and ch == "?" and not lazy:
                lazy = True  # '+?' / '*?': lazy modifier
            elif after_quantifier:
                return "nested repetition (e.g. 'a*+' or 'a**') is not supported by RE2"
            else:
                after_quantifier, lazy = True, False
        else:
            after_quantifier = lazy = False
        i += width
    return None


def regex_issue(pattern: str) -> tuple[str, str] | None:
    """(severity, message) for an unusable regex, else None."""
    problem = re2_problem(pattern)
    if problem:
        return "error", problem
    try:
        re.compile(pattern)
    except re.error:
        if RE2_ONLY.search(pattern):
            return "warning", "uses RE2-specific syntax this page cannot check; Authelia will"
        return "error", "is not a valid regular expression"
    return None


def literal_path(pattern: str) -> str | None:
    """'^/api/ping$' -> '/api/ping' when the pattern can only match that one path."""
    m = LITERAL_PATH.match(pattern)
    if not m:
        return None
    return re.sub(r"\\(.)", r"\1", m.group(1))


# --------------------------------------------------------------------------- coverage


def _domains(rule: Mapping[str, Any]) -> list[str]:
    return [str(d).lower() for d in as_list(rule.get("domain"))]


def _domain_covers(general: str, specific: str) -> bool:
    if general == specific:
        return True
    if general.startswith("*."):
        suffix = general[1:]
        host = specific[1:] if specific.startswith("*.") else specific
        return host.endswith(suffix) or (specific.startswith("*.") and host == suffix[1:])
    return False


def covers(earlier: Mapping[str, Any], later: Mapping[str, Any]) -> bool:
    """True only if every request matching `later` provably matches `earlier` too."""
    e_dom, l_dom = _domains(earlier), _domains(later)
    e_re, l_re = (
        list(as_list(earlier.get("domain_regex"))),
        list(as_list(later.get("domain_regex"))),
    )
    if e_dom or e_re:
        if e_re or l_re:
            if e_re != l_re or e_dom != l_dom:
                return False
        elif not l_dom or not all(any(_domain_covers(e, d) for e in e_dom) for d in l_dom):
            return False
    for key in ("resources", "methods", "networks"):
        e_vals = {str(v).upper() if key == "methods" else str(v) for v in as_list(earlier.get(key))}
        l_vals = {str(v).upper() if key == "methods" else str(v) for v in as_list(later.get(key))}
        if e_vals and (not l_vals or not l_vals <= e_vals):
            return False
    if earlier.get("query") and earlier.get("query") != later.get("query"):
        return False
    e_subj = {frozenset(g) for g in normalise_subjects(earlier.get("subject"))}
    l_subj = {frozenset(g) for g in normalise_subjects(later.get("subject"))}
    return not (e_subj and (not l_subj or not l_subj <= e_subj))


# --------------------------------------------------------------------------- lint


def lint(
    rules: Sequence[Mapping[str, Any]],
    *,
    users: UsersInfo | None = None,
    default_policy: str = "deny",
    known_networks: frozenset[str] = frozenset(),
) -> list[Issue]:
    issues: list[Issue] = []

    def add(rule: int | None, severity: str, code: str, message: str) -> None:
        issues.append(Issue(rule, severity, code, message))

    for i, rule in enumerate(rules):
        n = i + 1
        if not as_list(rule.get("domain")) and not as_list(rule.get("domain_regex")):
            add(i, "error", "no-domain", f"Rule #{n} needs a domain or domain regex.")
        if rule.get("policy") not in POLICIES:
            add(
                i, "error", "bad-policy", f"Rule #{n}: policy must be one of {', '.join(POLICIES)}."
            )
        for key in ("resources", "domain_regex"):
            for pattern in as_list(rule.get(key)):
                found = regex_issue(str(pattern))
                if found:
                    add(i, found[0], "regex", f"Rule #{n} {key} '{pattern}': {found[1]}.")
        subjects = normalise_subjects(rule.get("subject"))
        for term in (t for group in subjects for t in group):
            if not term.startswith(SUBJECT_PREFIXES):
                add(
                    i, "error", "bad-subject",
                    f"Rule #{n}: subject '{term}' must start with user:, group: or oauth2:client:.",
                )  # fmt: skip
            elif users and users.available:
                if term.startswith("user:") and term[5:] not in users.usernames:
                    add(i, "warning", "unknown-user",
                        f"Rule #{n}: user '{term[5:]}' is not in the users file.")  # fmt: skip
                if term.startswith("group:") and term[6:] not in users.groups:
                    add(i, "warning", "unknown-group",
                        f"Rule #{n}: no user is in group '{term[6:]}'.")  # fmt: skip
        policy = rule.get("policy")
        if policy == "bypass" and subjects:
            add(i, "error", "bypass-subject",
                f"Rule #{n}: bypass cannot be combined with a subject.")  # fmt: skip
        if policy == "bypass" and not as_list(rule.get("resources")):
            add(i, "warning", "bypass-open",
                f"Rule #{n} bypasses authentication for every path of its domain.")  # fmt: skip
        for net in as_list(rule.get("networks")):
            text = str(net)
            if text in known_networks:
                continue
            try:
                ipaddress.ip_network(text, strict=False)
            except ValueError:
                add(i, "error", "bad-network",
                    f"Rule #{n}: '{text}' is not a CIDR or a defined network name.")  # fmt: skip

    seen: dict[str, int] = {}
    for i, rule in enumerate(rules):
        key = repr(sorted((k, repr(v)) for k, v in rule.items()))
        if key in seen:
            add(i, "warning", "duplicate", f"Rule #{i + 1} is identical to rule #{seen[key] + 1}.")
        else:
            seen[key] = i
        for j in range(i):
            if covers(rules[j], rule) and seen.get(key) == i:
                message = f"Rule #{i + 1} never applies: rule #{j + 1} above already catches it."
                add(i, "warning", "shadowed", message)
                break
    issues.extend(_redundant_patterns(rules, default_policy))
    return issues


def _subjects_to_try(rules: Sequence[Mapping[str, Any]]) -> list[Subject]:
    groups: set[str] = set()
    users: set[str] = set()
    for rule in rules:
        for group in normalise_subjects(rule.get("subject")):
            for term in group:
                (groups if term.startswith("group:") else users).add(term.split(":", 1)[-1])
    out = [Subject(), Subject("probe", ()), Subject("probe", tuple(sorted(groups)))]
    out += [Subject(name, ()) for name in sorted(users)]
    return out


def _redundant_patterns(rules: Sequence[Mapping[str, Any]], default_policy: str) -> list[Issue]:
    """Literal paths in a rule that later rules already treat exactly the same way."""
    issues: list[Issue] = []
    probes = _subjects_to_try(rules)
    full = RuleTester({"access_control": {"default_policy": default_policy, "rules": list(rules)}})
    for j, rule in enumerate(rules):
        if any(rule.get(k) for k in ("subject", "methods", "networks", "query", "domain_regex")):
            continue
        domains = [d for d in _domains(rule) if "*" not in d and "{" not in d]
        patterns = [str(p) for p in as_list(rule.get("resources"))]
        if not domains or not patterns:
            continue
        without = RuleTester({"access_control": {
            "default_policy": default_policy,
            "rules": [r for k, r in enumerate(rules) if k != j]}})  # fmt: skip
        redundant = []
        for pattern in patterns:
            path = literal_path(pattern)
            if path is None:
                continue
            decided, same = False, True
            for domain in domains:
                for subject in probes:
                    obj = RequestObject.from_url(f"https://{domain}{path}", "GET")
                    a, b = full.evaluate(obj, subject), without.evaluate(obj, subject)
                    if a.rule_index != j:
                        continue  # another rule decides here: this rule's pattern is moot
                    decided = True
                    if (a.policy, a.login_required) != (b.policy, b.login_required):
                        same = False
            if decided and same:
                redundant.append(pattern)
        if redundant:
            issues.append(Issue(j, "warning", "redundant-paths",
                f"Rule #{j + 1}: these paths are already handled the same way by later rules: "
                + ", ".join(redundant) + "."))  # fmt: skip
    return issues


def blocking(issues: Sequence[Issue]) -> list[Issue]:
    return [i for i in issues if i.severity == "error"]


def counts(issues: Sequence[Issue]) -> Counter[int | None]:
    return Counter(i.rule for i in issues)
