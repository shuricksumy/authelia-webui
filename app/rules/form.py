"""Editor form <-> rule mapping (SPEC §4 data model).

`apply_form` mutates the rule's existing round-trip node in place when editing, so keys the
form does not touch keep their quoting and inline comments. Unknown keys live in `extra`
(raw YAML) and are preserved verbatim.
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap
from ruamel.yaml.error import YAMLError

from app.rules.tester import POLICIES, as_list, normalise_subjects

KNOWN_KEYS = (
    "domain",
    "domain_regex",
    "resources",
    "subject",
    "methods",
    "networks",
    "query",
    "policy",
)
# Order used when a key has to be added: policy stays last, like in hand-written configs.
INSERT_BEFORE_POLICY = (
    "domain",
    "domain_regex",
    "resources",
    "subject",
    "methods",
    "networks",
    "query",
)


class FormError(ValueError):
    """User-correctable form problem; message is safe to show."""


@dataclass
class RuleForm:
    domain: list[str] = field(default_factory=list)
    domain_regex: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)  # empty = all paths
    subject: list[list[str]] = field(default_factory=list)  # empty = anyone
    methods: list[str] = field(default_factory=list)
    networks: list[str] = field(default_factory=list)
    query_yaml: str = ""
    extra_yaml: str = ""  # unknown keys as a YAML mapping
    policy: str = "two_factor"
    note: str = ""

    @classmethod
    def from_data(cls, data: dict[str, Any], note: str = "") -> RuleForm:
        extra = {k: v for k, v in data.items() if k not in KNOWN_KEYS}
        return cls(
            domain=[str(d) for d in as_list(data.get("domain"))],
            domain_regex=[str(d) for d in as_list(data.get("domain_regex"))],
            resources=[str(r) for r in as_list(data.get("resources"))],
            subject=normalise_subjects(data.get("subject")),
            methods=[str(m) for m in as_list(data.get("methods"))],
            networks=[str(n) for n in as_list(data.get("networks"))],
            query_yaml=_dump(data["query"]) if data.get("query") else "",
            extra_yaml=_dump(extra) if extra else "",
            policy=str(data.get("policy", "")),
            note=note,
        )

    def validate(self) -> list[str]:
        problems = []
        if not self.domain and not self.domain_regex:
            problems.append("Add at least one domain (or domain regex).")
        if self.policy not in POLICIES:
            problems.append(f"Policy must be one of: {', '.join(POLICIES)}.")
        for label, text in (("Query", self.query_yaml), ("Extra keys", self.extra_yaml)):
            try:
                _load(text)
            except FormError as exc:
                problems.append(f"{label}: {exc}")
        extra = _safe_extra(self.extra_yaml)
        if isinstance(extra, str):
            problems.append(extra)
        return problems


def _yaml() -> YAML:
    yaml = YAML(typ="rt")
    yaml.preserve_quotes = True
    yaml.indent(mapping=2, sequence=4, offset=2)
    return yaml


def _dump(value: Any) -> str:
    buf = io.StringIO()
    _yaml().dump(value, buf)
    return buf.getvalue().rstrip("\n")


def _load(text: str) -> Any:
    if not text.strip():
        return None
    try:
        return _yaml().load(text)
    except YAMLError:
        raise FormError("not valid YAML") from None


def _safe_extra(text: str) -> dict[str, Any] | str:
    try:
        value = _load(text)
    except FormError as exc:
        return str(exc)
    if value is None:
        return {}
    if not isinstance(value, dict):
        return "Extra keys must be a YAML mapping (key: value)."
    clash = [k for k in value if k in KNOWN_KEYS]
    if clash:
        return f"Extra keys must not repeat form fields ({', '.join(map(str, clash))})."
    return dict(value)


def _set_list(node: CommentedMap, key: str, values: list[Any]) -> None:
    if not values:
        node.pop(key, None)
        return
    new: Any = values[0] if len(values) == 1 and key == "domain" else list(values)
    if key in node:
        if [str(v) for v in as_list(node[key])] == values:
            return  # same meaning: keep the original node (quoting, comments, scalar vs list)
        node[key] = new
    else:
        _insert(node, key, new)


def _plain(value: Any) -> Any:
    if isinstance(value, list):
        return [_plain(v) for v in value]
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    return value


def _insert(node: CommentedMap, key: str, value: Any) -> None:
    keys = list(node.keys())
    if "policy" in keys:
        node.insert(keys.index("policy"), key, value)
    else:
        node[key] = value


def apply_form(form: RuleForm, node: CommentedMap | None = None) -> CommentedMap:
    problems = form.validate()
    if problems:
        raise FormError(" ".join(problems))
    node = node if node is not None else CommentedMap()
    _set_list(node, "domain", form.domain)
    _set_list(node, "domain_regex", form.domain_regex)
    _set_list(node, "resources", form.resources)
    subject = _subject_value(form.subject)
    if not subject:
        node.pop("subject", None)
    elif "subject" not in node:
        _insert(node, "subject", subject)
    elif normalise_subjects(node["subject"]) != subject:
        node["subject"] = subject
    _set_list(node, "methods", form.methods)
    _set_list(node, "networks", form.networks)
    query = _load(form.query_yaml)
    if query:
        if "query" in node:
            if _plain(node["query"]) != _plain(query):
                node["query"] = query
        else:
            _insert(node, "query", query)
    else:
        node.pop("query", None)
    # unknown keys: replace the set with what the raw tab holds
    extra = _safe_extra(form.extra_yaml)
    if isinstance(extra, str):  # validate() already rejected this; keeps the type checker honest
        raise FormError(extra)
    for key in [k for k in node if k not in KNOWN_KEYS and k not in extra]:
        del node[key]
    for key, value in extra.items():
        if key not in node or _plain(node[key]) != _plain(value):
            node[key] = value
    if node.get("policy") != form.policy:
        node["policy"] = form.policy  # existing key keeps its position; a new one goes last
    return node


def _subject_value(groups: list[list[str]]) -> list[Any]:
    """Drop blanks; the result is the OR-of-AND list Authelia expects."""
    cleaned = [[t.strip() for t in g if t.strip()] for g in groups]
    return [g for g in cleaned if g]
