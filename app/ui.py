"""View models and small helpers for the templates (no HTTP here)."""

from __future__ import annotations

import difflib
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from app.rules.document import RuleBlock, RulesDocument
from app.rules.lint import Issue
from app.rules.tester import MatchResult, as_list, normalise_subjects

POLICY_LABEL = {"bypass": "BYPASS", "one_factor": "1FA", "two_factor": "2FA", "deny": "DENY"}
AND_SPLIT = re.compile(r"\s+(?:and|\+)\s+", re.IGNORECASE)


def lines_of(text: str) -> list[str]:
    """One entry per non-empty line, stripped (textarea list editors)."""
    return [line.strip() for line in text.splitlines() if line.strip()]


def parse_subject_lines(text: str) -> list[list[str]]:
    """Each line is an OR alternative; ' and ' / ' + ' joins AND terms within it."""
    return [[t.strip() for t in AND_SPLIT.split(line) if t.strip()] for line in lines_of(text)]


def format_subject_lines(groups: Sequence[Sequence[str]]) -> str:
    return "\n".join(" and ".join(g) for g in groups)


def who_summary(subject: Any) -> str:
    groups = normalise_subjects(subject)
    if not groups:
        return "anyone"
    return "  or  ".join(" + ".join(g) for g in groups)


@dataclass
class RuleRow:
    index: int
    domains: list[str]
    resources: list[str]
    who: str
    policy: str
    note: str
    status: str  # "", "new", "edited", "moved"
    locked: bool
    issues: list[Issue] = field(default_factory=list)
    inner_comments: bool = False

    @property
    def number(self) -> int:
        return self.index + 1

    @property
    def policy_label(self) -> str:
        return POLICY_LABEL.get(self.policy, self.policy.upper() or "?")

    @property
    def warnings(self) -> list[Issue]:
        return [i for i in self.issues if i.severity == "warning"]

    @property
    def errors(self) -> list[Issue]:
        return [i for i in self.issues if i.severity == "error"]


def block_statuses(live: Sequence[RuleBlock], current: Sequence[RuleBlock]) -> list[str]:
    """Per current block: '' unchanged, 'moved', 'edited' or 'new' relative to the live file."""
    live_lines = [b.lines for b in live]
    cur_lines = [b.lines for b in current]
    status = [""] * len(current)
    known = set(live_lines)
    matcher = difflib.SequenceMatcher(None, live_lines, cur_lines, autojunk=False)
    for tag, _i1, _i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        for j in range(j1, j2):
            if tag in ("replace", "insert"):
                status[j] = "moved" if cur_lines[j] in known else (
                    "edited" if tag == "replace" else "new"
                )  # fmt: skip
    return status


def build_rows(
    doc: RulesDocument,
    live: RulesDocument,
    issues: Iterable[Issue],
    locked: frozenset[int],
) -> list[RuleRow]:
    by_rule: dict[int, list[Issue]] = {}
    for issue in issues:
        if issue.rule is not None:
            by_rule.setdefault(issue.rule, []).append(issue)
    statuses = block_statuses(live.blocks, doc.blocks)
    rows = []
    for i, block in enumerate(doc.blocks):
        data = block.data()
        domains = [str(d) for d in as_list(data.get("domain"))] or [
            f"regex: {d}" for d in as_list(data.get("domain_regex"))
        ]
        rows.append(
            RuleRow(
                index=i,
                domains=domains,
                resources=[str(r) for r in as_list(data.get("resources"))],
                who=who_summary(data.get("subject")),
                policy=str(data.get("policy", "")),
                note=block.note,
                status=statuses[i],
                locked=i in locked,
                issues=by_rule.get(i, []),
                inner_comments=block.has_inner_comments,
            )
        )
    return rows


def group_by_domain(rows: Sequence[RuleRow]) -> list[tuple[str, list[RuleRow]]]:
    groups: dict[str, list[RuleRow]] = {}
    for row in rows:
        groups.setdefault(row.domains[0] if row.domains else "(no domain)", []).append(row)
    return sorted(groups.items(), key=lambda item: item[0])


def filter_rows(rows: Sequence[RuleRow], query: str) -> list[RuleRow]:
    q = query.strip().lower()
    if not q:
        return list(rows)
    return [r for r in rows if q in " ".join([*r.domains, r.who, r.note, r.policy_label]).lower()]


def diff_lines(diff: str) -> list[tuple[str, str]]:
    """(css class, text) per diff line, so the template needs no inline styles."""
    out = []
    for line in diff.splitlines():
        if line.startswith(("+++", "---")):
            kind = "meta"
        elif line.startswith("@@"):
            kind = "hunk"
        elif line.startswith("+"):
            kind = "add"
        elif line.startswith("-"):
            kind = "del"
        else:
            kind = "ctx"
        out.append((kind, line))
    return out


def skipped_summary(result: MatchResult) -> list[str]:
    """'Rules #1-2 skipped: different domain' with consecutive equal reasons merged."""
    out: list[str] = []
    run_start = run_end = None
    run_reason = ""
    for skip in result.skipped:
        if run_reason == skip.reason and run_end is not None and skip.index == run_end + 1:
            run_end = skip.index
            continue
        if run_start is not None and run_end is not None:
            out.append(_span(run_start, run_end, run_reason))
        run_start = run_end = skip.index
        run_reason = skip.reason
    if run_start is not None and run_end is not None:
        out.append(_span(run_start, run_end, run_reason))
    return out


def _span(start: int, end: int, reason: str) -> str:
    label = f"#{start + 1}" if start == end else f"#{start + 1}-{end + 1}"
    return f"Rule{'' if start == end else 's'} {label} skipped: {reason}"
