"""The managed access_control.yml as an ordered list of text blocks.

Why text blocks and not a re-dumped YAML tree: untouched rules must stay byte-identical
(comments, quoting, commented-out paths, blank lines) and a rule's explanatory comment must
travel with it when rules are reordered. So the file is cut into
  prefix | block 0 | block 1 | ... | suffix
and operations (move, delete, insert, replace) only shuffle or regenerate blocks. A block holds
the comment lines directly above its rule, the rule itself, and the blank lines after it.
Only a rule that is edited through the form is re-serialised (ruamel round-trip on that one
rule, so untouched keys of it keep their quoting and inline comments).

Same comment-ownership rules as scripts/split_config.py: a comment directly above a rule
(no blank line) whose text is not indented deeper than the rule's dash belongs to that rule.
"""

from __future__ import annotations

import io
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq
from ruamel.yaml.error import YAMLError

DEFAULT_POLICY_LINE = re.compile(r"^(\s*default_policy\s*:\s*)([^\s#]+)(.*)$")


class DocumentError(ValueError):
    """The file cannot be handled; message is safe to show."""


def _rt() -> YAML:
    yaml = YAML(typ="rt")
    yaml.preserve_quotes = True
    yaml.width = 4096
    return yaml


def _safe_load(text: str) -> Any:
    return YAML(typ="safe", pure=True).load(text)


def _is_comment(line: str) -> bool:
    return line.lstrip().startswith("#")


def _is_blank(line: str) -> bool:
    return not line.strip()


def _comment_text_col(line: str) -> int:
    """Indent of a comment's text if it were uncommented ('    # Foo' -> 4)."""
    idx = line.index("#")
    rest = line[idx + 1 :]
    if rest.startswith(" "):
        rest = rest[1:]
    return len(line[:idx] + rest) - len((line[:idx] + rest).lstrip(" "))


def _dash_col(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


@dataclass(frozen=True)
class RuleBlock:
    """Exact source lines of one rule: leading comments, the rule, trailing blank lines."""

    lines: tuple[str, ...]

    @property
    def rule_start(self) -> int:
        for i, line in enumerate(self.lines):
            if line.lstrip(" ").startswith("- "):
                return i
        raise DocumentError("rule block without a list item")

    @property
    def dash_col(self) -> int:
        return _dash_col(self.lines[self.rule_start])

    @property
    def note(self) -> str:
        """Comment lines directly above the rule, without the '#'."""
        out = []
        for line in self.lines[: self.rule_start]:
            if _is_comment(line):
                out.append(line.lstrip()[1:].removeprefix(" ").rstrip())
        return "\n".join(out)

    def _rule_lines(self) -> list[str]:
        end = len(self.lines)
        while end > self.rule_start + 1 and _is_blank(self.lines[end - 1]):
            end -= 1
        return list(self.lines[self.rule_start : end])

    def _dedented(self) -> str:
        col = self.dash_col
        return "\n".join(
            line[col:] if line[:col].strip() == "" else line for line in self._rule_lines()
        )

    def data(self) -> dict[str, Any]:
        try:
            parsed = _safe_load(self._dedented())
        except YAMLError:
            raise DocumentError("a rule is not valid YAML") from None
        if not isinstance(parsed, list) or len(parsed) != 1 or not isinstance(parsed[0], dict):
            raise DocumentError("a rule block does not hold exactly one mapping")
        return dict(parsed[0])

    def rule_yaml(self) -> str:
        """The rule as a YAML mapping (no leading dash), comments inside it included."""
        buf = io.StringIO()
        yaml = _rt()
        yaml.indent(mapping=2, sequence=4, offset=2)
        yaml.dump(self.node(), buf)
        return buf.getvalue().rstrip("\n")

    def node(self) -> CommentedMap:
        parsed = _rt().load(self._dedented())
        node = parsed[0]
        if not isinstance(node, CommentedMap):
            raise DocumentError("rule is not a mapping")
        return node

    @property
    def has_inner_comments(self) -> bool:
        """Comments inside the rule body (commented-out paths, inline notes)."""
        return any("#" in line for line in self._rule_lines())


def _normalise_style(dash_col: int, lines: Sequence[str]) -> list[str]:
    return [(" " * dash_col + line) if line.strip() else line for line in lines]


def dump_rule(node: CommentedMap, dash_col: int) -> list[str]:
    """Serialise one rule (ruamel round-trip) with its dash at `dash_col`."""
    yaml = _rt()
    yaml.indent(mapping=2, sequence=4, offset=2)
    buf = io.StringIO()
    yaml.dump({"r": [node]}, buf)
    lines = buf.getvalue().splitlines()[1:]  # drop "r:"; dash now sits at column 2
    shift = dash_col - 2
    out = []
    for line in lines:
        if not line.strip():
            out.append(line)
        elif shift >= 0:
            out.append(" " * shift + line)
        else:
            out.append(line[-shift:] if line[:-shift].strip() == "" else line)
    return out


@dataclass(frozen=True)
class RulesDocument:
    prefix: tuple[str, ...]
    blocks: tuple[RuleBlock, ...]
    suffix: tuple[str, ...]

    # ------------------------------------------------------------------ parse / render

    @classmethod
    def parse(cls, text: str) -> RulesDocument:
        try:
            data = _rt().load(text)
        except YAMLError:
            raise DocumentError("access_control.yml is not valid YAML") from None
        if not isinstance(data, CommentedMap) or "access_control" not in data:
            raise DocumentError("no top-level access_control section")
        access_control = data["access_control"]
        lines = text.splitlines()
        if not isinstance(access_control, CommentedMap):
            raise DocumentError("access_control is not a mapping")
        rules = access_control.get("rules")
        if rules is None or (isinstance(rules, list) and not rules):
            rules_key_line = (
                int(access_control.lc.key("rules")[0]) if "rules" in access_control else None
            )
            end = _access_control_end(data, access_control, len(lines))
            split_at = (rules_key_line + 1) if rules_key_line is not None else end
            return cls(tuple(lines[:split_at]), (), tuple(lines[split_at:]))
        if not isinstance(rules, CommentedSeq):
            raise DocumentError("access_control.rules is not a list")

        starts = [int(rules.lc.item(i)[0]) for i in range(len(rules))]
        dash_col = _dash_col(lines[starts[0]])
        floors = [int(access_control.lc.key("rules")[0]) + 1, *starts[:-1]]
        leads = [
            _leading_start(lines, start, dash_col, floor)
            for start, floor in zip(starts, floors, strict=True)
        ]
        end = _access_control_end(data, access_control, len(lines), after_key="rules")
        while end > starts[-1] + 1 and _is_blank(lines[end - 1]):
            end -= 1
        # trailing comments directly above the next key belong to that key
        blocks = []
        for i, lead in enumerate(leads):
            stop = leads[i + 1] if i + 1 < len(leads) else end
            blocks.append(RuleBlock(tuple(lines[lead:stop])))
        return cls(tuple(lines[: leads[0]]), tuple(blocks), tuple(lines[end:]))

    def render(self) -> str:
        out = [*self.prefix]
        for block in self.blocks:
            out.extend(block.lines)
        out.extend(self.suffix)
        return "\n".join(out) + "\n"

    # ------------------------------------------------------------------ read

    def rules(self) -> list[dict[str, Any]]:
        return [b.data() for b in self.blocks]

    def default_policy(self) -> str:
        for line in self.prefix:
            m = DEFAULT_POLICY_LINE.match(line)
            if m:
                return m.group(2).strip("'\"")
        return "deny"

    def effective(self) -> dict[str, Any]:
        """Parsed access_control block, for the tester and the linter."""
        return {"access_control": {"default_policy": self.default_policy(), "rules": self.rules()}}

    # ------------------------------------------------------------------ edit (all return new docs)

    def with_default_policy(self, policy: str) -> RulesDocument:
        prefix = list(self.prefix)
        for i, line in enumerate(prefix):
            m = DEFAULT_POLICY_LINE.match(line)
            if m:
                prefix[i] = f"{m.group(1)}{policy}{m.group(3)}"
                return replace(self, prefix=tuple(prefix))
        raise DocumentError("default_policy line not found")

    def move(self, src: int, dst: int) -> RulesDocument:
        blocks = list(self.blocks)
        if not (0 <= src < len(blocks) and 0 <= dst < len(blocks)):
            raise DocumentError("rule index out of range")
        blocks.insert(dst, blocks.pop(src))
        return replace(self, blocks=tuple(blocks))

    def delete(self, index: int) -> RulesDocument:
        self._check(index)
        return replace(self, blocks=tuple(b for i, b in enumerate(self.blocks) if i != index))

    def insert(self, index: int, node: CommentedMap, note: str = "") -> RulesDocument:
        index = max(0, min(index, len(self.blocks)))
        dash = self.blocks[0].dash_col if self.blocks else _default_dash(self.prefix)
        block = _new_block(node, dash, note)
        blocks = list(self.blocks)
        blocks.insert(index, block)
        return replace(self, blocks=tuple(blocks))

    def replace_rule(
        self, index: int, node: CommentedMap, note: str | None = None
    ) -> RulesDocument:
        self._check(index)
        old = self.blocks[index]
        dash = old.dash_col
        lead = old.lines[: old.rule_start]
        if note is not None:
            lead = tuple(_note_lines(note, dash))
        trailing = []
        end = len(old.lines)
        while end > old.rule_start + 1 and _is_blank(old.lines[end - 1]):
            end -= 1
        trailing = list(old.lines[end:])
        new = RuleBlock((*lead, *dump_rule(node, dash), *trailing))
        blocks = list(self.blocks)
        blocks[index] = new
        return replace(self, blocks=tuple(blocks))

    def _check(self, index: int) -> None:
        if not 0 <= index < len(self.blocks):
            raise DocumentError("rule index out of range")


# --------------------------------------------------------------------------- helpers


def _note_lines(note: str, dash: int) -> list[str]:
    return [" " * dash + ("# " + n if n else "#") for n in note.splitlines()]


def _new_block(node: CommentedMap, dash: int, note: str) -> RuleBlock:
    return RuleBlock((*_note_lines(note, dash), *dump_rule(node, dash), ""))


def _default_dash(prefix: Sequence[str]) -> int:
    for line in reversed(prefix):
        m = re.match(r"^(\s*)rules\s*:", line)
        if m:
            return len(m.group(1)) + 2
    return 4


def _leading_start(lines: Sequence[str], rule_line: int, dash: int, floor: int) -> int:
    """First line of the comment run directly above a rule that belongs to it."""
    start = rule_line
    while (
        start > floor
        and _is_comment(lines[start - 1])
        and _comment_text_col(lines[start - 1]) <= dash
    ):
        start -= 1
    return start


def _access_control_end(
    data: CommentedMap, access_control: CommentedMap, total: int, after_key: str | None = None
) -> int:
    """First line after the rules: next access_control key, else next top-level key, else EOF."""
    if after_key is not None:
        keys = list(access_control.keys())
        for later in keys[keys.index(after_key) + 1 :]:
            return int(access_control.lc.key(later)[0])
    top = list(data.keys())
    for later in top[top.index("access_control") + 1 :]:
        return int(data.lc.key(later)[0])
    return total


def mapping_to_node(values: Mapping[str, Any]) -> CommentedMap:
    node = CommentedMap()
    for key, value in values.items():
        node[key] = value
    return node
