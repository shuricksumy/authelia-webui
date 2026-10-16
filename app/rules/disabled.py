"""Disabled rules (SPEC §16.1): rules switched off in the configurator, never passed to Authelia.

Stored in CONFIG_MANAGED_DIR/disabled_rules.yml. Each entry keeps the rule's exact text block
(its note, inner comments and quoting) plus the position it had, so disabling and re-enabling
is byte-identical. Entries written by the migration script (`{position, rule}` without `yaml`)
are still read: their block is rendered from the rule mapping.
"""

from __future__ import annotations

import io
from dataclasses import dataclass, replace
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError
from ruamel.yaml.scalarstring import LiteralScalarString

from app.rules.document import DocumentError, RuleBlock, dump_rule, mapping_to_node

DISABLED_NAME = "disabled_rules.yml"
HEADER = "# Rules disabled in the configurator; never passed to Authelia.\n"
DEFAULT_DASH = 4


@dataclass(frozen=True)
class DisabledEntry:
    position: int  # index the rule had among the live rules when it was disabled
    lines: tuple[str, ...]  # exact block lines, dash at DEFAULT_DASH or as written

    @property
    def block(self) -> RuleBlock:
        return RuleBlock(self.lines)

    def data(self) -> dict[str, Any]:
        return self.block.data()


def _check_entry(entry: DisabledEntry) -> None:
    """An entry is pasted back into access_control.yml verbatim, so it must be exactly one rule:
    only comments or blank lines above it, nothing outdented inside or after it."""
    block = entry.block
    start = block.rule_start
    if any(line.strip() and not line.lstrip().startswith("#") for line in entry.lines[:start]):
        raise DocumentError("disabled_rules.yml: an entry has text above its rule")
    for line in entry.lines[start + 1 :]:
        outdented = len(line) - len(line.lstrip(" ")) <= block.dash_col
        if line.strip() and outdented and not line.lstrip().startswith("#"):
            raise DocumentError("disabled_rules.yml: an entry holds more than one rule")
    block.data()  # must parse as exactly one rule mapping


@dataclass(frozen=True)
class DisabledRules:
    entries: tuple[DisabledEntry, ...] = ()

    @classmethod
    def parse(cls, text: str) -> DisabledRules:
        if not text.strip():
            return cls()
        try:
            data = YAML(typ="safe", pure=True).load(text)
        except YAMLError:
            raise DocumentError("disabled_rules.yml is not valid YAML") from None
        items = (data or {}).get("disabled_rules") if isinstance(data, dict) else None
        if items is None:
            return cls()
        if not isinstance(items, list):
            raise DocumentError("disabled_rules.yml: disabled_rules is not a list")
        entries = []
        for item in items:
            if not isinstance(item, dict):
                raise DocumentError("disabled_rules.yml: an entry is not a mapping")
            position = int(item.get("position", 0))
            if isinstance(item.get("yaml"), str):
                lines = tuple(str(item["yaml"]).rstrip("\n").split("\n"))
            elif isinstance(item.get("rule"), dict):  # migration-script format
                lines = (*dump_rule(mapping_to_node(item["rule"]), DEFAULT_DASH), "")
            else:
                raise DocumentError("disabled_rules.yml: an entry has neither yaml nor rule")
            entry = DisabledEntry(max(0, position), lines)
            _check_entry(entry)
            entries.append(entry)
        return cls(tuple(entries))

    def render(self) -> str:
        """ "" when empty, so an untouched missing file stays missing."""
        if not self.entries:
            return ""
        yaml = YAML(typ="rt")
        yaml.indent(mapping=2, sequence=4, offset=2)
        yaml.width = 4096
        buf = io.StringIO()
        yaml.dump(
            {"disabled_rules": [
                {"position": e.position, "yaml": LiteralScalarString("\n".join(e.lines) + "\n")}
                for e in self.entries
            ]},
            buf,
        )  # fmt: skip
        return HEADER + buf.getvalue()

    def add(self, position: int, block: RuleBlock) -> DisabledRules:
        lines = list(block.lines)
        while lines and not lines[-1].strip():
            lines.pop()  # blank separators are re-added when the rule is enabled again
        return replace(self, entries=(*self.entries, DisabledEntry(position, tuple(lines))))

    def remove(self, index: int) -> tuple[DisabledRules, DisabledEntry]:
        if not 0 <= index < len(self.entries):
            raise DocumentError("disabled rule index out of range")
        entry = self.entries[index]
        rest = tuple(e for i, e in enumerate(self.entries) if i != index)
        return replace(self, entries=rest), entry
