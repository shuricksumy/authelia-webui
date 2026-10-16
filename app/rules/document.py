"""The managed access_control.yml as an ordered list of text blocks (see app/blocklist.py for
why text blocks). This module adds what is specific to rules: the default policy line and the
names the rest of the code uses (RuleBlock, replace_rule, rules())."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Any

from ruamel.yaml.comments import CommentedMap

from app.blocklist import (
    Block,
    BlockList,
    DocumentError,
    dump_item,
    locate,
    mapping_to_node,
)

__all__ = ["DocumentError", "RuleBlock", "RulesDocument", "dump_rule", "mapping_to_node"]

DEFAULT_POLICY_LINE = re.compile(r"^(\s*default_policy\s*:\s*)([^\s#]+)(.*)$")

RuleBlock = Block
dump_rule = dump_item


@dataclass(frozen=True)
class RulesDocument(BlockList):
    policy_line: int | None = None  # index in `prefix` of access_control.default_policy

    LIST_KEY = "rules"

    # ------------------------------------------------------------------ parse

    @classmethod
    def parse(cls, text: str) -> RulesDocument:
        loc, rules = locate(text, ("access_control", "rules"), "access_control.yml")
        access_control = loc.parent
        policy_line = (
            int(access_control.lc.key("default_policy")[0])
            if "default_policy" in access_control
            else None
        )
        prefix, blocks, suffix = cls.cut(loc, rules, "access_control.rules")
        if policy_line is not None and policy_line >= len(prefix):
            raise DocumentError("default_policy after the rules is not supported")
        return cls(prefix, blocks, suffix, policy_line)

    # ------------------------------------------------------------------ read

    def rules(self) -> list[dict[str, Any]]:
        return self.items()

    def default_policy(self) -> str:
        """Authelia's default when the key is absent is `deny`."""
        if self.policy_line is None:
            return "deny"
        m = DEFAULT_POLICY_LINE.match(self.prefix[self.policy_line])
        return m.group(2).strip("'\"") if m else "deny"

    def effective(self) -> dict[str, Any]:
        """Parsed access_control block, for the tester and the linter."""
        return {"access_control": {"default_policy": self.default_policy(), "rules": self.rules()}}

    # ------------------------------------------------------------------ edit (all return new docs)

    def with_default_policy(self, policy: str) -> RulesDocument:
        if self.policy_line is None:
            raise DocumentError("default_policy line not found")
        prefix = list(self.prefix)
        m = DEFAULT_POLICY_LINE.match(prefix[self.policy_line])
        if not m:  # e.g. a flow-style mapping on one line
            raise DocumentError("default_policy is not on its own line; edit it as YAML")
        prefix[self.policy_line] = f"{m.group(1)}{policy}{m.group(3)}"
        return replace(self, prefix=tuple(prefix))

    def replace_rule(
        self, index: int, node: CommentedMap, note: str | None = None
    ) -> RulesDocument:
        return self.replace_item(index, node, note)
