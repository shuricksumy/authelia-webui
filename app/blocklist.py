"""A YAML list inside a larger file, handled as an ordered list of exact text blocks.

Why text blocks and not a re-dumped YAML tree: untouched items must stay byte-identical
(comments, quoting, commented-out lines, blank lines) and an item's explanatory comment must
travel with it when items are reordered. So the file is cut into
  prefix | block 0 | block 1 | ... | suffix
and operations (move, delete, insert, replace) only shuffle or regenerate blocks. A block holds
the comment lines directly above its item, the item itself, and the blank lines after it.
Only an item edited through a form is re-serialised (ruamel round-trip on that one item, so its
untouched keys keep their quoting and inline comments).

Comment ownership (same as scripts/split_config.py): a comment directly above an item (no blank
line) whose text is not indented deeper than the item's dash belongs to that item.

Used for access_control.rules (app/rules/document.py) and identity_providers.oidc.clients
(app/oidc/document.py).
"""

from __future__ import annotations

import io
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any, Self

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq
from ruamel.yaml.error import YAMLError

# Python's splitlines() and ruamel both break lines on these, but differently from "\n" when the
# file is written back; they have no business in a config file, so refuse them.
ODD_LINE_BREAKS = re.compile("[\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029]")


class DocumentError(ValueError):
    """The file cannot be handled; message is safe to show."""


def rt_yaml() -> YAML:
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
class Block:
    """Exact source lines of one list item: leading comments, the item, trailing blank lines."""

    lines: tuple[str, ...]

    @property
    def rule_start(self) -> int:
        for i, line in enumerate(self.lines):
            if line.lstrip(" ").startswith("- "):
                return i
        raise DocumentError("block without a list item")

    @property
    def dash_col(self) -> int:
        return _dash_col(self.lines[self.rule_start])

    @property
    def note(self) -> str:
        """Comment lines directly above the item, without the '#'."""
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
            raise DocumentError("an item is not valid YAML") from None
        if not isinstance(parsed, list) or len(parsed) != 1 or not isinstance(parsed[0], dict):
            raise DocumentError("a block does not hold exactly one mapping")
        return dict(parsed[0])

    def rule_yaml(self) -> str:
        """The item as a YAML mapping (no leading dash), comments inside it included."""
        buf = io.StringIO()
        yaml = rt_yaml()
        yaml.indent(mapping=2, sequence=4, offset=2)
        yaml.dump(self.node(), buf)
        return buf.getvalue().rstrip("\n")

    def node(self) -> CommentedMap:
        parsed = rt_yaml().load(self._dedented())
        node = parsed[0]
        if not isinstance(node, CommentedMap):
            raise DocumentError("item is not a mapping")
        return node

    @property
    def has_inner_comments(self) -> bool:
        """Comments inside the item body (commented-out paths, inline notes)."""
        return any("#" in line for line in self._rule_lines())


def dump_item(node: CommentedMap, dash_col: int) -> list[str]:
    """Serialise one item (ruamel round-trip) with its dash at `dash_col`."""
    yaml = rt_yaml()
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
class Located:
    """Where the list sits in a parsed file (before cutting it into blocks)."""

    data: CommentedMap
    chain: list[tuple[CommentedMap, str]]  # (mapping, key) from the top down to the list key
    lines: list[str]

    @property
    def parent(self) -> CommentedMap:
        return self.chain[-1][0]

    def end_after(self, level: int) -> int:
        """First line after chain[level]'s value: the next sibling key at that level or above."""
        for mapping, key in reversed(self.chain[: level + 1]):
            keys = list(mapping.keys())
            for later in keys[keys.index(key) + 1 :]:
                return int(mapping.lc.key(later)[0])
        return len(self.lines)


def locate(text: str, path: Sequence[str], name: str) -> tuple[Located, Any]:
    """Parse `text` and walk `path`. Returns where the list is and its value (None if absent).
    Every level but the last must be a mapping; `name` is the file name for messages."""
    if ODD_LINE_BREAKS.search(text):
        raise DocumentError(f"{name} contains unusual line-break characters")
    try:
        data = rt_yaml().load(text)
    except YAMLError:
        raise DocumentError(f"{name} is not valid YAML") from None
    if not isinstance(data, CommentedMap) or path[0] not in data:
        raise DocumentError(f"no top-level {path[0]} section")
    chain: list[tuple[CommentedMap, str]] = []
    node: Any = data
    for depth, key in enumerate(path):
        if not isinstance(node, CommentedMap):
            raise DocumentError(f"{'.'.join(path[:depth])} is not a mapping")
        chain.append((node, key))
        if key not in node:
            if depth < len(path) - 1:
                raise DocumentError(f"no {'.'.join(path[: depth + 1])} section")
            return Located(data, chain, text.splitlines()), None
        node = node[key]
    return Located(data, chain, text.splitlines()), node


@dataclass(frozen=True)
class BlockList:
    prefix: tuple[str, ...]
    blocks: tuple[Block, ...]
    suffix: tuple[str, ...]

    LIST_KEY = "items"  # the key that holds the list (for the default dash column)

    @classmethod
    def cut(
        cls, loc: Located, items: Any, dotted: str
    ) -> tuple[tuple[str, ...], tuple[Block, ...], tuple[str, ...]]:
        """(prefix, blocks, suffix) for the list `items` found by `locate`."""
        lines = loc.lines
        parent, key = loc.chain[-1]
        level = len(loc.chain) - 1
        if items is None or (isinstance(items, list) and not items):
            key_line = int(parent.lc.key(key)[0]) if key in parent else None
            split_at = (key_line + 1) if key_line is not None else loc.end_after(level - 1)
            return tuple(lines[:split_at]), (), tuple(lines[split_at:])
        if not isinstance(items, CommentedSeq):
            raise DocumentError(f"{dotted} is not a list")
        starts = [int(items.lc.item(i)[0]) for i in range(len(items))]
        dash_col = _dash_col(lines[starts[0]])
        floors = [int(parent.lc.key(key)[0]) + 1, *starts[:-1]]
        leads = [
            _leading_start(lines, start, dash_col, floor)
            for start, floor in zip(starts, floors, strict=True)
        ]
        end = loc.end_after(level)
        while end > starts[-1] + 1 and _is_blank(lines[end - 1]):
            end -= 1
        blocks = []
        for i, lead in enumerate(leads):
            stop = leads[i + 1] if i + 1 < len(leads) else end
            blocks.append(Block(tuple(lines[lead:stop])))
        return tuple(lines[: leads[0]]), tuple(blocks), tuple(lines[end:])

    def render(self) -> str:
        out = [*self.prefix]
        for block in self.blocks:
            out.extend(block.lines)
        out.extend(self.suffix)
        return "\n".join(out) + "\n"

    def items(self) -> list[dict[str, Any]]:
        return [b.data() for b in self.blocks]

    # ------------------------------------------------------------------ edit (all return new docs)

    def _default_dash(self) -> int:
        if self.blocks:
            return self.blocks[0].dash_col
        for line in reversed(self.prefix):
            m = re.match(rf"^(\s*){re.escape(self.LIST_KEY)}\s*:", line)
            if m:
                return len(m.group(1)) + 2
        return 4

    def move(self, src: int, dst: int) -> Self:
        blocks = list(self.blocks)
        if not (0 <= src < len(blocks) and 0 <= dst < len(blocks)):
            raise DocumentError("index out of range")
        blocks.insert(dst, blocks.pop(src))
        return replace(self, blocks=tuple(blocks))

    def delete(self, index: int) -> Self:
        self._check(index)
        return replace(self, blocks=tuple(b for i, b in enumerate(self.blocks) if i != index))

    def insert(self, index: int, node: CommentedMap, note: str = "") -> Self:
        index = max(0, min(index, len(self.blocks)))
        block = _new_block(node, self._default_dash(), note)
        blocks = list(self.blocks)
        blocks.insert(index, block)
        return replace(self, blocks=tuple(blocks))

    def insert_block(self, index: int, block: Block) -> Self:
        """Insert an existing block verbatim (re-enabling a disabled rule). If the document uses a
        different dash column, the item is re-serialised at that column (note kept)."""
        index = max(0, min(index, len(self.blocks)))
        dash = self._default_dash()
        if block.dash_col != dash:
            block = _new_block(block.node(), dash, block.note)
        lines = list(block.lines)
        while lines and not lines[-1].strip():
            lines.pop()
        blocks = list(self.blocks)
        suffix = self.suffix
        if index < len(blocks):
            lines.append("")  # a blank line separates it from the item that follows
        elif blocks and blocks[-1].lines and blocks[-1].lines[-1].strip():
            # Appended at the end: the separator goes after the previous last item. After a
            # save/re-parse that blank line sits at the start of the suffix: reuse it.
            if suffix and not suffix[0].strip():
                suffix = suffix[1:]
            blocks[-1] = Block((*blocks[-1].lines, ""))
        blocks.insert(index, Block(tuple(lines)))
        return replace(self, blocks=tuple(blocks), suffix=suffix)

    def replace_item(self, index: int, node: CommentedMap, note: str | None = None) -> Self:
        self._check(index)
        old = self.blocks[index]
        dash = old.dash_col
        lead = old.lines[: old.rule_start]
        if note is not None:
            lead = tuple(_note_lines(note, dash))
        end = len(old.lines)
        while end > old.rule_start + 1 and _is_blank(old.lines[end - 1]):
            end -= 1
        trailing = list(old.lines[end:])
        new = Block((*lead, *dump_item(node, dash), *trailing))
        blocks = list(self.blocks)
        blocks[index] = new
        return replace(self, blocks=tuple(blocks))

    def _check(self, index: int) -> None:
        if not 0 <= index < len(self.blocks):
            raise DocumentError("index out of range")


# --------------------------------------------------------------------------- helpers


def _note_lines(note: str, dash: int) -> list[str]:
    return [" " * dash + ("# " + n if n else "#") for n in note.splitlines()]


def _new_block(node: CommentedMap, dash: int, note: str) -> Block:
    return Block((*_note_lines(note, dash), *dump_item(node, dash), ""))


def _leading_start(lines: Sequence[str], rule_line: int, dash: int, floor: int) -> int:
    """First line of the comment run directly above an item that belongs to it."""
    start = rule_line
    while (
        start > floor
        and _is_comment(lines[start - 1])
        and _comment_text_col(lines[start - 1]) <= dash
    ):
        start -= 1
    return start


def mapping_to_node(values: Mapping[str, Any]) -> CommentedMap:
    node = CommentedMap()
    for key, value in values.items():
        node[key] = value
    return node
