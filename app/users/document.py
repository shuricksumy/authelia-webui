"""The managed users file (Authelia file backend) as text blocks, one per user.

Same reasoning as app/blocklist.py: untouched users must stay byte-identical (indentation,
quoting, comments), and a ruamel round trip of the whole file does not guarantee that (it
re-indents lists). Inside a user, only the keys that change are rewritten; every edit is
re-parsed and compared with the intended result, so a file written in an unusual style is
refused rather than corrupted.

Password hashes live here, so nothing in this module ever returns them for display:
`users()` drops `password`, `has_password()` says whether one is set.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap
from ruamel.yaml.error import YAMLError

from app.blocklist import ODD_LINE_BREAKS, DocumentError, _is_blank, _is_comment

USERS_NAME = "users.yml"
DELETE = object()  # sentinel for set_fields: remove the key
KEY_LINE = re.compile(r"^(\s*)([^\s#:'\"][^:#]*?|'[^']*'|\"[^\"]*\")\s*:(\s|$)")
USERNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$")


def _safe_load(text: str) -> Any:
    return YAML(typ="safe", pure=True).load(text)


def _scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    text = str(value)
    if "\n" in text or "\r" in text:
        raise DocumentError("values cannot contain line breaks")
    return "'" + text.replace("'", "''") + "'"


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


@dataclass(frozen=True)
class UserBlock:
    name: str
    lines: tuple[str, ...]  # leading comments, the key line, its body, trailing blank lines


@dataclass(frozen=True)
class UsersDocument:
    prefix: tuple[str, ...]
    blocks: tuple[UserBlock, ...]
    suffix: tuple[str, ...]
    key_col: int = 4  # column of a username
    step: int = 4  # indentation of a user's keys relative to the username
    seq_offset: int = 4  # column of '- ' relative to its key

    # ------------------------------------------------------------------ parse / render

    @classmethod
    def parse(cls, text: str) -> UsersDocument:
        if ODD_LINE_BREAKS.search(text):
            raise DocumentError("the users file contains unusual line-break characters")
        try:
            data = YAML(typ="rt").load(text)
        except YAMLError:
            raise DocumentError("the users file is not valid YAML") from None
        if not isinstance(data, CommentedMap) or not isinstance(data.get("users"), CommentedMap):
            raise DocumentError("the users file has no 'users:' mapping")
        users: CommentedMap = data["users"]
        lines = text.splitlines()
        names = [str(k) for k in users]
        top = list(data.keys())
        after = top[top.index("users") + 1 :]
        end = int(data.lc.key(after[0])[0]) if after else len(lines)
        if not names:
            split = int(data.lc.key("users")[0]) + 1
            return cls(tuple(lines[:split]), (), tuple(lines[split:]))
        starts = [int(users.lc.key(n)[0]) for n in users]
        key_col = _indent(lines[starts[0]])
        floor = int(data.lc.key("users")[0]) + 1
        leads = []
        for i, start in enumerate(starts):
            lo = floor if i == 0 else starts[i - 1] + 1
            lead = start
            while (
                lead > lo and _is_comment(lines[lead - 1]) and _indent(lines[lead - 1]) <= key_col
            ):
                lead -= 1
            leads.append(lead)
        while end > starts[-1] + 1 and _is_blank(lines[end - 1]):
            end -= 1
        blocks = []
        for i, lead in enumerate(leads):
            stop = leads[i + 1] if i + 1 < len(leads) else end
            blocks.append(UserBlock(names[i], tuple(lines[lead:stop])))
        step, seq = _detect_style(lines, starts, key_col)
        return cls(tuple(lines[: leads[0]]), tuple(blocks), tuple(lines[end:]), key_col, step, seq)

    def render(self) -> str:
        out = [*self.prefix]
        for block in self.blocks:
            out.extend(block.lines)
        out.extend(self.suffix)
        return "\n".join(out) + "\n"

    # ------------------------------------------------------------------ read

    def names(self) -> list[str]:
        return [b.name for b in self.blocks]

    def _data(self, block: UserBlock) -> dict[str, Any]:
        body = "\n".join(
            line[self.key_col :] if line[: self.key_col].strip() == "" else line
            for line in block.lines
        )
        try:
            parsed = _safe_load(body)
        except YAMLError:
            raise DocumentError(f"user '{block.name}' is not valid YAML") from None
        if not isinstance(parsed, dict) or list(parsed) != [block.name]:
            raise DocumentError(f"user '{block.name}' could not be read on its own")
        value = parsed[block.name]
        return dict(value) if isinstance(value, dict) else {}

    def raw(self, name: str) -> dict[str, Any]:
        """Everything about a user, password hash included: for checks, never for display."""
        return self._data(self._block(name))

    def users(self) -> dict[str, dict[str, Any]]:
        """name -> fields without the password hash (safe to show)."""
        out = {}
        for block in self.blocks:
            data = self._data(block)
            data.pop("password", None)
            out[block.name] = data
        return out

    def has_password(self, name: str) -> bool:
        return bool(self._data(self._block(name)).get("password"))

    def _block(self, name: str) -> UserBlock:
        for block in self.blocks:
            if block.name == name:
                return block
        raise DocumentError(f"no user '{name}'")

    def _index(self, name: str) -> int:
        return self.names().index(self._block(name).name)

    # ------------------------------------------------------------------ edit (all return new docs)

    def set_fields(self, name: str, changes: dict[str, Any]) -> UsersDocument:
        """Change, add or (with DELETE) remove top-level keys of one user; other lines stay."""
        block = self._block(name)
        expected = self._data(block)
        lines = list(block.lines)
        body_start = next(i for i, ln in enumerate(lines) if not _is_comment(ln)) + 1
        child = self.key_col + self.step
        for key, value in changes.items():
            end = _body_end(lines, body_start)
            spans = _child_spans(lines, body_start, end, child)
            if value is DELETE:
                expected.pop(key, None)
                new_lines: list[str] = []
            else:
                expected[key] = value
                new_lines = self._emit(key, value, child)
            if key in spans:
                lo, hi = spans[key]
                lines[lo:hi] = new_lines
            else:
                lines[end:end] = new_lines
        new_block = UserBlock(name, tuple(lines))
        doc = self._with_block(self._index(name), new_block)
        if doc._data(new_block) != expected:
            raise DocumentError(f"user '{name}' is written in a way this tool cannot edit safely")
        return doc

    def add(self, name: str, fields: dict[str, Any]) -> UsersDocument:
        if not USERNAME.match(name):
            raise DocumentError("usernames may use letters, digits and . _ @ - (max 64)")
        if name in self.names():
            raise DocumentError(f"user '{name}' already exists")
        lines = [" " * self.key_col + f"{name}:"]
        for key, value in fields.items():
            lines += self._emit(key, value, self.key_col + self.step)
        blocks = list(self.blocks)
        if blocks and blocks[-1].lines and blocks[-1].lines[-1].strip():
            gap = any(_is_blank(ln) for b in blocks[:-1] for ln in b.lines[-1:])
            if gap:  # the file separates users with a blank line: keep doing so
                blocks[-1] = UserBlock(blocks[-1].name, (*blocks[-1].lines, ""))
        blocks.append(UserBlock(name, tuple(lines)))
        doc = replace(self, blocks=tuple(blocks))
        if doc._data(doc.blocks[-1]) != fields:
            raise DocumentError("the new user could not be written safely")
        return doc

    def delete(self, name: str) -> UsersDocument:
        index = self._index(name)
        return replace(self, blocks=tuple(b for i, b in enumerate(self.blocks) if i != index))

    def rename_group(self, old: str, new: str) -> UsersDocument:
        doc = self
        for name, data in self.users().items():
            groups = [str(g) for g in data.get("groups") or []]
            if old in groups:
                renamed = list(dict.fromkeys(new if g == old else g for g in groups))
                doc = doc.set_fields(name, {"groups": renamed})
        return doc

    def _with_block(self, index: int, block: UserBlock) -> UsersDocument:
        blocks = list(self.blocks)
        blocks[index] = block
        return replace(self, blocks=tuple(blocks))

    def _emit(self, key: str, value: Any, col: int) -> list[str]:
        pad = " " * col
        if isinstance(value, list):
            if not value:
                return [f"{pad}{key}: []"]
            dash = " " * (col + self.seq_offset)
            return [f"{pad}{key}:", *(f"{dash}- {_scalar(v)}" for v in value)]
        if isinstance(value, dict):
            out = [f"{pad}{key}:"]
            for k, v in value.items():
                out += self._emit(str(k), v, col + self.step)
            return out
        return [f"{pad}{key}: {_scalar(value)}"]


def _detect_style(lines: list[str], starts: list[int], key_col: int) -> tuple[int, int]:
    """(key step, sequence offset) as the file writes them; Authelia's examples use 2/2."""
    step = seq = 0
    for start in starts:
        for line in lines[start + 1 : start + 40]:
            if not line.strip() or _is_comment(line):
                continue
            col = _indent(line)
            if col <= key_col:
                break
            if not step and not line.lstrip().startswith("- "):
                step = col - key_col
            elif step and line.lstrip().startswith("- ") and not seq:
                seq = col - (key_col + step)
        if step and seq:
            break
    return step or 2, seq if seq >= 0 and step else 2


def _body_end(lines: list[str], start: int) -> int:
    end = len(lines)
    while end > start and _is_blank(lines[end - 1]):
        end -= 1
    return end


def _child_spans(lines: list[str], start: int, end: int, col: int) -> dict[str, tuple[int, int]]:
    """key -> [first line, line after its last line) for the user's top-level keys."""
    keys: list[tuple[str, int]] = []
    for i in range(start, end):
        line = lines[i]
        if _is_comment(line) or _is_blank(line) or _indent(line) != col:
            continue
        m = KEY_LINE.match(line)
        if m:
            keys.append((m.group(2).strip("'\""), i))
    spans = {}
    for n, (key, i) in enumerate(keys):
        stop = keys[n + 1][1] if n + 1 < len(keys) else end
        while stop > i + 1 and _is_blank(lines[stop - 1]):
            stop -= 1
        spans[key] = (i, stop)
    return spans
