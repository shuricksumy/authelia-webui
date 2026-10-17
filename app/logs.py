"""Read Authelia's log file (and the rotated copies next to it) for the log viewer.

Read-only and bounded: a log can be gigabytes, so nothing here ever loads a whole file.
- plain files are read backwards in chunks, newest line first, from an optional byte offset;
- `.gz` copies cannot be read backwards, so they are streamed once and only the last lines are
  kept (the same bound applies to every request);
- a request stops at its line/byte budget, at the start of the time window, or at its page size.

Every line is cut at `MAX_LINE`, scrubbed (password hashes, PEM blocks, tokens, cookies) and
only then parsed, so nothing secret reaches a template, a download or a log of ours.
Authelia writes JSON (`log.format: json`) or logrus text (`time="..." level=info msg="..."`);
anything else is shown raw with no level.
"""

from __future__ import annotations

import gzip
import json
import os
import re
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from app.authelia_cli import redact

MAX_LINE = 4096
CHUNK = 64 * 1024
GZIP_CAP = 512 * 1024 * 1024  # decompressed bytes read from one archive
LEVELS = ("error", "warn", "info", "debug")  # most to least severe
SHOWN_FIELDS = ("method", "path", "remote_ip", "error", "status_code")
WINDOWS = {"1h": timedelta(hours=1), "24h": timedelta(hours=24), "7d": timedelta(days=7)}

_LEVEL_NAMES = {
    "fatal": "error", "panic": "error", "error": "error", "err": "error",
    "warn": "warn", "warning": "warn",
    "info": "info",
    "debug": "debug", "trace": "debug",
}  # fmt: skip
_LOGFMT = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S*)')
_SCRUB = [
    (re.compile(r"\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]*"), "<jwt>"),
    (re.compile(r"(?i)\b(bearer|basic)\s+[\w.~+/=-]{8,}"), r"\1 <token>"),
    (
        re.compile(r"(?i)\b(authelia_session|session|cookie)(=|\":\s*\")[^\s;\"',]{6,}"),
        r"\1\2<hidden>",
    ),
    (
        re.compile(
            r"(?i)\b(client_secret|password|secret|token|code|refresh_token|access_token)"
            r"(=|\":\s*\"|:\s+)[^\s&\"',}]{4,}"
        ),
        r"\1\2<hidden>",
    ),
]  # fmt: skip
_NORMALISE = [
    (re.compile(r"'[^']*'"), "'…'"),
    (
        re.compile(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
        ),
        "<id>",
    ),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "<ip>"),
    (re.compile(r"\b\d{2,}\b"), "#"),
]
_ROTATED = r"(?:\.\d+|-\d{8,14})(?:\.gz)?"


def scrub(text: str) -> str:
    text = redact(text)
    for pattern, replacement in _SCRUB:
        text = pattern.sub(replacement, text)
    return text


@dataclass(frozen=True)
class Entry:
    time: datetime | None
    level: str  # one of LEVELS, or "" when unknown
    message: str
    fields: dict[str, str]
    raw: str  # scrubbed and cut, for display and download
    file: str = ""  # file name and byte offset of the line: the paging cursor
    offset: int = 0

    @property
    def cursor(self) -> str:
        return f"{self.file}:{self.offset}"

    @property
    def key(self) -> str:
        """What makes two problems 'the same': message and error with the variable bits blanked."""
        text = " | ".join(p for p in (self.message, self.fields.get("error", "")) if p)
        for pattern, replacement in _NORMALISE:
            text = pattern.sub(replacement, text)
        return text[:300]


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.strip())
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        try:
            return str(json.loads(value))
        except ValueError:
            return value[1:-1]
    return value


def _salvage(text: str) -> dict[str, Any] | None:
    found = {
        key: m.group(1)
        for key in ("level", "time", "msg")
        if (m := re.search(rf'"{key}"\s*:\s*"((?:[^"\\]|\\.)*)', text))
    }
    return found if "level" in found else None


def parse_line(line: str, file: str = "", offset: int = 0) -> Entry:
    """One log line -> Entry; never raises."""
    clean = scrub(line.strip()[:MAX_LINE])
    data: dict[str, Any] | None = None
    if clean.startswith("{"):
        try:
            loaded = json.loads(clean)
            data = loaded if isinstance(loaded, dict) else None
        except ValueError:
            data = _salvage(clean)  # cut at MAX_LINE: the start still names level and message
    elif "level=" in clean and "msg=" in clean:
        data = {k: _unquote(v) for k, v in _LOGFMT.findall(clean)}
    if data is None:
        return Entry(None, "", clean, {}, clean, file, offset)
    level = _LEVEL_NAMES.get(str(data.get("level", "")).lower(), "")
    message = str(data.get("msg", data.get("message", "")))
    fields = {k: str(data[k])[:300] for k in SHOWN_FIELDS if data.get(k) not in (None, "")}
    return Entry(_time(data.get("time")), level, message, fields, clean, file, offset)


# --------------------------------------------------------------------------- files


def log_files(path: Path) -> list[Path]:
    """The live file first, then the rotated copies, newest first. Missing files are skipped."""
    rotated = re.compile(re.escape(path.name) + _ROTATED + "$")
    found: list[tuple[float, Path]] = []
    try:
        for candidate in path.parent.iterdir():
            if rotated.match(candidate.name) and candidate.is_file():
                found.append((candidate.stat().st_mtime, candidate))
    except OSError:
        pass
    ordered = [p for _, p in sorted(found, key=lambda item: item[0], reverse=True)]
    return ([path] if path.is_file() else []) + ordered


def _mtime(path: Path) -> datetime | None:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, UTC)
    except OSError:
        return None


def _plain_backwards(path: Path, end: int | None) -> Iterator[tuple[int, str, int]]:
    """(offset of line, line, bytes read so far) from `end` backwards, whole lines only."""
    with path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        position = size = handle.tell()
        if end is not None:
            position = min(end, size)
        tail = b""
        end_of_tail = position
        read = 0
        while position > 0:
            step = min(CHUNK, position)
            position -= step
            handle.seek(position)
            block = handle.read(step) + tail
            read += step
            pieces = block.split(b"\n")
            tail = pieces[0]  # may be the end of a line that starts in an earlier chunk
            at = end_of_tail
            for piece in reversed(pieces[1:]):
                at -= len(piece) + 1
                if piece.strip():
                    yield at + 1, piece[: MAX_LINE * 2].decode("utf-8", "replace"), read
            end_of_tail = position + len(tail)
        if tail.strip():
            yield 0, tail[: MAX_LINE * 2].decode("utf-8", "replace"), read


def _gzip_backwards(path: Path, end: int | None, keep: int) -> Iterator[tuple[int, str, int]]:
    """Stream forward, keep only the last `keep` lines, hand them out newest first."""
    lines: deque[tuple[int, str]] = deque(maxlen=keep)
    offset = 0
    try:
        with gzip.open(path, "rb") as handle:
            for raw in handle:
                if (end is not None and offset >= end) or offset > GZIP_CAP:
                    break
                if raw.strip():
                    lines.append((offset, raw[: MAX_LINE * 2].decode("utf-8", "replace")))
                offset += len(raw)
    except (OSError, EOFError):
        pass  # a truncated archive still gives what was readable
    for at, text in reversed(lines):
        yield at, text, offset


# --------------------------------------------------------------------------- queries


@dataclass(frozen=True)
class Query:
    level: str = "warn"  # this level and everything more severe
    since: datetime | None = None
    text: str = ""
    ip: str = ""

    def matches(self, entry: Entry) -> bool:
        if entry.level:
            if LEVELS.index(entry.level) > LEVELS.index(self.level):
                return False
        elif self.level != "debug":
            return False  # lines without a level are only shown at "everything"
        if self.ip and self.ip not in entry.fields.get("remote_ip", ""):
            return False
        if self.text:
            return self.text.lower() in entry.raw.lower()
        return True


@dataclass(frozen=True)
class Budget:
    lines: int = 200_000  # lines parsed per request
    gzip_lines: int = 100_000  # lines kept per compressed file
    bytes: int = 64 * 1024 * 1024  # plain bytes read per request


@dataclass
class Page:
    entries: list[Entry] = field(default_factory=list)
    older: str | None = None  # cursor for the next page, when there may be more
    limited: bool = False  # stopped by the budget before the window start / the end of the logs
    files: int = 0  # how many log files exist


def _scan(path: Path, cursor: str, budget: Budget, spent: list[int],
          since: datetime | None = None) -> Iterator[Entry]:  # fmt: skip
    """Entries newest first across the live file and its rotated copies."""
    files = log_files(path)
    start_file, start_offset = "", None
    if cursor:
        name, _, number = cursor.rpartition(":")
        if number.isdigit() and name in {f.name for f in files}:
            start_file, start_offset = name, int(number)
    skipping = bool(start_file)
    for file in files:
        if skipping:
            if file.name != start_file:
                continue
            skipping = False
        if since and file != path and (stamp := _mtime(file)) and stamp < since:
            return  # a rotated copy last written before the window holds nothing in it
        end = start_offset if file.name == start_file else None
        source = (
            _gzip_backwards(file, end, budget.gzip_lines)
            if file.suffix == ".gz"
            else _plain_backwards(file, end)
        )
        last_read = 0
        try:
            for offset, text, read in source:
                if file.suffix != ".gz":
                    spent[1] += read - last_read
                    last_read = read
                spent[0] += 1
                if spent[0] > budget.lines or spent[1] > budget.bytes:
                    spent[2] = 1
                    return
                yield parse_line(text, file.name, offset)
        except OSError:
            continue


def read(path: Path, query: Query, limit: int = 200, cursor: str = "",
         budget: Budget | None = None) -> Page:  # fmt: skip
    """The newest `limit` entries matching `query`, plus a cursor for the next (older) page."""
    budget = budget or Budget()
    spent = [0, 0, 0]  # lines, bytes, budget hit
    page = Page(files=len(log_files(path)))
    for entry in _scan(path, cursor, budget, spent, query.since):
        if query.since and entry.time and entry.time < query.since:
            break  # logs are chronological: everything further back is older still
        if not query.matches(entry):
            continue
        page.entries.append(entry)
        if len(page.entries) >= limit:
            page.older = entry.cursor
            return page
    page.limited = bool(spent[2])
    if page.limited and page.entries:
        page.older = page.entries[-1].cursor
    return page


@dataclass
class Problem:
    key: str
    level: str
    count: int
    first: datetime | None
    last: datetime | None
    sample: Entry
    ips: dict[str, int] = field(default_factory=dict)

    @property
    def top_ips(self) -> list[tuple[str, int]]:
        return sorted(self.ips.items(), key=lambda item: -item[1])[:3]


def problems(path: Path, since: datetime | None, budget: Budget | None = None,
             level: str = "warn") -> tuple[list[Problem], bool]:  # fmt: skip
    """Warnings and errors in the window grouped by message; most frequent first.

    The second value says the budget ended the scan before the window start.
    """
    budget = budget or Budget()
    spent = [0, 0, 0]
    groups: dict[tuple[str, str], Problem] = {}
    query = Query(level=level, since=since)
    for entry in _scan(path, "", budget, spent, since):
        if since and entry.time and entry.time < since:
            break
        if not entry.level or not query.matches(entry):
            continue
        key = (entry.level, entry.key)
        group = groups.get(key)
        if group is None:
            group = groups[key] = Problem(entry.key, entry.level, 0, entry.time, entry.time, entry)
        group.count += 1
        if entry.time:
            group.first = entry.time if group.first is None else min(group.first, entry.time)
            group.last = entry.time if group.last is None else max(group.last, entry.time)
        ip = entry.fields.get("remote_ip")
        if ip and (ip in group.ips or len(group.ips) < 50):
            group.ips[ip] = group.ips.get(ip, 0) + 1
    ordered = sorted(groups.values(), key=lambda g: (LEVELS.index(g.level), -g.count))
    return ordered, bool(spent[2])


def counts(path: Path, since: datetime) -> dict[str, int] | None:
    """{'error': n, 'warn': n} in the window, or None when there is no readable log."""
    if not log_files(path):
        return None
    found, _ = problems(path, since)
    out = {"error": 0, "warn": 0}
    for group in found:
        out[group.level] += group.count
    return out


def window_start(name: str, now: datetime | None = None) -> datetime | None:
    delta = WINDOWS.get(name)
    return (now or datetime.now(UTC)) - delta if delta else None
