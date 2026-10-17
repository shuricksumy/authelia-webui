"""The log reader: bounded, newest first, filtered, grouped, and free of secrets."""

from __future__ import annotations

import gzip
import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app import logs

FAIL = "Unsuccessful 1FA authentication attempt by user"
NOW = datetime(2030, 1, 2, 12, 0, 0, tzinfo=UTC)
HASH = "$" + "argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo"


def line(minutes_ago: float, level: str, msg: str, **fields: str) -> str:
    stamp = (NOW - timedelta(minutes=minutes_ago)).isoformat().replace("+00:00", "Z")
    return json.dumps({"level": level, "msg": msg, "time": stamp, **fields})


def write(path: Path, lines: list[str]) -> Path:
    path.write_text("\n".join(lines) + "\n")
    return path


def test_json_and_text_lines_are_parsed() -> None:
    e = logs.parse_line(line(5, "error", "Boom", remote_ip="192.0.2.7", path="/api/x"))
    assert e.level == "error" and e.message == "Boom" and e.fields["remote_ip"] == "192.0.2.7"
    assert e.time == NOW - timedelta(minutes=5)
    t = logs.parse_line(
        'time="2030-01-02T11:00:00Z" level=warning msg="Careful, \\"quoted\\"" path=/x'
    )
    assert t.level == "warn" and t.message == 'Careful, "quoted"' and t.fields["path"] == "/x"
    odd = logs.parse_line("panic: something unstructured")
    assert odd.level == "" and odd.time is None and odd.raw == "panic: something unstructured"
    assert logs.parse_line("{broken json").level == ""
    assert logs.parse_line('["a list"]').level == ""


def test_secrets_never_survive(tmp_path: Path) -> None:
    secret = line(1, "error", f"bad hash {HASH}", error="password=hunter2hunter2 failed")
    jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl"
    other = line(1, "info", f"got Bearer abcdefghijkl and {jwt} cookie=authelia_session_value123")
    block = "-----BEGIN " + "PRIVATE KEY-----\\nAAAA\\n-----END PRIVATE KEY-----"
    pem = line(1, "error", "key " + block)
    path = write(tmp_path / "a.log", [secret, other, pem])
    page = logs.read(path, logs.Query(level="debug"))
    blob = "\n".join(e.raw + e.message + str(e.fields) for e in page.entries)
    for needle in (HASH, "hunter2", jwt, "abcdefghijkl", "authelia_session_value", "AAAA"):
        assert needle not in blob


def test_newest_first_filters_and_levels(tmp_path: Path) -> None:
    path = write(tmp_path / "a.log", [
        line(50, "info", "old info"), line(40, "error", "old error", remote_ip="192.0.2.1"),
        line(30, "warning", "a warning"), line(20, "debug", "chatter"),
        line(10, "error", "new error", remote_ip="192.0.2.2"), "free text line",
    ])  # fmt: skip
    page = logs.read(path, logs.Query(level="warn"))
    assert [e.message for e in page.entries] == ["new error", "a warning", "old error"]
    assert [e.message for e in logs.read(path, logs.Query(level="error")).entries] == [
        "new error", "old error"]  # fmt: skip
    everything = logs.read(path, logs.Query(level="debug")).entries
    assert len(everything) == 6 and everything[0].raw == "free text line"
    assert [e.message for e in logs.read(path, logs.Query("debug", text="WARN")).entries] == [
        "a warning"]  # fmt: skip
    ips = logs.read(path, logs.Query("error", ip="192.0.2.2")).entries
    assert [e.message for e in ips] == ["new error"]
    since = NOW - timedelta(minutes=35)
    assert [e.message for e in logs.read(path, logs.Query("debug", since=since)).entries][-1] == (
        "a warning"
    )


def test_paging_walks_back_without_gaps_or_repeats(tmp_path: Path) -> None:
    path = write(tmp_path / "a.log", [line(1000 - i, "error", f"m{i}") for i in range(250)])
    seen: list[str] = []
    cursor = ""
    for _ in range(10):
        page = logs.read(path, logs.Query("error"), limit=60, cursor=cursor)
        seen += [e.message for e in page.entries]
        if not page.older:
            break
        cursor = page.older
    assert seen == [f"m{i}" for i in reversed(range(250))]


def test_reads_across_rotated_and_gzipped_copies(tmp_path: Path) -> None:
    live = write(tmp_path / "authelia.log", [line(5, "error", "live")])
    old = write(tmp_path / "authelia.log.1", [line(100, "error", "rotated")])
    zipped = tmp_path / "authelia.log.2.gz"
    zipped.write_bytes(gzip.compress((line(500, "error", "zipped") + "\n").encode()))
    for i, p in enumerate((zipped, old, live)):  # mtime order = age
        stamp = time.time() - 1000 * (3 - i)
        import os

        os.utime(p, (stamp, stamp))
    (tmp_path / "authelia.log.notes").write_text("not a log")
    assert [p.name for p in logs.log_files(live)] == [
        "authelia.log",
        "authelia.log.1",
        "authelia.log.2.gz",
    ]
    page = logs.read(live, logs.Query("error"))
    assert [e.message for e in page.entries] == ["live", "rotated", "zipped"]
    # a cursor taken in a rotated file continues in the older ones
    first = logs.read(live, logs.Query("error"), limit=2)
    rest = logs.read(live, logs.Query("error"), limit=10, cursor=first.older or "")
    assert [e.message for e in rest.entries] == ["zipped"]


def test_old_rotated_copies_are_not_opened_for_a_recent_window(tmp_path: Path) -> None:
    import os

    live = write(tmp_path / "authelia.log", [line(5, "error", "live")])
    old = tmp_path / "authelia.log.1.gz"
    old.write_bytes(b"this is not gzip at all")
    stamp = time.time() - 10 * 86400
    os.utime(old, (stamp, stamp))
    since = datetime.now(UTC) - timedelta(hours=1)
    # the live entry is from 2030 (the future for the clock): it is simply listed, and the
    # ancient archive is skipped without being read
    page = logs.read(live, logs.Query("error", since=since))
    assert [e.message for e in page.entries] == ["live"]


def test_a_huge_file_is_read_within_the_budget(tmp_path: Path) -> None:
    path = tmp_path / "big.log"
    row = line(1, "info", "x" * 200) + "\n"
    with path.open("w") as handle:
        for _ in range(60_000):  # ~15 MB
            handle.write(row)
        handle.write(line(0, "error", "the end") + "\n")
    started = time.monotonic()
    page = logs.read(path, logs.Query("error"), limit=5, budget=logs.Budget(lines=10_000))
    assert [e.message for e in page.entries] == ["the end"]
    assert page.limited and time.monotonic() - started < 3
    assert logs.read(path, logs.Query("debug"), limit=3).entries[0].message == "the end"


def test_very_long_lines_are_cut(tmp_path: Path) -> None:
    path = write(tmp_path / "a.log", [line(1, "error", "z" * 50_000)])
    e = logs.read(path, logs.Query("error")).entries[0]
    assert len(e.raw) <= logs.MAX_LINE


def test_no_trailing_newline_and_blank_lines(tmp_path: Path) -> None:
    path = tmp_path / "a.log"
    path.write_text(line(2, "error", "one") + "\n\n\n" + line(1, "error", "two"))
    assert [e.message for e in logs.read(path, logs.Query("error")).entries] == ["two", "one"]
    assert logs.read(tmp_path / "missing.log", logs.Query()).entries == []


def test_problems_are_grouped_by_message_with_the_variable_parts_blanked(tmp_path: Path) -> None:
    rows = [
        line(30, "error", f"{FAIL} 'alice'", remote_ip="192.0.2.5"),
        line(20, "error", f"{FAIL} 'bob'", remote_ip="192.0.2.5"),
        line(10, "error", f"{FAIL} 'carol'", remote_ip="192.0.2.6"),
        line(5, "warning", "Request took 5230 ms"), line(4, "warning", "Request took 8801 ms"),
        line(3, "info", "fine"),
    ]  # fmt: skip
    found, limited = logs.problems(write(tmp_path / "a.log", rows), None)
    assert not limited
    assert [(p.level, p.count) for p in found] == [("error", 3), ("warn", 2)]
    top = found[0]
    assert top.top_ips == [("192.0.2.5", 2), ("192.0.2.6", 1)]
    assert top.first == NOW - timedelta(minutes=30) and top.last == NOW - timedelta(minutes=10)
    counted = logs.counts(tmp_path / "a.log", NOW - timedelta(hours=1))
    assert counted == {"error": 3, "warn": 2}
    assert logs.counts(tmp_path / "none.log", NOW) is None
