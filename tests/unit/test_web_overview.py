"""Overview dashboard and log viewer through HTTP."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tests.unit.test_web import HASH, UI, env  # noqa: F401  (fixture)

FAIL = "Unsuccessful 1FA authentication attempt by user"


def entry(minutes_ago: float, level: str, msg: str, **fields: str) -> str:
    stamp = (datetime.now(UTC) - timedelta(minutes=minutes_ago)).isoformat()
    return json.dumps({"level": level, "msg": msg, "time": stamp, **fields})


@pytest.fixture
def logfile(env: dict[str, Path]) -> Path:  # noqa: F811
    path = env["managed"].parent / "authelia.log"
    path.write_text(
        "\n".join([
            entry(90, "error", f"{FAIL} 'bob'", remote_ip="192.0.2.9"),
            entry(60, "info", "all fine"),
            entry(30, "error", f"{FAIL} 'carol'", remote_ip="192.0.2.9"),
            entry(20, "warning", "slow thing <script>alert(1)</script>"),
            entry(10, "error", f"hash leaked {HASH}"),
        ]) + "\n"
    )  # fmt: skip
    return path


def with_log(env: dict[str, Path], path: Path | None) -> UI:  # noqa: F811
    ui = UI(env)
    ui.settings.AUTHELIA_LOG_FILE = path
    return ui


def test_overview_is_the_home_page_and_shows_the_basics(env: dict[str, Path]) -> None:  # noqa: F811
    ui = UI(env)
    r = ui.get("/")
    assert r.status_code == 200 and "<h1>Overview</h1>" in r.text
    assert 'title="Overview" aria-current="page"' in r.text
    for word in ("Needs attention", "Authelia", "Changes", "Configuration", "Rules"):
        assert word in r.text
    assert "No log file is configured" in r.text
    assert HASH not in r.text


def test_overview_flags_a_lone_admin_and_unreachable_authelia(env: dict[str, Path]) -> None:  # noqa: F811
    text = UI(env).get("/").text
    assert "Only 1 enabled administrator" in text  # alice is the only admin in the fixture
    assert "Cannot reach Authelia" in text  # no socket proxy in unit tests


def test_overview_counts_log_errors_and_links_to_them(env: dict[str, Path], logfile: Path) -> None:  # noqa: F811
    text = with_log(env, logfile).get("/").text
    assert "3 errors in Authelia" in text and "/logs?level=error&amp;window=24h" in text


def test_a_broken_check_does_not_break_the_page(env: dict[str, Path]) -> None:  # noqa: F811
    env["users"].write_text("not: [valid")
    r = UI(env).get("/")
    assert r.status_code == 200 and "users file could not be read" in r.text


def test_logs_page_without_a_log_file_explains_itself(env: dict[str, Path]) -> None:  # noqa: F811
    text = UI(env).get("/logs").text
    assert "No log file is configured" in text and "AUTHELIA_LOG_FILE" in text


def test_logs_page_groups_problems_and_hides_secrets(env: dict[str, Path], logfile: Path) -> None:  # noqa: F811
    text = with_log(env, logfile).get("/logs").text
    assert "Top problems" in text and "1FA authentication attempt by user" in text
    assert "192.0.2.9 (2)" in text
    assert HASH not in text and "&lt;hash&gt;" in text
    assert "<script>alert(1)" not in text and "&lt;script&gt;" in text
    assert "all fine" not in text  # default level: warnings and errors


def test_logs_filters(env: dict[str, Path], logfile: Path) -> None:  # noqa: F811
    ui = with_log(env, logfile)
    assert "all fine" in ui.get("/logs?level=info").text
    entries = ui.get("/logs?level=error&q=carol").text.split("<h2>Entries</h2>")[1]
    assert entries.count("<tr") == 2 and "carol" in entries and "slow thing" not in entries
    assert "192.0.2.9" in ui.get("/logs?ip=192.0.2.9").text
    narrow = ui.get("/logs?level=error&window=1h").text
    assert "bob" not in narrow.split("<h2>Entries</h2>")[1]  # 90 minutes ago is outside the hour
    junk = ui.get("/logs?level=nope&window=nope&older=garbage:::")
    assert junk.status_code == 200


def test_download_is_plain_text_redacted(env: dict[str, Path], logfile: Path) -> None:  # noqa: F811
    r = with_log(env, logfile).get("/logs/download?level=debug&window=all")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    assert (
        "attachment" in r.headers["content-disposition"]
        and "no-store" in r.headers["cache-control"]
    )
    assert HASH not in r.text and "all fine" in r.text
    assert r.text.index("bob") < r.text.index("all fine") < r.text.index("carol")  # oldest first
    assert with_log(env, None).get("/logs/download").status_code == 404


def test_logs_need_the_admin_identity(env: dict[str, Path], logfile: Path) -> None:  # noqa: F811
    ui = with_log(env, logfile)
    ui.headers = {**ui.headers, "Remote-Groups": "family"}
    assert ui.get("/logs").status_code == 403 and ui.get("/logs/download").status_code == 403


def test_up_since_is_shown_in_utc_whatever_docker_returns() -> None:
    from app.web_overview import _up_since

    assert _up_since("2030-01-02T03:04:05.123456789Z") == "2030-01-02 03:04 UTC"
    assert _up_since("2030-01-02T03:04:05Z") == "2030-01-02 03:04 UTC"
    assert _up_since("garbage") == ""
