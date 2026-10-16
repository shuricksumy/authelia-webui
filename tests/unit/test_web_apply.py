"""Apply, progress, banners, footer and history through HTTP (engine thread is real)."""

from __future__ import annotations

import re
import threading
import time
from pathlib import Path
from typing import Any

from app.apply.engine import ApplyEngine
from app.apply.health import HealthResult
from app.apply.jobs import JobBoard
from app.apply.services import ApplyServices
from app.apply.status import StatusCache
from tests.unit.test_apply import FakeRuntime, ScriptedHealth, ok_validator
from tests.unit.test_web import UI, env  # noqa: F401  (fixture)


def build(ui_env: dict[str, Path], health: list[bool], runtime: FakeRuntime | None = None,
          waiter: Any = None) -> tuple[UI, ApplyServices, FakeRuntime]:  # fmt: skip
    probe = UI(ui_env)  # only to reuse its Settings
    settings = probe.settings
    runtime = runtime or FakeRuntime()
    board = JobBoard(ui_env["managed"])
    engine = ApplyEngine(settings, runtime, board, ok_validator,  # type: ignore[arg-type]
                         waiter or ScriptedHealth(list(health)))  # fmt: skip
    status = StatusCache(settings, runtime, check=lambda url: True)  # type: ignore[arg-type]
    services = ApplyServices(runtime, board, engine, status, engine.repo)  # type: ignore[arg-type]
    return UI(ui_env, services=services), services, runtime


def wait_done(ui: UI, timeout: float = 10.0) -> str:
    deadline = time.time() + timeout
    while time.time() < deadline:
        page = ui.get("/apply/status", htmx=True).text
        if "apply-progress done" in page:
            return page
        time.sleep(0.05)
    raise AssertionError("apply did not finish: " + page[:400])


def start(ui: UI) -> Any:
    ui.post("/rules/move", {"src": "3", "dst": "4"})  # a valid, non-weakening draft
    return ui.post("/apply")


# --------------------------------------------------------------------- review page


def test_review_enables_apply_when_everything_is_in_order(env: dict[str, Path]) -> None:  # noqa: F811
    ui, _, _ = build(env, [True])
    ui.post("/rules/move", {"src": "3", "dst": "4"})
    page = ui.get("/review").text
    assert re.search(r'<button[^>]*hx-post="/apply"[^>]*>Validate &amp; apply', page)
    assert "Apply is disabled" not in page and 'id="apply-panel"' in page


def test_review_explains_why_apply_is_disabled(env: dict[str, Path]) -> None:  # noqa: F811
    ui, _, _ = build(env, [True], runtime=FakeRuntime(version="4.40.1"))
    ui.post("/rules/move", {"src": "3", "dst": "4"})
    page = ui.get("/review").text
    assert re.search(r"<button[^>]*disabled[^>]*>Validate &amp; apply", page)
    assert "Apply is disabled" in page and "4.40.1 is running" in page
    assert "authelia-4.40.1" in page  # tells which image tag to deploy


# --------------------------------------------------------------------- apply flow


def test_apply_runs_in_the_background_and_reports_success(env: dict[str, Path]) -> None:  # noqa: F811
    ui, services, runtime = build(env, [True])
    r = start(ui)
    assert r.status_code == 200 and 'id="apply-progress"' in r.text
    page = wait_done(ui)
    assert "Applied" in page and "Authelia is healthy" in page
    assert "hx-trigger" not in page  # polling stops once finished
    assert runtime.restarts == 1 and not (env["managed"] / ".draft" / "access_control.yml").exists()
    rules = ui.get("/rules").text
    assert 'class="banner job applied"' in rules and "by alice" in rules
    assert re.search(r'data-job-id="[0-9a-f]{12}"', rules) and "data-dismissable" in rules
    assert "Authelia running: <strong>4.39.28</strong>" in rules and "&#10003; healthy" in rules
    assert services.board.current().result == "applied"  # type: ignore[union-attr]


def test_result_page_survives_a_new_app_instance(env: dict[str, Path]) -> None:  # noqa: F811
    """The session is lost when Authelia restarts; the result is what greets the next login."""
    ui, _, _ = build(env, [True])
    start(ui)
    wait_done(ui)
    fresh, _, _ = build(env, [True])  # a new process reading .apply/last.json
    page = fresh.get("/apply/result").text
    assert "Applied" in page and "Authelia is healthy" in page


def test_unhealthy_apply_shows_the_rollback(env: dict[str, Path]) -> None:  # noqa: F811
    ui, _, runtime = build(env, [False, True])
    start(ui)
    page = wait_done(ui)
    assert "Rolled back" in page and "previous version is live again" in page
    assert runtime.restarts == 2
    banner = ui.get("/rules").text
    assert 'class="banner job rolled-back"' in banner and "Rolled back." in banner
    assert "your change is back in the draft" in ui.get("/apply/result").text
    assert ui.get("/review").text.count("order changed") >= 1  # still reviewable


def test_failed_rollback_asks_for_manual_action(env: dict[str, Path]) -> None:  # noqa: F811
    ui, _, _ = build(env, [False, False])
    start(ui)
    page = wait_done(ui)
    assert "Failed - action needed" in page and "Manual action needed" in page
    assert 'class="banner job failed"' in ui.get("/rules").text


def test_apply_is_refused_without_changes_or_with_a_stale_revision(env: dict[str, Path]) -> None:  # noqa: F811
    ui, _, runtime = build(env, [True])
    nothing = ui.post("/apply")
    assert nothing.status_code == 422 and "no unapplied changes" in nothing.text
    ui.post("/rules/move", {"src": "3", "dst": "4"})
    stale = ui.post("/apply", rev="deadbeef")
    assert stale.status_code == 409 and "changed in another tab" in stale.text
    assert runtime.restarts == 0


def test_second_apply_while_one_is_running_is_refused(env: dict[str, Path]) -> None:  # noqa: F811
    release = threading.Event()

    def blocking(runtime: Any, url: str, previous: str, timeout_s: float = 30) -> HealthResult:
        release.wait(10)
        return HealthResult(True, "healthy")

    ui, services, _ = build(env, [], waiter=blocking)
    start(ui)
    deadline = time.time() + 5
    while not services.board.running() and time.time() < deadline:
        time.sleep(0.02)
    second = ui.post("/apply")  # correct revision, so the only problem is the running apply
    assert second.status_code == 422 and "Another apply is running" in second.text
    banner = ui.get("/rules").text
    assert "An apply is running" in banner and "/apply/result" in banner
    release.set()
    wait_done(ui)


def test_refused_apply_never_changes_the_live_file(env: dict[str, Path]) -> None:  # noqa: F811
    ui, _, runtime = build(env, [True], runtime=FakeRuntime(version="9.9.9"))
    live = (env["managed"] / "access_control.yml").read_text()
    ui.post("/rules/move", {"src": "3", "dst": "4"})
    r = ui.post("/apply")
    assert r.status_code == 422 and "9.9.9 is running" in r.text
    assert (env["managed"] / "access_control.yml").read_text() == live and runtime.restarts == 0


# --------------------------------------------------------------------- footer, banners, /version


def test_version_mismatch_banner_and_footer(env: dict[str, Path]) -> None:  # noqa: F811
    ui, _, _ = build(env, [True], runtime=FakeRuntime(version="4.40.1"))
    page = ui.get("/rules").text
    assert 'class="banner error"' in page and "Deploy the image tagged authelia-4.40.1" in page
    assert 'class="statusbar bad"' in page and "&#10007; differs" in page
    assert ui.get("/version").json() == {
        "bundled": "4.39.28", "running": "4.40.1", "healthy": True, "match": False,
    }  # fmt: skip


def test_warn_policy_shows_a_banner_without_blocking_styling(env: dict[str, Path]) -> None:  # noqa: F811
    probe = UI(env)
    probe.settings.VERSION_MISMATCH = "warn"  # type: ignore[assignment]
    runtime = FakeRuntime(version="4.40.1")
    board = JobBoard(env["managed"])
    engine = ApplyEngine(probe.settings, runtime, board, ok_validator, ScriptedHealth([True]))  # type: ignore[arg-type]
    status = StatusCache(probe.settings, runtime, check=lambda url: True)  # type: ignore[arg-type]
    ui = UI(env, services=ApplyServices(runtime, board, engine, status, engine.repo))  # type: ignore[arg-type]
    ui.settings.VERSION_MISMATCH = "warn"  # type: ignore[assignment]
    page = ui.get("/rules").text
    assert "banner warn" in page and 'class="statusbar bad"' not in page


def test_unreachable_proxy_is_shown_not_hidden(env: dict[str, Path]) -> None:  # noqa: F811
    ui, _, runtime = build(env, [True])
    runtime.unavailable = True
    page = ui.get("/rules").text
    assert "Cannot reach Authelia" in page and "(cannot be determined)" in page


def test_no_job_means_no_result_banner(env: dict[str, Path]) -> None:  # noqa: F811
    ui, _, _ = build(env, [True])
    assert "banner job" not in ui.get("/rules").text
    assert "No apply has run yet" in ui.get("/apply/result").text


# --------------------------------------------------------------------- history


def test_history_lists_commits_with_results_and_diffs(env: dict[str, Path]) -> None:  # noqa: F811
    ui, _, _ = build(env, [True])
    assert "Nothing has been applied yet" in ui.get("/history").text
    start(ui)
    wait_done(ui)
    page = ui.get("/history").text
    assert "Rules: order changed" in page and "Initial import" in page
    assert page.count('class="result-badge applied"') == 1 and "(live)" in page
    sha = re.search(r"/history/([0-9a-f]{40})/diff", page).group(1)  # type: ignore[union-attr]
    diff = ui.get(f"/history/{sha}/diff", htmx=True).text
    assert 'class="d-add"' in diff and 'class="d-del"' in diff
    assert "Audit log" in page and ">apply<" in page and ">applied<" in page
    assert "photos.example.com" not in page.split("Audit log")[1]  # no config content in the audit


def test_history_marks_a_failed_apply_as_rolled_back(env: dict[str, Path]) -> None:  # noqa: F811
    ui, _, _ = build(env, [False, True])
    start(ui)
    wait_done(ui)
    page = ui.get("/history").text
    assert 'class="result-badge rolled-back"' in page and "automatic rollback" in page


def test_diff_for_unknown_or_malicious_commit_ids(env: dict[str, Path]) -> None:  # noqa: F811
    ui, _, _ = build(env, [True])
    start(ui)
    wait_done(ui)
    for bad in ("zzzzzzz", "0" * 40, "--output=x", "HEAD"):
        assert ui.get(f"/history/{bad}/diff", htmx=True).status_code == 404


def test_revert_loads_an_old_version_into_the_draft_for_review(env: dict[str, Path]) -> None:  # noqa: F811
    ui, services, _ = build(env, [True])
    original = (env["managed"] / "access_control.yml").read_text()
    start(ui)
    wait_done(ui)
    initial = next(c for c in services.repo.log() if c.subject.startswith("Initial import"))
    r = ui.post(f"/history/{initial.sha}/revert")
    assert r.status_code == 204 and r.headers["hx-redirect"] == "/review"
    from app.rules.store import DraftStore

    assert DraftStore(env["managed"]).current().render() == original  # draft = old version
    assert (env["managed"] / "access_control.yml").read_text() != original  # live untouched
    again = ui.post(f"/history/{initial.sha}/revert")
    assert again.status_code == 422 and "unapplied changes" in again.text
    from app.apply import audit

    assert audit.recent(env["managed"])[-1].action == "revert-to-draft"


def test_revert_to_the_live_version_or_garbage_is_refused(env: dict[str, Path]) -> None:  # noqa: F811
    ui, services, _ = build(env, [True])
    start(ui)
    wait_done(ui)
    head = services.repo.log()[0].sha
    live = ui.post(f"/history/{head}/revert")
    assert live.status_code == 422 and "already live" in live.text
    junk = ui.post("/history/not-a-sha/revert")
    assert junk.status_code == 422 and "could not be loaded" in junk.text
