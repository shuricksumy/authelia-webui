"""Real applies: Authelia is restarted through the socket proxy, every session is lost, and the
result is waiting after the next login. (File name sorts last: these invalidate other sessions;
`AliceSession` logs in again for anything that still needs one.)"""

from __future__ import annotations

import json
import subprocess
import time

import httpx
import pytest
from playwright.sync_api import Browser, Page, expect

from tests.e2e.auth import BASE, sign_in
from tests.e2e.conftest import AliceSession, open_rules
from tests.fixtures.stack import AUTH_HOST, PORTAL_PORT, STACK

pytestmark = pytest.mark.e2e

LAST_JOB = STACK / "managed" / ".apply" / "last.json"
FORWARD_AUTH = "http://127.0.0.1:19091/api/authz/forward-auth"


def forward_auth_status(host: str) -> int:
    headers = {"X-Forwarded-Method": "GET", "X-Forwarded-Proto": "https",
               "X-Forwarded-Host": host, "X-Forwarded-URI": "/",
               "X-Forwarded-For": "10.8.0.5"}  # fmt: skip
    return httpx.get(FORWARD_AUTH, headers=headers, timeout=10).status_code


def wait_for_job(result_in: tuple[str, ...] = ("applied", "rolled-back", "failed"),
                 timeout: float = 120) -> dict[str, object]:  # fmt: skip
    """Poll the persisted job from the host: the browser session is gone during the restart."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            job = json.loads(LAST_JOB.read_text())
            if job.get("result") in result_in:
                return job  # type: ignore[no-any-return]
        except (OSError, ValueError):
            pass
        time.sleep(1)
    raise AssertionError("the apply did not finish in time")


def git_log(*args: str) -> str:
    return subprocess.run(["git", "-C", str(STACK / "managed"), "log", *args],
                          capture_output=True, text=True, check=True).stdout  # fmt: skip


def add_rule(page: Page, domain: str, note: str, above_catch_all: bool = False) -> None:
    open_rules(page)
    page.get_by_role("button", name="+ Add rule").click()
    form = page.locator("#rule-form")
    form.get_by_label("Domain(s)").fill(domain)
    form.get_by_label("Policy").select_option("deny")
    form.get_by_label("Note").fill(note)
    expect(page.locator("#validation")).to_contain_text("Looks valid")
    form.get_by_role("button", name="Save to draft").click()
    expect(page.get_by_text("saved to the draft")).to_be_visible()
    if above_catch_all:
        # New rules are appended; the last live rule is the *.example.test catch-all, which
        # matches anonymous visitors first. One step up puts the new rule in front of it.
        number = page.locator("#rules-body tr").count()
        page.get_by_role("button", name=f"Move rule {number} up").click()
        expect(page.get_by_text(f"Moved rule #{number} to position {number - 1}.")).to_be_visible()


def review_and_apply(page: Page) -> None:
    page.goto(f"{BASE}/review", wait_until="networkidle")
    expect(page.get_by_text("Authelia accepts the draft")).to_be_visible()
    apply_button = page.get_by_role("button", name="Validate & apply")
    expect(apply_button).to_be_enabled()
    apply_button.click()
    expect(page.locator("#apply-progress")).to_be_visible()


def log_back_in_after_restart(page: Page) -> None:
    """Authelia restarted (twice after a rollback). The job is finished, so load the result page
    afresh: the login form must come from the final Authelia instance, not from one that was
    served between the two restarts (a form from the first instance cannot complete a login)."""
    page.goto(f"{BASE}/apply/result")
    page.wait_for_url(f"https://{AUTH_HOST}:{PORTAL_PORT}/**", timeout=60_000)
    sign_in(page)
    page.wait_for_url(f"{BASE}/apply/result", timeout=20_000)


def test_apply_restarts_authelia_and_the_result_is_shown_after_login(
    browser: Browser, alice_state: AliceSession
) -> None:
    context = browser.new_context(ignore_https_errors=True, storage_state=alice_state.state())
    page = context.new_page()
    try:
        assert forward_auth_status("applied.example.test") in (302, 401)  # catch-all: log in
        add_rule(page, "applied.example.test", "e2e: applied through the UI", above_catch_all=True)
        review_and_apply(page)

        job = wait_for_job()
        assert job["result"] == "applied", job
        log_back_in_after_restart(page)

        expect(page.locator("#apply-progress")).to_contain_text("Applied")
        expect(page.locator("#apply-progress")).to_contain_text("Authelia is healthy")
        expect(page.locator("footer.statusbar")).to_contain_text("healthy")
        expect(page.locator("footer.statusbar")).to_contain_text("matches")
        assert forward_auth_status("applied.example.test") == 403  # the new rule is live

        page.get_by_role("navigation", name="Main").get_by_role("link", name="History").click()
        row = page.locator("table.history:not(.audit) tbody tr").first
        expect(row).to_contain_text("Rules: 1 added")
        expect(row).to_contain_text("applied")
        row.get_by_text("Show diff").click()
        expect(row.locator("pre.diff")).to_contain_text("applied.example.test")
        expect(page.locator("table.audit")).to_contain_text("apply")

        # "Revert to this version" goes through the draft and the review, nothing is applied.
        initial = page.locator("table.history:not(.audit) tbody tr", has_text="initial import")
        initial.get_by_role("button", name="Revert to this").click()
        page.wait_for_url(f"{BASE}/review")
        expect(page.locator(".draftbar")).to_contain_text("unapplied change")
        expect(page.locator("pre.diff .d-del").first).to_be_visible()
        page.get_by_role("button", name="Discard").click()
        page.get_by_role("button", name="Discard draft").click()
        expect(page.locator(".draftbar")).to_have_count(0)
    finally:
        context.close()


def test_unhealthy_apply_is_rolled_back_and_the_user_is_told(
    browser: Browser, alice_state: AliceSession
) -> None:
    """`X-Test-Instance: broken` routes to the instance whose health goes through health-switch:
    it reports unhealthy while the live rules contain "break-health", so Authelia 'fails'."""
    live_before = (STACK / "managed" / "access_control.yml").read_text()
    context = browser.new_context(
        ignore_https_errors=True, storage_state=alice_state.state(),
        extra_http_headers={"X-Test-Instance": "broken"},
    )  # fmt: skip
    page = context.new_page()
    try:
        add_rule(page, "broken.example.test", "break-health e2e marker")
        review_and_apply(page)

        job = wait_for_job()  # two restarts: the apply, then the rollback
        assert job["result"] == "rolled-back", job
        log_back_in_after_restart(page)

        expect(page.locator("#apply-progress")).to_contain_text("Rolled back")
        expect(page.locator("#apply-progress")).to_contain_text("back in the draft")
        assert (STACK / "managed" / "access_control.yml").read_text() == live_before
        assert git_log("--format=%s", "-n1").startswith("Rollback:")
        assert httpx.get("http://127.0.0.1:19091/api/health", timeout=10).status_code == 200
        assert forward_auth_status("broken.example.test") in (302, 401)  # rule is not live

        banner = page.locator(".banner.job.rolled-back")
        expect(banner).to_contain_text("Rolled back")
        banner.get_by_role("button", name="Dismiss").click()
        expect(banner).to_be_hidden()
        page.goto(f"{BASE}/rules", wait_until="networkidle")
        expect(page.locator(".banner.job")).to_be_hidden()  # dismissal is remembered

        # the failed change waits in the draft so it can be fixed
        assert (STACK / "managed" / ".draft" / "access_control.yml").is_file()
        page.goto(f"{BASE}/history", wait_until="networkidle")
        commits = page.locator("table.history:not(.audit)")
        expect(commits.locator(".result-badge.rolled-back")).to_have_count(1)
        expect(commits).to_contain_text("automatic rollback")
    finally:
        context.close()
