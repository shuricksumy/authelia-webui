"""`make screenshots`: capture every screen of the UI (SPEC §15.10).

Runs against the compose test stack with synthetic data, logs in through the real Authelia
portal (password + TOTP), and writes docs/screenshots/<screen>-<width>-<light|dark>.png at
1280 px and 390 px. Review the PNGs against the wireframes in SPEC §15 after every UI change.

    make screenshots
"""

from __future__ import annotations

import shutil
import sys
from collections.abc import Callable
from pathlib import Path

from playwright.sync_api import BrowserContext, Page, sync_playwright

from app.apply import audit
from app.apply import state as apply_state
from app.apply.engine import TRACKED
from app.apply.jobs import JobBoard
from app.apply.repo import ManagedRepo
from app.rules.document import RulesDocument
from app.rules.store import sha256
from tests.e2e.auth import BASE, login
from tests.e2e.conftest import rule_number
from tests.fixtures.stack import STACK

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "docs" / "screenshots"
VIEWPORTS = {"1280": {"width": 1280, "height": 900}, "390": {"width": 390, "height": 844}}
SCHEMES = ("light", "dark")


MANAGED = STACK / "managed"
LIVE = MANAGED / "access_control.yml"
MAIN = STACK / "configuration.yml"
ORIGINAL = ""  # the stack's access_control.yml, restored after every scenario
ORIGINAL_MAIN = ""  # the stack's configuration.yml, restored likewise
ORIGINAL_TESTS = ""  # and access_tests.yml


def reset_draft() -> None:
    """Back to a pristine stack: no draft, no apply state, no git history, original rules."""
    shutil.rmtree(MANAGED / ".draft", ignore_errors=True)
    shutil.rmtree(MANAGED / ".apply", ignore_errors=True)
    shutil.rmtree(MANAGED / ".git", ignore_errors=True)
    for name in (".gitignore", "audit.log"):
        (MANAGED / name).unlink(missing_ok=True)
    if ORIGINAL:
        LIVE.write_text(ORIGINAL)
        MAIN.write_text(ORIGINAL_MAIN)
        (MANAGED / "access_tests.yml").write_text(ORIGINAL_TESTS)


def repo() -> ManagedRepo:
    return ManagedRepo(MANAGED, "authcfg.example.test")


def seed_history() -> None:
    """Synthetic past: an initial import, one applied change, one change that was rolled back."""
    git = repo()
    git.ensure(TRACKED)
    doc = RulesDocument.parse(ORIGINAL)
    applied = doc.move(8, 9)
    LIVE.write_text(applied.render())
    first = git.commit(["access_control.yml"], "Rules: order changed",
                       "Applied-by: alice\nClient-IP: 10.8.0.5", "alice")  # fmt: skip
    LIVE.write_text(applied.move(4, 5).render())
    git.commit(["access_control.yml"], "Rules: order changed",
               "Applied-by: alice\nClient-IP: 10.8.0.5", "alice")  # fmt: skip
    rollback = git.revert_head("Authelia did not come back up within 30 s.", author="alice")
    now = audit.now()
    entries = [
        (now - 3600, "apply", "applied", first, "Applied. Authelia is healthy."),
        (now - 600, "rollback", "rolled-back", rollback,
         "Authelia did not come back up within 30 s. The previous version is live again."),
    ]  # fmt: skip
    for ts, action, result, commit, summary in entries:
        audit.append(
            MANAGED,
            audit.AuditEntry(ts, "alice", "10.8.0.5", action, result, commit[:12], summary),
        )


def seed_job(
    result: str | None, statuses: list[str], message: str = "", details: list[str] | None = None
) -> None:
    board = JobBoard(MANAGED)
    job = board.new("alice")
    for step, status in zip(job.steps, statuses, strict=True):
        step.status = status
    fields: dict[str, object] = {"message": message, "details": details or [], "commit": "9f3c2ab"}
    if result:
        fields["result"] = result
    board.update(job, **fields)


def settle(page: Page) -> None:
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(250)


# Each scenario drives the page into a state and returns; the caller takes the picture.
def rules(page: Page) -> None:
    page.goto(f"{BASE}/rules", wait_until="networkidle")


def by_domain(page: Page) -> None:
    page.goto(f"{BASE}/rules?view=domain", wait_until="networkidle")


def editor(page: Page) -> None:
    index = rule_number("photos.example.test", "bypass") - 1  # warnings, many paths
    page.goto(f"{BASE}/rules?edit={index}", wait_until="networkidle")


def editor_locked(page: Page) -> None:
    index = rule_number("authcfg.example.test", "two_factor") - 1  # protected: read-only
    page.goto(f"{BASE}/rules?edit={index}", wait_until="networkidle")


def new_rule(page: Page) -> None:
    page.goto(f"{BASE}/rules?new=1", wait_until="networkidle")


def draft_with_changes(page: Page) -> None:
    page.goto(f"{BASE}/rules", wait_until="networkidle")
    page.get_by_role("button", name="Move rule 9 down").click()
    # HTMX applies out-of-band swaps (draft bar) before the main swap: wait for the new section.
    page.wait_for_selector("text=Moved rule #9")
    page.get_by_role("combobox", name="Default policy").select_option("one_factor")
    page.wait_for_selector("text=Default policy set to one_factor")


def review(page: Page) -> None:
    draft_with_changes(page)
    page.goto(f"{BASE}/review", wait_until="networkidle")


def tester(page: Page) -> None:
    page.goto(f"{BASE}/rules", wait_until="networkidle")
    page.get_by_role("button", name="Test a URL").click()
    page.fill("#tester-url", "https://photos.example.test/api/server/ping")
    page.select_option("#tester-user", "")
    page.get_by_role("button", name="Test", exact=True).click()
    page.wait_for_selector("text=matches")


def delete_confirm(page: Page) -> None:
    index = rule_number("home.example.test", "bypass") - 1
    page.goto(f"{BASE}/rules?edit={index}", wait_until="networkidle")
    page.get_by_role("button", name="Delete").click()
    page.wait_for_selector("dialog[open]")


def apply_running(page: Page) -> None:
    seed_job(None, ["done", "done", "running", "pending", "pending", "pending"])
    page.goto(f"{BASE}/apply/result", wait_until="networkidle")


def apply_applied(page: Page) -> None:
    seed_job("applied", ["done", "done", "done", "done", "done", "skipped"],
             "Applied. Authelia is healthy.")  # fmt: skip
    page.goto(f"{BASE}/rules", wait_until="networkidle")


def apply_rolled_back(page: Page) -> None:
    seed_job(
        "rolled-back", ["done", "done", "done", "done", "failed", "done"],
        "Authelia did not come back up within 30 s. The previous version is live again; your "
        "change is back in the draft so you can fix it.",
        ["error loading rule 3: option 'policy' must be one of 'bypass', 'one_factor'"],
    )  # fmt: skip
    page.goto(f"{BASE}/apply/result", wait_until="networkidle")


def history(page: Page) -> None:
    seed_history()
    page.goto(f"{BASE}/history", wait_until="networkidle")
    page.get_by_text("Show diff").nth(1).click()
    page.wait_for_selector("pre.diff")


def disable_rule(page: Page, domain: str, policy: str) -> None:
    index = rule_number(domain, policy) - 1
    page.goto(f"{BASE}/rules", wait_until="networkidle")
    page.locator(f'tr[data-index="{index}"]').get_by_role("button", name="Disable").click()
    page.wait_for_selector("text=disabled in the draft")


def disabled_rules(page: Page) -> None:
    disable_rule(page, "home.example.test", "bypass")


def tests_page(page: Page) -> None:
    draft_with_changes(page)
    page.goto(f"{BASE}/tests", wait_until="networkidle")


def tests_dialog(page: Page) -> None:
    page.goto(f"{BASE}/tests", wait_until="networkidle")
    page.get_by_role("button", name="+ Add test").click()
    page.wait_for_selector("dialog[open]")


def review_failing_tests(page: Page) -> None:
    """Disabling the public home API rule makes the seeded 'API is public' test fail."""
    disable_rule(page, "home.example.test", "bypass")
    page.goto(f"{BASE}/review", wait_until="networkidle")


def external_change(page: Page) -> None:
    """A hand edit on the host is committed as an external change and announced."""
    git = repo()
    git.ensure(TRACKED)
    LIVE.write_text(ORIGINAL + "# edited over ssh\n")
    page.goto(f"{BASE}/rules", wait_until="networkidle")


def main_changed(page: Page) -> None:
    git = repo()
    git.ensure(TRACKED)
    apply_state.update(MANAGED, main_sha=sha256(MAIN.read_text()))
    MAIN.write_text(MAIN.read_text() + "# edited by hand\n")
    page.goto(f"{BASE}/rules", wait_until="networkidle")


SCREENS: dict[str, Callable[[Page], None]] = {
    "rules": rules,
    "rules-by-domain": by_domain,
    "rule-editor": editor,
    "rule-editor-protected": editor_locked,
    "rule-new": new_rule,
    "draft-review": review,
    "draft-rules": draft_with_changes,
    "tester": tester,
    "delete-confirm": delete_confirm,
    "disabled-rules": disabled_rules,
    "tests": tests_page,
    "test-dialog": tests_dialog,
    "review-failing-tests": review_failing_tests,
    "external-change": external_change,
    "main-changed": main_changed,
    "apply-running": apply_running,
    "apply-applied": apply_applied,
    "apply-rolled-back": apply_rolled_back,
    "history": history,
}


def shoot(context: BrowserContext, name: str, width: str, scheme: str) -> None:
    reset_draft()
    page = context.new_page()
    try:
        SCREENS[name](page)
        settle(page)
        # The panel scrolls inside the viewport; show all of it for review (CSSOM: CSP allows it).
        page.evaluate(
            "() => { const p = document.getElementById('panel'); "
            "if (p) { p.style.maxHeight = 'none'; p.style.position = 'static'; } }"
        )
        page.screenshot(path=str(OUT / f"{name}-{width}-{scheme}.png"), full_page=True)
    finally:
        page.close()
        reset_draft()


def main(only: list[str] | None = None) -> int:
    global ORIGINAL, ORIGINAL_MAIN, ORIGINAL_TESTS
    ORIGINAL = LIVE.read_text()
    ORIGINAL_MAIN = MAIN.read_text()
    ORIGINAL_TESTS = (MANAGED / "access_tests.yml").read_text()
    OUT.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--host-resolver-rules=MAP *.example.test 127.0.0.1"])
        state = login(browser)
        for scheme in SCHEMES:
            for width, viewport in VIEWPORTS.items():
                context = browser.new_context(
                    ignore_https_errors=True,
                    storage_state=state,
                    viewport=viewport,  # type: ignore[arg-type]
                    color_scheme=scheme,  # type: ignore[arg-type]
                )
                for name in only or SCREENS:
                    shoot(context, name, width, scheme)
                context.close()
        browser.close()
    print(f"wrote {len(list(OUT.glob('*.png')))} screenshots to {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:] or None))
