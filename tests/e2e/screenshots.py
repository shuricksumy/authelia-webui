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

from tests.e2e.auth import BASE, login
from tests.e2e.conftest import rule_number
from tests.fixtures.stack import STACK

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "docs" / "screenshots"
VIEWPORTS = {"1280": {"width": 1280, "height": 900}, "390": {"width": 390, "height": 844}}
SCHEMES = ("light", "dark")


def reset_draft() -> None:
    shutil.rmtree(STACK / "managed" / ".draft", ignore_errors=True)


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
