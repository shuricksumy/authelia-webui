"""`make browse`: open a browser window already logged in as alice (password + TOTP are typed
for you through the real Authelia portal). Dev convenience only - nothing about the security
path changes. No /etc/hosts entry needed: *.example.test is resolved inside this browser.

After an apply Authelia restarts and signs everyone out; run `make browse` again (or log in in
the window with `make totp`).
"""

from __future__ import annotations

from playwright.sync_api import sync_playwright

from tests.e2e.auth import BASE, login
from tests.e2e.conftest import RESOLVER


def main() -> int:
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False, args=[RESOLVER])
        state = login(browser)
        context = browser.new_context(
            ignore_https_errors=True,
            storage_state=state,
            no_viewport=True,  # type: ignore[arg-type]
        )
        page = context.new_page()
        page.goto(f"{BASE}/rules")
        print(f"Logged in as alice at {BASE}. Close the browser window to quit.")
        page.wait_for_event("close", timeout=0)
        browser.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
