"""Log in through the real Authelia portal (password + TOTP) for e2e tests and screenshots."""

from __future__ import annotations

import json
import time
from typing import Any

import pyotp
from playwright.sync_api import Browser

from tests.fixtures.stack import CONFIGURATOR_HOST, INTERNAL_PORT, STACK

BASE = f"https://{CONFIGURATOR_HOST}:{INTERNAL_PORT}"
CREDENTIALS = STACK.parent / "credentials.json"
LAST_CODE = STACK.parent / ".last_totp"


def fresh_totp(secret: str) -> str:
    """A TOTP code Authelia has not seen yet: it rejects replays within the same 30 s step."""
    totp = pyotp.TOTP(secret)
    previous = LAST_CODE.read_text().strip() if LAST_CODE.exists() else ""
    deadline = time.time() + 40
    while totp.now() == previous and time.time() < deadline:
        time.sleep(1)
    code = totp.now()
    LAST_CODE.write_text(code)
    return code


def login(browser: Browser, username: str | None = None, password: str | None = None,
          totp: bool = True) -> dict[str, Any]:  # fmt: skip
    """Return a Playwright storage state for a logged-in session (alice by default)."""
    creds = json.loads(CREDENTIALS.read_text())
    context = browser.new_context(ignore_https_errors=True)
    page = context.new_page()
    page.goto(f"{BASE}/", wait_until="networkidle")
    page.get_by_role("textbox", name="Username").fill(username or creds["username"])
    page.get_by_role("textbox", name="Password").fill(password or creds["password"])
    page.get_by_role("button", name="Sign in").click()
    if totp:
        page.wait_for_url("**/2fa/one-time-password**")
        page.locator("input[autocomplete=one-time-code]").first.click()
        page.keyboard.type(fresh_totp(creds["totp_secret"]), delay=40)
    # Both flows end with Authelia redirecting back to the app (a non-admin lands on its 403).
    page.wait_for_url(f"{BASE}/**", timeout=20000)
    state: dict[str, Any] = context.storage_state()  # type: ignore[assignment]
    context.close()
    return state
