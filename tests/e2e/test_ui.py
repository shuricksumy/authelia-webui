"""The configurator through the real stack: Traefik -> Authelia forwardAuth -> app."""

from __future__ import annotations

import pytest
from playwright.sync_api import Browser, Page, expect

from tests.e2e.auth import BASE, login
from tests.e2e.conftest import AliceSession, live_rules, open_rules, rule_number

pytestmark = pytest.mark.e2e


# --------------------------------------------------------------------- access control


def test_admin_logs_in_with_2fa_and_sees_the_rules(admin: Page) -> None:
    open_rules(admin)
    expect(admin).to_have_title("Rules · Authelia Configurator")
    expect(admin.locator("#rules-body tr")).to_have_count(len(live_rules()))
    expect(admin.get_by_text("alice")).to_be_visible()


def test_non_admin_is_denied(browser: Browser, stack: dict[str, str]) -> None:
    state = login(browser, username="bob", totp=False)
    context = browser.new_context(ignore_https_errors=True, storage_state=state)  # type: ignore[arg-type]
    response = context.new_page().goto(f"{BASE}/rules")
    context.close()
    assert response is not None and response.status == 403


def test_valid_admin_is_still_denied_from_a_disallowed_network(
    browser: Browser, alice_state: AliceSession
) -> None:
    """locked.example.test allows only 192.0.2.0/24: Authelia lets alice in, the app says no."""
    context = browser.new_context(ignore_https_errors=True, storage_state=alice_state.state())  # type: ignore[arg-type]
    response = context.new_page().goto("https://locked.example.test:8444/rules")
    context.close()
    assert response is not None and response.status == 403


def test_configurator_is_not_routable_on_the_public_entrypoint(
    browser: Browser, alice_state: AliceSession
) -> None:
    context = browser.new_context(ignore_https_errors=True, storage_state=alice_state.state())  # type: ignore[arg-type]
    response = context.new_page().goto("https://authcfg.example.test:8443/rules")
    context.close()
    assert response is not None and response.status == 404


def test_proxy_drops_forged_identity_headers(browser: Browser, stack: dict[str, str]) -> None:
    """forge.example.test is bypassed by Authelia on purpose. A client that sends its own
    Remote-User/Remote-Groups must still not reach the app as an admin: Traefik's forwardAuth
    removes the listed authResponseHeaders when Authelia does not set them. If a proxy upgrade
    ever changes that, this fails (the app would trust the forged admin identity)."""
    forged = {"Remote-User": "mallory", "Remote-Groups": "admin", "X-Forwarded-For": "10.8.0.5"}
    # Through the browser (it honours the *.example.test resolver rule), with the headers forged.
    context = browser.new_context(ignore_https_errors=True, extra_http_headers=forged)
    response = context.new_page().goto("https://forge.example.test:8444/rules")
    context.close()
    assert response is not None and response.status == 403


# --------------------------------------------------------------------- editing a draft


def test_filter_narrows_the_table(admin: Page) -> None:
    open_rules(admin)
    admin.get_by_role("searchbox").fill("family")
    expect(admin.locator("#rules-body tr")).to_have_count(1)
    expect(admin.locator("#rules-body")).to_contain_text("photos.example.test")


def test_reorder_with_buttons_then_review_and_discard(admin: Page) -> None:
    open_rules(admin)
    admin.get_by_role("button", name="Move rule 9 down").click()
    expect(admin.get_by_text("Moved rule #9 to position 10.")).to_be_visible()
    expect(admin.locator(".draftbar")).to_contain_text("1 unapplied change")
    expect(admin.locator("tr.status-moved")).to_have_count(1)

    admin.goto(f"{BASE}/review", wait_until="networkidle")
    expect(admin.get_by_text("order changed")).to_be_visible()
    expect(admin.locator("pre.diff .d-add").first).to_be_visible()
    expect(admin.get_by_text("Authelia accepts the draft")).to_be_visible()
    # regression: the app's own AUTHELIA_* variables must not leak into the validator
    expect(admin.get_by_text("environment variable not expected")).to_have_count(0)
    expect(admin.get_by_role("button", name="Validate & apply")).to_be_enabled()  # not clicked

    admin.get_by_role("button", name="Discard").click()
    admin.get_by_role("button", name="Discard draft").click()
    expect(admin.locator(".draftbar")).to_have_count(0)


def test_keyboard_can_reorder(admin: Page) -> None:
    open_rules(admin)
    button = admin.get_by_role("button", name="Move rule 5 up")
    button.focus()
    admin.keyboard.press("Enter")
    expect(admin.get_by_text("Moved rule #5 to position 4.")).to_be_visible()


def test_drag_and_drop_reorders(admin: Page) -> None:
    open_rules(admin)
    handles = admin.locator(".drag-handle")
    handles.nth(8).drag_to(handles.nth(11))
    expect(admin.locator(".draftbar")).to_contain_text("unapplied change")
    expect(admin.locator("tr.status-moved")).not_to_have_count(0)


def test_add_a_rule_through_the_form(admin: Page) -> None:
    open_rules(admin)
    admin.get_by_role("button", name="+ Add rule").click()
    form = admin.locator("#rule-form")
    form.get_by_label("Domain(s)").fill("notes2.example.test")
    form.get_by_label("Who").fill("group:family")
    form.get_by_label("Policy").select_option("two_factor")
    expect(admin.locator("#validation")).to_contain_text("Looks valid")
    form.get_by_role("button", name="Save to draft").click()
    count = len(live_rules())
    expect(admin.get_by_text(f"Rule #{count + 1} saved to the draft.")).to_be_visible()
    expect(admin.locator("#rules-body tr")).to_have_count(count + 1)


def test_invalid_rule_cannot_be_saved(admin: Page) -> None:
    open_rules(admin)
    admin.get_by_role("button", name="+ Add rule").click()
    form = admin.locator("#rule-form")
    form.get_by_label("Domain(s)").fill("x.example.test")
    form.get_by_label("Paths (regex)").fill("^(?!/admin).*$")
    form.get_by_label("Policy").select_option("deny")
    expect(admin.locator("#validation")).to_contain_text("RE2")
    expect(form.get_by_role("button", name="Save to draft")).to_be_disabled()


def test_protected_rule_is_read_only_and_cannot_be_deleted(admin: Page) -> None:
    admin.goto(f"{BASE}/rules?edit=2", wait_until="networkidle")
    expect(admin.get_by_text("Protected rule.")).to_be_visible()
    expect(admin.get_by_label("Domain(s)")).to_be_disabled()
    expect(admin.get_by_role("button", name="Delete")).to_have_count(0)


def test_tester_explains_the_matching_rule(admin: Page) -> None:
    open_rules(admin)
    admin.get_by_role("button", name="Test a URL").click()
    admin.fill("#tester-url", "https://photos.example.test/api/server/ping")
    admin.get_by_role("button", name="Test", exact=True).click()
    result = admin.locator("#tester-result")
    number = rule_number("photos.example.test", "bypass")
    expect(result).to_contain_text(f"Rule #{number} matches")
    expect(result).to_contain_text("BYPASS")
    expect(result).to_contain_text("skipped: different domain")


def test_no_inline_script_or_style_violations_in_the_browser(admin: Page) -> None:
    violations: list[str] = []
    admin.on(
        "console",
        lambda m: violations.append(m.text) if "Content Security Policy" in m.text else None,
    )
    open_rules(admin)
    admin.get_by_role("button", name="+ Add rule").click()
    admin.get_by_role("button", name="Test a URL").click()
    admin.wait_for_timeout(300)
    assert violations == []
