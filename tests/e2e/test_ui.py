"""The configurator through the real stack: Traefik -> Authelia forwardAuth -> app."""

from __future__ import annotations

import pytest
from playwright.sync_api import Browser, Page, expect

from tests.e2e.auth import BASE, login
from tests.e2e.conftest import AliceSession, live_rules, open_rules, rule_number
from tests.fixtures.stack import STACK

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


# --------------------------------------------------------------------- Phase 1c (no restart)


def test_access_tests_can_be_added_and_deleted(admin: Page) -> None:
    admin.goto(f"{BASE}/tests", wait_until="networkidle")
    expect(admin.locator("table.tests")).to_contain_text("Photos server ping is public")
    admin.get_by_role("button", name="+ Add test").click()
    admin.get_by_label("Name").fill("e2e: scratch test")
    admin.get_by_label("URL").fill("https://scratch.example.test/")
    admin.get_by_label("Must get").select_option("two_factor")
    admin.get_by_role("button", name="Save test").click()
    admin.wait_for_url(f"{BASE}/tests")
    row = admin.locator("table.tests tbody tr", has_text="e2e: scratch test")
    expect(row).to_have_count(1)
    admin.once("dialog", lambda dialog: dialog.accept())
    row.get_by_role("button", name="Delete").click()
    expect(admin.locator("table.tests tbody tr", has_text="e2e: scratch test")).to_have_count(0)


def test_tester_result_can_become_a_test(admin: Page) -> None:
    open_rules(admin)
    admin.get_by_role("button", name="Test a URL").click()
    admin.fill("#tester-url", "https://photos.example.test/api/server/ping")
    admin.get_by_role("button", name="Test", exact=True).click()
    admin.get_by_role("button", name="Add as test").click()
    expect(admin.locator("#t-url")).to_have_value("https://photos.example.test/api/server/ping")
    expect(admin.locator("#t-expect")).to_have_value("bypass")


def test_disable_and_enable_roundtrip_in_the_draft(admin: Page) -> None:
    index = rule_number("home.example.test", "bypass") - 1
    open_rules(admin)
    count = admin.locator("#rules-body tr").count()
    admin.locator(f'tr[data-index="{index}"]').get_by_role("button", name="Disable").click()
    expect(admin.locator("#rules-body tr")).to_have_count(count - 1)
    expect(admin.locator("table.disabled-rules")).to_contain_text("home.example.test")
    admin.get_by_role("button", name="Enable").click()
    expect(admin.locator("#rules-body tr")).to_have_count(count)
    expect(admin.locator("table.disabled-rules")).to_have_count(0)
    expect(admin.locator(".draftbar")).to_have_count(0)  # byte-identical to live: no draft left


def test_a_hand_edit_is_recorded_and_announced(admin: Page) -> None:
    live = STACK / "managed" / "access_control.yml"
    original = live.read_text()
    try:
        live.write_text(original + "# edited over ssh (e2e)\n")
        open_rules(admin)
        expect(admin.get_by_text("Files were edited outside the configurator")).to_be_visible()
        admin.goto(f"{BASE}/history", wait_until="networkidle")
        expect(admin.locator("table.history:not(.audit)")).to_contain_text("edited outside")
        admin.goto(f"{BASE}/rules", wait_until="networkidle")
        admin.get_by_role("button", name="Mark as seen").click()
        expect(admin.get_by_text("Files were edited outside")).to_have_count(0)
    finally:
        live.write_text(original)


# ----------------------------------------------------------------- OIDC clients (no restart)


def clients_file() -> str:
    return (STACK / "managed" / "oidc_clients.yml").read_text()


def test_clients_list_and_editor_never_show_hashes(admin: Page) -> None:
    admin.goto(f"{BASE}/clients", wait_until="networkidle")
    expect(admin.locator("table.clients")).to_contain_text("portainer")
    admin.get_by_role("button", name="Edit").first.click()
    expect(admin.locator("#client-form")).to_be_visible()
    assert "$pbkdf2" not in admin.content() and "$argon2" not in admin.content()
    expect(admin.get_by_text("Secret: set")).to_be_visible()


def test_rotating_a_secret_shows_it_once_masked_and_leaves_the_live_file_alone(admin: Page) -> None:
    before = clients_file()
    admin.goto(f"{BASE}/clients/1/edit", wait_until="networkidle")
    admin.once("dialog", lambda dialog: dialog.accept())
    admin.get_by_role("button", name="Generate new secret").click()
    secret_input = admin.locator("#one-time-secret")
    expect(secret_input).to_have_attribute("type", "password")  # masked until Show
    secret = secret_input.input_value()
    assert len(secret) >= 32
    done = admin.get_by_role("button", name="Done")
    expect(done).to_be_disabled()
    admin.get_by_role("button", name="Show").click()
    expect(secret_input).to_have_attribute("type", "text")
    admin.get_by_label("I have copied the secret").check()
    expect(done).to_be_enabled()
    done.click()
    admin.wait_for_url(f"{BASE}/clients")
    assert secret not in admin.content()  # gone with the dialog
    assert secret not in clients_file() and clients_file() == before  # live untouched, no plaintext
    admin.goto(f"{BASE}/review", wait_until="networkidle")
    expect(admin.get_by_text("1 new secret")).to_be_visible()
    assert secret not in admin.content() and "$pbkdf2" not in admin.content()
    expect(admin.locator("pre.diff")).to_contain_text("<hash>")


def test_editing_a_client_changes_only_that_client_in_the_diff(admin: Page) -> None:
    admin.goto(f"{BASE}/clients/1/edit", wait_until="networkidle")
    admin.locator("#f-client_name").fill("Portainer (renamed in e2e)")
    admin.get_by_role("button", name="Save to draft").click()
    admin.wait_for_url(f"{BASE}/clients?saved=2")
    admin.goto(f"{BASE}/review", wait_until="networkidle")
    added = admin.locator("pre.diff .d-add")
    expect(added).to_have_count(1)  # only the new name line: nothing else was rewritten
    expect(added).to_contain_text("Portainer (renamed in e2e)")
    assert admin.locator("pre.diff .d-del").count() == 0


def test_deleting_a_client_asks_first(admin: Page) -> None:
    admin.goto(f"{BASE}/clients/1/edit", wait_until="networkidle")
    admin.get_by_role("button", name="Delete").click()
    expect(admin.get_by_text("Delete client?")).to_be_visible()
    admin.locator("#modal").get_by_role("button", name="Cancel").click()
    expect(admin.locator("dialog")).to_have_count(0)
    assert not (STACK / "managed" / ".draft").exists()


# ----------------------------------------------------------------- users and groups (no restart)

USERS = STACK / "managed" / "users.yml"
FIRST_FACTOR = "http://127.0.0.1:19091/api/firstfactor"


def first_factor(username: str, password: str) -> int:
    import httpx

    headers = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "auth.example.test:8443",
               "X-Forwarded-For": "10.8.0.5"}  # fmt: skip
    body = {"username": username, "password": password, "keepMeLoggedIn": False}
    return httpx.post(FIRST_FACTOR, json=body, headers=headers, timeout=10).status_code


def wait_for_login(username: str, password: str, want: int, seconds: float = 20) -> bool:
    import time

    deadline = time.time() + seconds
    while time.time() < deadline:
        if first_factor(username, password) == want:
            return True
        time.sleep(3)
    return False


def test_a_user_created_in_the_ui_can_log_in_without_a_restart_and_is_then_locked_out(
    admin: Page,
) -> None:
    original = USERS.read_text()
    try:
        admin.goto(f"{BASE}/users/new", wait_until="networkidle")
        admin.locator("#f-username").fill("e2e-user")
        admin.locator("#f-displayname").fill("E2E User")
        admin.locator("#f-email").fill("e2e-user@example.test")
        admin.locator("#f-new-groups").fill("e2e-group")
        admin.get_by_role("button", name="Create user").click()
        password_input = admin.locator("#one-time-secret")
        expect(password_input).to_have_attribute("type", "password")  # masked until Show
        password = password_input.input_value()
        assert len(password) >= 8
        admin.get_by_label("I have copied the password").check()
        admin.get_by_role("button", name="Done").click()
        admin.wait_for_url(f"{BASE}/users")
        assert password not in admin.content() and password not in USERS.read_text()
        assert "$argon2" not in admin.content()
        expect(admin.locator("table.users")).to_contain_text("e2e-user")

        assert wait_for_login("e2e-user", password, 200), "the new user could not log in"

        admin.goto(f"{BASE}/users/e2e-user/edit", wait_until="networkidle")
        admin.get_by_label("Disabled").check()
        admin.get_by_role("button", name="Save").click()
        admin.wait_for_url(f"{BASE}/users?saved=e2e-user")
        expect(admin.locator("tr.is-disabled")).to_contain_text("e2e-user")
        import time

        time.sleep(5)
        assert first_factor("e2e-user", password) == 401  # disabled: refused after the reload
    finally:
        USERS.write_text(original)


def test_you_cannot_lock_yourself_out(admin: Page) -> None:
    admin.goto(f"{BASE}/users/alice/edit", wait_until="networkidle")
    admin.locator('input[name="l_groups"][value="admin"]').uncheck()
    admin.get_by_role("button", name="Save").click()
    expect(admin.get_by_text("cannot remove, disable or demote yourself")).to_be_visible()
    assert "- admin" in USERS.read_text()
    admin.goto(f"{BASE}/users/alice/edit", wait_until="networkidle")
    admin.get_by_role("button", name="Delete").click()
    admin.get_by_role("button", name="Delete user").click()
    expect(admin.locator("#flash")).to_contain_text("yourself")


def test_groups_page_shows_members_and_rules(admin: Page) -> None:
    admin.goto(f"{BASE}/groups", wait_until="networkidle")
    card = admin.locator("article.card").filter(
        has=admin.get_by_role("heading", name="family", exact=True)
    )
    expect(card).to_contain_text("Used by rule")
    expect(card.locator("ul.members")).to_contain_text("family")  # the family user is a member
    assert "$argon2" not in admin.content()


# ------------------------------------------------------------------ UI: font and columns


def column_lefts(page: Page, table: str) -> list[list[int]]:
    """x of every cell's left edge, per row (rounded to a pixel)."""
    return page.evaluate(
        """(selector) => [...document.querySelectorAll(selector + ' tr')].map(
             row => [...row.children].map(
               cell => Math.round(cell.getBoundingClientRect().left)))""",
        table,
    )


def test_the_font_is_compact_at_every_width(admin: Page) -> None:
    for width in (1280, 1920, 2560):
        admin.set_viewport_size({"width": width, "height": 900})
        open_rules(admin)
        size = admin.evaluate("() => parseFloat(getComputedStyle(document.body).fontSize)")
        assert size <= 15, (width, size)  # Pico alone would be 20-21 px here


def test_rules_columns_line_up_in_every_row_and_between_domain_groups(admin: Page) -> None:
    admin.set_viewport_size({"width": 1600, "height": 900})
    open_rules(admin)
    rows = [r for r in column_lefts(admin, "#rules-body") if len(r) == 7]
    assert len(rows) > 5 and all(r == rows[0] for r in rows), "columns shift between rows"
    header = column_lefts(admin, "#rules-table thead")[0]
    assert header == rows[0]
    admin.goto(f"{BASE}/rules?view=domain", wait_until="networkidle")
    groups = admin.evaluate(
        """() => [...document.querySelectorAll('table.rules.readonly')].map(
             t => [...t.querySelector('tr').children].map(
               c => Math.round(c.getBoundingClientRect().left)))"""
    )
    assert len(groups) > 2, groups
    assert all(g == groups[0] for g in groups), "groups do not line up"
    assert groups[0] == rows[0]


def test_other_tables_have_stable_columns(admin: Page) -> None:
    admin.set_viewport_size({"width": 1600, "height": 900})
    for path, selector in (("/clients", "table.clients"), ("/users", "table.users"),
                           ("/tests", "table.tests"),
                           ("/history", "table.history:not(.audit)")):  # fmt: skip
        admin.goto(f"{BASE}{path}", wait_until="networkidle")
        if admin.locator(f"{selector} tbody tr").count() < 2:
            continue
        rows = [r for r in column_lefts(admin, f"{selector} tbody") if len(r) > 3]
        assert rows and all(r == rows[0] for r in rows), f"{path}: columns shift between rows"


# --------------------------------------------------------------------- overview and logs


def test_overview_is_the_landing_page(admin: Page) -> None:
    admin.goto(f"{BASE}/", wait_until="networkidle")
    expect(admin.get_by_role("heading", name="Overview")).to_be_visible()
    expect(admin.get_by_role("heading", name="Needs attention")).to_be_visible()
    expect(admin.get_by_role("link", name="Overview")).to_have_attribute("aria-current", "page")


def test_a_failed_login_shows_up_under_top_problems(admin: Page) -> None:
    import time

    import httpx

    headers = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "auth.example.test:8443",
               "X-Forwarded-For": "10.8.0.77"}  # fmt: skip
    body = {"username": "nobody-e2e", "password": "wrong-password-e2e", "keepMeLoggedIn": False}
    assert httpx.post("http://127.0.0.1:19091/api/firstfactor", json=body, headers=headers,
                      timeout=10).status_code == 401  # fmt: skip
    for _ in range(10):  # the log line is written a moment later
        admin.goto(f"{BASE}/logs?level=error&window=1h", wait_until="networkidle")
        if admin.locator(
            'table.log-table td[data-label="Remote IP"]', has_text="10.8.0.77"
        ).count():
            break
        time.sleep(1)
    expect(admin.get_by_role("heading", name="Top problems")).to_be_visible()
    expect(
        admin.locator("table.problems-table").get_by_text("Unsuccessful 1FA").first
    ).to_be_visible()
    expect(
        admin.locator('table.log-table td[data-label="Remote IP"]', has_text="10.8.0.77").first
    ).to_be_visible()
    admin.set_viewport_size({"width": 1600, "height": 900})
    rows = [r for r in column_lefts(admin, "table.log-table tbody") if len(r) > 3]
    assert rows and all(r == rows[0] for r in rows)
    # fetched by the page itself: Playwright's request API ignores Chromium's host-resolver rule
    ok, text = admin.evaluate(
        "async (url) => { const r = await fetch(url); return [r.ok, await r.text()]; }",
        "/logs/download?level=error&window=1h",
    )
    assert ok and "Unsuccessful 1FA" in text
