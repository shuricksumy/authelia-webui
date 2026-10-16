"""Phase 1c pages: disabled rules, access tests, the accept gate, banners (through HTTP)."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from app.rules import access_tests
from tests.unit.test_web import UI, env  # noqa: F401  (fixture)
from tests.unit.test_web_apply import build, wait_done


def managed_git(
    env: dict[str, Path],  # noqa: F811
    *args: str,
) -> str:
    return subprocess.run(
        ["git", "-C", str(env["managed"]), *args], capture_output=True, text=True, check=True
    ).stdout


# --------------------------------------------------------------------- disabled rules


def test_disable_then_enable_restores_the_file_byte_for_byte(env: dict[str, Path]) -> None:  # noqa: F811
    ui = UI(env)
    live = (env["managed"] / "access_control.yml").read_text()
    before = ui.domains()
    page = ui.post("/rules/3/disable")
    assert page.status_code == 200 and "Disabled rules" in page.text
    assert len(ui.domains()) == len(before) - 1
    assert "Enable" in ui.get("/rules").text
    assert (env["managed"] / "access_control.yml").read_text() == live  # live is never touched
    assert ui.post("/disabled/0/enable").status_code == 200
    assert ui.domains() == before
    assert "Disabled rules" not in ui.get("/rules").text


def test_locked_rule_cannot_be_disabled(env: dict[str, Path]) -> None:  # noqa: F811
    ui = UI(env)
    assert ui.post("/rules/1/disable").status_code == 422
    assert "/rules/1/disable" not in ui.get("/rules").text  # no button on locked rows


def test_delete_disabled_rule_permanently_asks_first(env: dict[str, Path]) -> None:  # noqa: F811
    ui = UI(env)
    ui.post("/rules/3/disable")
    confirm = ui.get("/disabled/0/delete", htmx=True).text
    assert "Delete disabled rule permanently?" in confirm and "cannot be enabled again" in confirm
    assert ui.post("/disabled/0/delete").status_code == 200
    assert "Disabled rules" not in ui.get("/rules").text
    assert ui.post("/disabled/0/enable").status_code == 404  # gone


def test_review_counts_disabled_rules(env: dict[str, Path]) -> None:  # noqa: F811
    ui = UI(env)
    ui.post("/rules/3/disable")
    page = ui.get("/review").text
    assert "1 disabled" in page and "removed" not in page.split("Lint")[0]


# --------------------------------------------------------------------- access tests


def current_tests_rev(ui: UI) -> str:
    page = ui.get("/tests/new", htmx=True).text
    return re.search(r'name="tests_rev" value="([0-9a-f]+)"', page).group(1)  # type: ignore[union-attr]


def save_test(ui: UI, data: dict[str, str]):  # type: ignore[no-untyped-def]
    return ui.post("/tests/save", {**data, "tests_rev": current_tests_rev(ui)})


def delete_test(ui: UI, index: int):  # type: ignore[no-untyped-def]
    return ui.post(f"/tests/{index}/delete", {"tests_rev": current_tests_rev(ui)})


CASE = {"url": "https://photos.example.com/api/ping", "method": "GET", "user": "",
        "groups": "", "ip": "", "expect": "bypass", "name": "Ping stays open"}  # fmt: skip


def test_add_edit_delete_tests_commit_immediately(env: dict[str, Path]) -> None:  # noqa: F811
    ui = UI(env)
    assert "No tests yet" in ui.get("/tests").text
    r = save_test(ui, CASE)
    assert r.status_code == 204 and r.headers["HX-Redirect"] == "/tests"
    assert len(access_tests.load(env["managed"])) == 1
    assert "Tests: added Ping stays open" in managed_git(env, "log", "-1", "--format=%s")
    assert "Ping stays open" in ui.get("/tests").text
    edited = {**CASE, "index": "0", "expect": "deny", "name": "Ping is closed"}
    assert save_test(ui, edited).status_code == 204
    assert access_tests.load(env["managed"])[0].expect == "deny"
    assert delete_test(ui, 0).status_code == 204
    assert access_tests.load(env["managed"]) == []
    assert "Tests: removed" in managed_git(env, "log", "-1", "--format=%s")


def test_invalid_test_is_rejected_with_a_reason(env: dict[str, Path]) -> None:  # noqa: F811
    ui = UI(env)
    bad = save_test(ui, {**CASE, "url": "not a url"})
    assert bad.status_code == 422 and "must be absolute" in bad.text
    bad = save_test(ui, {**CASE, "ip": "999.1.1.1"})
    assert bad.status_code == 422 and "not a valid IP" in bad.text
    assert not (env["managed"] / "access_tests.yml").exists()


def test_tester_offers_add_as_test_prefilled(env: dict[str, Path]) -> None:  # noqa: F811
    ui = UI(env)
    page = ui.post("/tester/run", {"url": "https://photos.example.com/x", "method": "GET"}).text
    assert "Add as test" in page and "/tests/new?" in page and "expect=" in page
    form = ui.get("/tests/new?url=https%3A%2F%2Fphotos.example.com%2Fx&expect=deny", htmx=True).text
    assert 'value="https://photos.example.com/x"' in form
    assert re.search(r'<option value="deny"\s+selected', form)


# --------------------------------------------------------------------- the accept gate


def test_failing_test_needs_acceptance_before_apply(env: dict[str, Path]) -> None:  # noqa: F811
    ui, _, _ = build(env, [True])
    save_test(ui, CASE)  # the photos ping is bypass
    ui.post("/rules/move", {"src": "3", "dst": "4"})  # the 2FA photos rule now matches first
    page = ui.get("/review").text
    assert "would not get the expected result" in page
    assert re.search(r'<button[^>]*id="apply-button"[^>]*disabled', page)
    assert 'name="accept_tests"' in page
    refused = ui.post("/apply")
    assert refused.status_code == 422 and "access test" in refused.text
    ok = ui.post("/apply", {"accept_tests": "1"})
    assert ok.status_code == 200 and "apply-progress" in ok.text
    wait_done(ui)


def test_passing_tests_do_not_gate_apply(env: dict[str, Path]) -> None:  # noqa: F811
    ui, _, _ = build(env, [True])
    save_test(ui, CASE)
    ui.post("/rules/default-policy", {"policy": "one_factor"})  # does not touch the ping rule
    page = ui.get("/review").text
    assert "Access tests" in page and 'name="accept_tests"' not in page
    assert ui.post("/apply").status_code == 200
    wait_done(ui)


# --------------------------------------------------------------------- banners and history


def test_hand_edit_is_committed_and_announced(env: dict[str, Path]) -> None:  # noqa: F811
    ui, _, _ = build(env, [True])
    save_test(ui, CASE)  # creates the repository
    live = env["managed"] / "access_control.yml"
    live.write_text(live.read_text() + "# edited over ssh\n")
    page = ui.get("/rules").text
    assert "edited outside the configurator" in page
    assert "External change" in managed_git(env, "log", "-1", "--format=%s")
    history = ui.get("/history").text
    assert "edited outside the configurator" in history
    assert ui.post("/notices/external/seen").status_code == 200
    assert (
        "edited outside the configurator"
        not in ui.get("/rules").text.split("</header>")[1].split("<main")[0]
    )


def test_main_config_change_banner_revalidate_and_mark_seen(env: dict[str, Path]) -> None:  # noqa: F811
    ui, _, _ = build(env, [True])
    ui.post("/rules/move", {"src": "3", "dst": "4"})
    ui.post("/apply")
    wait_done(ui)
    assert "main Authelia configuration changed" not in ui.get("/rules").text
    env["main"].write_text("theme: dark\n")
    assert "main Authelia configuration changed" in ui.get("/rules").text
    page = ui.post("/notices/main/revalidate").text
    assert "Authelia accepts the current configuration" in page
    assert ui.post("/notices/main/seen").status_code == 200
    assert "main Authelia configuration changed" not in ui.get("/rules").text


def test_test_edits_are_refused_when_the_file_changed_meanwhile(env: dict[str, Path]) -> None:  # noqa: F811
    ui = UI(env)
    save_test(ui, CASE)
    old = current_tests_rev(ui)
    save_test(ui, {**CASE, "name": "second"})  # someone else adds a test
    r = ui.post("/tests/0/delete", {"tests_rev": old})
    assert r.status_code == 422 and "changed in the meantime" in r.text
    assert len(access_tests.load(env["managed"])) == 2
    assert ui.post("/tests/save", {**CASE, "tests_rev": "0" * 16}).status_code == 422


def test_test_name_is_one_bounded_line_in_the_commit(env: dict[str, Path]) -> None:  # noqa: F811
    ui = UI(env)
    save_test(ui, {**CASE, "name": "two\nlines " + "x" * 500})
    subject = managed_git(env, "log", "-1", "--format=%B").strip()
    assert "\n" not in subject and len(subject) <= 120


def test_disabled_entry_with_extra_text_is_rejected(env: dict[str, Path]) -> None:  # noqa: F811
    from app.rules.disabled import DisabledRules
    from app.rules.document import DocumentError

    sneaky = (
        "disabled_rules:\n  - position: 0\n    yaml: |\n"
        "      session:\n        expiration: 1y\n"
        "      - domain: x.example.com\n        policy: bypass\n"
    )
    trailing = (
        "disabled_rules:\n  - position: 0\n    yaml: |\n"
        "          - domain: x.example.com\n            policy: bypass\n"
        "      session: {}\n"
    )
    for text in (sneaky, trailing):
        try:
            DisabledRules.parse(text)
        except DocumentError:
            continue
        raise AssertionError("accepted: " + text)
