"""The UI end to end through the ASGI app (security layer included)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.settings import Settings

PROXY, VPN = "172.20.0.2", "10.8.0.5"
HASH = "$" + "argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2hoYXNo"

ACCESS_CONTROL = """access_control:
  default_policy: deny

  rules:
    # Portal endpoints must stay public for OIDC
    - domain: auth.example.com
      resources:
        - '^/\\.well-known/openid-configuration$'
        - '^/jwks\\.json$'
        - '^/api/oidc/.*'
      policy: bypass

    - domain: authcfg.example.com
      networks: [10.8.0.0/24]
      subject: 'group:admin'
      policy: two_factor

    - domain: authcfg.example.com
      policy: deny

    # Photos
    - domain: photos.example.com
      resources:
        - '^/api/ping$'
      policy: bypass

    - domain: photos.example.com
      subject:
        - ['group:family']
        - ['user:carol']
      policy: two_factor

    - domain: '*.example.com'
      subject: 'group:admin'
      policy: two_factor
"""


@pytest.fixture
def env(tmp_path: Path) -> dict[str, Path]:
    managed = tmp_path / "managed"
    managed.mkdir()
    (managed / "access_control.yml").write_text(ACCESS_CONTROL)
    users = tmp_path / "users.yml"
    users.write_text(
        f"users:\n  alice:\n    password: '{HASH}'\n    groups: [admin]\n"
        "  bob:\n    groups: [family, home]\n"
    )
    main = tmp_path / "configuration.yml"
    main.write_text("theme: light\n")
    return {"managed": managed, "users": users, "main": main}


class UI:
    def __init__(
        self,
        env: dict[str, Path],
        user: str = "alice",
        groups: str = "admin",
        services: Any = None,
    ) -> None:
        settings = Settings(
            AUTH_DOMAIN="auth.example.com",
            CONFIGURATOR_DOMAIN="authcfg.example.com",
            ADMIN_GROUP="admin",
            ALLOWED_CLIENT_CIDRS="10.8.0.0/24",  # type: ignore[arg-type]
            TRUSTED_PROXY_CIDRS="172.20.0.0/16",  # type: ignore[arg-type]
            AUTHELIA_CONTAINER="authelia",
            AUTHELIA_HEALTH_URL="http://authelia:9091/api/health",
            APP_SECRET_KEY="k" * 40,  # type: ignore[arg-type]
            CONFIG_MANAGED_DIR=env["managed"],
            USERS_FILE=env["users"],
            CONFIG_MAIN=env["main"],
            AUTHELIA_BINARY="authelia-not-installed",
            AUTHELIA_VERSION="4.39.28",
        )
        self.settings = settings
        self.client = TestClient(
            create_app(settings, services), client=(PROXY, 5000),
            base_url="https://authcfg.example.com",
        )  # fmt: skip
        self.headers = {"Remote-User": user, "Remote-Groups": groups, "X-Forwarded-For": VPN}
        self.env = env

    def get(self, path: str, htmx: bool = False, **kw: str):  # type: ignore[no-untyped-def]
        headers = {**self.headers, **({"HX-Request": "true"} if htmx else {})}
        return self.client.get(path, headers=headers, follow_redirects=False, **kw)

    def token(self) -> str:
        page = self.get("/rules").text
        return re.search(r'name="csrf-token" content="([^"]+)"', page).group(1)  # type: ignore[union-attr]

    def rev(self) -> str:
        page = self.get("/rules").text
        return re.search(r'id="rules-section" data-rev="([^"]+)"', page).group(1)  # type: ignore[union-attr]

    def post(self, path: str, data: dict[str, str] | None = None, rev: str | None = "auto"):  # type: ignore[no-untyped-def]
        body = dict(data or {})
        if rev == "auto":
            body["rev"] = self.rev()
        elif rev is not None:
            body["rev"] = rev
        headers = {**self.headers, "HX-Request": "true", "X-CSRF-Token": self.token(),
                   "Origin": "https://authcfg.example.com"}  # fmt: skip
        return self.client.post(path, data=body, headers=headers, follow_redirects=False)

    def domains(self) -> list[str]:
        from app.rules.store import DraftStore

        return [str(r["domain"]) for r in DraftStore(self.env["managed"]).current().rules()]


@pytest.fixture
def ui(env: dict[str, Path]) -> UI:
    return UI(env)


# --------------------------------------------------------------------- rendering


def test_rules_page_lists_rules_with_badges_and_locks(ui: UI) -> None:
    r = ui.get("/rules")
    assert r.status_code == 200
    html = r.text
    assert "photos.example.com" in html and "*.example.com" in html
    assert html.count('class="badge bypass"') == 2 and 'class="badge deny"' in html
    assert "BYPASS" in html and "2FA" in html and "DENY" in html  # text, not only colour
    assert "Portal endpoints must stay public for OIDC" in html  # the note
    assert html.count('title="Protected rule') == 3  # portal, admin and deny rules
    assert "3 paths" in html and "1 path<" in html
    assert "group:family  or  user:carol" in html
    assert "default policy" in html and 'value="deny" selected' in html


def test_page_never_contains_secrets_and_is_csp_clean(ui: UI) -> None:
    for path in ("/rules", "/rules?edit=0", "/rules/new", "/review", "/tester"):
        text = ui.get(path, htmx=path in ("/tester",)).text
        assert HASH not in text and "c2FsdHNhbHQ" not in text  # no hash material, ever
        assert not re.search(r"<script(?![^>]*\bsrc=)", text), path  # no inline scripts
        assert " style=" not in text and not re.search(r"\son\w+=", text), path


def test_templates_have_no_inline_script_style_or_event_handlers() -> None:
    root = Path(__file__).resolve().parents[2] / "app" / "templates"
    for path in root.rglob("*.html"):
        text = path.read_text()
        assert not re.search(r"<script(?![^>]*\bsrc=)", text), path
        assert " style=" not in text and "javascript:" not in text, path
        assert not re.search(r"\son[a-z]+=", text) and "hx-on" not in text, path


def test_static_assets_are_served_and_cacheable(ui: UI) -> None:
    for name in ("vendor/pico.min.css", "vendor/htmx.min.js", "vendor/Sortable.min.js", "app.js"):
        r = ui.get(f"/static/{name}")
        assert r.status_code == 200 and "max-age" in r.headers["cache-control"]
    assert ui.get("/rules").headers["cache-control"] == "no-store"


def test_non_admin_and_outside_networks_are_denied(env: dict[str, Path]) -> None:
    assert UI(env, user="bob", groups="family").get("/rules").status_code == 403
    ui = UI(env)
    ui.headers["X-Forwarded-For"] = "203.0.113.9"
    assert ui.get("/rules").status_code == 403


def test_missing_live_file_shows_a_helpful_page(env: dict[str, Path]) -> None:
    (env["managed"] / "access_control.yml").unlink()
    r = UI(env).get("/rules")
    assert r.status_code == 503 and "migration script" in r.text


def test_filter_and_by_domain_views(ui: UI) -> None:
    filtered = ui.get("/rules?q=family").text
    assert filtered.count('data-index="') == 1 and "photos.example.com" in filtered
    assert "Clear the filter to reorder" in filtered
    grouped = ui.get("/rules?view=domain").text
    assert '<h2 class="group-title">photos.example.com</h2>' in grouped


# --------------------------------------------------------------------- mutations


def test_move_creates_a_draft_and_never_touches_live(ui: UI) -> None:
    live = (ui.env["managed"] / "access_control.yml").read_text()
    r = ui.post("/rules/move", {"src": "3", "dst": "4"})
    assert r.status_code == 200
    assert 'id="draftbar" hx-swap-oob="true"' in r.text and "1 unapplied change" in r.text
    assert 'class="status-moved"' in r.text
    assert ui.domains()[3:5] == ["photos.example.com", "photos.example.com"]
    assert (ui.env["managed"] / "access_control.yml").read_text() == live
    assert (ui.env["managed"] / ".draft" / "access_control.yml").is_file()


def test_move_buttons_and_edges(ui: UI) -> None:
    assert ui.post("/rules/5/move", {"dir": "up"}).status_code == 200
    assert ui.domains()[4] == "*.example.com"
    assert ui.post("/rules/5/move", {"dir": "down"}).status_code == 200  # edge: no-op
    assert ui.post("/rules/99/move", {"dir": "up"}).status_code == 404


def test_stale_revision_is_rejected_with_a_message(ui: UI) -> None:
    r = ui.post("/rules/move", {"src": "3", "dst": "4"}, rev="deadbeef")
    assert r.status_code == 409 and r.headers["hx-reswap"] == "none"
    assert "changed in another tab" in r.text and 'id="flash"' in r.text
    assert not (ui.env["managed"] / ".draft").exists()


def test_weakening_a_protected_rule_is_refused(ui: UI) -> None:
    # deny rule above the admin rule locks the admin out of the configurator
    r = ui.post("/rules/move", {"src": "2", "dst": "1"})
    assert r.status_code == 422 and "weaken a protected rule" in r.text
    assert not (ui.env["managed"] / ".draft").exists()


def test_cannot_delete_a_protected_rule_but_can_delete_others(ui: UI) -> None:
    confirm = ui.get("/rules/1/delete", htmx=True).text
    assert "protected rule and cannot be deleted" in confirm and "hx-post" not in confirm
    assert ui.post("/rules/1/delete").status_code == 422
    ok = ui.get("/rules/3/delete", htmx=True).text
    assert "Delete rule #4?" in ok and "photos.example.com" in ok
    assert ui.post("/rules/3/delete").status_code == 200
    assert len(ui.domains()) == 5


def test_default_policy_change(ui: UI) -> None:
    r = ui.post("/rules/default-policy", {"policy": "one_factor"})
    assert r.status_code == 200 and "Default policy set to one_factor" in r.text
    assert ui.post("/rules/default-policy", {"policy": "allow"}).status_code == 400
    from app.rules.store import DraftStore

    assert DraftStore(ui.env["managed"]).current().default_policy() == "one_factor"


def test_save_new_rule_and_edit_existing(ui: UI) -> None:
    created = ui.post(
        "/rules/save",
        {"index": "", "domain": "notes.example.com", "resources": "^/api/.*$",
         "subject": "group:family\nuser:bob and group:home", "policy": "two_factor",
         "note": "Notes app"},
    )  # fmt: skip
    assert created.status_code == 204 and created.headers["hx-redirect"] == "/rules?saved=7"
    from app.rules.store import DraftStore

    rules = DraftStore(ui.env["managed"]).current().rules()
    assert rules[-1]["domain"] == "notes.example.com"
    assert rules[-1]["subject"] == [["group:family"], ["user:bob", "group:home"]]

    edited = ui.post(
        "/rules/save",
        {"index": "3", "domain": "photos.example.com", "resources": "^/api/ping$\n^/api/version$",
         "subject": "", "policy": "bypass", "note": ""},
    )  # fmt: skip
    assert edited.status_code == 204
    assert DraftStore(ui.env["managed"]).current().rules()[3]["resources"] == [
        "^/api/ping$", "^/api/version$",
    ]  # fmt: skip


@pytest.mark.parametrize(
    ("fields", "fragment"),
    [
        ({"domain": "", "policy": "deny"}, "domain"),
        ({"domain": "a.example.com", "policy": "nope"}, "Policy"),
        ({"domain": "a.example.com", "policy": "deny", "resources": "^(?!/x).*$"}, "RE2"),
        ({"domain": "a.example.com", "policy": "bypass", "subject": "group:x"}, "bypass"),
        ({"domain": "a.example.com", "policy": "deny", "extra_yaml": "- list"}, "mapping"),
    ],
)
def test_invalid_rule_is_rejected_with_a_reason(
    ui: UI, fields: dict[str, str], fragment: str
) -> None:
    r = ui.post("/rules/save", {"index": "", **fields})
    assert r.status_code == 422 and fragment in r.text
    assert not (ui.env["managed"] / ".draft").exists()


def test_inline_validation_disables_save_on_blocking_errors(ui: UI) -> None:
    bad = ui.post("/rules/validate", {"index": "", "domain": "a.example.com", "policy": "deny",
                                      "resources": "(?=x)"}, rev=None)  # fmt: skip
    assert "Blocking" in bad.text and re.search(r'id="save-btn"[^>]*disabled', bad.text)
    good = ui.post(
        "/rules/validate", {"index": "", "domain": "a.example.com", "policy": "deny"}, rev=None
    )
    assert "Looks valid" in good.text and not re.search(r'id="save-btn"[^>]*disabled', good.text)


def test_raw_yaml_editor_round_trip(ui: UI) -> None:
    page = ui.get("/rules/3/raw")
    assert page.status_code == 200 and "domain: photos.example.com" in page.text
    bad = ui.post("/rules/3/raw", {"text": "- not a mapping"})
    assert bad.status_code == 422
    ok = ui.post(
        "/rules/3/raw", {"text": "domain: photos.example.com\npolicy: deny  # tightened\n"}
    )
    assert ok.status_code == 204
    from app.rules.store import DraftStore

    assert "# tightened" in DraftStore(ui.env["managed"]).current().render()


# --------------------------------------------------------------------- tester / review / discard


def test_tester_dialog_autofills_groups_and_explains_results(ui: UI) -> None:
    dialog = ui.get("/tester", htmx=True).text
    assert "(anonymous)" in dialog and "alice" in dialog and "bob" in dialog
    assert 'value="family, home"' in ui.get("/tester/groups?user=bob", htmx=True).text

    def run(**kw: str) -> str:
        return ui.post("/tester/run", {"url": "https://photos.example.com/api/ping",
                                       "method": "GET", **kw}, rev=None).text  # fmt: skip

    anonymous = run()
    assert "Rule #4 matches" in anonymous and "BYPASS" in anonymous
    assert "Rules #1-3 skipped: different domain" in anonymous
    family = run(url="https://photos.example.com/other", user="bob", groups="family")
    assert "Rule #5 matches" in family and "2FA" in family
    anon_login = run(url="https://photos.example.com/other")
    assert "sent to log in first" in anon_login
    nomatch = run(url="https://other.test/")
    assert "No rule matches" in nomatch and "DENY" in nomatch
    assert "URL must be absolute" in run(url="photos.example.com/x")


def test_review_page_shows_diff_and_disabled_apply(ui: UI) -> None:
    empty = ui.get("/review").text
    assert "No unapplied changes" in empty
    ui.post("/rules/move", {"src": "3", "dst": "4"})
    page = ui.get("/review").text
    assert "order changed" in page and 'class="d-add"' in page and 'class="d-del"' in page
    assert re.search(r"<button[^>]*disabled[^>]*>Validate &amp; apply", page)
    assert "not available in this environment" in page  # no authelia binary in the test env
    assert "satisfied" in page


def test_discard_confirm_then_discard(ui: UI) -> None:
    ui.post("/rules/move", {"src": "3", "dst": "4"})
    assert "Discard the draft?" in ui.get("/draft/discard", htmx=True).text
    r = ui.post("/draft/discard")
    assert r.status_code == 204 and r.headers["hx-redirect"] == "/rules"
    assert not (ui.env["managed"] / ".draft" / "access_control.yml").exists()


def test_stale_draft_is_flagged_everywhere(ui: UI) -> None:
    ui.post("/rules/move", {"src": "3", "dst": "4"})
    live = ui.env["managed"] / "access_control.yml"
    live.write_text(live.read_text() + "\n# changed over ssh\n")
    assert "the live file changed since this draft started" in ui.get("/rules").text
    assert "The live file changed after this draft" in ui.get("/review").text


# --------------------------------------------------------------------- review findings


def test_protected_rule_cannot_be_edited_even_bypassing_the_ui(ui: UI) -> None:
    """The editor disables protected rules; the server must refuse too (SPEC §4)."""
    r = ui.post("/rules/save", {"index": "1", "domain": "authcfg.example.com",
                                "networks": "10.8.0.0/24", "subject": "group:admin",
                                "policy": "two_factor", "note": "harmless looking"})  # fmt: skip
    assert r.status_code == 422 and "read-only" in r.text
    raw = ui.post("/rules/1/raw", {"text": "domain: authcfg.example.com\npolicy: two_factor\n"})
    assert raw.status_code == 422
    assert not (ui.env["managed"] / ".draft" / "access_control.yml").exists()


def test_sneaky_path_limited_bypass_on_the_configurator_is_refused(ui: UI) -> None:
    """Appended at the end it sits below the explicit deny and is harmless (accepted);
    moving it above the admin rule would open a path of the admin UI, so that is refused."""
    r = ui.post("/rules/save", {"index": "", "domain": "authcfg.example.com",
                                "resources": "^/version$", "policy": "bypass"})  # fmt: skip
    assert r.status_code == 204
    moved = ui.post("/rules/move", {"src": "6", "dst": "1"})
    assert moved.status_code == 422 and "weaken a protected rule" in moved.text
    assert ui.domains()[1] == "authcfg.example.com" and ui.domains()[6] == "authcfg.example.com"


def test_subject_lines_split_on_and_and_plus_in_linear_time() -> None:
    import time

    from app.ui import parse_subject_lines

    assert parse_subject_lines("user:alice and group:dev\ngroup:admin\n  \nuser:bob + group:x") == [
        ["user:alice", "group:dev"], ["group:admin"], ["user:bob", "group:x"]]  # fmt: skip
    assert parse_subject_lines("group:a AND group:b") == [["group:a", "group:b"]]
    assert parse_subject_lines("user:a+group:b") == [["user:a+group:b"]]  # needs spaces, as before
    assert parse_subject_lines("and group:a and") == [["group:a"]]
    started = time.monotonic()
    parse_subject_lines("a" + " " * 200_000 + "b")  # the ReDoS input for the old regex
    assert time.monotonic() - started < 1


def test_the_status_bar_shows_the_address_the_configurator_sees(ui: UI) -> None:
    assert f"you: <strong>{VPN}</strong>" in ui.get("/rules").text


def test_any_network_mode_is_announced_on_every_page(env: dict[str, Path]) -> None:
    ui = UI(env)
    assert "Reachable from any network" not in ui.get("/rules").text
    ui.settings.ALLOW_ANY_CLIENT_NETWORK = True
    assert "Reachable from any network" in ui.get("/rules").text
