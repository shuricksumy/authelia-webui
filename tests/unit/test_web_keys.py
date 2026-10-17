"""Keys page, certificate banner and the keys step endpoint through HTTP."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from app import certs
from app.apply import keys
from app.oidc.jwks import entry_lines, key_path, new_document
from tests.unit.test_web import UI, env  # noqa: F401  (fixture)


def jwks(env: dict[str, Path], *kids: str) -> None:  # noqa: F811
    entries = []
    for kid in kids:
        path = key_path(env["managed"], kid)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"fake")
        entries.append(entry_lines(kid, "RS256", path))
    (env["managed"] / "oidc_jwks.yml").write_text(new_document(entries).render())


def test_keys_page_explains_the_one_time_move(env: dict[str, Path]) -> None:  # noqa: F811
    page = UI(env).get("/keys").text
    assert "Key rotation is not set up yet" in page and "migrate_jwks" in page
    assert 'aria-current="page">Keys<' in page


def test_keys_page_lists_roles_and_offers_the_right_steps(env: dict[str, Path]) -> None:  # noqa: F811
    jwks(env, "first")
    ui = UI(env)
    ui.settings.CONFIG_FILTERS = "template"
    page = ui.get("/keys").text
    assert "first" in page and "signing" in page and "1. Add a new key" in page
    assert "Make it sign" not in page and "fake" not in page
    jwks(env, "first", "second")
    page = ui.get("/keys").text
    assert "published" in page and "Make it sign" in page and "1. Add a new key" not in page
    assert "Rotation in progress" in page


def test_keys_page_needs_the_template_filter(env: dict[str, Path]) -> None:  # noqa: F811
    jwks(env, "first")
    assert "CONFIG_FILTERS=template" in UI(env).get("/keys").text


def test_a_step_is_refused_with_reasons_and_changes_nothing(env: dict[str, Path]) -> None:  # noqa: F811
    jwks(env, "first")
    ui = UI(env)
    ui.settings.CONFIG_FILTERS = "template"
    before = (env["managed"] / "oidc_jwks.yml").read_text()
    r = ui.post("/keys/promote", {"kid": "first", "keys_rev": keys_rev(ui)}, rev=None)
    assert r.status_code == 422 and "first key signs" in r.text
    r = ui.post("/keys/prepare", {"keys_rev": "0" * 16}, rev=None)
    assert r.status_code == 422 and "keys changed" in r.text
    assert (env["managed"] / "oidc_jwks.yml").read_text() == before
    assert ui.post("/keys/explode", {}, rev=None).status_code == 422


def keys_rev(ui: UI) -> str:
    m = re.search(r'name="keys_rev" value="([0-9a-f]+)"', ui.get("/keys").text)
    return m.group(1) if m else ""


def test_certificate_warnings_show_in_the_banner_the_overview_and_the_page(
    env: dict[str, Path],  # noqa: F811
) -> None:
    ui = UI(env)
    soon = certs.CertInfo("TLS auth.example.com:443", "auth.example.com",
                          datetime.now(UTC) + timedelta(days=5, hours=1))  # fmt: skip
    fine = certs.CertInfo("OIDC key a", "x", datetime.now(UTC) + timedelta(days=200))
    watcher = ui.client.app.state.services.certs  # type: ignore[attr-defined]
    watcher._collector = lambda s: [soon, fine]
    watcher.refresh()
    for path in ("/rules", "/keys", "/"):
        text = ui.get(path).text
        assert "expires soon" in text or "Certificate TLS auth.example.com" in text
    assert "expires in 5 days" in ui.get("/keys").text
    assert "Certificate TLS auth.example.com:443" in ui.get("/").text


def test_history_labels_key_commits_without_a_revert_button(env: dict[str, Path]) -> None:  # noqa: F811
    jwks(env, "first")
    ui = UI(env)
    services: Any = ui.client.app.state.services  # type: ignore[attr-defined]
    services.repo.ensure(("access_control.yml", "oidc_jwks.yml"))
    (env["managed"] / "oidc_jwks.yml").write_text(
        (env["managed"] / "oidc_jwks.yml").read_text() + "# touched\n"
    )
    services.repo.commit(["oidc_jwks.yml"], "OIDC keys: retired key x", "", "alice")
    page = ui.get("/history").text
    row = page.split("OIDC keys: retired key x")[1].split("</tr>")[0]
    assert "OIDC keys (restarts Authelia)" in row and "Revert to this" not in row


def test_keys_module_exposes_the_documented_actions() -> None:
    assert keys.ACTIONS == ("prepare", "promote", "retire")


@pytest.mark.parametrize("path", ["/keys"])
def test_keys_need_the_admin_identity(env: dict[str, Path], path: str) -> None:  # noqa: F811
    assert UI(env, user="bob", groups="family").get(path).status_code == 403
