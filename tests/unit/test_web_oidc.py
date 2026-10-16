"""OIDC clients pages through HTTP (Phase 2a), with the secret-hygiene guarantees."""

from __future__ import annotations

import logging
import re
from pathlib import Path

import pytest

from app.authelia_cli import AutheliaCLI
from app.rules.store import DraftStore
from tests.unit.test_oidc import FAKE_DIGEST, FAKE_DIGEST_2
from tests.unit.test_web import UI, env  # noqa: F401  (fixture)

PLAINTEXT = "one-time-plaintext-secret-value"

MAIN = """identity_providers:
  oidc:
    hmac_secret: 'not-a-real-hmac-value'
    authorization_policies:
      family_only:
        default_policy: deny
    claims_policies:
      default:
        id_token: ['groups']
    scopes:
      photos_scope:
        claims: ['photo_quota']
"""
CLIENTS = f"""identity_providers:
  oidc:
    clients:
      # Garage door app
      - client_id: 'garage'
        client_name: 'Garage'
        client_secret: '{FAKE_DIGEST}'
        authorization_policy: 'two_factor'
        redirect_uris:
          - 'https://garage.example.com/cb'
        scopes: ['openid', 'groups']
        #consent_mode: 'explicit'
        consent_mode: 'auto'

      - client_id: 'spa'
        public: true
        require_pkce: true
        pkce_challenge_method: 'S256'
        redirect_uris: ['https://spa.example.com/cb']
"""


@pytest.fixture
def oidc(env: dict[str, Path], monkeypatch: pytest.MonkeyPatch) -> UI:  # noqa: F811
    env["main"].write_text(MAIN)
    (env["managed"] / "oidc_clients.yml").write_text(CLIENTS)
    digests = iter([FAKE_DIGEST_2, FAKE_DIGEST])
    monkeypatch.setattr(AutheliaCLI, "hash_random_pbkdf2", lambda self: (PLAINTEXT, next(digests)))
    monkeypatch.setattr(AutheliaCLI, "rand_client_id", lambda self: "generated-id-123")
    return UI(env)


def everything_on_disk(managed: Path) -> str:
    return "\n".join(p.read_text(errors="replace") for p in managed.rglob("*") if p.is_file()
                     and ".git" not in p.parts)  # fmt: skip


def test_list_page_shows_clients_without_hashes(oidc: UI) -> None:
    page = oidc.get("/clients").text
    assert "Garage" in page and "garage.example.com" in page and "spa" in page
    assert "pbkdf2" not in page and "dummy-hash" not in page
    assert 'aria-current="page"' in page.split("OIDC Clients")[0][-200:] or "/clients" in page


def test_editor_never_holds_the_hash_and_offers_names_only(oidc: UI) -> None:
    page = oidc.get("/clients/0/edit").text
    assert "dummy-hash" not in page and "pbkdf2 hash" in page  # kind shown, value never
    assert "family_only" in page and "photos_scope" in page and "default" in page
    assert "not-a-real-hmac-value" not in page
    assert "client_secret" not in page.split('name="extra_yaml"')[1].split("</textarea>")[0]


def test_saving_an_edit_keeps_the_hash_and_the_other_client(oidc: UI, env: dict[str, Path]) -> None:  # noqa: F811
    r = oidc.post("/clients/save", {
        "index": "0", "client_id": "garage", "s_client_name": "Garage door",
        "b_public": "false", "s_authorization_policy": "two_factor",
        "s_token_endpoint_auth_method": "__unset__", "b_require_pkce": "__unset__",
        "s_pkce_challenge_method": "__unset__", "s_claims_policy": "__unset__",
        "s_consent_mode": "auto", "l_redirect_uris": "https://garage.example.com/cb",
        "present_redirect_uris": "1", "l_scopes": ["openid", "groups"], "present_scopes": "1",
    })  # fmt: skip
    assert r.status_code == 204, r.text
    draft = DraftStore(env["managed"]).current_clients_text()
    assert "client_name: Garage door" in draft or "client_name: 'Garage door'" in draft
    assert FAKE_DIGEST in draft and "#consent_mode: 'explicit'" in draft
    assert "      - client_id: 'spa'\n        public: true" in draft  # untouched, byte-identical
    assert (env["managed"] / "oidc_clients.yml").read_text() == CLIENTS  # live untouched


def test_new_confidential_client_shows_the_secret_once_and_stores_the_hash(
    oidc: UI,
    env: dict[str, Path],  # noqa: F811
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    r = oidc.post("/clients/save", {
        "client_id": "photos", "b_public": "false", "s_authorization_policy": "two_factor",
        "l_redirect_uris": "https://photos.example.com/auth/login", "l_scopes": ["openid"],
        "present_scopes": "1", "s_token_endpoint_auth_method": "client_secret_basic",
    })  # fmt: skip
    assert r.status_code == 200, r.text
    assert PLAINTEXT in r.text and 'type="password"' in r.text  # masked until "Show"
    assert "no-store" in r.headers["cache-control"] and r.headers["hx-retarget"] == "#modal"
    assert "I have copied the secret" in r.text and "https://auth.example.com" in r.text
    draft = DraftStore(env["managed"]).current_clients_text()
    assert FAKE_DIGEST_2 in draft and "photos" in draft
    assert PLAINTEXT not in everything_on_disk(env["managed"])  # draft, audit log, everything
    assert PLAINTEXT not in caplog.text
    assert "client-secret" in (env["managed"] / "audit.log").read_text()
    for page in ("/clients", "/clients/2/edit", "/review"):
        assert PLAINTEXT not in oidc.get(page).text
        assert "dummy-hash" not in oidc.get(page).text and "other-hash" not in oidc.get(page).text


def test_rotating_a_secret(oidc: UI, env: dict[str, Path]) -> None:  # noqa: F811
    r = oidc.post("/clients/0/secret")
    assert r.status_code == 200 and PLAINTEXT in r.text and "old secret keeps working" in r.text
    draft = DraftStore(env["managed"]).current_clients_text()
    assert FAKE_DIGEST_2 in draft and FAKE_DIGEST not in draft.split("'spa'")[0]
    assert DraftStore(env["managed"]).changes().clients.secrets_rotated == 1
    assert oidc.post("/clients/1/secret").status_code == 422  # public: no secret


def test_invalid_client_is_refused_with_reasons(oidc: UI, env: dict[str, Path]) -> None:  # noqa: F811
    r = oidc.post("/clients/save", {
        "client_id": "garage", "b_public": "false", "l_redirect_uris": "http://x.example.com/cb",
        "s_authorization_policy": "nope", "l_scopes": ["openid", "made_up"], "present_scopes": "1",
    })  # fmt: skip
    assert r.status_code == 422
    text = r.text
    assert "used by another client" in text and "nope" in text and "made_up" in text
    assert not DraftStore(env["managed"]).has_draft()


def test_raw_yaml_cannot_smuggle_a_secret(oidc: UI) -> None:
    r = oidc.post("/clients/save", {
        "index": "1", "client_id": "spa", "b_public": "true", "b_require_pkce": "true",
        "s_pkce_challenge_method": "S256", "l_redirect_uris": "https://spa.example.com/cb",
        "extra_yaml": "client_secret: 'plain'",
    })  # fmt: skip
    assert r.status_code == 422 and "may only hold keys the form does not have" in r.text


def test_delete_asks_first_then_removes_from_the_draft(oidc: UI, env: dict[str, Path]) -> None:  # noqa: F811
    confirm = oidc.get("/clients/1/delete", htmx=True).text
    assert "Delete client?" in confirm and "spa" in confirm
    assert oidc.post("/clients/1/delete").status_code == 204
    assert DraftStore(env["managed"]).changes().clients.removed == 1


def test_generate_id(oidc: UI) -> None:
    r = oidc.post("/clients/generate-id")
    assert r.status_code == 200 and 'value="generated-id-123"' in r.text


def test_review_counts_clients_and_hides_hashes(oidc: UI) -> None:
    oidc.post("/clients/0/secret")
    page = oidc.get("/review").text
    assert "1 new secret" in page and "~1 edited" in page
    assert "&lt;hash&gt;" in page and "other-hash" not in page and "dummy-hash" not in page


def test_no_clients_file_is_explained(env: dict[str, Path]) -> None:  # noqa: F811
    (env["managed"] / "oidc_clients.yml").unlink(missing_ok=True)
    ui = UI(env)
    page = ui.get("/clients").text
    assert "has no <code>oidc_clients.yml</code>" in page
    assert ui.post("/clients/0/secret").status_code == 404
    assert re.search(r"New client", page) is None


def test_an_absent_public_key_stays_absent_on_save(oidc: UI, env: dict[str, Path]) -> None:  # noqa: F811
    text = CLIENTS.replace(
        "        client_secret:",
        "        token_endpoint_auth_method: 'client_secret_basic'\n        client_secret:",
        1,
    )
    (env["managed"] / "oidc_clients.yml").write_text(text)
    page = oidc.get("/clients/0/edit").text
    assert 'name="b_public" value="__unset__"' in page  # garage has no public: key
    r = oidc.post("/clients/save", {
        "index": "0", "client_id": "garage", "s_client_name": "Garage 2", "b_public": "__unset__",
        "s_authorization_policy": "two_factor", "s_consent_mode": "auto",
        "s_token_endpoint_auth_method": "client_secret_basic",
        "l_redirect_uris": "https://garage.example.com/cb", "present_redirect_uris": "1",
        "l_scopes": ["openid", "groups"], "present_scopes": "1",
    })  # fmt: skip
    assert r.status_code == 204, r.text
    draft = DraftStore(env["managed"]).current_clients_text()
    assert "public:" not in draft.split("'spa'")[0]


def test_rotation_is_refused_for_jwt_auth_methods(oidc: UI, env: dict[str, Path]) -> None:  # noqa: F811
    text = CLIENTS.replace(
        "        client_secret:",
        "        token_endpoint_auth_method: 'client_secret_jwt'\n        client_secret:",
        1,
    )
    (env["managed"] / "oidc_clients.yml").write_text(text)
    r = oidc.post("/clients/0/secret")
    assert r.status_code == 422 and "client_secret_jwt" in r.text
    assert "Generate new secret" not in oidc.get("/clients/0/edit").text
    assert not DraftStore(env["managed"]).has_draft()
