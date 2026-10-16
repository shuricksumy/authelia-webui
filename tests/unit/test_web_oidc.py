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


# --------------------------------------------------------------------- presets (2b)


def test_every_preset_is_well_formed_and_lints_clean_when_its_names_exist() -> None:
    from app.blocklist import mapping_to_node
    from app.oidc import templates
    from app.oidc.form import ClientForm, apply_client_form
    from app.oidc.lint import lint_clients
    from app.oidc.names import STANDARD_SCOPES, OidcNames

    all_t = templates.load_all()
    assert len(all_t) >= 10 and all_t[0].id == "generic" and all_t[1].id == "generic-public"
    wanted = {
        "immich",
        "home-assistant",
        "nextcloud-user-oidc",
        "nextcloud-oidc-login",
        "portainer",
        "cloudflare-zero-trust",
        "librechat",
        "grafana",
    }
    assert wanted <= {t.id for t in all_t}
    for t in all_t:
        client = t.instantiate("app.example.com")
        assert "client_secret" not in client and client["client_id"] == t.id
        assert t.guide_url == "" or t.guide_url.startswith("https://www.authelia.com/")
        names = OidcNames(
            True,
            ("one_factor", "two_factor"),
            tuple(filter(None, [client.get("claims_policy")])),
            (*STANDARD_SCOPES, *t.needed_names.get("scope", "").split(", ")),
        )
        if not client.get("public"):
            client["client_secret"] = FAKE_DIGEST  # added when saved
        issues = lint_clients([client], names)
        assert not [i.message for i in issues if i.severity == "error"], (t.id, issues)
        form = ClientForm.from_data({k: v for k, v in client.items() if k != "client_secret"})
        node = apply_client_form(form, mapping_to_node({"client_id": t.id}))
        assert node["redirect_uris"] == client["redirect_uris"], t.id


def test_presets_needing_main_config_say_exactly_what() -> None:
    from app.oidc import templates

    cf = templates.get("cloudflare-zero-trust")
    nc = templates.get("nextcloud-oidc-login")
    assert (
        cf and nc and "claims_policies" in cf.main_config and "is_nextcloud_admin" in nc.main_config
    )
    assert cf.needed_names == {"claims_policy": "cloudflare"}
    assert nc.needed_names["scope"] == "nextcloud_userinfo"
    plain = templates.get("grafana")
    assert plain and not plain.main_config and not plain.needed_names


def test_clean_host() -> None:
    from app.oidc.templates import clean_host

    assert clean_host("photos.example.com") == "photos.example.com"
    assert clean_host(" https://photos.example.com/some/path ") == "photos.example.com"
    assert clean_host("grafana.example.com:3000") == "grafana.example.com:3000"
    for bad in ("", "bad host", "a b/c", "javascript:alert(1)", "x" * 300, "https://"):
        assert clean_host(bad) is None


def test_picker_lists_presets_and_the_editor_is_prefilled(oidc: UI) -> None:
    picker = oidc.get("/clients/new").text
    for name in (
        "Immich",
        "Grafana",
        "Portainer",
        "Cloudflare Zero Trust",
        "Home Assistant",
        "LibreChat",
    ):
        assert name in picker
    assert (
        "Needs claims policy &#39;cloudflare&#39;" in picker
        or "Needs claims policy 'cloudflare'" in picker
    )
    page = oidc.get("/clients/new?template=grafana&host=https://dash.example.com/").text
    assert "https://dash.example.com/login/generic_oauth" in page
    assert "Replace <code>app.example.com</code>" not in page  # a host was given
    assert 'value="grafana"' in page and "Preset: Grafana" in page
    assert "authelia.com/integration/openid-connect/clients/grafana/" in page


def test_missing_main_config_names_are_explained_with_the_snippet(oidc: UI) -> None:
    page = oidc.get("/clients/new?template=cloudflare-zero-trust&host=team.example.com").text
    assert "does not define claims policy" in page and "alt_emails" in page
    # defined in the main config: no warning
    from pathlib import Path as P

    main = P(oidc.settings.CONFIG_MAIN)
    main.write_text(main.read_text() + "    # x\n")
    text = main.read_text().replace(
        "claims_policies:\n", "claims_policies:\n      cloudflare:\n        id_token: ['groups']\n"
    )
    main.write_text(text)
    assert (
        "does not define claims policy"
        not in oidc.get("/clients/new?template=cloudflare-zero-trust").text
    )


def test_invalid_host_and_id_collisions(oidc: UI) -> None:
    r = oidc.get("/clients/new?template=grafana&host=not a host")
    assert r.status_code == 422 and "not a valid address" in r.text
    assert oidc.get("/clients/new?template=nope").status_code == 404
    first = oidc.get("/clients/new?template=generic").text
    assert 'value="generic"' in first
    # a second client of an app that already exists gets a free id
    text = CLIENTS.replace("client_id: 'garage'", "client_id: 'grafana'", 1)
    (oidc.env["managed"] / "oidc_clients.yml").write_text(text)
    assert 'value="grafana-2"' in oidc.get("/clients/new?template=grafana").text


def test_editor_of_an_existing_client_shows_the_setup_info(oidc: UI) -> None:
    page = oidc.get("/clients/0/edit").text
    assert (
        "Setup info for the app" in page
        and "https://auth.example.com/.well-known/openid-configuration" in page
    )
    assert "https://garage.example.com/cb" in page and 'data-copy="garage"' in page


def test_template_files_hold_no_secret_or_real_domain() -> None:
    from app.oidc.templates import DIRECTORY

    for path in DIRECTORY.glob("*.yml"):
        text = path.read_text()
        assert "client_secret:" not in text and "$pbkdf2" not in text and "$argon2" not in text, (
            path
        )
