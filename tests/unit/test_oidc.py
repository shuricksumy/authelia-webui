"""OIDC clients core (Phase 2a): document, secrets, names, lint, three-file draft, apply."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from app.authelia_cli import AutheliaCLI, AutheliaCLIError
from app.oidc.document import ClientsDocument, secret_kind, summarise_clients
from app.oidc.lint import lint_clients, redirect_problem
from app.oidc.names import load_oidc_names
from app.rules.document import DocumentError
from app.rules.store import DraftStore, Snapshot
from scripts.split_config import split
from tests.unit.test_apply import env, git, make, run  # noqa: F401  (fixture)

# Shaped like a real digest for the app, deliberately not for the hygiene scanner ('-' in salt).
FAKE_DIGEST = "$pbkdf2-sha512$310000$dummy-salt$dummy-hash"
FAKE_DIGEST_2 = "$pbkdf2-sha512$310000$other-salt$other-hash"


@pytest.fixture
def clients_text(realistic_main: str) -> str:
    text = split(realistic_main).oidc_clients_text
    assert text
    return text


# --------------------------------------------------------------------- document


def test_round_trip_is_byte_identical(clients_text: str) -> None:
    doc = ClientsDocument.parse(clients_text)
    assert doc.render() == clients_text
    assert len(doc.clients()) >= 5 and "photos" in doc.client_ids()


def test_editing_one_client_leaves_the_others_byte_identical(clients_text: str) -> None:
    doc = ClientsDocument.parse(clients_text)
    i = doc.client_ids().index("portainer")
    node = doc.blocks[i].node()
    node["consent_mode"] = "explicit"
    edited = doc.replace_item(i, node)
    for j, block in enumerate(doc.blocks):
        if j != i:
            assert edited.blocks[j] == block
    assert ClientsDocument.parse(edited.render()).clients()[i]["consent_mode"] == "explicit"


def test_inner_comments_and_odd_values_survive(clients_text: str) -> None:
    assert "#consent_mode: 'explicit'" in clients_text
    doc = ClientsDocument.parse(clients_text)
    chat = doc.clients()[doc.client_ids().index("chat")]
    assert chat["pkce_challenge_method"] == ""  # empty string is not "absent"
    assert chat["require_pkce"] is False


def test_with_secret_changes_only_the_secret_line(clients_text: str) -> None:
    doc = ClientsDocument.parse(clients_text)
    i = doc.client_ids().index("garage_app")
    new = doc.with_secret(i, FAKE_DIGEST)
    old_lines, new_lines = doc.blocks[i].lines, new.blocks[i].lines
    changed = [k for k, (a, b) in enumerate(zip(old_lines, new_lines, strict=True)) if a != b]
    assert len(changed) == 1 and FAKE_DIGEST in new_lines[changed[0]]
    assert new.clients()[i]["client_secret"] == FAKE_DIGEST
    assert all(new.blocks[j] == b for j, b in enumerate(doc.blocks) if j != i)


def test_with_secret_keeps_a_trailing_comment_and_adds_a_missing_key() -> None:
    text = (
        "identity_providers:\n  oidc:\n    clients:\n"
        "      - client_id: 'a'\n        client_secret: 'x' # rotate yearly\n"
        "        redirect_uris: ['https://a.example.com/cb']\n"
        "      - client_id: 'b'\n        public: true\n"
    )
    doc = ClientsDocument.parse(text)
    one = doc.with_secret(0, FAKE_DIGEST)
    assert f"client_secret: '{FAKE_DIGEST}' # rotate yearly" in one.render()
    two = doc.with_secret(1, FAKE_DIGEST)
    assert two.clients()[1]["client_secret"] == FAKE_DIGEST
    assert two.blocks[0] == doc.blocks[0]


def test_with_secret_falls_back_when_the_line_trick_would_break_yaml() -> None:
    text = (
        "identity_providers:\n  oidc:\n    clients:\n"
        "      - client_id: 'a'\n        client_secret: 'plain #text'\n"
    )
    doc = ClientsDocument.parse(text).with_secret(0, FAKE_DIGEST)
    assert doc.clients()[0] == {"client_id": "a", "client_secret": FAKE_DIGEST}


def test_with_secret_refuses_anything_but_a_hash(clients_text: str) -> None:
    doc = ClientsDocument.parse(clients_text)
    for bad in ("plaintext", "$pbkdf2-sha512$x\nkey: 1", "'$a$b'", ""):
        with pytest.raises(DocumentError):
            doc.with_secret(0, bad)


def test_secret_kind() -> None:
    assert secret_kind(None) == "" and secret_kind("") == ""
    assert secret_kind(FAKE_DIGEST) == "pbkdf2"
    assert secret_kind("$argon2id$v=19$whatever") == "argon2"
    assert secret_kind("$plaintext$abc") == "plaintext" and secret_kind("abc") == "plaintext"


def test_summary_counts_by_client_id(clients_text: str) -> None:
    live = ClientsDocument.parse(clients_text)
    i = live.client_ids().index("photos")
    draft = live.with_secret(i, FAKE_DIGEST).delete(live.client_ids().index("chat"))
    changes = summarise_clients(live, draft)
    assert (changes.added, changes.removed, changes.edited, changes.secrets_rotated) == (0, 1, 1, 1)


# --------------------------------------------------------------------- names


def test_names_are_names_only(tmp_path: Path, realistic_main: str) -> None:
    main = tmp_path / "configuration.yml"
    main.write_text(realistic_main)
    names = load_oidc_names(main)
    assert names.configured
    assert names.authorization_policies[:2] == ("one_factor", "two_factor")
    assert "policy_name" in names.authorization_policies
    assert set(names.claims_policies) >= {"default", "photos_policy"}
    assert "photos_scope" in names.custom_scopes and "openid" in names.scopes
    flat = repr(names)
    for secret in ("dummy-", "hmac", "BEGIN", "key_id"):
        assert secret not in flat


def test_names_without_oidc(tmp_path: Path) -> None:
    main = tmp_path / "configuration.yml"
    main.write_text("theme: light\n")
    assert not load_oidc_names(main).configured


# --------------------------------------------------------------------- lint


def codes(client: dict[str, Any], tmp_path: Path, realistic_main: str) -> set[str]:
    main = tmp_path / "configuration.yml"
    main.write_text(realistic_main)
    return {i.code for i in lint_clients([client], load_oidc_names(main))}


GOOD = {
    "client_id": "app",
    "client_secret": FAKE_DIGEST,
    "authorization_policy": "two_factor",
    "redirect_uris": ["https://app.example.com/cb"],
    "scopes": ["openid", "photos_scope"],
}


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ({}, set()),
        ({"public": True}, {"public-with-secret", "public-without-pkce"}),
        (
            {
                "public": True,
                "client_secret": None,
                "token_endpoint_auth_method": "client_secret_post",
            },
            {"public-auth-method", "public-without-pkce"},
        ),
        ({"client_secret": None}, {"confidential-without-secret"}),
        ({"token_endpoint_auth_method": "none"}, {"confidential-auth-none"}),
        ({"client_secret": "plain"}, {"plaintext-secret"}),
        ({"authorization_policy": "nope"}, {"unknown-policy"}),
        ({"claims_policy": "nope"}, {"unknown-claims-policy"}),
        ({"scopes": ["openid", "nope"]}, {"unknown-scope"}),
        ({"redirect_uris": []}, {"no-redirect-uri"}),
        ({"redirect_uris": ["http://app.example.com/cb"]}, {"redirect-uri"}),
        ({"client_id": ""}, {"no-client-id"}),
    ],
)
def test_lint(
    change: dict[str, Any], expected: set[str], tmp_path: Path, realistic_main: str
) -> None:
    client = {k: v for k, v in {**GOOD, **change}.items() if v is not None}
    assert codes(client, tmp_path, realistic_main) == expected


def test_lint_public_client_done_right(tmp_path: Path, realistic_main: str) -> None:
    client = {
        "client_id": "spa",
        "public": True,
        "require_pkce": True,
        "pkce_challenge_method": "S256",
        "redirect_uris": ["https://spa.example.com/cb"],
    }
    assert codes(client, tmp_path, realistic_main) == set()


def test_duplicates_and_no_clients(tmp_path: Path, realistic_main: str) -> None:
    main = tmp_path / "configuration.yml"
    main.write_text(realistic_main)
    names = load_oidc_names(main)
    assert {i.code for i in lint_clients([GOOD, GOOD], names)} == {"duplicate-client-id"}
    assert {i.code for i in lint_clients([], names)} == {"no-clients"}


def test_redirect_uris() -> None:
    assert redirect_problem("https://a.example.com/cb") is None
    assert redirect_problem("http://localhost:8080/cb") is None
    assert redirect_problem("app.immich:///oauth-callback") is None  # native app scheme
    assert redirect_problem("/relative")[0] == "error"  # type: ignore[index]
    assert redirect_problem("https://a.example.com/cb#x")[0] == "error"  # type: ignore[index]


# --------------------------------------------------------------------- CLI


def fake_cli(monkeypatch: pytest.MonkeyPatch, stdout: str, code: int = 0) -> list[list[str]]:
    calls: list[list[str]] = []

    def run(self: AutheliaCLI, args: Any, **_: Any) -> subprocess.CompletedProcess[str]:
        calls.append(list(args))
        return subprocess.CompletedProcess(args, code, stdout, "")

    monkeypatch.setattr(AutheliaCLI, "run", run)
    return calls


def test_random_secret_is_generated_by_authelia_not_passed_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = fake_cli(monkeypatch, f"Random Password: s3cret-value\nDigest: {FAKE_DIGEST}\n")
    assert AutheliaCLI.local().hash_random_pbkdf2() == ("s3cret-value", FAKE_DIGEST)
    argv = calls[0]
    assert "--random" in argv and "--password" not in argv
    assert argv[argv.index("--variant") + 1] == "sha512"


@pytest.mark.parametrize("out", ["", "Digest: $argon2id$x\nRandom Password: a\n", "garbage"])
def test_random_secret_rejects_unexpected_output(monkeypatch: pytest.MonkeyPatch, out: str) -> None:
    fake_cli(monkeypatch, out)
    with pytest.raises(AutheliaCLIError, match="unexpected output"):
        AutheliaCLI.local().hash_random_pbkdf2()


def test_random_secret_failure_says_nothing_about_the_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_cli(monkeypatch, "Random Password: leaked\n", code=1)
    with pytest.raises(AutheliaCLIError) as exc:
        AutheliaCLI.local().hash_random_pbkdf2()
    assert "leaked" not in str(exc.value)


# --------------------------------------------------------------------- three-file draft


def test_clients_take_part_in_the_draft(env: dict[str, Any]) -> None:  # noqa: F811
    store: DraftStore = env["store"]
    clients = env["managed"] / "oidc_clients.yml"
    clients.write_text(
        "identity_providers:\n  oidc:\n    clients:\n"
        f"      - client_id: 'app'\n        client_secret: '{FAKE_DIGEST}'\n"
        "        redirect_uris: ['https://app.example.com/cb']\n"
    )
    before = store.current_sha()
    doc = store.current_clients()
    assert doc is not None
    store.save(store.current(), clients=doc.with_secret(0, FAKE_DIGEST_2))
    assert store.has_draft() and store.current_sha() != before
    assert store.changes().clients.secrets_rotated == 1 and store.changes().count == 1
    assert clients.read_text().count(FAKE_DIGEST) == 1  # live untouched
    diff = store.diff()
    assert "oidc_clients.yml (draft)" in diff and "<hash>" in diff and "pbkdf2" not in diff
    clients.write_text(clients.read_text() + "# hand edit\n")
    assert store.is_stale()


def test_a_draft_from_before_phase_2_still_loads(env: dict[str, Any]) -> None:  # noqa: F811
    store: DraftStore = env["store"]
    store.save(store.current().move(3, 4))
    (store.draft_dir / "oidc_clients.yml").unlink(missing_ok=True)
    meta = json.loads(store.meta_path.read_text())
    meta.pop("base_clients_sha256")
    store.meta_path.write_text(json.dumps(meta))
    assert store.has_draft() and not store.is_stale()
    assert store.current_clients_text() == store.live_clients_text()


def test_identical_snapshot_discards_the_draft(env: dict[str, Any]) -> None:  # noqa: F811
    store: DraftStore = env["store"]
    store.save(store.current().move(3, 4))
    store.save_snapshot(
        Snapshot(store.live_text(), store.live_disabled_text(), store.live_clients_text())
    )
    assert not store.has_draft()


# --------------------------------------------------------------------- apply


def test_apply_commits_clients_with_the_rules_and_validates_the_candidate(
    env: dict[str, Any],  # noqa: F811
) -> None:
    seen: list[str | None] = []

    def validator(settings: Any, text: str, clients: str | None = None) -> Any:
        from tests.unit.test_apply import ok_validator

        seen.append(clients)
        return ok_validator(settings, text)

    store: DraftStore = env["store"]
    clients = env["managed"] / "oidc_clients.yml"
    clients.write_text(
        "identity_providers:\n  oidc:\n    clients:\n"
        f"      - client_id: 'app'\n        client_secret: '{FAKE_DIGEST}'\n"
        "        redirect_uris: ['https://app.example.com/cb']\n"
    )
    engine, _, _ = make(env, [True], validator=validator)
    doc = store.current_clients()
    assert doc is not None
    store.save(store.current().move(3, 4), clients=doc.with_secret(0, FAKE_DIGEST_2))
    job = run(engine, store.current_sha()[:16])
    assert job.result == "applied", job.message
    assert seen and seen[0] is not None and FAKE_DIGEST_2 in seen[0]  # the candidate, not live
    assert FAKE_DIGEST_2 in clients.read_text()
    changed = git(env["managed"], "show", "--name-only", "--format=%s", "HEAD").split()
    assert "oidc_clients.yml" in changed and "access_control.yml" in changed
    assert "OIDC clients: 1 edited, 1 secret(s) rotated" in git(
        env["managed"], "log", "-1", "--format=%s"
    )


def test_unhealthy_apply_puts_the_clients_back_in_the_draft(env: dict[str, Any]) -> None:  # noqa: F811
    store: DraftStore = env["store"]
    clients = env["managed"] / "oidc_clients.yml"
    clients.write_text(
        "identity_providers:\n  oidc:\n    clients:\n"
        f"      - client_id: 'app'\n        client_secret: '{FAKE_DIGEST}'\n"
        "        redirect_uris: ['https://app.example.com/cb']\n"
    )
    engine, _, _ = make(env, [False, True])
    doc = store.current_clients()
    assert doc is not None
    store.save(store.current(), clients=doc.with_secret(0, FAKE_DIGEST_2))
    job = run(engine, store.current_sha()[:16])
    assert job.result == "rolled-back", job.message
    assert FAKE_DIGEST in clients.read_text() and FAKE_DIGEST_2 not in clients.read_text()
    assert FAKE_DIGEST_2 in store.current_clients_text()  # the change is back in the draft


def test_portal_host_comes_from_the_session_cookie_config(tmp_path: Path) -> None:
    from app.apply.probe import portal_host

    main = tmp_path / "configuration.yml"
    main.write_text(
        "session:\n  cookies:\n    - domain: example.test\n"
        "      authelia_url: 'https://auth.example.test:8443'\n"
    )
    assert portal_host(main, "auth.example.test") == "auth.example.test:8443"
    assert portal_host(main, "other.example.test") == "other.example.test"
    main.write_text("theme: light\n")
    assert portal_host(main, "auth.example.com") == "auth.example.com"


def test_form_keeps_the_file_order_of_an_unchanged_checkbox_group(clients_text: str) -> None:
    from app.oidc.form import ClientForm, apply_client_form

    doc = ClientsDocument.parse(clients_text)
    i = doc.client_ids().index("portainer")
    data = doc.clients()[i]
    form = ClientForm.from_data(data)
    form.lists["scopes"] = ["openid", "profile", "email", "groups"]  # page order, not file order
    node = apply_client_form(form, doc.blocks[i].node())
    assert doc.replace_item(i, node).blocks[i].lines == doc.blocks[i].lines  # no diff at all
    form.lists["scopes"] = ["openid", "email"]  # a real change is written
    node = apply_client_form(form, doc.blocks[i].node())
    assert doc.replace_item(i, node).clients()[i]["scopes"] == ["openid", "email"]


def test_redaction_keeps_the_quotes_around_a_hash() -> None:
    from app.authelia_cli import redact

    assert redact(f"client_secret: '{FAKE_DIGEST}'") == "client_secret: '<hash>'"
    assert redact(f'x: "{FAKE_DIGEST}" # c') == 'x: "<hash>" # c'
    assert redact(f"error with {FAKE_DIGEST}") == "error with <hash>"


def test_portal_url_is_the_issuer_with_port_and_path(tmp_path: Path) -> None:
    from app.apply.probe import portal_host, portal_url

    main = tmp_path / "configuration.yml"
    main.write_text(
        "session:\n  cookies:\n    - domain: example.test\n"
        "      authelia_url: 'https://auth.example.test:8443/authelia/'\n"
    )
    assert portal_url(main, "auth.example.test") == "https://auth.example.test:8443/authelia"
    assert portal_host(main, "auth.example.test") == "auth.example.test:8443"
    main.write_text("theme: light\n")
    assert portal_url(main, "auth.example.com") == "https://auth.example.com"
