"""The signing-keys file as text: strict parsing, byte-stable edits, no key material."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.blocklist import DocumentError
from app.oidc.jwks import JwksDocument, entry_lines, key_path, new_document

MANAGED = Path("/config/managed")


def doc_with(*kids: str) -> JwksDocument:
    return new_document([entry_lines(k, "RS256", key_path(MANAGED, k)) for k in kids])


def test_round_trip_and_fields() -> None:
    d = doc_with("alpha", "beta")
    again = JwksDocument.parse(d.render())
    assert again.render() == d.render() and again.kids() == ["alpha", "beta"]
    info = again.get("alpha")
    assert info.algorithm == "RS256" and info.use == "sig" and not info.inline
    assert info.secret_path == "/config/managed/secrets/jwks/alpha.pem"
    assert "BEGIN" not in d.render()  # never any key material, only the file name


def test_add_promote_remove_leave_other_keys_byte_identical() -> None:
    base = doc_with("old")
    added = base.with_added("new", "RS256", key_path(MANAGED, "new"))
    assert added.kids() == ["old", "new"]
    assert added.blocks[0].lines == base.blocks[0].lines
    promoted = added.promoted("new")
    assert promoted.kids() == ["new", "old"]
    assert promoted.blocks[1].lines == base.blocks[0].lines
    retired = promoted.removed("old")
    assert retired.kids() == ["new"] and JwksDocument.parse(retired.render()).kids() == ["new"]


def test_refuses_duplicates_unknown_and_the_last_key() -> None:
    d = doc_with("a")
    with pytest.raises(DocumentError):
        d.with_added("a", "RS256", key_path(MANAGED, "a"))
    with pytest.raises(DocumentError):
        d.promoted("zzz")
    with pytest.raises(DocumentError):
        d.removed("a")


def test_key_ids_cannot_escape_the_secrets_folder() -> None:
    for bad in ("../x", "a/b", "", "a b", "x" * 80, '"q'):
        with pytest.raises(DocumentError):
            key_path(MANAGED, bad)
        with pytest.raises(DocumentError):
            entry_lines(bad, "RS256", MANAGED)
    with pytest.raises(DocumentError):
        entry_lines("ok", "RS256'; rm", MANAGED)


def test_certificate_chain_is_kept_and_read() -> None:
    chain = "-----BEGIN " + "CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"
    rendered = doc_with("a", "b")
    first_key = rendered.blocks[0].lines[-1]
    body = "".join(f"          {line}\n" for line in chain.splitlines())
    text = rendered.render().replace(
        first_key + "\n", first_key + "\n        certificate_chain: |\n" + body, 1
    )
    d = JwksDocument.parse(text)
    assert d.get("a").chain == chain and d.get("b").chain == ""
    assert d.promoted("b").render().count("BEGIN CERTIFICATE") == 1  # travels with its key


def test_unexpected_layouts_are_refused() -> None:
    for text in (
        "identity_providers:\n  oidc:\n    jwks: []\n",
        "nothing: here\n",
        "identity_providers:\n  oidc:\n    jwks:\n      - algorithm: 'RS256'\n        key: 'x'\n",
    ):
        with pytest.raises(DocumentError):
            JwksDocument.parse(text)
    dup = doc_with("a").render() + "\n".join(doc_with("a").blocks[0].lines) + "\n"
    with pytest.raises(DocumentError):
        JwksDocument.parse(dup)


def test_an_inline_key_is_recognised_but_flagged() -> None:
    text = (
        "identity_providers:\n  oidc:\n    jwks:\n      - key_id: 'x'\n"
        "        algorithm: 'RS256'\n        key: |\n          line\n"
    )
    info = JwksDocument.parse(text).get("x")
    assert info.inline and info.secret_path == ""
