"""The one-time key move: keys to files, a keys file that reads back, main config untouched."""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from app.oidc.jwks import JwksDocument
from scripts import migrate_jwks as m

BEGIN, END = "-----BEGIN ", "-----END "
PRIVATE = f"{BEGIN}TEST KEY-----\nQUJD\n{END}TEST KEY-----"
CERT = f"{BEGIN}CERTIFICATE-----\nQ0VSVA==\n{END}CERTIFICATE-----"
MAIN = f"""theme: light
identity_providers:
  oidc:
    hmac_secret: 'x'
    jwks:
      - key_id: 'alpha'
        algorithm: 'RS256'
        use: 'sig'
        key: |
          {PRIVATE.replace(chr(10), chr(10) + "          ")}

        certificate_chain: |
          {CERT.replace(chr(10), chr(10) + "          ")}

      - algorithm: 'ES256'
        key: |
          {PRIVATE.replace(chr(10), chr(10) + "          ")}

    enforce_pkce: 'public_clients_only'
"""


def test_plan_names_the_files_and_keeps_the_chain() -> None:
    result = m.plan(MAIN, Path("/config/managed"))
    assert result.kids == ["alpha", "key-2"] and result.generated_kids == ["key-2"]
    assert "BEGIN TEST KEY" not in result.keys_file  # no private key in the keys file
    doc = JwksDocument.parse(result.keys_file)
    assert doc.get("alpha").secret_path == "/config/managed/secrets/jwks/alpha.pem"
    assert doc.get("alpha").chain.startswith(BEGIN + "CERTIFICATE") and doc.get("key-2").chain == ""
    assert doc.get("key-2").algorithm == "ES256"
    assert result.private_keys["alpha"].startswith(BEGIN + "TEST KEY")


def test_without_jwks_removes_only_that_list() -> None:
    reduced = m.without_jwks(MAIN)
    assert "jwks:" not in reduced and "BEGIN TEST KEY" not in reduced
    assert "hmac_secret: 'x'" in reduced and "enforce_pkce: 'public_clients_only'" in reduced
    assert reduced.startswith("theme: light\n")
    keep = [line for line in MAIN.splitlines() if "hmac_secret" in line or "theme" in line]
    assert all(line in reduced for line in keep)


def test_write_is_private_and_never_overwrites(tmp_path: Path) -> None:
    result = m.plan(MAIN, tmp_path)
    files = m.write(result, tmp_path)
    keys_file, first = files[0], files[1]
    assert stat.S_IMODE(first.stat().st_mode) == 0o600
    assert stat.S_IMODE(first.parent.stat().st_mode) == 0o700
    assert first.read_text().startswith(BEGIN + "TEST KEY")
    assert keys_file.name == "oidc_jwks.yml"
    with pytest.raises(m.MigrationError, match="already exists"):
        m.write(result, tmp_path)


def test_refuses_what_it_cannot_move_safely() -> None:
    with pytest.raises(m.MigrationError, match="no OIDC signing keys"):
        m.plan("theme: light\n", Path("/c"))
    odd = MAIN.replace("use: 'sig'", "use: 'sig'\n        mystery: 1")
    with pytest.raises(m.MigrationError, match="mystery"):
        m.plan(odd, Path("/c"))
    bad = MAIN.replace("'alpha'", "'../evil'")
    with pytest.raises(m.MigrationError, match="file name"):
        m.plan(bad, Path("/c"))
    twin = MAIN.replace("- algorithm: 'ES256'", "- key_id: 'alpha'\n        algorithm: 'ES256'")
    with pytest.raises(m.MigrationError, match="share"):
        m.plan(twin, Path("/c"))


def test_cli_prints_no_key_material_and_leaves_the_main_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main = tmp_path / "configuration.yml"
    main.write_text(MAIN)
    managed = tmp_path / "managed"
    managed.mkdir()
    reduced = tmp_path / "reduced.yml"
    code = m.main(
        ["--config", str(main), "--managed", str(managed), "--reduced-main", str(reduced)]
    )
    out = capsys.readouterr().out
    assert code == 0 and "BEGIN" not in out and "QUJD" not in out
    assert main.read_text() == MAIN and "jwks:" not in reduced.read_text()
    assert m.main(["--config", str(main), "--managed", str(managed)]) == 1  # second run refuses


def test_existing_folders_keep_their_permissions(tmp_path: Path) -> None:
    import os

    managed = tmp_path / "managed"
    managed.mkdir(mode=0o750)
    os.chmod(managed, 0o750)  # noqa: S103  (a group-readable folder, as some setups use)
    m.write(m.plan(MAIN, managed), managed)
    assert stat.S_IMODE(managed.stat().st_mode) == 0o750  # not tightened behind the user's back
    assert stat.S_IMODE((managed / "secrets").stat().st_mode) == 0o700
