"""Signing keys as files, with the real Authelia: the template filter, our keys file, the key
generator and the one-time move. Documented in docs/jwks.md."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from app.apply.validate import validate_keys
from app.authelia_cli import AutheliaCLI
from app.oidc.jwks import JwksDocument, key_path
from app.settings import Settings
from scripts import migrate_jwks
from scripts.split_config import split

pytestmark = pytest.mark.integration


@pytest.fixture
def moved(generated: dict[str, Path], tmp_path: Path) -> dict[str, Path]:
    """The generated realistic config after the one-time move, in a temp dir."""
    original = generated["configuration.yml"].read_text()
    parts = split(original)
    managed = tmp_path / "managed"
    managed.mkdir()
    migration = migrate_jwks.plan(parts.main_text, managed)  # paths as Authelia will see them
    migrate_jwks.write(migration, managed)
    main = tmp_path / "configuration.yml"
    main.write_text(migrate_jwks.without_jwks(parts.main_text))
    (managed / "access_control.yml").write_text(parts.access_control_text)
    (managed / "oidc_clients.yml").write_text(parts.oidc_clients_text or "")
    return {"main": main, "managed": managed}


def files(moved: dict[str, Path]) -> list[Path]:
    m = moved["managed"]
    return [moved["main"], m / "access_control.yml", m / "oidc_clients.yml", m / "oidc_jwks.yml"]


def test_the_moved_setup_validates_only_with_the_template_filter(
    cli: AutheliaCLI, moved: dict[str, Path]
) -> None:
    filtered = replace(cli, filters="template")
    ok = filtered.validate(files(moved))
    assert ok.ok and not ok.warnings, ok.raw
    plain = cli.validate(files(moved))
    assert not plain.ok  # without the filter the keys file is not valid YAML: the control


def test_the_move_changes_nothing_authelia_sees(
    cli: AutheliaCLI, generated: dict[str, Path], moved: dict[str, Path]
) -> None:
    before = cli.validate([generated["configuration.yml"]])
    after = replace(cli, filters="template").validate(files(moved))
    assert (before.ok, before.warnings) == (after.ok, after.warnings), after.raw


def test_a_missing_key_file_is_caught_before_anything_is_written(
    cli: AutheliaCLI, moved: dict[str, Path]
) -> None:
    filtered = replace(cli, filters="template")
    managed = moved["managed"]
    doc = JwksDocument.parse((managed / "oidc_jwks.yml").read_text())
    ghost = key_path(managed, "ghost")
    broken = doc.with_added("ghost", "RS256", ghost)
    assert not ghost.exists()
    result = filtered.validate(
        [*files(moved)[:3], _write(managed / "candidate.yml", broken.render())]
    )
    assert not result.ok


def _write(path: Path, text: str) -> Path:
    path.write_text(text)
    return path


@pytest.mark.parametrize("algorithm", ["RS256", "ES256"])
def test_generated_keys_work_as_a_second_key(
    cli: AutheliaCLI, moved: dict[str, Path], algorithm: str
) -> None:
    filtered = replace(cli, filters="template")
    managed = moved["managed"]
    work = managed / ".work"
    private = cli.generate_key_pair(work, algorithm, bits=2048)
    assert private.read_text().startswith("-----BEGIN")
    target = key_path(managed, "second")
    private.rename(target)
    doc = JwksDocument.parse((managed / "oidc_jwks.yml").read_text())
    two = doc.with_added("second", algorithm, target)
    result = filtered.validate([*files(moved)[:3], _write(managed / "candidate.yml", two.render())])
    assert result.ok, result.raw
    # and the order a promotion produces is accepted too
    promoted = two.promoted("second")
    result = filtered.validate(
        [*files(moved)[:3], _write(managed / "candidate.yml", promoted.render())]
    )
    assert result.ok, result.raw


def test_validate_keys_uses_the_same_view_as_authelia(
    cli: AutheliaCLI, moved: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The app's own validator (a local binary in production) with the docker CLI here."""
    settings = Settings(
        AUTH_DOMAIN="auth.example.com", CONFIGURATOR_DOMAIN="authcfg.example.com",
        ADMIN_GROUP="admin", ALLOWED_CLIENT_CIDRS="10.8.0.0/24",  # type: ignore[arg-type]
        TRUSTED_PROXY_CIDRS="172.20.0.0/16",  # type: ignore[arg-type]
        AUTHELIA_CONTAINER="authelia", AUTHELIA_HEALTH_URL="http://authelia:9091/api/health",
        APP_SECRET_KEY="k" * 40,  # type: ignore[arg-type]
        CONFIG_MAIN=moved["main"], CONFIG_MANAGED_DIR=moved["managed"], CONFIG_FILTERS="template",
    )  # fmt: skip
    monkeypatch.setattr(
        AutheliaCLI,
        "local",
        classmethod(lambda c, binary="authelia", filters="": replace(cli, filters=filters)),
    )
    text = (moved["managed"] / "oidc_jwks.yml").read_text()
    result = validate_keys(settings, text)
    assert result is not None and result.ok, result.raw if result else ""


def test_the_main_file_may_keep_its_jwks_list(
    cli: AutheliaCLI, generated: dict[str, Path], tmp_path: Path
) -> None:
    """Lists are replaced across files: the managed keys file wins, so removing the list from
    the main file is optional tidying, not a required step of the move."""
    parts = split(generated["configuration.yml"].read_text())
    managed = tmp_path / "managed"
    managed.mkdir()
    migrate_jwks.write(migrate_jwks.plan(parts.main_text, managed), managed)
    main = tmp_path / "configuration.yml"
    main.write_text(parts.main_text)  # still contains jwks:
    (managed / "access_control.yml").write_text(parts.access_control_text)
    (managed / "oidc_clients.yml").write_text(parts.oidc_clients_text or "")
    paths = [main, managed / "access_control.yml", managed / "oidc_clients.yml",
             managed / "oidc_jwks.yml"]  # fmt: skip
    result = replace(cli, filters="template").validate(paths)
    assert result.ok and not result.warnings, result.raw
