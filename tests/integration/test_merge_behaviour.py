"""SPEC §3 Phase 0: how the pinned Authelia merges our managed files.

Every case runs the real `authelia config validate`. Results are documented in
docs/merge-behaviour.md; keep both in sync.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from ruamel.yaml import YAML

from app.authelia_cli import AutheliaCLI
from scripts.split_config import split

pytestmark = pytest.mark.integration


def write(path: Path, text: str) -> Path:
    path.write_text(text)
    return path


@pytest.fixture
def parts(generated: dict[str, Path], tmp_path: Path) -> dict[str, Path]:
    result = split(generated["configuration.yml"].read_text())
    out = {
        "main": write(tmp_path / "configuration.yml", result.main_text),
        "ac": write(tmp_path / "access_control.yml", result.access_control_text),
        "clients": write(tmp_path / "oidc_clients.yml", result.oidc_clients_text or ""),
    }
    return out


def test_original_is_clean(cli: AutheliaCLI, generated: dict[str, Path]) -> None:
    res = cli.validate([generated["configuration.yml"]])
    assert res.ok and not res.warnings, res.raw


def test_a_access_control_in_own_file(cli: AutheliaCLI, parts: dict[str, Path]) -> None:
    res = cli.validate([parts["main"], parts["ac"], parts["clients"]])
    assert res.ok and not res.warnings, res.raw


def test_b_oidc_clients_deep_merge_into_oidc_map(cli: AutheliaCLI, parts: dict[str, Path]) -> None:
    """Clients-only file merges into identity_providers.oidc without replacing it."""
    full = cli.validate([parts["main"], parts["ac"], parts["clients"]])
    assert full.ok, full.raw
    # Negative control: without the clients file the config is invalid, proving the
    # clients really came from the second file and the oidc map was merged, not replaced.
    without = cli.validate([parts["main"], parts["ac"]])
    assert not without.ok
    assert any("client" in e.lower() for e in without.errors), without.raw


def test_c_duplicate_rules_in_two_files_replace_not_append(
    cli: AutheliaCLI, parts: dict[str, Path], tmp_path: Path
) -> None:
    """Lists are replaced by the later file; we therefore never split rules across files.

    File 1 holds an INVALID rule, file 2 a valid one. If the later list replaced the
    earlier one the set validates; if it were appended the invalid rule would remain.
    """
    first = write(
        tmp_path / "first.yml",
        "access_control:\n  default_policy: deny\n  rules:\n"
        "    - domain: one.example.com\n      policy: not-a-policy\n",
    )
    second = write(
        tmp_path / "second.yml",
        "access_control:\n  rules:\n    - domain: two.example.com\n      policy: bypass\n",
    )
    assert not cli.validate([parts["main"], first, parts["clients"]]).ok  # control
    res = cli.validate([parts["main"], first, second, parts["clients"]])
    assert res.ok, res.raw


def test_d_networks_in_definitions_and_access_control_is_an_error(
    cli: AutheliaCLI, parts: dict[str, Path], tmp_path: Path
) -> None:
    defs = write(
        tmp_path / "defs.yml",
        "definitions:\n  network:\n    lan:\n      - 192.0.2.0/24\n"
        "access_control:\n  networks:\n    - name: lan\n      networks:\n        - 192.0.2.0/24\n",
    )
    res = cli.validate([parts["main"], parts["ac"], parts["clients"], defs])
    assert not res.ok
    assert any("network" in e.lower() for e in res.errors), res.raw


def test_e_validator_reports_warnings_for_deprecated_keys(
    cli: AutheliaCLI, parts: dict[str, Path], tmp_path: Path
) -> None:
    """Deprecations come back as warnings (not errors); CI treats them as failures (§16.3)."""
    main = parts["main"].read_text()
    assert "address: 'tcp://0.0.0.0:9091/'" in main
    deprecated = write(
        tmp_path / "deprecated.yml",
        main.replace("address: 'tcp://0.0.0.0:9091/'", "host: 0.0.0.0\n  port: 9091"),
    )
    res = cli.validate([deprecated, parts["ac"], parts["clients"]])
    assert res.ok, res.raw  # warnings do not fail validation on their own
    assert any("deprecated" in w.lower() for w in res.warnings), res.raw


def test_realistic_split_round_trips_through_ruamel(generated: dict[str, Path]) -> None:
    """The moved clients block stays valid YAML on its own."""
    yaml = YAML(typ="safe")
    result = split(generated["configuration.yml"].read_text())
    assert result.oidc_clients_text is not None
    data = yaml.load(result.oidc_clients_text)
    assert len(data["identity_providers"]["oidc"]["clients"]) == 5
