from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest
from ruamel.yaml import YAML

from app.authelia_cli import ValidationResult
from scripts.split_config import (
    SplitError,
    check_structural_equality,
    main,
    split,
)
from tests.unit.conftest import fill_placeholders

SAFE = YAML(typ="safe")


def test_counts_and_disabled_rule_positions(realistic_main: str) -> None:
    result = split(realistic_main)
    assert result.rule_count == 12
    assert result.client_count == 5
    assert [(d.position, d.rule["domain"]) for d in result.disabled] == [
        (0, "auth.example.com"),
        (2, "home.example.com"),
    ]
    assert result.disabled[1].rule["resources"] == ["^/api.*", "^/auth/.*", "^/static.*"]
    assert result.leftovers == []


def test_main_has_no_access_control_or_clients_but_keeps_everything_else(
    realistic_main: str,
) -> None:
    result = split(realistic_main)
    main_data = SAFE.load(result.main_text)
    assert "access_control" not in main_data
    oidc = main_data["identity_providers"]["oidc"]
    assert "clients" not in oidc
    # secrets/policies/scopes stay in the main file
    assert {"hmac_secret", "jwks", "authorization_policies", "claims_policies", "scopes"} <= set(
        oidc
    )
    assert "session" in main_data and "storage" in main_data


def test_structural_merge_equals_original(realistic_main: str) -> None:
    check_structural_equality(realistic_main, split(realistic_main))


def test_no_line_is_lost_or_invented(realistic_main: str) -> None:
    """Text is moved verbatim: output lines == input lines, minus the imported
    commented-out rules and plus the two header lines wrapping the clients."""
    result = split(realistic_main)
    original = Counter(realistic_main.splitlines())
    out = Counter(result.main_text.splitlines())
    out.update(result.access_control_text.splitlines())
    assert result.oidc_clients_text is not None
    out.update(result.oidc_clients_text.splitlines())
    out.subtract(Counter(["identity_providers:", "  oidc:"]))
    lines = realistic_main.splitlines()
    dropped = Counter(lines[n] for d in result.disabled for n in d.lines)
    out.update(dropped)
    # blank lines may be added where blocks were cut out; ignore them
    for counter in (original, out):
        counter.pop("", None)
    assert +(original - out) == Counter(), "lines were lost"
    assert +(out - original) == Counter(), "lines were invented"


def test_commented_paths_inside_live_rules_stay_in_place(realistic_main: str) -> None:
    ac = split(realistic_main).access_control_text
    assert '#        - "^/frontend_latest/.*"' in ac
    assert any("^/mcp.*" in ln and ln.lstrip().startswith("#") for ln in ac.splitlines())


def test_prose_comments_travel_with_their_rule(realistic_main: str) -> None:
    ac = split(realistic_main).access_control_text
    assert "# 1. Public endpoints (Must be bypassed so OIDC works)" in ac
    assert "# 2. Protect the actual Authelia Portal/Settings" in ac


def test_imported_disabled_rules_are_removed_from_access_control(realistic_main: str) -> None:
    imported = split(realistic_main).access_control_text
    kept = split(realistic_main, import_disabled=False)
    assert '#    - domain: "auth.example.com"' not in imported
    assert '#    - domain: "auth.example.com"' in kept.access_control_text
    assert kept.disabled == [] and kept.disabled_text is None


def test_unparsable_commented_rule_goes_to_leftovers() -> None:
    text = (
        "access_control:\n  default_policy: deny\n  rules:\n"
        "#    - domain: a.example.com\n#      policy: [broken\n"
        "    - domain: b.example.com\n      policy: bypass\n"
        "session:\n  secret: x\n"
    )
    result = split(text)
    assert result.disabled == []
    assert len(result.leftovers) == 1 and result.leftovers[0].position == 0
    assert "a.example.com" in (result.leftovers_text or "")
    assert "a.example.com" not in result.access_control_text
    check_structural_equality(text, result)


def test_commented_block_without_policy_is_a_leftover_not_a_rule() -> None:
    text = (
        "access_control:\n  default_policy: deny\n  rules:\n"
        "#    - domain: a.example.com\n"
        "    - domain: b.example.com\n      policy: bypass\n"
    )
    result = split(text)
    assert result.disabled == [] and len(result.leftovers) == 1


def test_access_control_is_required() -> None:
    with pytest.raises(SplitError, match="access_control"):
        split("session:\n  secret: x\n")


def test_not_a_mapping_and_invalid_yaml_rejected() -> None:
    with pytest.raises(SplitError):
        split("- a\n- b\n")
    with pytest.raises(SplitError):
        split("a: [unclosed\n")


def test_anchors_are_rejected() -> None:
    text = "base: &b\n  x: 1\naccess_control:\n  default_policy: deny\n  rules: []\nother: *b\n"
    with pytest.raises(SplitError, match="anchors"):
        split(text)


def test_config_without_oidc_clients_still_splits() -> None:
    result = split("access_control:\n  default_policy: deny\n  rules: []\nsession:\n  secret: x\n")
    assert result.oidc_clients_text is None and result.client_count == 0


def test_cli_writes_outputs_and_never_touches_input(
    realistic_main: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    src = tmp_path / "configuration.yml"
    src.write_text(realistic_main)
    before = src.read_bytes()
    out = tmp_path / "out"
    assert main(["--config", str(src), "--out", str(out), "--authelia", "none"]) == 0
    assert src.read_bytes() == before
    names = {p.name for p in out.rglob("*") if p.is_file()}
    assert names == {
        "configuration.split.yml",
        "access_control.yml",
        "oidc_clients.yml",
        "disabled_rules.yml",
    }
    assert (out / "managed" / "access_control.yml").stat().st_mode & 0o777 == 0o600
    printed = capsys.readouterr()
    assert "managed/access_control.yml" in printed.out


def test_cli_refuses_existing_output_dir(
    realistic_main: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    src = tmp_path / "c.yml"
    src.write_text(realistic_main)
    (tmp_path / "out").mkdir()
    assert main(["--config", str(src), "--out", str(tmp_path / "out"), "--authelia", "none"]) == 1
    assert "already exists" in capsys.readouterr().err


def test_cli_output_contains_no_secret_values(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Every placeholder becomes a recognisable dummy value; none may reach stdout/stderr."""
    from tests.unit.conftest import FIXTURES

    text = fill_placeholders((FIXTURES / "main.example.yml").read_text())
    secrets = {f"dummy-{n:03d}" for n in range(1, 40)}
    src = tmp_path / "c.yml"
    src.write_text(text)
    main(["--config", str(src), "--out", str(tmp_path / "o"), "--authelia", "none"])
    printed = capsys.readouterr()
    assert not any(s in printed.out + printed.err for s in secrets)


# --- regressions from the Phase 0 review -------------------------------------------------


def test_prose_comment_after_a_commented_rule_stays_with_the_next_rule() -> None:
    text = (
        "access_control:\n  default_policy: deny\n  rules:\n"
        "#    - domain: a.example.com\n#      policy: bypass\n"
        "    # Public endpoints of b\n"
        "    - domain: b.example.com\n      policy: bypass\n"
    )
    result = split(text)
    assert [d.rule["domain"] for d in result.disabled] == ["a.example.com"]
    assert result.leftovers == []
    assert "    # Public endpoints of b" in result.access_control_text


def test_commented_rule_with_policy_first_is_detected() -> None:
    text = (
        "access_control:\n  default_policy: deny\n  rules:\n"
        "#    - policy: bypass\n#      domain: a.example.com\n"
        "    - domain: b.example.com\n      policy: bypass\n"
    )
    assert [d.rule["policy"] for d in split(text).disabled] == ["bypass"]


def test_structural_check_never_surfaces_parser_messages(realistic_main: str) -> None:
    result = split(realistic_main)
    result.access_control_text = "access_control:\n  rules:\n   - secret: VALUE-123\n  bad: [\n"
    with pytest.raises(SplitError) as exc:
        check_structural_equality(realistic_main, result)
    assert "VALUE-123" not in str(exc.value) and "not valid YAML" in str(exc.value)


def test_outputs_are_private_from_creation(realistic_main: str, tmp_path: Path) -> None:
    src = tmp_path / "c.yml"
    src.write_text(realistic_main)
    out = tmp_path / "out"
    assert main(["--config", str(src), "--out", str(out), "--authelia", "none"]) == 0
    assert out.stat().st_mode & 0o777 == 0o700
    assert (out / "managed").stat().st_mode & 0o777 == 0o700
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in out.rglob("*") if p.is_file())
    assert not (tmp_path / "out.partial").exists()


class _FakeValidator:
    """Stands in for the Authelia CLI only to drive main()'s decision logic; real
    validation is covered by tests/integration."""

    argv_prefix = ("fake-authelia",)

    def __init__(self, results: list[ValidationResult]) -> None:
        self.results = results

    def validate(self, paths: object) -> ValidationResult:
        return self.results.pop(0)


@pytest.mark.parametrize(
    "after",
    [
        ValidationResult(ok=False, errors=["boom"]),
        ValidationResult(ok=True, warnings=["new warning"]),
    ],
)
def test_split_that_fails_validation_is_not_put_in_place(
    realistic_main: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    after: ValidationResult,
) -> None:
    import scripts.split_config as sc

    fake = _FakeValidator([ValidationResult(ok=True), after])
    monkeypatch.setattr(sc, "_validator", lambda mode: fake)
    src = tmp_path / "c.yml"
    src.write_text(realistic_main)
    out = tmp_path / "out"
    assert main(["--config", str(src), "--out", str(out), "--authelia", "auto"]) == 1
    assert not out.exists()
    assert (tmp_path / "out.rejected").is_dir()
    assert "DO NOT USE" in capsys.readouterr().err
