"""examples/production/compose.sessions.yml and docs/sessions.md: what the guide promises.

The security claim of the feature lives in the Redis user's line (it may scan, read and delete the
session keys and nothing else), so it is pinned here; tests/integration/test_sessions_example.py
runs that exact line against a real Redis.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from app.settings import Settings

ROOT = Path(__file__).resolve().parents[2]
PRODUCTION = ROOT / "examples" / "production"
OVERLAY = PRODUCTION / "compose.sessions.yml"
DOC = ROOT / "docs" / "sessions.md"


def _services(path: Path) -> dict[str, Any]:
    loaded: dict[str, Any] = YAML(typ="safe").load(path.read_text())
    services: dict[str, Any] = loaded["services"]
    return services


def _redis_command() -> list[str]:
    return [str(x) for x in _services(OVERLAY)["redis"]["command"]]


def _user_definition() -> list[str]:
    command = _redis_command()
    return command[command.index("--user") + 1 :]


def test_the_redis_command_is_composes_own_command_plus_one_user() -> None:
    base = [str(x) for x in _services(PRODUCTION / "compose.yml")["redis"]["command"]]
    ours = _redis_command()
    # the overlay replaces the whole command, so it must not drift from the base one
    assert ours[: len(base)] == base
    assert ours[len(base)] == "--user"  # and adds exactly one more directive


def test_the_configurators_redis_user_can_only_scan_read_and_delete_session_keys() -> None:
    name, state, password, keys, *rules = _user_definition()
    assert name == "configurator" and state == "on"
    assert password.startswith(">${CONFIGURATOR_REDIS_PASSWORD:?")  # required, never empty
    assert keys == "~authelia-session:*"  # only these keys
    assert rules == ["-@all", "+scan", "+get", "+del", "+pttl", "+ping"]  # and no write command
    joined = " ".join(_user_definition())
    for broader in ("+@", "allkeys", "~*", "&", "+set", "+flush", "+config", "nopass"):
        assert broader not in joined.replace("-@all", "")


def test_the_default_redis_user_keeps_its_password_and_redis_is_not_published() -> None:
    command = _redis_command()
    assert command[command.index("--requirepass") + 1] == "${REDIS_PASSWORD}"
    assert "ports" not in _services(OVERLAY)["redis"]


def test_the_configurator_gets_the_settings_a_read_only_secret_and_the_redis_network() -> None:
    configurator = _services(OVERLAY)["configurator"]
    env = configurator["environment"]
    assert env["SESSIONS_REDIS_URL"] == "redis://redis:6379/0"
    assert env["SESSIONS_REDIS_PASSWORD"] == "${CONFIGURATOR_REDIS_PASSWORD}"
    assert env["SESSIONS_SECRET_FILE"] == "/run/secrets/session_secret"
    assert configurator["volumes"] == ["./secrets/session_secret:/run/secrets/session_secret:ro"]
    assert configurator["networks"] == ["sessions"]  # compose.yml's own networks stay


def test_the_overlay_holds_no_real_secret() -> None:
    text = OVERLAY.read_text()
    assert "THE-VALUE-OF-session.secret" in text  # a placeholder, not a value
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        if "PASSWORD" in line:
            assert "${" in line, line  # always read from the environment


def test_the_env_example_names_the_new_variable_and_keeps_it_optional() -> None:
    text = (PRODUCTION / "production.env.example").read_text()
    assert "# CONFIGURATOR_REDIS_PASSWORD=" in text  # commented out: only with the add-on


def test_every_sessions_setting_is_in_the_guide() -> None:
    text = DOC.read_text()
    for name in Settings.model_fields:
        if name.startswith("SESSIONS_"):
            assert f"`{name}`" in text, f"docs/sessions.md does not mention {name}"


def test_the_guide_covers_every_message_the_app_shows() -> None:
    text = DOC.read_text()
    for phrase in (
        "Open sessions are not set up",
        "does not exist",
        "is a folder",
        "not readable by the configurator's user",
        "Redis cannot be reached",
        "Redis refused the configurator's login",
        "may not read or delete the session keys",
        "None of the sessions could be read",
        "+select",  # a database other than 0 needs it
        "Your own compose file, with other names?",  # the add-on assumes the example's names
    ):
        assert phrase in text, phrase


def test_the_guide_is_linked_from_where_people_start() -> None:
    assert "docs/sessions.md" in (ROOT / "README.md").read_text()
    assert "sessions.md" in (ROOT / "docs" / "deployment.md").read_text()
    assert "compose.sessions.yml" in (PRODUCTION / "README.md").read_text()
