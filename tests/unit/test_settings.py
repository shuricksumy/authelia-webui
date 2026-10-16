from __future__ import annotations

import pytest

from app.settings import SettingsError, load_settings, parse_cidrs

GOOD = {
    "AUTH_DOMAIN": "auth.example.com",
    "CONFIGURATOR_DOMAIN": "authcfg.example.com",
    "ADMIN_GROUP": "admin",
    "ALLOWED_CLIENT_CIDRS": "10.8.0.0/24, 192.168.1.0/24",
    "TRUSTED_PROXY_CIDRS": "172.20.0.0/16",
    "AUTHELIA_CONTAINER": "authelia",
    "AUTHELIA_HEALTH_URL": "http://authelia:9091/api/health",
    "APP_SECRET_KEY": "k" * 32,
}


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    for key in [*GOOD, "RESTART_MODE", "VERSION_MISMATCH"]:
        monkeypatch.delenv(key, raising=False)
    for key, value in GOOD.items():
        monkeypatch.setenv(key, value)
    return monkeypatch


def test_valid_environment_loads(env: pytest.MonkeyPatch) -> None:
    settings = load_settings()
    assert [str(n) for n in settings.ALLOWED_CLIENT_CIDRS] == ["10.8.0.0/24", "192.168.1.0/24"]
    assert settings.VERSION_MISMATCH == "block"  # default is fail closed


@pytest.mark.parametrize("name", list(GOOD))
def test_each_required_variable_is_required(env: pytest.MonkeyPatch, name: str) -> None:
    env.delenv(name)
    with pytest.raises(SettingsError, match=name):
        load_settings()


@pytest.mark.parametrize("value", ["", " , ", "not-a-cidr", "10.0.0.0/33"])
def test_allowed_cidrs_empty_or_invalid_refuses_to_start(
    env: pytest.MonkeyPatch, value: str
) -> None:
    env.setenv("ALLOWED_CLIENT_CIDRS", value)
    with pytest.raises(SettingsError, match="ALLOWED_CLIENT_CIDRS"):
        load_settings()


def test_short_secret_key_rejected_without_echoing_it(env: pytest.MonkeyPatch) -> None:
    env.setenv("APP_SECRET_KEY", "short-secret-value")
    with pytest.raises(SettingsError) as exc:
        load_settings()
    assert "APP_SECRET_KEY" in str(exc.value)
    assert "short-secret-value" not in str(exc.value)


def test_invalid_cidr_error_does_not_echo_input() -> None:
    with pytest.raises(ValueError) as exc:
        parse_cidrs("10.8.0.0/24,203.0.113.77/99")
    assert "203.0.113.77" not in str(exc.value)
    assert "#2" in str(exc.value)


def test_bad_enum_rejected(env: pytest.MonkeyPatch) -> None:
    env.setenv("VERSION_MISMATCH", "ignore")
    with pytest.raises(SettingsError, match="VERSION_MISMATCH"):
        load_settings()


@pytest.mark.parametrize("name", ["ALLOWED_CLIENT_CIDRS", "TRUSTED_PROXY_CIDRS"])
@pytest.mark.parametrize("value", ["0.0.0.0/0", "10.8.0.0/24,::/0"])
def test_catch_all_networks_are_rejected(env: pytest.MonkeyPatch, name: str, value: str) -> None:
    """/0 would turn the allow-list (or the trusted-proxy list) into 'everyone'."""
    env.setenv(name, value)
    with pytest.raises(SettingsError, match=f"{name}.*catch-all"):
        load_settings()


def test_whitespace_is_stripped_and_blank_rejected(env: pytest.MonkeyPatch) -> None:
    env.setenv("CONFIGURATOR_DOMAIN", "  authcfg.example.com ")
    assert load_settings().CONFIGURATOR_DOMAIN == "authcfg.example.com"
    env.setenv("AUTH_DOMAIN", "   ")
    with pytest.raises(SettingsError, match="AUTH_DOMAIN"):
        load_settings()


def test_empty_optional_values_mean_unset(env: pytest.MonkeyPatch) -> None:
    env.setenv("AUTHELIA_LOG_FILE", "")
    env.setenv("NOTIFY_WEBHOOK_URL", " ")
    settings = load_settings()
    assert settings.AUTHELIA_LOG_FILE is None  # not Path(".")
    assert settings.NOTIFY_WEBHOOK_URL is None


def test_webhook_url_is_not_exposed_in_repr(env: pytest.MonkeyPatch) -> None:
    env.setenv("NOTIFY_WEBHOOK_URL", "https://hooks.example.com/bot-token-xyz")
    settings = load_settings()
    assert "bot-token-xyz" not in repr(settings)
    assert settings.NOTIFY_WEBHOOK_URL is not None
    assert settings.NOTIFY_WEBHOOK_URL.get_secret_value().endswith("bot-token-xyz")
