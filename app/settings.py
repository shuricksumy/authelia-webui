"""Runtime configuration from environment variables (SPEC §2).

Fail closed: any missing or invalid required variable stops the app at startup.
Error messages name the variable but never echo its value.
"""

from __future__ import annotations

import ipaddress
from enum import StrEnum
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, ValidationError, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

type Network = ipaddress.IPv4Network | ipaddress.IPv6Network

MIN_SECRET_KEY_BYTES = 32
APP_PORT = 8080  # the normal port (Dockerfile, healthcheck, compose)


class RestartMode(StrEnum):
    SOCKET_PROXY = "socket-proxy"
    SIGNAL = "signal"


class VersionMismatch(StrEnum):
    BLOCK = "block"
    WARN = "warn"


def parse_cidrs(value: object) -> list[Network]:
    """Parse a comma-separated CIDR list. Raises ValueError without echoing input."""
    if isinstance(value, list):
        items = [str(v) for v in value]
    elif isinstance(value, str):
        items = [part.strip() for part in value.split(",")]
    else:
        raise ValueError("must be a comma-separated list of CIDRs")
    items = [i for i in items if i]
    if not items:
        raise ValueError("must not be empty")
    networks: list[Network] = []
    for position, item in enumerate(items, start=1):
        try:
            network = ipaddress.ip_network(item, strict=False)
        except ValueError:
            raise ValueError(f"entry #{position} is not a valid CIDR") from None
        if network.prefixlen == 0:
            # 0.0.0.0/0 or ::/0 would silently turn "allow-list" into "allow everyone".
            raise ValueError(f"entry #{position} is a catch-all (/0), which is not allowed")
        networks.append(network)
    return networks


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        case_sensitive=True, extra="ignore", str_strip_whitespace=True
    )

    AUTH_DOMAIN: str = Field(min_length=1)
    CONFIGURATOR_DOMAIN: str = Field(min_length=1)
    ADMIN_GROUP: str = Field(min_length=1)
    ALLOWED_CLIENT_CIDRS: Annotated[list[Network], NoDecode]
    TRUSTED_PROXY_CIDRS: Annotated[list[Network], NoDecode]
    AUTHELIA_CONTAINER: str = Field(min_length=1)
    AUTHELIA_HEALTH_URL: str = Field(min_length=1)
    # Internal base URL for forward-auth probes; derived from AUTHELIA_HEALTH_URL when unset.
    AUTHELIA_URL: str | None = None
    APP_SECRET_KEY: SecretStr

    CONFIG_MAIN: Path = Path("/config/configuration.yml")
    CONFIG_MANAGED_DIR: Path = Path("/config/managed")
    USERS_FILE: Path = Path("/config/users.yml")
    RESTART_MODE: RestartMode = RestartMode.SOCKET_PROXY
    DOCKER_PROXY_URL: str = "http://socket-proxy:2375"
    VERSION_MISMATCH: VersionMismatch = VersionMismatch.BLOCK
    AUTHELIA_LOG_FILE: Path | None = None
    NOTIFY_WEBHOOK_URL: SecretStr | None = None  # may embed a token (e.g. Telegram)
    AUTHELIA_BINARY: str = "authelia"
    # Same value as Authelia's X_AUTHELIA_CONFIG_FILTERS ("template" once the OIDC signing keys
    # live in managed/secrets/): validation must see the files exactly as Authelia does.
    CONFIG_FILTERS: str = ""
    CERT_WARN_DAYS: int = Field(default=21, ge=1, le=365)
    # host[:port] list whose TLS certificates are checked; unset: AUTH_DOMAIN and
    # CONFIGURATOR_DOMAIN on 443; empty: no live check.
    CERT_CHECK_HOSTS: str | None = None
    # Break-glass access for when Authelia itself is down (docs/emergency.md): a second port that
    # the compose file must publish on the host's 127.0.0.1 only, protected by one password.
    # Both unset (the default) means no such port exists.
    EMERGENCY_PORT: int | None = Field(default=None, ge=1024, le=65535)
    EMERGENCY_PASSWORD_HASH: SecretStr | None = None  # an Authelia digest ($argon2id$...)
    APPLY_HEALTH_TIMEOUT_S: int = Field(default=30, ge=5, le=300)
    AUTHELIA_VERSION: str = "unknown"  # baked into the image at build time

    @field_validator("ALLOWED_CLIENT_CIDRS", "TRUSTED_PROXY_CIDRS", mode="before")
    @classmethod
    def _cidrs(cls, value: object) -> list[Network]:
        return parse_cidrs(value)

    @field_validator("EMERGENCY_PORT", "EMERGENCY_PASSWORD_HASH", mode="before")
    @classmethod
    def _empty_emergency_is_unset(cls, value: object) -> object:
        return None if isinstance(value, str) and not value.strip() else value

    @model_validator(mode="after")
    def _emergency_needs_both(self) -> Settings:
        digest = self.EMERGENCY_PASSWORD_HASH
        if (self.EMERGENCY_PORT is None) != (digest is None):
            raise ValueError("EMERGENCY_PORT and EMERGENCY_PASSWORD_HASH must be set together")
        if self.EMERGENCY_PORT == APP_PORT:
            raise ValueError(f"EMERGENCY_PORT must differ from the application port {APP_PORT}")
        if digest is not None and not digest.get_secret_value().startswith("$"):
            raise ValueError("EMERGENCY_PASSWORD_HASH must be an Authelia password digest ($...)")
        return self

    @field_validator("AUTHELIA_LOG_FILE", "NOTIFY_WEBHOOK_URL", mode="before")
    @classmethod
    def _empty_is_unset(cls, value: object) -> object:
        # `VAR=` in compose/.env means "not set", not Path(".") or an empty URL.
        return None if isinstance(value, str) and not value.strip() else value

    @property
    def authelia_base_url(self) -> str:
        if self.AUTHELIA_URL:
            return self.AUTHELIA_URL.rstrip("/")
        parts = urlsplit(self.AUTHELIA_HEALTH_URL)
        return f"{parts.scheme}://{parts.netloc}"

    @property
    def default_client_ip(self) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        """An address inside the allowed networks, used when an access test names none."""
        first = self.ALLOWED_CLIENT_CIDRS[0]
        return next(first.hosts(), first.network_address)

    @field_validator("APP_SECRET_KEY")
    @classmethod
    def _secret_length(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value().encode()) < MIN_SECRET_KEY_BYTES:
            raise ValueError(f"must be at least {MIN_SECRET_KEY_BYTES} bytes")
        return value


class SettingsError(RuntimeError):
    """Startup configuration error; message is safe to log."""


def load_settings() -> Settings:
    try:
        return Settings()  # type: ignore[call-arg]  # values come from the environment
    except ValidationError as exc:
        problems = []
        for err in exc.errors(include_input=False, include_url=False):
            name = ".".join(str(p) for p in err["loc"]) or "?"
            message = err["msg"].removeprefix("Value error, ")
            problems.append(f"{name}: {message}")
        raise SettingsError(
            "refusing to start, invalid environment: " + "; ".join(problems)
        ) from None
