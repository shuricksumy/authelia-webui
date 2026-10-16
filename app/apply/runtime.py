"""Talk to the Docker daemon *only* through the socket proxy (SPEC §7).

The proxy allows exactly two calls for the Authelia container: inspect and restart. This
client never builds any other path, and the proxy refuses everything else anyway.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import quote

import httpx

API_VERSION = "v1.41"  # Docker 20.10+; the proxy's regex accepts any v1.xx
CONTAINER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
VERSION_LABEL = "org.opencontainers.image.version"


class RuntimeUnavailable(RuntimeError):
    """The proxy or the container could not be reached; message is safe to show."""


@dataclass(frozen=True)
class ContainerState:
    started_at: str
    running: bool
    version: str | None  # from the image label; None when the image has none


class AutheliaRuntime:
    def __init__(self, proxy_url: str, container: str, timeout_s: float = 10.0) -> None:
        if not CONTAINER_NAME.match(container):
            raise ValueError("AUTHELIA_CONTAINER is not a valid container name")
        self.base = proxy_url.rstrip("/")
        self.container = quote(container, safe="")
        self.timeout_s = timeout_s

    def _url(self, action: str) -> str:
        return f"{self.base}/{API_VERSION}/containers/{self.container}/{action}"

    def inspect(self, timeout_s: float | None = None) -> ContainerState:
        try:
            response = httpx.get(self._url("json"), timeout=timeout_s or self.timeout_s)
        except httpx.HTTPError as exc:
            raise RuntimeUnavailable(f"socket proxy unreachable ({type(exc).__name__})") from None
        if response.status_code != 200:
            raise RuntimeUnavailable(f"inspecting Authelia failed (HTTP {response.status_code})")
        try:
            data = response.json()
            state = data["State"]
            labels = (data.get("Config") or {}).get("Labels") or {}
            return ContainerState(
                started_at=str(state["StartedAt"]),
                running=bool(state.get("Running")),
                version=str(labels[VERSION_LABEL]).lstrip("v") if VERSION_LABEL in labels else None,
            )
        except (ValueError, KeyError, TypeError):
            raise RuntimeUnavailable("unexpected answer from the socket proxy") from None

    def restart(self, grace_s: int = 10) -> None:
        try:
            response = httpx.post(
                self._url("restart"), params={"t": str(grace_s)}, timeout=grace_s + 30
            )
        except httpx.HTTPError as exc:
            raise RuntimeUnavailable(f"socket proxy unreachable ({type(exc).__name__})") from None
        if response.status_code not in (200, 204):
            raise RuntimeUnavailable(f"restarting Authelia failed (HTTP {response.status_code})")
