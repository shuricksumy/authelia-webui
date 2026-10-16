"""Running Authelia status for the footer and the version check (SPEC §11.5), cached briefly so a
slow or unreachable proxy never slows down page loads."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from app.apply import notify
from app.apply import state as apply_state
from app.apply.health import probe
from app.apply.runtime import AutheliaRuntime, RuntimeUnavailable
from app.settings import Settings, VersionMismatch

TTL_S = 15.0


@dataclass(frozen=True)
class RuntimeStatus:
    running_version: str | None
    healthy: bool | None  # None: could not be determined
    error: str  # why the status is unknown, plain language ("" when known)
    bundled_version: str
    mismatch_blocks: bool
    mismatch_warns: bool

    @property
    def mismatch(self) -> bool:
        return self.running_version is not None and self.running_version != self.bundled_version

    @property
    def bad(self) -> bool:
        return self.healthy is False or self.mismatch_blocks or bool(self.error)

    @property
    def explanation(self) -> str:
        if self.error:
            return f"Cannot reach Authelia's container: {self.error}. Applying is disabled."
        if self.healthy is False:
            return "Authelia is not answering its health check."
        if self.mismatch:
            action = "Applying is disabled until both match." if self.mismatch_blocks else ""
            return (
                f"Authelia {self.running_version} is running but this configurator bundles "
                f"{self.bundled_version}. Deploy the image tagged authelia-{self.running_version}"
                f" (or update Authelia to {self.bundled_version}). {action}"
            ).strip()
        return ""


class StatusCache:
    def __init__(
        self,
        settings: Settings,
        runtime: AutheliaRuntime,
        check: Callable[[str], bool] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.settings = settings
        self.runtime = runtime
        self._check = check or (lambda url: probe(url, timeout_s=1.0))
        self._clock = clock
        self._lock = threading.Lock()
        self._value: RuntimeStatus | None = None
        self._at = 0.0

    def get(self, fresh: bool = False) -> RuntimeStatus:
        with self._lock:
            if not fresh and self._value is not None and self._clock() - self._at < TTL_S:
                return self._value
        value = self._compute()
        with self._lock:
            self._value, self._at = value, self._clock()
        return value

    def invalidate(self) -> None:
        with self._lock:
            self._value = None

    def _notify_mismatch_once(self, running: str) -> None:
        """One notification per running version, remembered across restarts (state.json)."""
        managed = self.settings.CONFIG_MANAGED_DIR
        try:
            if apply_state.load(managed).get("mismatch_notified") == running:
                return
            apply_state.update(managed, mismatch_notified=running)
        except OSError:
            return
        blocked = self.settings.VERSION_MISMATCH == VersionMismatch.BLOCK
        effect = "disabled." if blocked else "allowed (warn)."
        notify.send(
            self.settings, "version-mismatch", "detected", "-",
            f"Authelia {running} is running but the configurator bundles "
            f"{self.settings.AUTHELIA_VERSION}; applying is {effect}",
        )  # fmt: skip

    def _compute(self) -> RuntimeStatus:
        s = self.settings
        block = s.VERSION_MISMATCH == VersionMismatch.BLOCK
        version: str | None = None
        error = ""
        try:
            version = self.runtime.inspect(timeout_s=1.0).version
        except RuntimeUnavailable as exc:
            error = str(exc)
        healthy = None if error else self._check(s.AUTHELIA_HEALTH_URL)
        mismatch = version is not None and version != s.AUTHELIA_VERSION
        if mismatch:
            self._notify_mismatch_once(str(version))
        return RuntimeStatus(
            running_version=version,
            healthy=healthy,
            error=error,
            bundled_version=s.AUTHELIA_VERSION,
            mismatch_blocks=mismatch and block,
            mismatch_warns=mismatch and not block,
        )
