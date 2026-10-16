"""Wait until a *restarted* Authelia is healthy (SPEC §6: 1 s interval, 30 s timeout)."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

import httpx

from app.apply.runtime import AutheliaRuntime, RuntimeUnavailable


@dataclass(frozen=True)
class HealthResult:
    healthy: bool
    reason: str  # plain language, for the result banner


def probe(url: str, timeout_s: float = 2.0) -> bool:
    try:
        return httpx.get(url, timeout=timeout_s).status_code == 200
    except httpx.HTTPError:
        return False


def wait_restarted_and_healthy(
    runtime: AutheliaRuntime,
    health_url: str,
    previous_started_at: str,
    timeout_s: float = 30.0,
    interval_s: float = 1.0,
    check: Callable[[str], bool] = probe,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> HealthResult:
    """Healthy only once the container really restarted (StartedAt changed) *and* the health
    endpoint answers 200 - so the old instance can never be mistaken for the new one."""
    deadline = clock() + timeout_s
    restarted = False
    while clock() < deadline:
        if not restarted:
            try:
                state = runtime.inspect(timeout_s=2.0)
                restarted = state.started_at != previous_started_at and state.running
            except RuntimeUnavailable:
                restarted = False
        if restarted and check(health_url):
            return HealthResult(True, "Authelia restarted and is healthy.")
        sleep(interval_s)
    if not restarted:
        return HealthResult(False, f"Authelia did not come back up within {int(timeout_s)} s.")
    return HealthResult(False, f"Authelia started but was not healthy within {int(timeout_s)} s.")
