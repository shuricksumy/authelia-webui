"""Everything the web layer needs for applying, built once per app (tests can replace it)."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

from app.apply.engine import ApplyEngine, Validator
from app.apply.jobs import JobBoard
from app.apply.repo import ManagedRepo
from app.apply.runtime import AutheliaRuntime
from app.apply.status import StatusCache
from app.apply.validate import validate_candidate
from app.settings import Settings


@dataclass
class ApplyServices:
    runtime: AutheliaRuntime
    board: JobBoard
    engine: ApplyEngine
    status: StatusCache
    repo: ManagedRepo
    start_lock: threading.Lock = field(default_factory=threading.Lock)


def build_services(settings: Settings, validator: Validator = validate_candidate) -> ApplyServices:
    runtime = AutheliaRuntime(settings.DOCKER_PROXY_URL, settings.AUTHELIA_CONTAINER)
    board = JobBoard(settings.CONFIG_MANAGED_DIR)
    engine = ApplyEngine(settings, runtime, board, validator)
    return ApplyServices(
        runtime=runtime,
        board=board,
        engine=engine,
        status=StatusCache(settings, runtime),
        repo=engine.repo,
    )
