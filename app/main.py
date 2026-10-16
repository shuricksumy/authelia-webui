"""FastAPI entrypoint: settings validation, security layer, pages, and apply wiring."""

from __future__ import annotations

import logging
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.apply.services import ApplyServices, build_services
from app.security import SecurityMiddleware
from app.settings import Settings, load_settings
from app.web import router
from app.web_apply import router as apply_router
from app.web_tests import router as tests_router

HERE = Path(__file__).resolve().parent
log = logging.getLogger("app.main")


def create_app(settings: Settings | None = None, services: ApplyServices | None = None) -> FastAPI:
    settings = settings or load_settings()
    services = services or build_services(settings)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        # Resolve an apply that was interrupted by a crash, without delaying startup/healthz.
        def recover() -> None:
            try:
                message = services.engine.recover()
                if message:
                    log.warning("recovered an interrupted apply: %s", message)
            except Exception:
                log.exception("recovery of an interrupted apply failed")

        threading.Thread(target=recover, name="apply-recovery", daemon=True).start()
        yield

    app = FastAPI(
        title="Authelia Configurator",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.services = services

    @app.get("/healthz", response_class=PlainTextResponse)
    def healthz() -> str:
        return "ok"

    @app.get("/version")
    def version() -> dict[str, Any]:
        status = services.status.get()
        return {
            "bundled": settings.AUTHELIA_VERSION,
            "running": status.running_version,
            "healthy": status.healthy,
            "match": not status.mismatch if status.running_version else None,
        }

    app.state.templates = Jinja2Templates(directory=str(HERE / "templates"))
    app.state.templates.env.filters["utc"] = lambda ts: datetime.fromtimestamp(
        int(ts), UTC
    ).strftime("%Y-%m-%d %H:%M UTC")
    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")
    app.include_router(router)
    app.include_router(apply_router)
    app.include_router(tests_router)
    # Outermost: every request (incl. static files) passes the IP/identity/CSRF checks.
    app.add_middleware(SecurityMiddleware, settings=settings)
    return app
