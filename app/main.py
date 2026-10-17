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

from app import certs
from app.apply.services import ApplyServices, build_services
from app.emergency import Emergency
from app.security import SecurityMiddleware
from app.settings import Settings, load_settings
from app.web import router
from app.web_apply import router as apply_router
from app.web_emergency import router as emergency_router
from app.web_keys import router as keys_router
from app.web_oidc import router as oidc_router
from app.web_overview import router as overview_router
from app.web_tests import router as tests_router
from app.web_users import router as users_router

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
        if services.certs is not None:
            services.certs.start()
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

    def utc(ts: Any) -> str:
        moment = ts if isinstance(ts, datetime) else datetime.fromtimestamp(int(ts), UTC)
        return moment.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")

    app.state.templates.env.filters["utc"] = utc
    app.state.templates.env.filters["cert_days"] = lambda c: certs.describe_days(c.days_left())
    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")
    app.include_router(router)
    app.include_router(apply_router)
    app.include_router(tests_router)
    app.include_router(oidc_router)
    app.include_router(users_router)
    app.include_router(overview_router)
    app.include_router(keys_router)
    app.include_router(emergency_router)
    # Outermost: every request (incl. static files) passes the IP/identity/CSRF checks.
    emergency = Emergency(settings)
    app.state.emergency = emergency
    app.add_middleware(SecurityMiddleware, settings=settings, emergency=emergency)
    return app
