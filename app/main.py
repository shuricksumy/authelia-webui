"""FastAPI entrypoint. Phase 0: settings validation, /healthz and /version only."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.security import SecurityMiddleware
from app.settings import Settings, load_settings
from app.web import router

HERE = Path(__file__).resolve().parent


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    app = FastAPI(title="Authelia Configurator", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings

    @app.get("/healthz", response_class=PlainTextResponse)
    def healthz() -> str:
        return "ok"

    @app.get("/version")
    def version() -> dict[str, Any]:
        # Running version comes from the socket proxy in Phase 1 (SPEC §11.5).
        return {"bundled": settings.AUTHELIA_VERSION, "running": None}

    app.state.templates = Jinja2Templates(directory=str(HERE / "templates"))
    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")
    app.include_router(router)
    # Outermost: every request (incl. static files) passes the IP/identity/CSRF checks.
    app.add_middleware(SecurityMiddleware, settings=settings)
    return app
