"""FastAPI entrypoint. Phase 0: settings validation, /healthz and /version only."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse

from app.settings import Settings, load_settings


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

    return app
