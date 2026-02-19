"""FastAPI app for SSI — web interface and REST API."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ssi.api.routes import router
from ssi.api.web import web_router
from ssi.settings import get_settings

try:
    from importlib.metadata import version

    VERSION = version("ssi")
except Exception:
    VERSION = "0.0.0"


def create_app() -> FastAPI:
    """Build and return the FastAPI application."""
    settings = get_settings()

    application = FastAPI(
        title="Scam Site Investigator",
        description="AI-driven scam URL reconnaissance and evidence packaging.",
        version=VERSION,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.api.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    application.include_router(router)
    application.include_router(web_router)
    return application


app = create_app()
