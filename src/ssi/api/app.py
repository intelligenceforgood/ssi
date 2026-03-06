"""FastAPI app for SSI — web interface and REST API."""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ssi.api.ecx_routes import ecx_router
from ssi.api.investigation_routes import investigation_router
from ssi.api.playbook_routes import playbook_router
from ssi.api.routes import router
from ssi.api.web import web_router
from ssi.api.ws_routes import ws_router
from ssi.settings import get_settings

logger = logging.getLogger(__name__)

try:
    from importlib.metadata import version

    VERSION = version("ssi")
except Exception:
    VERSION = "0.0.0"


def _cleanup_orphaned_scans() -> None:
    """Mark any 'running' site_scans rows as 'failed'.

    Called once during application startup.  When the SSI service is
    redeployed mid-investigation the background thread is killed and
    ``TaskStatusReporter`` never records a terminal status, leaving the
    ``site_scans`` row permanently at ``status='running'``.  This causes
    the UI to spin forever even after all services restart.

    Running this at boot ensures stale rows are cleaned up immediately,
    so the next ``GET /tasks/{task_id}`` call returns ``'failed'``.
    """
    try:
        from ssi.store import build_scan_store

        store = build_scan_store()
        orphaned = store.list_scans(status="running", limit=200)
        if not orphaned:
            logger.info("Startup scan cleanup: no orphaned 'running' scans found.")
            return
        err_msg = "Investigation interrupted by service restart."
        now = datetime.now(UTC)
        for scan in orphaned:
            scan_id = str(scan["scan_id"])
            try:
                store.update_scan(
                    scan_id,
                    status="failed",
                    error_message=err_msg,
                    completed_at=now,
                )
                logger.warning("Startup cleanup: marked orphaned scan %s as failed.", scan_id)
            except Exception as exc:
                logger.error("Startup cleanup: failed to update scan %s: %s", scan_id, exc)
    except Exception as exc:
        logger.error("Startup scan cleanup failed: %s", exc, exc_info=True)


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncGenerator[None, None]:  # noqa: ARG001
    """Application lifespan — run startup cleanup before serving requests."""
    _cleanup_orphaned_scans()
    yield


def create_app() -> FastAPI:
    """Build and return the FastAPI application."""
    settings = get_settings()

    application = FastAPI(
        title="Scam Site Investigator",
        description="AI-driven scam URL reconnaissance and evidence packaging.",
        version=VERSION,
        lifespan=_lifespan,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.api.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    application.include_router(router)
    application.include_router(ecx_router)
    application.include_router(investigation_router)
    application.include_router(playbook_router)
    application.include_router(ws_router)
    application.include_router(web_router)
    return application


app = create_app()
