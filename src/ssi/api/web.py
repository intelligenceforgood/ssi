"""Web UI routes for SSI — simple investigation submission and report viewer."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from ssi.api.routes import InvestigateRequest, _run_investigation_task
from ssi.store.task_store import build_task_store

logger = logging.getLogger(__name__)

_TEMPLATE_DIR = Path(__file__).resolve().parent / "web_templates"
templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))

web_router = APIRouter(tags=["web"])


@web_router.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    """Render the investigation submission form."""
    return templates.TemplateResponse("index.html", {"request": request})


@web_router.post("/submit", response_class=HTMLResponse)
async def submit_investigation(
    request: Request,
    url: str = Form(...),
    scan_type: str = Form("passive"),
) -> RedirectResponse:
    """Handle form submission and redirect to the status page."""
    from uuid import uuid4

    task_id = str(uuid4())
    store = build_task_store()
    store.set(task_id, {"status": "pending"})

    req = InvestigateRequest(url=url, scan_type=scan_type, push_to_core=True)

    import asyncio

    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, _run_investigation_task, task_id, req)

    return RedirectResponse(url=f"/status/{task_id}", status_code=303)


@web_router.get("/status/{task_id}", response_class=HTMLResponse)
async def investigation_status(request: Request, task_id: str) -> HTMLResponse:
    """Show investigation progress / results page."""
    store = build_task_store()
    task = store.get(task_id)
    if not task:
        return templates.TemplateResponse(
            "status.html",
            {"request": request, "task_id": task_id, "task": None, "error": "Investigation not found."},
        )

    result_data: dict[str, Any] | None = task.get("result")
    pdf_path: str | None = None

    if result_data and isinstance(result_data, dict):
        pdf_path = result_data.get("pdf_report_path", "")

    return templates.TemplateResponse(
        "status.html",
        {
            "request": request,
            "task_id": task_id,
            "task": task,
            "result": result_data,
            "pdf_path": pdf_path,
        },
    )


@web_router.get("/report/{task_id}/pdf")
async def download_pdf(task_id: str) -> FileResponse:
    """Download the PDF report for a completed investigation."""
    store = build_task_store()
    task = store.get(task_id)
    if not task or task.get("status") != "completed":
        raise HTTPException(status_code=404, detail="Report not ready or not found.")

    result_data = task.get("result", {})
    pdf_path = result_data.get("pdf_report_path", "")

    if not pdf_path or not Path(pdf_path).exists():
        raise HTTPException(status_code=404, detail="PDF report not available.")

    return FileResponse(
        path=pdf_path,
        media_type="application/pdf",
        filename=f"ssi_report_{task_id[:8]}.pdf",
    )
