"""API routes for SSI."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel, Field

from ssi.settings import get_settings

router = APIRouter()


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class InvestigateRequest(BaseModel):
    url: str = Field(..., description="The suspicious URL to investigate.")
    passive_only: bool = Field(True, description="Limit to passive reconnaissance.")
    skip_whois: bool = False
    skip_screenshot: bool = False
    skip_virustotal: bool = False


class InvestigateResponse(BaseModel):
    investigation_id: str
    status: str
    message: str


class InvestigationStatusResponse(BaseModel):
    investigation_id: str
    status: str
    result: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# In-memory task tracking (replace with Redis / DB in production)
# ---------------------------------------------------------------------------

_TASKS: dict[str, dict[str, Any]] = {}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.post("/investigate", response_model=InvestigateResponse)
def submit_investigation(req: InvestigateRequest, background_tasks: BackgroundTasks) -> InvestigateResponse:
    """Submit a URL for investigation. Returns immediately with a task ID."""
    from uuid import uuid4

    task_id = str(uuid4())
    _TASKS[task_id] = {"status": "pending"}

    background_tasks.add_task(_run_investigation_task, task_id, req)

    return InvestigateResponse(
        investigation_id=task_id,
        status="pending",
        message="Investigation queued. Poll /investigate/{id} for status.",
    )


@router.get("/investigate/{investigation_id}", response_model=InvestigationStatusResponse)
def get_investigation_status(investigation_id: str) -> InvestigationStatusResponse:
    """Check the status of a previously submitted investigation."""
    task = _TASKS.get(investigation_id)
    if not task:
        raise HTTPException(status_code=404, detail="Investigation not found.")
    return InvestigationStatusResponse(
        investigation_id=investigation_id,
        status=task["status"],
        result=task.get("result"),
    )


def _run_investigation_task(task_id: str, req: InvestigateRequest) -> None:
    """Background task that executes the investigation."""
    from ssi.investigator.orchestrator import run_investigation

    _TASKS[task_id]["status"] = "running"
    settings = get_settings()
    output_dir = Path(settings.evidence.output_dir)

    try:
        result = run_investigation(
            url=req.url,
            output_dir=output_dir,
            passive_only=req.passive_only,
            skip_whois=req.skip_whois,
            skip_screenshot=req.skip_screenshot,
            skip_virustotal=req.skip_virustotal,
        )
        _TASKS[task_id]["status"] = "completed" if result.success else "failed"
        _TASKS[task_id]["result"] = result.model_dump(mode="json")
    except Exception as e:
        _TASKS[task_id]["status"] = "failed"
        _TASKS[task_id]["result"] = {"error": str(e)}
