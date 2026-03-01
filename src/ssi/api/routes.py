"""API routes for SSI."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel, Field

from ssi.settings import get_settings
from ssi.store.task_store import build_task_store

router = APIRouter()


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class InvestigateRequest(BaseModel):
    """Parameters for a ``POST /investigate`` request."""

    url: str = Field(..., description="The suspicious URL to investigate.")
    scan_type: str = Field(
        "passive",
        description="Investigation mode: passive, active, or full.",
        pattern="^(passive|active|full)$",
    )
    passive_only: bool | None = Field(
        None,
        description="Deprecated — use scan_type instead. Kept for backward compatibility.",
    )
    skip_whois: bool = False
    skip_screenshot: bool = False
    skip_virustotal: bool = False
    push_to_core: bool = Field(True, description="Push results to i4g core platform.")
    trigger_dossier: bool = Field(False, description="Queue dossier generation after push.")
    dataset: str = Field("ssi", description="Dataset label for the core case.")

    def resolved_scan_type(self) -> str:
        """Return the effective scan_type, honouring the legacy passive_only flag.

        If *passive_only* is explicitly set and *scan_type* is still the default,
        derive scan_type from the boolean for backward compatibility.
        """
        if self.passive_only is not None and self.scan_type == "passive":
            return "passive" if self.passive_only else "full"
        return self.scan_type


class InvestigateResponse(BaseModel):
    """Acknowledgement returned when an investigation is submitted."""

    investigation_id: str
    status: str
    message: str


class InvestigationStatusResponse(BaseModel):
    """Polling response for a running or completed investigation."""

    investigation_id: str
    status: str
    result: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# In-memory concurrency limiter (survives task store backend changes)
# ---------------------------------------------------------------------------

# Concurrent investigation limiter
_ACTIVE_INVESTIGATIONS = 0
_ACTIVE_LOCK = threading.Lock()


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

    settings = get_settings()
    max_concurrent = settings.api.max_concurrent_investigations

    global _ACTIVE_INVESTIGATIONS  # noqa: PLW0603
    with _ACTIVE_LOCK:
        if _ACTIVE_INVESTIGATIONS >= max_concurrent:
            raise HTTPException(
                status_code=429,
                detail=f"Server is at capacity ({max_concurrent} concurrent investigations). Try again later.",
            )
        _ACTIVE_INVESTIGATIONS += 1

    task_id = str(uuid4())
    store = build_task_store()
    store.set(task_id, {"status": "pending"})

    background_tasks.add_task(_run_investigation_task, task_id, req)

    return InvestigateResponse(
        investigation_id=task_id,
        status="pending",
        message="Investigation queued. Poll /investigate/{id} for status.",
    )


@router.get("/investigate/{investigation_id}", response_model=InvestigationStatusResponse)
def get_investigation_status(investigation_id: str) -> InvestigationStatusResponse:
    """Check the status of a previously submitted investigation."""
    store = build_task_store()
    task = store.get(investigation_id)
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

    global _ACTIVE_INVESTIGATIONS  # noqa: PLW0603

    store = build_task_store()
    store.update(task_id, status="running")
    settings = get_settings()
    output_dir = Path(settings.evidence.output_dir)

    try:
        result = run_investigation(
            url=req.url,
            output_dir=output_dir,
            scan_type=req.resolved_scan_type(),
            skip_whois=req.skip_whois,
            skip_screenshot=req.skip_screenshot,
            skip_virustotal=req.skip_virustotal,
            report_format="both",
        )
        store.update(
            task_id,
            status="completed" if result.success else "failed",
            result=result.model_dump(mode="json"),
        )

        # Push to core platform if requested
        if req.push_to_core and result.success:
            _push_to_core(task_id, result, dataset=req.dataset, trigger_dossier=req.trigger_dossier)

    except Exception as e:
        import logging

        logging.getLogger(__name__).exception("Investigation task %s failed", task_id)
        store.update(
            task_id,
            status="failed",
            result={"error": "Internal investigation error. Check server logs for details."},
        )
    finally:
        with _ACTIVE_LOCK:
            _ACTIVE_INVESTIGATIONS = max(0, _ACTIVE_INVESTIGATIONS - 1)


def _push_to_core(task_id: str, result: Any, *, dataset: str, trigger_dossier: bool) -> None:
    """Create a case record directly in the shared DB and update the task store.

    Uses ``ScanStore.create_case_record()`` for a direct DB write so that
    Cloud Run Services — which cannot authenticate through IAP — bypass the
    deprecated ``CoreBridge`` HTTP path that used to fail silently with 403s.

    On success the ``case_id`` is stored in the task store so
    ``GET /investigate/{id}`` can return it immediately.
    """
    import logging

    logger = logging.getLogger(__name__)
    store = build_task_store()

    scan_id = str(getattr(result, "investigation_id", "") or "")

    try:
        from ssi.store import build_scan_store

        scan_store = build_scan_store()
        case_id = scan_store.create_case_record(
            scan_id=scan_id,
            result=result,
            dataset=dataset,
        )
        if case_id:
            store.update(task_id, core_case_id=case_id)
            logger.info(
                "Created case %s for investigation %s (direct DB, scan_id=%s)",
                case_id,
                task_id,
                scan_id,
            )
        else:
            logger.error(
                "create_case_record returned None for investigation %s (scan_id=%s) — "
                "case was NOT written to the cases table; "
                "check the preceding scan_store log lines for the root cause",
                task_id,
                scan_id,
            )
            store.update(task_id, core_push_error="case_record_creation_failed")

    except Exception:
        logger.exception(
            "Failed to create case record for investigation %s (scan_id=%s) — "
            "case was NOT written to the cases table",
            task_id,
            scan_id,
        )
        store.update(task_id, core_push_error="case_record_creation_failed")
