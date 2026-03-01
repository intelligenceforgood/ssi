"""HTTP-triggered job endpoints for the SSI Cloud Run Service.

Provides ``POST /jobs/investigate`` — an HTTP alternative to the
env-var-driven Cloud Run Job entrypoint.  The core API calls this
endpoint when ``ssi_job.mode == "service"`` instead of launching a
Cloud Run Job execution.

The endpoint spawns the investigation in a background thread so the
HTTP response returns immediately (202 Accepted).
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Literal

from fastapi import APIRouter, BackgroundTasks
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/jobs", tags=["jobs"])


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------


class InvestigateRequest(BaseModel):
    """Payload for triggering an SSI investigation via HTTP."""

    url: str = Field(..., description="The suspicious URL to investigate.")
    scan_type: Literal["passive", "active", "full"] = Field(
        default="full",
        description="Investigation mode: passive, active, or full.",
    )
    scan_id: str | None = Field(
        default=None,
        description="Pre-assigned scan ID (from core's pre-created site_scans row).",
    )
    push_to_core: bool = Field(
        default=True,
        description="Push results to a core case record.",
    )
    dataset: str = Field(
        default="ssi",
        description="Dataset label for the case created in core.",
    )


class InvestigateResponse(BaseModel):
    """Acknowledgement returned after spawning a background investigation."""

    scan_id: str | None
    status: str


# ---------------------------------------------------------------------------
# Background runner
# ---------------------------------------------------------------------------


def _run_investigation_job(
    *,
    url: str,
    scan_type: str,
    scan_id: str | None,
    push_to_core: bool,
    dataset: str,
) -> None:
    """Execute the investigation job in the current thread.

    Sets the same environment variables that ``_trigger_local_investigation``
    and the Cloud Run Job entrypoint expect, then delegates to
    ``ssi.worker.jobs.main()``.

    Args:
        url: Target URL to investigate.
        scan_type: Investigation mode (passive/active/full).
        scan_id: Pre-assigned scan ID.
        push_to_core: Whether to create a case record in core.
        dataset: Dataset label for the core case.
    """
    env_patch = {
        "SSI_JOB__URL": url,
        "SSI_JOB__SCAN_TYPE": scan_type,
        "SSI_JOB__PUSH_TO_CORE": str(push_to_core).lower(),
        "SSI_JOB__DATASET": dataset,
    }
    if scan_id:
        env_patch["SSI_JOB__SCAN_ID"] = scan_id

    # Apply env vars for the duration of this thread.
    original_env: dict[str, str | None] = {}
    for key, value in env_patch.items():
        original_env[key] = os.environ.get(key)
        os.environ[key] = value

    try:
        from ssi.worker.jobs import main

        exit_code = main()
        if exit_code != 0:
            logger.error("Investigation job exited with code %d for %s", exit_code, url)
    except Exception:
        logger.exception("Investigation job failed for %s", url)
    finally:
        # Restore original env state.
        for key, orig_value in original_env.items():
            if orig_value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = orig_value


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@router.post(
    "/investigate",
    summary="Trigger an SSI investigation",
    status_code=202,
    response_model=InvestigateResponse,
)
def trigger_investigate(payload: InvestigateRequest, background_tasks: BackgroundTasks) -> InvestigateResponse:
    """Launch an SSI investigation as a background task.

    Mirrors the Cloud Run Job entrypoint but accepts parameters via
    HTTP instead of environment variables.  Returns 202 immediately;
    the investigation runs in a background thread with CPU always
    allocated (Cloud Run Service with ``cpu_allocation=always``).

    Args:
        payload: Investigation parameters.
        background_tasks: FastAPI background task runner.

    Returns:
        Acknowledgement with the scan ID and ``accepted`` status.
    """
    logger.info(
        "POST /jobs/investigate: url=%s scan_type=%s scan_id=%s",
        payload.url,
        payload.scan_type,
        payload.scan_id,
    )

    background_tasks.add_task(
        _run_investigation_job,
        url=payload.url,
        scan_type=payload.scan_type,
        scan_id=payload.scan_id,
        push_to_core=payload.push_to_core,
        dataset=payload.dataset,
    )

    return InvestigateResponse(scan_id=payload.scan_id, status="accepted")
