"""SSI investigation Cloud Run Job.

Runs an SSI investigation as a standalone job, suitable for execution
as a Cloud Run Job (``ssi job investigate``) or triggered from the
core platform via the API.

Environment variables:
    SSI_JOB__URL:           Target URL to investigate (required).
    SSI_JOB__SCAN_TYPE:     Investigation mode: passive, active, or full
                            (default: full).
    SSI_JOB__PASSIVE_ONLY:  Legacy — maps to scan_type passive/full.
    SSI_JOB__PUSH_TO_CORE:  Push results to i4g core (default: false).
    SSI_JOB__TRIGGER_DOSSIER: Queue dossier generation (default: false).
    SSI_JOB__DATASET:       Dataset label for the case (default: ssi).
"""

from __future__ import annotations

import logging
import os
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ssi.models.investigation import InvestigationResult

logger = logging.getLogger(__name__)


def main() -> int:
    """Run an SSI investigation job.

    Reads configuration from environment variables, executes the
    investigation, and optionally pushes results to the i4g core
    platform.  When ``I4G_TASK_ID`` and ``I4G_TASK_STATUS_URL`` are
    set, progress updates are posted back to the core task-status API.

    Returns:
        Exit code: 0 for success, 1 for failure.
    """
    _configure_logging()

    # Initialise the task reporter (no-ops when env vars are absent).
    from ssi.worker.task_reporter import TaskStatusReporter

    reporter = TaskStatusReporter()

    url = os.environ.get("SSI_JOB__URL", "").strip()
    if not url:
        logger.error("SSI_JOB__URL is required")
        return 1

    # Prefer SSI_JOB__SCAN_TYPE; fall back to legacy SSI_JOB__PASSIVE_ONLY.
    scan_id = os.environ.get("SSI_JOB__SCAN_ID")
    scan_type = os.environ.get("SSI_JOB__SCAN_TYPE", "").strip().lower()
    if not scan_type:
        passive_only = os.environ.get("SSI_JOB__PASSIVE_ONLY", "false").lower() in ("true", "1", "yes")
        scan_type = "passive" if passive_only else "full"

    push_to_core = os.environ.get("SSI_JOB__PUSH_TO_CORE", "false").lower() in ("true", "1", "yes")
    trigger_dossier = os.environ.get("SSI_JOB__TRIGGER_DOSSIER", "false").lower() in ("true", "1", "yes")
    dataset = os.environ.get("SSI_JOB__DATASET", "ssi")

    logger.info(
        "SSI Job starting: url=%s scan_type=%s push_to_core=%s scan_id=%s",
        url,
        scan_type,
        push_to_core,
        scan_id,
    )

    reporter.update(status="running", message=f"Starting investigation for {url}")

    start = time.monotonic()

    try:
        from ssi.investigator.orchestrator import run_investigation
        from ssi.settings import get_settings

        settings = get_settings()
        output_dir = Path(settings.evidence.output_dir)

        result = run_investigation(
            url=url,
            output_dir=output_dir,
            scan_type=scan_type,
            report_format="both",
            investigation_id=scan_id,
        )

        elapsed = time.monotonic() - start
        logger.info(
            "Investigation %s completed: status=%s duration=%.1fs risk_score=%s",
            result.investigation_id,
            result.status.value,
            elapsed,
            f"{result.taxonomy_result.risk_score:.1f}" if result.taxonomy_result else "N/A",
        )

        if not result.success:
            logger.error("Investigation failed: %s", result.error)
            reporter.update(
                status="failed",
                message=result.error or "Investigation failed",
                investigation_id=str(result.investigation_id),
                scan_id=str(result.investigation_id),
            )
            return 1

        # Push to core platform if requested
        case_id = None
        if push_to_core:
            case_id = _push_to_core(result, dataset=dataset, trigger_dossier=trigger_dossier)

        # Report completion with all enrichment fields so core's
        # get_task_status can return them to the UI immediately.
        risk_score = result.taxonomy_result.risk_score if result.taxonomy_result else None
        reporter.update(
            status="completed",
            message=f"Investigation completed in {elapsed:.1f}s",
            investigation_id=str(result.investigation_id),
            scan_id=str(result.investigation_id),
            risk_score=risk_score,
            case_id=case_id,
            duration_seconds=elapsed,
        )

        # Update the scan row in the shared DB with the evidence path
        # (gs:// URI when GCS upload succeeded).
        _update_core_scan(str(result.investigation_id), result, case_id=case_id)

        logger.info("SSI Job completed successfully in %.1fs", elapsed)
        return 0

    except Exception:
        logger.exception("SSI Job failed")
        reporter.update(status="failed", message="SSI Job failed with an exception")
        return 1


def _push_to_core(
    result: InvestigationResult,
    *,
    dataset: str = "ssi",
    trigger_dossier: bool = False,
) -> str | None:
    """Push investigation results to the i4g core platform.

    Args:
        result: Completed investigation result.
        dataset: Dataset label for the core case.
        trigger_dossier: Queue dossier generation after push.

    Returns:
        The core case ID if successful, None otherwise.
    """
    from ssi.integration.core_bridge import CoreBridge

    bridge = CoreBridge()

    if not bridge.health_check():
        logger.warning("Core API not reachable — skipping push to core")
        return None

    try:
        case_id = bridge.push_investigation(
            result,
            dataset=dataset,
            trigger_dossier=trigger_dossier,
        )
        logger.info("Pushed to core: case_id=%s", case_id)
        return case_id
    except Exception as e:
        logger.error("Failed to push investigation to core: %s", e)
        return None
    finally:
        bridge.close()


def _update_core_scan(
    scan_id: str,
    result: InvestigationResult,
    *,
    case_id: str | None = None,
) -> None:
    """Update the pre-created scan row in core's DB via HTTP PATCH.

    Core pre-creates a ``site_scans`` row at trigger time.  After
    the investigation completes (and evidence is uploaded to GCS),
    this function patches the row with the final evidence path,
    risk score, and case ID so that core's report endpoint can
    serve the PDF via a GCS signed URL.

    Args:
        scan_id: The scan_id (= investigation_id) shared with core.
        result: Completed investigation result.
        case_id: Core case ID returned by ``CoreBridge.push_investigation``.
    """
    from ssi.integration.core_bridge import CoreBridge

    bridge = CoreBridge()
    try:
        # Build the completion payload matching core's SsiStore.complete_scan fields
        payload: dict[str, Any] = {
            "status": "completed" if result.success else "failed",
            "evidence_path": result.output_path or None,
            "duration_seconds": result.duration_seconds,
        }
        if case_id:
            payload["case_id"] = case_id
        if result.taxonomy_result:
            payload["risk_score"] = result.taxonomy_result.risk_score
            payload["classification_result"] = result.taxonomy_result.model_dump(mode="json")
        if result.error:
            payload["error_message"] = result.error

        # Use the core API endpoint to update the scan
        resp = bridge._client.patch(f"/investigations/ssi/{scan_id}", json=payload)
        resp.raise_for_status()
        logger.info("Updated core scan %s with evidence_path=%s", scan_id, result.output_path)
    except Exception as e:
        logger.warning("Failed to update core scan %s: %s", scan_id, e)
    finally:
        bridge.close()


def _configure_logging() -> None:
    """Set up logging for the job.

    On Cloud Run (``SSI_ENV != local``), emits JSON-structured logs
    compatible with Cloud Logging severity parsing::

        {"severity": "INFO", "message": "...", "logger": "..."}

    Locally, uses a human-readable plain-text format.
    """
    import json as _json

    log_level = os.environ.get("SSI_LOG_LEVEL", "INFO").upper()
    env = os.environ.get("SSI_ENV", "local").strip()

    if env != "local":
        # Cloud Logging JSON format — severity is parsed automatically
        class _CloudFormatter(logging.Formatter):
            """JSON formatter emitting Cloud Logging-compatible entries."""

            _LEVEL_MAP = {
                "DEBUG": "DEBUG",
                "INFO": "INFO",
                "WARNING": "WARNING",
                "ERROR": "ERROR",
                "CRITICAL": "CRITICAL",
            }

            def format(self, record: logging.LogRecord) -> str:
                """Format a log record as a JSON object with severity."""
                entry = {
                    "severity": self._LEVEL_MAP.get(record.levelname, "DEFAULT"),
                    "message": record.getMessage(),
                    "logger": record.name,
                    "time": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
                }
                if record.exc_info and record.exc_info[1]:
                    entry["exception"] = self.formatException(record.exc_info)
                return _json.dumps(entry, default=str)

        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(_CloudFormatter())
        logging.root.handlers.clear()
        logging.root.addHandler(handler)
        logging.root.setLevel(getattr(logging, log_level, logging.INFO))
    else:
        logging.basicConfig(
            level=getattr(logging, log_level, logging.INFO),
            format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
            stream=sys.stderr,
        )

    # Quieten noisy libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


if __name__ == "__main__":
    sys.exit(main())
