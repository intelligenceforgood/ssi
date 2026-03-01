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

    # Initialise the task reporter (no-ops when scan_id is absent).
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

    push_to_core = os.environ.get("SSI_JOB__PUSH_TO_CORE", "true").lower() in ("true", "1", "yes")
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
            )
            return 1

        # Create case record directly in the shared DB (no HTTP to core API).
        # The ScanStore already persisted the scan via persist_investigation()
        # during run_investigation(); this adds the cases/scam_records/
        # review_queue rows so the case appears on the /cases page.
        # Always create the case — the push_to_core flag is unreliable
        # via containerOverrides env vars in Cloud Run Jobs.
        case_id = _create_case_direct(result, dataset=dataset, scan_id=scan_id)

        # Report completion with all enrichment fields so core's
        # get_task_status can return them to the UI immediately.
        risk_score = result.taxonomy_result.risk_score if result.taxonomy_result else None
        reporter.update(
            status="completed",
            message=f"Investigation completed in {elapsed:.1f}s",
            risk_score=risk_score,
            case_id=case_id,
            duration_seconds=elapsed,
        )

        logger.info("SSI Job completed successfully in %.1fs", elapsed)
        return 0

    except Exception:
        logger.exception("SSI Job failed")
        reporter.update(status="failed", message="SSI Job failed with an exception")
        return 1


def _create_case_direct(
    result: InvestigationResult,
    *,
    dataset: str = "ssi",
    scan_id: str | None = None,
) -> str | None:
    """Create a case record directly in the shared database.

    Uses ``ScanStore.create_case_record()`` to write the ``cases``,
    ``scam_records``, and ``review_queue`` rows that the analyst console
    reads.  This replaces the HTTP-based ``CoreBridge.push_investigation()``
    path which required IAP/API-key auth.

    Args:
        result: Completed investigation result.
        dataset: Dataset label for the core case.
        scan_id: Authoritative scan ID from ``SSI_JOB__SCAN_ID``.

    Returns:
        The core case ID if successful, None otherwise.
    """
    from ssi.store import build_scan_store

    resolved_scan_id = scan_id or str(result.investigation_id)

    try:
        store = build_scan_store()
        case_id = store.create_case_record(
            scan_id=resolved_scan_id,
            result=result,
            dataset=dataset,
        )
        if case_id:
            logger.info("Created case %s for scan %s (direct DB)", case_id, resolved_scan_id)
        else:
            logger.error(
                "create_case_record returned None for scan %s — "
                "case was NOT written to the cases table; "
                "check the preceding scan_store log lines for the root cause",
                resolved_scan_id,
            )
        return case_id
    except Exception:
        logger.exception(
            "Failed to create case record for scan %s — "
            "case was NOT written to the cases table",
            resolved_scan_id,
        )
        return None


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
