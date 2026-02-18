"""SSI investigation Cloud Run Job.

Runs an SSI investigation as a standalone job, suitable for execution
as a Cloud Run Job (``ssi job investigate``) or triggered from the
core platform via the API.

Environment variables:
    SSI_JOB__URL:           Target URL to investigate (required).
    SSI_JOB__PASSIVE_ONLY:  Limit to passive recon (default: false).
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

logger = logging.getLogger(__name__)


def main() -> int:
    """Run an SSI investigation job.

    Reads configuration from environment variables, executes the
    investigation, and optionally pushes results to the i4g core
    platform.

    Returns:
        Exit code: 0 for success, 1 for failure.
    """
    _configure_logging()

    url = os.environ.get("SSI_JOB__URL", "").strip()
    if not url:
        logger.error("SSI_JOB__URL is required")
        return 1

    passive_only = os.environ.get("SSI_JOB__PASSIVE_ONLY", "false").lower() in ("true", "1", "yes")
    push_to_core = os.environ.get("SSI_JOB__PUSH_TO_CORE", "false").lower() in ("true", "1", "yes")
    trigger_dossier = os.environ.get("SSI_JOB__TRIGGER_DOSSIER", "false").lower() in ("true", "1", "yes")
    dataset = os.environ.get("SSI_JOB__DATASET", "ssi")

    logger.info(
        "SSI Job starting: url=%s passive_only=%s push_to_core=%s",
        url,
        passive_only,
        push_to_core,
    )

    start = time.monotonic()

    try:
        from ssi.investigator.orchestrator import run_investigation
        from ssi.settings import get_settings

        settings = get_settings()
        output_dir = Path(settings.evidence.output_dir)

        result = run_investigation(
            url=url,
            output_dir=output_dir,
            passive_only=passive_only,
            report_format="both",
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
            return 1

        # Push to core platform if requested
        if push_to_core:
            _push_to_core(result, dataset=dataset, trigger_dossier=trigger_dossier)

        logger.info("SSI Job completed successfully in %.1fs", elapsed)
        return 0

    except Exception:
        logger.exception("SSI Job failed")
        return 1


def _push_to_core(
    result,
    *,
    dataset: str = "ssi",
    trigger_dossier: bool = False,
) -> None:
    """Push investigation results to the i4g core platform."""
    from ssi.integration.core_bridge import CoreBridge

    bridge = CoreBridge()

    if not bridge.health_check():
        logger.warning("Core API not reachable — skipping push to core")
        return

    try:
        case_id = bridge.push_investigation(
            result,
            dataset=dataset,
            trigger_dossier=trigger_dossier,
        )
        logger.info("Pushed to core: case_id=%s", case_id)
    except Exception as e:
        logger.error("Failed to push investigation to core: %s", e)
    finally:
        bridge.close()


def _configure_logging() -> None:
    """Set up structured logging for the job."""
    log_level = os.environ.get("SSI_LOG_LEVEL", "INFO").upper()
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
