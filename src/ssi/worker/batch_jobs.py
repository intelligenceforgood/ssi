"""SSI batch investigation Cloud Run Job.

Processes multiple URLs from a JSON manifest (local file or GCS object).
Designed to run as a Cloud Run Job or via ``ssi job batch``.

Manifest format (JSON array of objects)::

    [
        {"url": "https://scam1.example.com", "scan_type": "full"},
        {"url": "https://scam2.example.com", "scan_type": "passive"},
        {"url": "https://scam3.example.com"}
    ]

Each entry requires ``url``; ``scan_type`` defaults to ``full``.
Results are written to the standard evidence directory and optionally
pushed to the core platform.

Environment variables:
    SSI_JOB__MANIFEST:        Path to local manifest or ``gs://bucket/path.json``.
    SSI_JOB__SCAN_TYPE:       Default scan type for entries without one (default: full).
    SSI_JOB__PUSH_TO_CORE:    Push each result to i4g core (default: false).
    SSI_JOB__TRIGGER_DOSSIER: Queue dossier generation (default: false).
    SSI_JOB__DATASET:         Dataset label for core cases (default: ssi).
    SSI_JOB__CONCURRENCY:     Max parallel investigations (default: 1 — sequential).
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Manifest loading
# ---------------------------------------------------------------------------


def load_manifest(manifest_path: str) -> list[dict[str, Any]]:
    """Load a batch manifest from a local file or GCS URI.

    Args:
        manifest_path: Local filesystem path or ``gs://bucket/object`` URI.

    Returns:
        List of manifest entries, each with at least a ``url`` key.

    Raises:
        FileNotFoundError: If the local file does not exist.
        ValueError: If the manifest is not valid JSON or has no entries.
    """
    if manifest_path.startswith("gs://"):
        return _load_from_gcs(manifest_path)
    return _load_from_local(manifest_path)


def _load_from_local(path: str) -> list[dict[str, Any]]:
    """Load manifest from a local JSON file."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Manifest file not found: {path}")

    data = json.loads(p.read_text(encoding="utf-8"))
    return _validate_manifest(data)


def _load_from_gcs(uri: str) -> list[dict[str, Any]]:
    """Load manifest from a GCS object (``gs://bucket/path.json``)."""
    try:
        from google.cloud import storage as gcs
    except ImportError:
        raise ImportError("google-cloud-storage is required for GCS manifests: pip install google-cloud-storage")

    parts = uri.replace("gs://", "").split("/", 1)
    if len(parts) != 2:
        raise ValueError(f"Invalid GCS URI: {uri} — expected gs://bucket/path")

    bucket_name, blob_name = parts
    client = gcs.Client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(blob_name)

    if not blob.exists():
        raise FileNotFoundError(f"GCS object not found: {uri}")

    data = json.loads(blob.download_as_text())
    return _validate_manifest(data)


def _validate_manifest(data: Any) -> list[dict[str, Any]]:
    """Validate that the parsed manifest is a non-empty list with URLs."""
    if not isinstance(data, list) or not data:
        raise ValueError("Manifest must be a non-empty JSON array")

    valid_entries: list[dict[str, Any]] = []
    for i, entry in enumerate(data):
        if not isinstance(entry, dict):
            logger.warning("Manifest entry %d is not an object — skipping", i)
            continue
        url = entry.get("url", "").strip()
        if not url:
            logger.warning("Manifest entry %d has no URL — skipping", i)
            continue
        valid_entries.append(entry)

    if not valid_entries:
        raise ValueError("Manifest contains no valid entries (each must have a 'url' key)")

    return valid_entries


# ---------------------------------------------------------------------------
# Batch execution
# ---------------------------------------------------------------------------


def run_batch(
    manifest: list[dict[str, Any]],
    *,
    default_scan_type: str = "full",
    push_to_core: bool = False,
    trigger_dossier: bool = False,
    dataset: str = "ssi",
) -> dict[str, Any]:
    """Execute investigations for all manifest entries sequentially.

    Args:
        manifest: List of manifest entries (each with at least ``url``).
        default_scan_type: Scan type to use when not specified per entry.
        push_to_core: Push each successful result to the core platform.
        trigger_dossier: Queue dossier generation for each pushed result.
        dataset: Dataset label for core cases.

    Returns:
        Summary dict with ``total``, ``succeeded``, ``failed``, and ``results``.
    """
    from ssi.investigator.orchestrator import run_investigation
    from ssi.settings import get_settings

    settings = get_settings()
    output_dir = Path(settings.evidence.output_dir)

    total = len(manifest)
    succeeded = 0
    failed = 0
    results: list[dict[str, Any]] = []

    logger.info("Batch starting: %d URLs, scan_type=%s, push_to_core=%s", total, default_scan_type, push_to_core)

    for i, entry in enumerate(manifest, 1):
        url = entry["url"].strip()
        scan_type = entry.get("scan_type", default_scan_type).strip().lower()

        logger.info("[%d/%d] Investigating: %s (scan_type=%s)", i, total, url, scan_type)
        start = time.monotonic()

        try:
            result = run_investigation(
                url=url,
                output_dir=output_dir,
                scan_type=scan_type,
                report_format="both",
            )
            elapsed = time.monotonic() - start

            entry_result: dict[str, Any] = {
                "url": url,
                "investigation_id": result.investigation_id,
                "status": result.status.value,
                "success": result.success,
                "duration_s": round(elapsed, 1),
                "risk_score": result.taxonomy_result.risk_score if result.taxonomy_result else None,
            }

            if result.success:
                succeeded += 1
                logger.info(
                    "[%d/%d] Success: %s (%.1fs, risk=%.1f)",
                    i, total, url, elapsed,
                    result.taxonomy_result.risk_score if result.taxonomy_result else 0,
                )

                if push_to_core:
                    core_case_id = _push_result_to_core(result, dataset=dataset, trigger_dossier=trigger_dossier)
                    entry_result["core_case_id"] = core_case_id
            else:
                failed += 1
                entry_result["error"] = result.error
                logger.error("[%d/%d] Failed: %s — %s", i, total, url, result.error)

            results.append(entry_result)

        except Exception as e:
            elapsed = time.monotonic() - start
            failed += 1
            results.append({
                "url": url,
                "investigation_id": None,
                "status": "error",
                "success": False,
                "duration_s": round(elapsed, 1),
                "error": str(e),
            })
            logger.exception("[%d/%d] Exception investigating %s", i, total, url)

    summary = {
        "total": total,
        "succeeded": succeeded,
        "failed": failed,
        "results": results,
    }
    logger.info(
        "Batch complete: %d total, %d succeeded, %d failed",
        total, succeeded, failed,
    )
    return summary


def _push_result_to_core(
    result: Any,
    *,
    dataset: str = "ssi",
    trigger_dossier: bool = False,
) -> str | None:
    """Push a single investigation result to the core platform.

    Args:
        result: An ``InvestigationResult`` from the orchestrator.
        dataset: Dataset label for the core case.
        trigger_dossier: Queue dossier generation.

    Returns:
        The core case ID if push succeeded, or ``None``.
    """
    from ssi.integration.core_bridge import CoreBridge

    bridge = CoreBridge()
    try:
        if not bridge.health_check():
            logger.warning("Core API not reachable — skipping push")
            return None

        case_id = bridge.push_investigation(result, dataset=dataset, trigger_dossier=trigger_dossier)
        logger.info("Pushed to core: case_id=%s", case_id)
        return case_id
    except Exception as e:
        logger.error("Failed to push to core: %s", e)
        return None
    finally:
        bridge.close()


# ---------------------------------------------------------------------------
# Cloud Run Job entry point
# ---------------------------------------------------------------------------


def main() -> int:
    """Run a batch investigation job.

    Reads configuration from environment variables, loads the manifest,
    and executes investigations sequentially.

    Returns:
        Exit code: 0 for success (all URLs), 1 for partial/full failure.
    """
    from ssi.worker.jobs import _configure_logging

    _configure_logging()

    manifest_path = os.environ.get("SSI_JOB__MANIFEST", "").strip()
    if not manifest_path:
        logger.error("SSI_JOB__MANIFEST is required (local path or gs:// URI)")
        return 1

    default_scan_type = os.environ.get("SSI_JOB__SCAN_TYPE", "full").strip().lower()
    push_to_core = os.environ.get("SSI_JOB__PUSH_TO_CORE", "false").lower() in ("true", "1", "yes")
    trigger_dossier = os.environ.get("SSI_JOB__TRIGGER_DOSSIER", "false").lower() in ("true", "1", "yes")
    dataset = os.environ.get("SSI_JOB__DATASET", "ssi")

    logger.info("SSI Batch Job starting: manifest=%s", manifest_path)

    try:
        manifest = load_manifest(manifest_path)
    except (FileNotFoundError, ValueError, ImportError) as e:
        logger.error("Failed to load manifest: %s", e)
        return 1

    try:
        summary = run_batch(
            manifest,
            default_scan_type=default_scan_type,
            push_to_core=push_to_core,
            trigger_dossier=trigger_dossier,
            dataset=dataset,
        )
    except Exception:
        logger.exception("Batch job failed")
        return 1

    # Write summary to stdout for Cloud Run job logs
    print(json.dumps(summary, indent=2, default=str))

    # Exit 0 only if all succeeded
    if summary["failed"] > 0:
        logger.warning("Batch had %d failures out of %d", summary["failed"], summary["total"])
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
