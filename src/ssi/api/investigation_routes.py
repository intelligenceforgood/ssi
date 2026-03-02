"""REST API routes for SSI investigations.

Provides:
- ``POST /trigger/investigate`` — trigger a single SSI investigation (returns 202).
- ``POST /trigger/batch`` — trigger batch investigations from a manifest.
- ``GET /investigations`` — list past investigations.
- ``GET /investigations/{scan_id}`` — detail view for a single investigation.
- ``GET /wallets`` — search wallet addresses across investigations.
- Evidence bundle and LEA package downloads.
"""

from __future__ import annotations

import logging
import tempfile
import time
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field

from ssi.store import build_scan_store

logger = logging.getLogger(__name__)

investigation_router = APIRouter(tags=["investigations"])


# ---------------------------------------------------------------------------
# Request / Response schemas for investigation triggers
# ---------------------------------------------------------------------------


class InvestigateRequest(BaseModel):
    """Payload for triggering a single SSI investigation."""

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
        description="Create a case record in the shared database.",
    )
    dataset: str = Field(
        default="ssi",
        description="Dataset label for the case created in core.",
    )


class InvestigateResponse(BaseModel):
    """Acknowledgement returned after spawning a background investigation."""

    scan_id: str | None
    status: str


class BatchInvestigateRequest(BaseModel):
    """Payload for triggering batch SSI investigations."""

    manifest: list[dict[str, Any]] | None = Field(
        default=None,
        description="Inline manifest — JSON array of objects with at least a 'url' key.",
    )
    manifest_uri: str | None = Field(
        default=None,
        description="GCS URI (gs://bucket/path.json) to a manifest file.",
    )
    default_scan_type: Literal["passive", "active", "full"] = Field(
        default="full",
        description="Default scan type for entries that don't specify one.",
    )
    push_to_core: bool = Field(
        default=True,
        description="Create case records in the shared database.",
    )
    dataset: str = Field(
        default="ssi",
        description="Dataset label for core cases.",
    )


class BatchInvestigateResponse(BaseModel):
    """Acknowledgement returned after spawning a batch investigation."""

    status: str
    entry_count: int


# ---------------------------------------------------------------------------
# Background investigation runner (no env-var patching)
# ---------------------------------------------------------------------------


def _run_investigation(
    *,
    url: str,
    scan_type: str,
    scan_id: str | None,
    push_to_core: bool,
    dataset: str,
) -> None:
    """Execute a single investigation in the background.

    Calls the orchestrator directly with function arguments — no
    environment variable patching.  Creates a case record in the
    shared database on success.

    Args:
        url: Target URL to investigate.
        scan_type: Investigation mode (passive/active/full).
        scan_id: Pre-assigned scan ID.
        push_to_core: Whether to create a case record.
        dataset: Dataset label for the core case.
    """
    from ssi.investigator.orchestrator import run_investigation
    from ssi.settings import get_settings
    from ssi.worker.task_reporter import TaskStatusReporter

    reporter = TaskStatusReporter(scan_id=scan_id)
    reporter.update(status="running", message=f"Starting investigation for {url}")
    start = time.monotonic()

    try:
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
            reporter.update(status="failed", message=result.error or "Investigation failed")
            return

        # Create case record directly in the shared DB.
        case_id = _create_case_direct(result, dataset=dataset, scan_id=scan_id)

        risk_score = result.taxonomy_result.risk_score if result.taxonomy_result else None
        reporter.update(
            status="completed",
            message=f"Investigation completed in {elapsed:.1f}s",
            risk_score=risk_score,
            case_id=case_id,
            duration_seconds=elapsed,
        )
        logger.info("Investigation completed successfully in %.1fs", elapsed)

    except Exception:
        logger.exception("Investigation failed for %s", url)
        reporter.update(status="failed", message="Investigation failed with an exception")


def _create_case_direct(
    result: Any,
    *,
    dataset: str = "ssi",
    scan_id: str | None = None,
) -> str | None:
    """Create a case record directly in the shared database.

    Args:
        result: Completed investigation result.
        dataset: Dataset label for the core case.
        scan_id: Authoritative scan ID from the trigger request.

    Returns:
        The core case ID if successful, None otherwise.
    """
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
                "case was NOT written to the cases table",
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


def _run_batch_investigation(
    *,
    manifest: list[dict[str, Any]],
    default_scan_type: str,
    push_to_core: bool,
    dataset: str,
) -> None:
    """Execute batch investigations sequentially in the background.

    Args:
        manifest: List of entries, each with at least a ``url`` key.
        default_scan_type: Scan type for entries that don't specify one.
        push_to_core: Whether to create case records.
        dataset: Dataset label for core cases.
    """
    total = len(manifest)
    succeeded = 0
    failed = 0

    logger.info("Batch starting: %d URLs, scan_type=%s, push_to_core=%s", total, default_scan_type, push_to_core)

    for i, entry in enumerate(manifest, 1):
        url = entry["url"].strip()
        scan_type = entry.get("scan_type", default_scan_type).strip().lower()
        scan_id = entry.get("scan_id")

        logger.info("[%d/%d] Investigating: %s (scan_type=%s)", i, total, url, scan_type)

        try:
            _run_investigation(
                url=url,
                scan_type=scan_type,
                scan_id=scan_id,
                push_to_core=push_to_core,
                dataset=dataset,
            )
            succeeded += 1
        except Exception:
            failed += 1
            logger.exception("[%d/%d] Exception investigating %s", i, total, url)

    logger.info("Batch complete: %d total, %d succeeded, %d failed", total, succeeded, failed)


# ---------------------------------------------------------------------------
# Investigation trigger endpoints
# ---------------------------------------------------------------------------


@investigation_router.post(
    "/trigger/investigate",
    summary="Trigger an SSI investigation",
    status_code=202,
    response_model=InvestigateResponse,
)
def trigger_investigate(
    payload: InvestigateRequest,
    background_tasks: BackgroundTasks,
) -> InvestigateResponse:
    """Launch an SSI investigation as a background task.

    Returns 202 immediately; the investigation runs in the background
    with CPU always allocated (Cloud Run Service with
    ``cpu_allocation=always``).

    Args:
        payload: Investigation parameters.
        background_tasks: FastAPI background task runner.

    Returns:
        Acknowledgement with the scan ID and ``accepted`` status.
    """
    logger.info(
        "POST /trigger/investigate: url=%s scan_type=%s scan_id=%s",
        payload.url,
        payload.scan_type,
        payload.scan_id,
    )

    background_tasks.add_task(
        _run_investigation,
        url=payload.url,
        scan_type=payload.scan_type,
        scan_id=payload.scan_id,
        push_to_core=payload.push_to_core,
        dataset=payload.dataset,
    )

    return InvestigateResponse(scan_id=payload.scan_id, status="accepted")


@investigation_router.post(
    "/trigger/batch",
    summary="Trigger batch SSI investigations",
    status_code=202,
    response_model=BatchInvestigateResponse,
)
def trigger_batch_investigate(
    payload: BatchInvestigateRequest,
    background_tasks: BackgroundTasks,
) -> BatchInvestigateResponse:
    """Launch batch SSI investigations as a background task.

    Accepts either an inline manifest (JSON array) or a GCS URI
    pointing to a manifest file.  Returns 202 immediately; the
    investigations run sequentially in the background.

    Args:
        payload: Batch investigation parameters.
        background_tasks: FastAPI background task runner.

    Returns:
        Acknowledgement with entry count and ``accepted`` status.

    Raises:
        HTTPException: If neither manifest nor manifest_uri is provided,
            or if the manifest is invalid.
    """
    if payload.manifest:
        manifest = payload.manifest
    elif payload.manifest_uri:
        from ssi.worker.batch import load_manifest

        try:
            manifest = load_manifest(payload.manifest_uri)
        except (FileNotFoundError, ValueError, ImportError) as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    else:
        raise HTTPException(
            status_code=422,
            detail="Either 'manifest' (inline array) or 'manifest_uri' (GCS URI) is required.",
        )

    # Validate entries
    valid_entries: list[dict[str, Any]] = []
    for entry in manifest:
        if isinstance(entry, dict) and entry.get("url", "").strip():
            valid_entries.append(entry)

    if not valid_entries:
        raise HTTPException(status_code=422, detail="Manifest contains no valid entries with a 'url' key.")

    logger.info(
        "POST /trigger/batch: %d entries, scan_type=%s",
        len(valid_entries),
        payload.default_scan_type,
    )

    background_tasks.add_task(
        _run_batch_investigation,
        manifest=valid_entries,
        default_scan_type=payload.default_scan_type,
        push_to_core=payload.push_to_core,
        dataset=payload.dataset,
    )

    return BatchInvestigateResponse(status="accepted", entry_count=len(valid_entries))


# ---------------------------------------------------------------------------
# Investigation list / detail
# ---------------------------------------------------------------------------


@investigation_router.get("/investigations")
def list_investigations(
    domain: str | None = Query(None, description="Filter by domain."),
    status: str | None = Query(None, description="Filter by status (completed, failed, running)."),
    limit: int = Query(50, ge=1, le=200, description="Page size."),
    offset: int = Query(0, ge=0, description="Page offset."),
) -> dict[str, Any]:
    """Return a paginated list of historical investigations from the scan store."""
    store = build_scan_store()
    scans = store.list_scans(domain=domain, status=status, limit=limit, offset=offset)
    # Serialise datetime objects for JSON
    for scan in scans:
        for key, val in scan.items():
            if hasattr(val, "isoformat"):
                scan[key] = val.isoformat()
    return {"items": scans, "count": len(scans), "limit": limit, "offset": offset}


@investigation_router.get("/investigations/active", tags=["monitoring"])
def list_active_investigations_endpoint() -> dict[str, Any]:
    """List currently active (running) investigations with event buses."""
    from ssi.api.ws_routes import get_bus, list_active_investigations

    active = list_active_investigations()
    result: list[dict[str, Any]] = []
    for inv_id in active:
        bus = get_bus(inv_id)
        if bus:
            snap = bus.get_snapshot()
            result.append({"investigation_id": inv_id, **snap})
    return {"active": result, "count": len(result)}


@investigation_router.get("/investigations/{scan_id}")
def get_investigation(scan_id: str) -> dict[str, Any]:
    """Return full detail for a single investigation (scan + wallets + PII exposures)."""
    store = build_scan_store()
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    wallets = store.get_wallets(scan_id)
    pii_exposures = store.get_pii_exposures(scan_id)
    agent_actions = store.get_agent_actions(scan_id)

    # Serialise datetime objects for JSON
    for collection in [wallets, pii_exposures, agent_actions]:
        for row in collection:
            for key, val in row.items():
                if hasattr(val, "isoformat"):
                    row[key] = val.isoformat()
    for key, val in scan.items():
        if hasattr(val, "isoformat"):
            scan[key] = val.isoformat()

    return {
        "scan": scan,
        "wallets": wallets,
        "pii_exposures": pii_exposures,
        "agent_actions": agent_actions,
    }


# ---------------------------------------------------------------------------
# Wallet search
# ---------------------------------------------------------------------------


@investigation_router.get("/wallets")
def search_wallets(
    address: str | None = Query(None, description="Filter by wallet address."),
    token_symbol: str | None = Query(None, description="Filter by token symbol (e.g. ETH, BTC)."),
    deduplicate: bool = Query(True, description="Deduplicate across scans (default: true)."),
    limit: int = Query(100, ge=1, le=500, description="Max results."),
) -> dict[str, Any]:
    """Search wallet addresses across all investigations.

    With ``deduplicate=true`` (default), returns one row per unique
    address with ``first_seen_at``, ``last_seen_at``, and ``seen_count``.
    """
    store = build_scan_store()
    wallets = store.search_wallets(
        address=address, token_symbol=token_symbol, limit=limit, deduplicate=deduplicate,
    )
    for wallet in wallets:
        for key, val in wallet.items():
            if hasattr(val, "isoformat"):
                wallet[key] = val.isoformat()
    return {"items": wallets, "count": len(wallets)}


# ---------------------------------------------------------------------------
# Wallet export (XLSX / CSV)
# ---------------------------------------------------------------------------


@investigation_router.get(
    "/investigations/{scan_id}/wallets.xlsx",
    tags=["export"],
    response_class=FileResponse,
    responses={
        200: {"content": {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": {}}},
        404: {"description": "Investigation not found or has no wallets."},
    },
)
def export_wallets_xlsx(scan_id: str) -> FileResponse:
    """Export wallet addresses for a single investigation as XLSX.

    Returns a downloadable XLSX file with all wallet entries associated
    with the given ``scan_id``.
    """
    return _export_wallets(scan_id, fmt="xlsx")


@investigation_router.get(
    "/investigations/{scan_id}/wallets.csv",
    tags=["export"],
    response_class=FileResponse,
    responses={
        200: {"content": {"text/csv": {}}},
        404: {"description": "Investigation not found or has no wallets."},
    },
)
def export_wallets_csv(scan_id: str) -> FileResponse:
    """Export wallet addresses for a single investigation as CSV."""
    return _export_wallets(scan_id, fmt="csv")


def _export_wallets(scan_id: str, *, fmt: str) -> FileResponse:
    """Shared implementation for wallet export endpoints.

    Args:
        scan_id: Investigation scan ID.
        fmt: Export format — ``"xlsx"`` or ``"csv"``.

    Returns:
        A ``FileResponse`` streaming the exported file.

    Raises:
        HTTPException: If the investigation or its wallets are not found.
    """
    from ssi.wallet.export import WalletExporter
    from ssi.wallet.models import WalletEntry

    store = build_scan_store()
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    wallet_rows = store.get_wallets(scan_id)
    if not wallet_rows:
        raise HTTPException(status_code=404, detail="No wallets found for this investigation.")

    # Convert store rows back to WalletEntry model instances
    entries: list[WalletEntry] = []
    for row in wallet_rows:
        entries.append(
            WalletEntry(
                site_url=row.get("site_url", scan.get("url", "")),
                token_symbol=row.get("token_symbol", ""),
                network_short=row.get("network_short", ""),
                wallet_address=row.get("wallet_address", ""),
                source=row.get("source", ""),
                confidence=float(row.get("confidence", 0.0)),
            )
        )

    exporter = WalletExporter()
    tmp_dir = Path(tempfile.mkdtemp(prefix="ssi_export_"))
    filename = f"wallets_{scan_id[:8]}.{fmt}"
    output_path = tmp_dir / filename

    if fmt == "xlsx":
        exporter.to_xlsx(entries, output_path, apply_filter=False)
        media_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    elif fmt == "csv":
        exporter.to_csv(entries, output_path, apply_filter=False)
        media_type = "text/csv"
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {fmt}")

    return FileResponse(
        path=str(output_path),
        filename=filename,
        media_type=media_type,
    )


# ---------------------------------------------------------------------------
# Evidence bundle download (Phase 2A)
# ---------------------------------------------------------------------------


@investigation_router.get(
    "/investigations/{scan_id}/evidence-bundle",
    tags=["evidence"],
    responses={
        200: {"content": {"application/zip": {}}, "description": "Evidence ZIP (PDF + all artifacts)."},
        404: {"description": "Investigation not found or evidence not available."},
    },
)
def download_evidence_bundle(scan_id: str) -> Response:
    """Download the evidence ZIP bundle for an investigation.

    Returns a ZIP archive containing the PDF report, screenshots, DOM
    snapshots, HAR logs, STIX bundle, wallet manifest, and a
    ``manifest.json`` with SHA-256 hashes for integrity verification.

    For GCS-backed storage the response redirects to a signed URL.
    """
    from fastapi.responses import RedirectResponse

    from ssi.evidence.storage import build_evidence_storage_client
    from ssi.settings import get_settings

    store = build_scan_store()
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    evidence_path = scan.get("evidence_path")
    if not evidence_path:
        raise HTTPException(status_code=404, detail="No evidence path recorded for this investigation.")

    inv_dir = Path(evidence_path)
    zip_path = inv_dir / "evidence.zip"

    settings = get_settings()
    if settings.evidence.storage_backend == "gcs":
        client = build_evidence_storage_client()
        signed_url = client.get_evidence_zip_url(scan_id, inv_dir)
        if signed_url:
            return RedirectResponse(url=signed_url, status_code=307)

    # Fall back to serving the local file
    if not zip_path.exists():
        raise HTTPException(status_code=404, detail="Evidence ZIP not found on disk.")

    return FileResponse(
        path=str(zip_path),
        filename=f"evidence_{scan_id[:8]}.zip",
        media_type="application/zip",
    )


@investigation_router.get(
    "/investigations/{scan_id}/lea-package",
    tags=["evidence"],
    responses={
        200: {"content": {"application/zip": {}}, "description": "LEA-ready signed evidence package."},
        404: {"description": "Investigation not found or evidence not available."},
    },
)
def download_lea_package(scan_id: str) -> Response:
    """Download a law-enforcement-ready evidence package.

    Returns a ZIP archive containing:
    - PDF investigation report
    - LEO evidence summary report
    - Evidence artifacts (screenshots, DOM, HAR)
    - Chain-of-custody manifest with SHA-256 hashes
    - STIX 2.1 threat indicator bundle

    The package includes the ``evidence_zip_sha256`` for tamper detection.
    """
    import io
    import json
    import zipfile

    from fastapi.responses import StreamingResponse

    store = build_scan_store()
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    evidence_path = scan.get("evidence_path")
    if not evidence_path:
        raise HTTPException(status_code=404, detail="No evidence path recorded for this investigation.")

    inv_dir = Path(evidence_path)
    if not inv_dir.exists():
        raise HTTPException(status_code=404, detail="Evidence directory not found on disk.")

    # LEA package includes: PDF, LEO report, STIX, evidence ZIP, chain-of-custody
    lea_files = [
        "report.pdf",
        "leo_evidence_report.md",
        "stix_bundle.json",
        "evidence.zip",
        "wallet_manifest.json",
    ]

    buf = io.BytesIO()
    included_count = 0

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for fname in lea_files:
            fpath = inv_dir / fname
            if fpath.exists():
                zf.write(fpath, fname)
                included_count += 1

        # Generate chain-of-custody summary for the LEA package
        custody_info = {
            "scan_id": scan_id,
            "investigation_url": scan.get("url", ""),
            "evidence_zip_sha256": scan.get("evidence_zip_sha256", ""),
            "files_included": included_count,
            "package_note": (
                "This package is generated for law enforcement use. "
                "Verify evidence.zip integrity against evidence_zip_sha256."
            ),
        }
        zf.writestr("chain_of_custody.json", json.dumps(custody_info, indent=2))

    if included_count == 0:
        raise HTTPException(status_code=404, detail="No LEA-relevant evidence files found.")

    buf.seek(0)

    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="lea_package_{scan_id[:8]}.zip"',
        },
    )

