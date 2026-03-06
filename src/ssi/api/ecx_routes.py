"""REST API routes for eCrimeX (eCX) integration.

Provides search endpoints for ad-hoc eCX queries:
- ``POST /ecx/search/phish`` — search phish module
- ``POST /ecx/search/domain`` — search malicious-domain module
- ``POST /ecx/search/ip`` — search malicious-ip module
- ``POST /ecx/search/crypto`` — search cryptocurrency-addresses module

Phase 2 — submission management:
- ``GET /ecx/submissions`` — list submission queue
- ``POST /ecx/submissions/{id}/approve`` — analyst approval
- ``POST /ecx/submissions/{id}/reject`` — analyst rejection
- ``POST /ecx/submissions/{id}/retract`` — retract a submitted record
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from ssi.models.ecx import ECXApproveRequest, ECXRejectRequest, ECXSubmissionResponse

logger = logging.getLogger(__name__)

ecx_router = APIRouter(prefix="/ecx", tags=["ecx"])


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------


class ECXSearchRequest(BaseModel):
    """Generic eCX search request."""

    query: str = Field(..., description="The value to search for (URL, domain, IP, or address).")
    limit: int = Field(default=10, ge=1, le=100, description="Maximum number of results.")


class ECXSearchResponse(BaseModel):
    """Generic eCX search response wrapper."""

    module: str
    query: str
    count: int
    results: list[dict[str, Any]]


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _require_client() -> Any:
    """Return an ECXClient or raise 503 if not configured.

    Returns:
        An initialized ECXClient instance.

    Raises:
        HTTPException: With status 503 if eCX is not configured or disabled.
    """
    from ssi.osint.ecrimex import _get_client

    client = _get_client()
    if client is None:
        raise HTTPException(status_code=503, detail="eCX integration is not configured or disabled.")
    return client


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@ecx_router.post("/search/phish", response_model=ECXSearchResponse)
def search_phish(body: ECXSearchRequest) -> ECXSearchResponse:
    """Search eCrimeX phish module.

    Args:
        body: Search request with query URL and optional limit.

    Returns:
        Search results with module name, query, count, and hit records.
    """
    client = _require_client()
    results = client.search_phish(body.query, limit=body.limit)
    return ECXSearchResponse(
        module="phish",
        query=body.query,
        count=len(results),
        results=[r.model_dump(mode="json") for r in results],
    )


@ecx_router.post("/search/domain", response_model=ECXSearchResponse)
def search_domain(body: ECXSearchRequest) -> ECXSearchResponse:
    """Search eCrimeX malicious-domain module.

    Args:
        body: Search request with query domain and optional limit.

    Returns:
        Search results with module name, query, count, and hit records.
    """
    client = _require_client()
    results = client.search_domain(body.query, limit=body.limit)
    return ECXSearchResponse(
        module="malicious-domain",
        query=body.query,
        count=len(results),
        results=[r.model_dump(mode="json") for r in results],
    )


@ecx_router.post("/search/ip", response_model=ECXSearchResponse)
def search_ip(body: ECXSearchRequest) -> ECXSearchResponse:
    """Search eCrimeX malicious-ip module.

    Args:
        body: Search request with query IP address and optional limit.

    Returns:
        Search results with module name, query, count, and hit records.
    """
    client = _require_client()
    results = client.search_ip(body.query, limit=body.limit)
    return ECXSearchResponse(
        module="malicious-ip",
        query=body.query,
        count=len(results),
        results=[r.model_dump(mode="json") for r in results],
    )


@ecx_router.post("/search/crypto", response_model=ECXSearchResponse)
def search_crypto(body: ECXSearchRequest) -> ECXSearchResponse:
    """Search eCrimeX cryptocurrency-addresses module.

    Args:
        body: Search request with wallet address and optional limit.

    Returns:
        Search results with module name, query, count, and hit records.
    """
    client = _require_client()
    results = client.search_crypto(body.query, limit=body.limit)
    return ECXSearchResponse(
        module="cryptocurrency-addresses",
        query=body.query,
        count=len(results),
        results=[r.model_dump(mode="json") for r in results],
    )


# ---------------------------------------------------------------------------
# Cached enrichment retrieval
# ---------------------------------------------------------------------------


class ECXEnrichmentCacheResponse(BaseModel):
    """Cached eCX enrichment data for an investigation."""

    scan_id: str
    count: int
    enrichments: list[dict[str, Any]]


@ecx_router.get("/investigate/{scan_id}", response_model=ECXEnrichmentCacheResponse)
def get_investigation_ecx(scan_id: str) -> ECXEnrichmentCacheResponse:
    """Return cached eCX enrichment results for an investigation.

    Args:
        scan_id: The investigation scan ID.

    Returns:
        Cached enrichment data including scan_id, count, and enrichment rows.

    Raises:
        HTTPException: With status 404 if the investigation is not found.
    """
    from ssi.store import build_scan_store

    store = build_scan_store()
    scan = store.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    enrichments = store.get_ecx_enrichments(scan_id)
    return ECXEnrichmentCacheResponse(
        scan_id=scan_id,
        count=len(enrichments),
        enrichments=enrichments,
    )


# ---------------------------------------------------------------------------
# Phase 2 — Submission management
# ---------------------------------------------------------------------------


class ECXSubmissionListResponse(BaseModel):
    """Paginated list of eCX submission records."""

    count: int
    submissions: list[dict[str, Any]]


def _require_submission_service() -> Any:
    """Return an ECXSubmissionService or raise 503 if not configured.

    Returns:
        An initialized ECXSubmissionService.

    Raises:
        HTTPException: With status 503 when submission service is unavailable.
    """
    from ssi.ecx.submission import get_submission_service

    service = get_submission_service()
    if service is None:
        raise HTTPException(
            status_code=503,
            detail="eCX submission is not configured or disabled.",
        )
    return service


@ecx_router.get("/submissions", response_model=ECXSubmissionListResponse)
def list_submissions(
    scan_id: str | None = Query(default=None, description="Filter by scan ID."),
    case_id: str | None = Query(default=None, description="Filter by case ID."),
    status: str | None = Query(default=None, description="Filter by status (pending/queued/submitted/…)."),
    limit: int = Query(default=50, ge=1, le=200, description="Page size."),
    offset: int = Query(default=0, ge=0, description="Pagination offset."),
) -> ECXSubmissionListResponse:
    """List eCX submission records with optional filters.

    Args:
        scan_id: Optional scan ID filter.
        case_id: Optional case ID filter.
        status: Optional status filter.
        limit: Page size (1–200).
        offset: Pagination offset.

    Returns:
        Paginated list of submission records.
    """
    from ssi.store import build_scan_store

    store = build_scan_store()
    rows = store.list_ecx_submissions(scan_id=scan_id, case_id=case_id, status=status, limit=limit, offset=offset)
    return ECXSubmissionListResponse(count=len(rows), submissions=rows)


@ecx_router.post("/submissions/{submission_id}/approve", response_model=ECXSubmissionResponse)
def approve_submission(submission_id: str, body: ECXApproveRequest) -> ECXSubmissionResponse:
    """Approve a queued eCX submission and transmit it to eCrimeX.

    Args:
        submission_id: UUID of the queued submission.
        body: Approval request with release label and analyst identifier.

    Returns:
        Updated submission record.

    Raises:
        HTTPException: 503 if eCX not configured, 404 if not found,
            400 if submission is not in ``queued`` status.
    """
    service = _require_submission_service()
    from ssi.store import build_scan_store

    store = build_scan_store()
    existing = store.get_ecx_submission(submission_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Submission not found.")
    if existing.get("status") != "queued":
        raise HTTPException(
            status_code=400,
            detail=f"Submission status is '{existing.get('status')}' — only 'queued' submissions can be approved.",
        )

    updated = service.analyst_approve(submission_id, body.release_label, body.analyst)
    if not updated:
        raise HTTPException(status_code=500, detail="Approval failed.")
    return _submission_to_response(updated)


@ecx_router.post("/submissions/{submission_id}/reject", response_model=ECXSubmissionResponse)
def reject_submission(submission_id: str, body: ECXRejectRequest) -> ECXSubmissionResponse:
    """Reject a queued eCX submission without transmitting to eCrimeX.

    Args:
        submission_id: UUID of the queued submission.
        body: Rejection request with analyst identifier and optional reason.

    Returns:
        Updated submission record.

    Raises:
        HTTPException: 404 if not found, 400 if not queued/pending.
    """
    from ssi.store import build_scan_store

    store = build_scan_store()
    existing = store.get_ecx_submission(submission_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Submission not found.")
    if existing.get("status") not in ("queued", "pending"):
        current = existing.get("status")
        raise HTTPException(
            status_code=400,
            detail=f"Submission status is '{current}' — only queued/pending submissions can be rejected.",
        )

    # Rejection doesn't need the eCX client — it's a local-only state change.
    from ssi.ecx.submission import ECXSubmissionService
    from ssi.osint.ecrimex import _get_client

    client = _get_client()
    if client is None:
        raise HTTPException(status_code=503, detail="eCX not configured.")
    service = ECXSubmissionService(client=client, store=store)
    updated = service.analyst_reject(submission_id, body.analyst, body.reason)
    if not updated:
        raise HTTPException(status_code=500, detail="Rejection failed.")
    return _submission_to_response(updated)


@ecx_router.post("/submissions/{submission_id}/retract", response_model=ECXSubmissionResponse)
def retract_submission(submission_id: str, body: ECXRejectRequest) -> ECXSubmissionResponse:
    """Retract a previously submitted eCX record.

    Calls the eCX API to mark the record as removed, then marks the local
    row as ``"retracted"``.

    Args:
        submission_id: UUID of the submitted record.
        body: Retraction request with analyst identifier and optional reason.

    Returns:
        Updated submission record.

    Raises:
        HTTPException: 503 if eCX not configured, 404 if not found,
            400 if not in ``submitted`` status.
    """
    service = _require_submission_service()
    from ssi.store import build_scan_store

    store = build_scan_store()
    existing = store.get_ecx_submission(submission_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Submission not found.")
    if existing.get("status") != "submitted":
        raise HTTPException(
            status_code=400,
            detail=f"Submission status is '{existing.get('status')}' — only 'submitted' records can be retracted.",
        )

    updated = service.retract(submission_id, body.analyst)
    if not updated:
        raise HTTPException(status_code=500, detail="Retraction failed.")
    return _submission_to_response(updated)


def _submission_to_response(row: dict[str, Any]) -> ECXSubmissionResponse:
    """Convert a submission store row to an API response model.

    Args:
        row: Raw submission dict from ``ScanStore``.

    Returns:
        Serialisable :class:`~ssi.models.ecx.ECXSubmissionResponse`.
    """
    from datetime import datetime

    def _parse_dt(val: Any) -> datetime | None:
        if val is None:
            return None
        if isinstance(val, datetime):
            return val
        try:
            return datetime.fromisoformat(str(val))
        except (ValueError, TypeError):
            return None

    return ECXSubmissionResponse(
        submission_id=row.get("submission_id", ""),
        ecx_module=row.get("ecx_module", ""),
        ecx_record_id=row.get("ecx_record_id"),
        scan_id=row.get("scan_id", ""),
        submitted_value=row.get("submitted_value", ""),
        confidence=row.get("confidence", 0),
        status=row.get("status", ""),
        submitted_by=row.get("submitted_by", ""),
        submitted_at=_parse_dt(row.get("submitted_at")),
        error_message=row.get("error_message", ""),
        created_at=_parse_dt(row.get("created_at")),
    )
