"""REST API routes for eCrimeX (eCX) integration.

Provides search endpoints for ad-hoc eCX queries:
- ``POST /ecx/search/phish`` — search phish module
- ``POST /ecx/search/domain`` — search malicious-domain module
- ``POST /ecx/search/ip`` — search malicious-ip module
- ``POST /ecx/search/crypto`` — search cryptocurrency-addresses module
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

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
