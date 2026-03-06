"""Pydantic models for eCrimeX (eCX) integration.

These models represent eCX API response records, aggregated enrichment
results, and submission tracking.  All field names use ``snake_case``
internally; the :class:`ECXClient` normalises eCX's ``camelCase`` keys
before constructing these models.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class ECXPhishRecord(BaseModel):
    """A phish record from eCrimeX."""

    id: int
    url: str = ""
    brand: str = ""
    confidence: int = 0
    status: str = ""
    discovered_at: int | None = None
    created_at: int | None = None
    updated_at: int | None = None
    ip: list[str] = Field(default_factory=list)
    asn: list[int] = Field(default_factory=list)
    tld: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class ECXCryptoRecord(BaseModel):
    """A cryptocurrency address record from eCrimeX."""

    id: int
    currency: str = ""
    address: str = ""
    crime_category: str = ""
    site_link: str = ""
    price: int = 0
    source: str = ""
    procedure: str = ""
    actor_category: str = ""
    confidence: int = 0
    status: str = ""
    discovered_at: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    notes: list[dict[str, Any]] = Field(default_factory=list)


class ECXMalDomainRecord(BaseModel):
    """A malicious domain record from eCrimeX."""

    id: int
    domain: str = ""
    classification: str = ""
    confidence: int = 0
    status: str = ""
    discovered_at: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    notes: list[dict[str, Any]] = Field(default_factory=list)


class ECXMalIPRecord(BaseModel):
    """A malicious IP record from eCrimeX."""

    id: int
    ip: str = ""
    brand: str = ""
    description: str = ""
    confidence: int = 0
    status: str = ""
    asn: list[int] = Field(default_factory=list)
    port: int | None = None
    discovered_at: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ECXEnrichmentResult(BaseModel):
    """Aggregated eCX enrichment for a single investigation.

    Collects hits from all queried eCX modules into a single container,
    along with query metadata (count, timing, errors).
    """

    phish_hits: list[ECXPhishRecord] = Field(default_factory=list)
    domain_hits: list[ECXMalDomainRecord] = Field(default_factory=list)
    ip_hits: list[ECXMalIPRecord] = Field(default_factory=list)
    crypto_hits: list[ECXCryptoRecord] = Field(default_factory=list)
    report_phishing_hits: list[dict[str, Any]] = Field(default_factory=list)
    query_count: int = 0
    total_hits: int = 0
    query_duration_ms: float = 0.0
    errors: list[str] = Field(default_factory=list)

    @property
    def has_hits(self) -> bool:
        """Return ``True`` if any module returned at least one hit."""
        return self.total_hits > 0


class ECXSubmissionRecord(BaseModel):
    """Tracks a single indicator submission to eCrimeX (Phase 2).

    One row is created per indicator per investigation: the scam URL,
    each harvested wallet, the hosting domain, and the primary IP are
    each submitted as separate records.

    Statuses:
        ``pending``   — created but not yet processed.
        ``queued``    — below auto-submit threshold, waiting for analyst review.
        ``submitted`` — successfully posted to eCX.
        ``updated``   — existing eCX record updated (confidence/status bump).
        ``failed``    — eCX API error; see ``error_message``.
        ``rejected``  — analyst declined submission.
        ``retracted`` — previously submitted record retracted from eCX.
    """

    submission_id: str = Field(default_factory=lambda: str(__import__("uuid").uuid4()))
    ecx_module: str = ""  # phish | malicious-domain | malicious-ip | cryptocurrency-addresses
    ecx_record_id: int | None = None  # Server-assigned ID after a successful POST/PUT
    case_id: str = ""
    scan_id: str = ""
    submitted_value: str = ""  # URL / domain / IP / wallet address
    confidence: int = 0  # 0–100 integer confidence passed to eCX
    release_label: str = ""  # eCX release label for phish (e.g. "active")
    status: str = "pending"  # See docstring for valid values
    submitted_by: str = ""  # "auto" or analyst identifier
    submitted_at: datetime | None = None
    error_message: str = ""
    created_at: datetime = Field(
        default_factory=lambda: __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
    )


class ECXApproveRequest(BaseModel):
    """Request body for approving a queued eCX submission."""

    release_label: str = Field(default="", description="eCX release label (e.g. 'active').")
    analyst: str = Field(..., description="Analyst identifier approving this submission.")


class ECXRejectRequest(BaseModel):
    """Request body for rejecting a queued eCX submission."""

    analyst: str = Field(..., description="Analyst identifier rejecting this submission.")
    reason: str = Field(default="", description="Optional rejection reason.")


class ECXSubmissionResponse(BaseModel):
    """API response wrapper for a single submission record."""

    submission_id: str
    ecx_module: str
    ecx_record_id: int | None
    scan_id: str
    submitted_value: str
    confidence: int
    status: str
    submitted_by: str
    submitted_at: datetime | None
    error_message: str | None = None
    created_at: datetime | None
