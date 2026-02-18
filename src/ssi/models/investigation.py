"""Domain models for investigation results and evidence."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class InvestigationStatus(str, Enum):
    """Investigation lifecycle states."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


class ScamClassification(BaseModel):
    """Scam type classification aligned with i4g fraud taxonomy."""

    scam_type: str = ""
    confidence: float = 0.0
    intent: str = ""
    channel: str = ""
    technique: str = ""
    action: str = ""
    persona: str = ""
    summary: str = ""


class WHOISRecord(BaseModel):
    """Parsed WHOIS/RDAP data."""

    domain: str = ""
    registrar: str = ""
    creation_date: str = ""
    expiration_date: str = ""
    updated_date: str = ""
    registrant_name: str = ""
    registrant_org: str = ""
    registrant_country: str = ""
    name_servers: list[str] = Field(default_factory=list)
    status: list[str] = Field(default_factory=list)
    raw: str = ""


class DNSRecords(BaseModel):
    """DNS lookup results."""

    a: list[str] = Field(default_factory=list)
    aaaa: list[str] = Field(default_factory=list)
    mx: list[str] = Field(default_factory=list)
    txt: list[str] = Field(default_factory=list)
    ns: list[str] = Field(default_factory=list)
    cname: list[str] = Field(default_factory=list)


class SSLInfo(BaseModel):
    """TLS certificate details."""

    issuer: str = ""
    subject: str = ""
    serial_number: str = ""
    not_before: str = ""
    not_after: str = ""
    san: list[str] = Field(default_factory=list)
    fingerprint_sha256: str = ""
    is_valid: bool = False
    is_self_signed: bool = False


class GeoIPInfo(BaseModel):
    """IP geolocation data."""

    ip: str = ""
    hostname: str = ""
    city: str = ""
    region: str = ""
    country: str = ""
    loc: str = ""
    org: str = ""
    asn: str = ""
    as_name: str = ""


class FormField(BaseModel):
    """A form input field found on the page."""

    tag: str = ""
    field_type: str = ""
    name: str = ""
    label: str = ""
    placeholder: str = ""
    required: bool = False
    pii_category: str = ""


class PageSnapshot(BaseModel):
    """Captured state of a single page visit."""

    url: str
    final_url: str = ""
    status_code: int = 0
    title: str = ""
    screenshot_path: str = ""
    dom_snapshot_path: str = ""
    har_path: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    redirect_chain: list[str] = Field(default_factory=list)
    form_fields: list[FormField] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    external_resources: list[str] = Field(default_factory=list)


class ThreatIndicator(BaseModel):
    """An indicator of compromise (IOC)."""

    indicator_type: str = ""  # ip, domain, email, crypto_wallet, phone, url
    value: str = ""
    context: str = ""
    source: str = ""


class InvestigationResult(BaseModel):
    """Complete result of an SSI investigation."""

    investigation_id: UUID = Field(default_factory=uuid4)
    url: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    status: InvestigationStatus = InvestigationStatus.PENDING
    success: bool = False
    error: str = ""
    output_path: str = ""

    # Passive recon
    whois: WHOISRecord | None = None
    dns: DNSRecords | None = None
    ssl: SSLInfo | None = None
    geoip: GeoIPInfo | None = None
    page_snapshot: PageSnapshot | None = None

    # Analysis
    classification: ScamClassification | None = None
    threat_indicators: list[ThreatIndicator] = Field(default_factory=list)
    brand_impersonation: str = ""

    # Evidence packaging
    evidence_zip_path: str = ""
    report_path: str = ""

    # Metadata
    passive_only: bool = True
    agent_steps: list[dict[str, Any]] = Field(default_factory=list)
    token_usage: int = 0
    duration_seconds: float = 0.0
