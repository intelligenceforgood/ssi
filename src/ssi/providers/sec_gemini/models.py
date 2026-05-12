"""Pydantic models for Sec-Gemini enrichment results.

These models capture the structured output parsed from Sec-Gemini's
free-form agent responses.  All fields have sensible defaults so that
partial or failed parses still produce valid (if empty) objects.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from ssi.models.investigation import ThreatIndicator


class EmailSecurityPosture(BaseModel):
    """SPF/DKIM/DMARC analysis for a single email domain."""

    domain: str = ""
    spf_record: str | None = None
    spf_valid: bool = False
    dkim_configured: bool = False
    dmarc_record: str | None = None
    dmarc_policy: str | None = None  # none | quarantine | reject
    mx_records: list[str] = Field(default_factory=list)
    assessment: str = ""  # Human-readable summary from the agent


class VulnerabilityFinding(BaseModel):
    """A CVE or vulnerability finding correlated to the site's infrastructure."""

    cve_id: str = ""
    software: str = ""
    severity: str = ""  # critical | high | medium | low
    cvss_score: float | None = None
    is_exploited: bool = False
    patch_available: bool = False
    description: str = ""


class InfraFingerprint(BaseModel):
    """Technology stack identification from HTTP fingerprinting."""

    web_server: str | None = None
    framework: str | None = None
    cms: str | None = None
    hosting_provider: str | None = None
    cdn: str | None = None
    technologies: list[str] = Field(default_factory=list)
    vulnerabilities: list[VulnerabilityFinding] = Field(default_factory=list)


class SecGeminiAnalysis(BaseModel):
    """Structured output from a Sec-Gemini enrichment session.

    This is the top-level result persisted on ``InvestigationResult.sec_gemini_analysis``.
    """

    email_security: list[EmailSecurityPosture] = Field(default_factory=list)
    infrastructure: InfraFingerprint | None = None
    threat_synthesis: str = ""  # AI-reasoned narrative summary
    threat_indicators: list[ThreatIndicator] = Field(default_factory=list)
    risk_adjustment: float = 0.0  # Delta to apply to the overall risk score (-10 to +10)
    raw_agent_response: str = ""  # Full response retained for audit trail
    session_id: str = ""
    duration_seconds: float = 0.0
