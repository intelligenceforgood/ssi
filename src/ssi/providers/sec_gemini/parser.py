"""Response parser for Sec-Gemini agent output.

The Sec-Gemini agent returns free-form markdown/text that may or may
not contain the JSON block we requested.  This module extracts and
validates the structured data, falling back to empty defaults when
the agent's output doesn't match expectations.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from ssi.models.investigation import ThreatIndicator
from ssi.providers.sec_gemini.models import (
    EmailSecurityPosture,
    InfraFingerprint,
    SecGeminiAnalysis,
    VulnerabilityFinding,
)

logger = logging.getLogger(__name__)


def parse_sec_gemini_response(raw_response: str) -> SecGeminiAnalysis:
    """Parse the Sec-Gemini agent's combined response into a structured model.

    Attempts to extract a JSON block from the response.  If no valid JSON
    is found, returns a minimal ``SecGeminiAnalysis`` with just the raw
    response and threat synthesis extracted from the text.

    Args:
        raw_response: Combined text from all ``MESSAGE_TYPE_RESPONSE`` messages.

    Returns:
        A populated ``SecGeminiAnalysis`` instance.
    """
    if not raw_response.strip():
        return SecGeminiAnalysis()

    # Try to extract JSON from code blocks or raw JSON
    json_data = _extract_json(raw_response)

    if json_data:
        return _parse_structured(json_data, raw_response)

    # Fallback: no JSON found — store raw response as threat synthesis
    logger.info("Sec-Gemini response did not contain parseable JSON; storing as narrative")
    return SecGeminiAnalysis(
        threat_synthesis=raw_response.strip(),
        raw_agent_response=raw_response,
    )


def _extract_json(text: str) -> dict[str, Any] | None:
    """Extract a JSON object from text that may contain markdown code fences.

    Tries, in order:
    1. JSON inside ```json ... ``` fences
    2. JSON inside ``` ... ``` fences
    3. Raw JSON starting with ``{``
    """
    # Pattern 1: ```json ... ```
    match = re.search(r"```json\s*\n(.*?)\n\s*```", text, re.DOTALL)
    if match:
        return _try_parse(match.group(1))

    # Pattern 2: ``` ... ``` containing JSON
    match = re.search(r"```\s*\n(.*?)\n\s*```", text, re.DOTALL)
    if match:
        result = _try_parse(match.group(1))
        if result is not None:
            return result

    # Pattern 3: raw JSON object
    match = re.search(r"\{[\s\S]*\}", text)
    if match:
        return _try_parse(match.group(0))

    return None


def _try_parse(text: str) -> dict[str, Any] | None:
    """Attempt to parse a JSON string, returning None on failure."""
    try:
        data = json.loads(text.strip())
        if isinstance(data, dict):
            return data
    except (json.JSONDecodeError, ValueError):
        pass
    return None


def _parse_structured(data: dict[str, Any], raw_response: str) -> SecGeminiAnalysis:
    """Convert a parsed JSON dict into a ``SecGeminiAnalysis``.

    Uses ``.get()`` with defaults throughout to tolerate partial output
    from the agent.
    """
    # Email security
    email_security: list[EmailSecurityPosture] = []
    for item in data.get("email_security", []):
        if isinstance(item, dict):
            email_security.append(
                EmailSecurityPosture(
                    domain=item.get("domain", ""),
                    spf_record=item.get("spf_record"),
                    spf_valid=item.get("spf_valid", False),
                    dkim_configured=item.get("dkim_configured", False),
                    dmarc_record=item.get("dmarc_record"),
                    dmarc_policy=item.get("dmarc_policy"),
                    mx_records=item.get("mx_records", []),
                    assessment=item.get("assessment", ""),
                )
            )

    # Infrastructure
    infra = None
    infra_data = data.get("infrastructure")
    if isinstance(infra_data, dict):
        vulns = []
        for v in infra_data.get("vulnerabilities", []):
            if isinstance(v, dict):
                vulns.append(
                    VulnerabilityFinding(
                        cve_id=v.get("cve_id", ""),
                        software=v.get("software", ""),
                        severity=v.get("severity", ""),
                        cvss_score=v.get("cvss_score"),
                        is_exploited=v.get("is_exploited", False),
                        patch_available=v.get("patch_available", False),
                        description=v.get("description", ""),
                    )
                )
        infra = InfraFingerprint(
            web_server=infra_data.get("web_server"),
            framework=infra_data.get("framework"),
            cms=infra_data.get("cms"),
            hosting_provider=infra_data.get("hosting_provider"),
            cdn=infra_data.get("cdn"),
            technologies=infra_data.get("technologies", []),
            vulnerabilities=vulns,
        )

    # Build threat indicators from findings
    indicators = _build_indicators(email_security, infra)

    # Risk adjustment
    risk_adj = data.get("risk_adjustment", 0)
    try:
        risk_adj = max(-10.0, min(10.0, float(risk_adj)))
    except (TypeError, ValueError):
        risk_adj = 0.0

    return SecGeminiAnalysis(
        email_security=email_security,
        infrastructure=infra,
        threat_synthesis=data.get("threat_synthesis", ""),
        threat_indicators=indicators,
        risk_adjustment=risk_adj,
        raw_agent_response=raw_response,
    )


def _build_indicators(
    email_security: list[EmailSecurityPosture],
    infra: InfraFingerprint | None,
) -> list[ThreatIndicator]:
    """Generate ``ThreatIndicator`` records from parsed findings."""
    indicators: list[ThreatIndicator] = []

    # Email security indicators
    for es in email_security:
        if not es.spf_valid:
            indicators.append(
                ThreatIndicator(
                    indicator_type="email_security",
                    value=es.domain,
                    context=f"SPF invalid or missing for {es.domain}",
                    source="sec_gemini",
                )
            )
        if es.dmarc_policy in (None, "none", ""):
            indicators.append(
                ThreatIndicator(
                    indicator_type="email_security",
                    value=es.domain,
                    context=f"DMARC policy is '{es.dmarc_policy or 'missing'}' for {es.domain}",
                    source="sec_gemini",
                )
            )

    # Vulnerability indicators
    if infra:
        for vuln in infra.vulnerabilities:
            indicators.append(
                ThreatIndicator(
                    indicator_type="vulnerability",
                    value=vuln.cve_id,
                    context=(
                        f"{vuln.software}: {vuln.severity} severity"
                        f"{' (actively exploited)' if vuln.is_exploited else ''}"
                        f" — {vuln.description[:200]}"
                    ),
                    source="sec_gemini",
                )
            )

    return indicators
