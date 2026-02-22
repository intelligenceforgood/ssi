"""VirusTotal URL scan module."""

from __future__ import annotations

import logging

import httpx

from ssi.models.investigation import ThreatIndicator
from ssi.osint import with_retries

logger = logging.getLogger(__name__)

VT_API_BASE = "https://www.virustotal.com/api/v3"


@with_retries(max_retries=2, backoff_seconds=1.0, retryable_exceptions=(httpx.TransportError, httpx.HTTPStatusError))
def check_url(url: str) -> list[ThreatIndicator]:
    """Submit *url* to VirusTotal and return any threat indicators.

    Requires ``SSI_OSINT__VIRUSTOTAL_API_KEY`` to be set. Returns an empty
    list if the key is missing (graceful degradation for PoC).

    Args:
        url: The URL to check.

    Returns:
        List of threat indicators extracted from the VT response.
    """
    from ssi.settings import get_settings

    settings = get_settings()
    api_key = settings.osint.virustotal_api_key
    if not api_key:
        logger.info("VirusTotal API key not configured — skipping.")
        return []

    headers = {"x-apikey": api_key}
    indicators: list[ThreatIndicator] = []

    try:
        import base64

        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        resp = httpx.get(f"{VT_API_BASE}/urls/{url_id}", headers=headers, timeout=15)

        if resp.status_code == 404:
            logger.info("URL not in VirusTotal database — submitting for scan.")
            submit = httpx.post(f"{VT_API_BASE}/urls", headers=headers, data={"url": url}, timeout=15)
            submit.raise_for_status()
            return indicators  # Results available later

        resp.raise_for_status()
        data = resp.json().get("data", {}).get("attributes", {})

        # Extract detection stats
        stats = data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious or suspicious:
            indicators.append(
                ThreatIndicator(
                    indicator_type="url",
                    value=url,
                    context=f"VirusTotal: {malicious} malicious, {suspicious} suspicious detections",
                    source="virustotal",
                )
            )

    except Exception as e:
        logger.warning("VirusTotal check failed: %s", e)

    return indicators
