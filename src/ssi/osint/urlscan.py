"""urlscan.io URL scan and lookup module.

Submits a URL to urlscan.io for analysis and retrieves results including
page details, contacted IPs/domains, and brand impersonation indicators.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from ssi.models.investigation import ThreatIndicator
from ssi.osint import with_retries

logger = logging.getLogger(__name__)

URLSCAN_API_BASE = "https://urlscan.io/api/v1"

# How long to wait for urlscan.io to finish processing (seconds)
_POLL_TIMEOUT = 60
_POLL_INTERVAL = 5


@with_retries(max_retries=2, backoff_seconds=1.0, retryable_exceptions=(httpx.TransportError, httpx.HTTPStatusError))
def scan_url(url: str) -> dict[str, Any]:
    """Submit *url* to urlscan.io and return the full result.

    If no API key is configured, falls back to a public search for existing
    scans of the URL.

    Args:
        url: The URL to scan.

    Returns:
        A dict with keys ``page`` (page metadata), ``lists`` (contacted
        domains/IPs), ``stats`` (resource stats), ``verdicts`` (threat
        verdicts), and ``task`` (scan metadata).  Returns an empty dict
        on failure.
    """
    from ssi.settings import get_settings

    settings = get_settings()
    api_key = settings.osint.urlscan_api_key

    if api_key:
        return _submit_and_poll(url, api_key)
    else:
        logger.info("urlscan.io API key not configured — searching existing scans.")
        return _search_existing(url)


def extract_threat_indicators(scan_result: dict[str, Any], source_url: str) -> list[ThreatIndicator]:
    """Extract threat indicators from a urlscan.io result.

    Args:
        scan_result: The full urlscan.io result dict.
        source_url: The original URL being investigated.

    Returns:
        List of ``ThreatIndicator`` objects.
    """
    indicators: list[ThreatIndicator] = []

    if not scan_result:
        return indicators

    # Verdicts — overall and community
    verdicts = scan_result.get("verdicts", {})
    overall = verdicts.get("overall", {})
    if overall.get("malicious"):
        indicators.append(
            ThreatIndicator(
                indicator_type="url",
                value=source_url,
                context=f"urlscan.io: malicious (score={overall.get('score', 'N/A')})",
                source="urlscan.io",
            )
        )

    # Contacted IPs
    lists = scan_result.get("lists", {})
    for ip in lists.get("ips", [])[:10]:  # Limit to first 10
        indicators.append(
            ThreatIndicator(
                indicator_type="ip",
                value=ip,
                context="Contacted IP during page load",
                source="urlscan.io",
            )
        )

    # Contacted domains (exclude the target domain itself)
    from urllib.parse import urlparse

    target_domain = urlparse(source_url).hostname or ""
    for domain in lists.get("domains", [])[:10]:
        if domain != target_domain:
            indicators.append(
                ThreatIndicator(
                    indicator_type="domain",
                    value=domain,
                    context="External domain contacted during page load",
                    source="urlscan.io",
                )
            )

    # Certificates
    for cert in lists.get("certificates", [])[:5]:
        issuer = cert.get("issuer", "")
        subject = cert.get("subjectName", "")
        if subject and subject != target_domain:
            indicators.append(
                ThreatIndicator(
                    indicator_type="domain",
                    value=subject,
                    context=f"TLS certificate subject (issuer: {issuer})",
                    source="urlscan.io",
                )
            )

    return indicators


def get_page_metadata(scan_result: dict[str, Any]) -> dict[str, Any]:
    """Extract page-level metadata from a urlscan.io result.

    Returns a summary dict with server, domain, IP, country, ASN, and
    technology information suitable for inclusion in reports.
    """
    if not scan_result:
        return {}

    page = scan_result.get("page", {})
    stats = scan_result.get("stats", {})

    return {
        "server": page.get("server", ""),
        "domain": page.get("domain", ""),
        "ip": page.get("ip", ""),
        "country": page.get("country", ""),
        "asn": page.get("asn", ""),
        "asnname": page.get("asnname", ""),
        "title": page.get("title", ""),
        "status_code": page.get("status", 0),
        "mime_type": page.get("mimeType", ""),
        "total_resources": stats.get("resourceStats", [{}])[0].get("count", 0) if stats.get("resourceStats") else 0,
        "unique_countries": stats.get("uniqCountries", 0),
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _submit_and_poll(url: str, api_key: str) -> dict[str, Any]:
    """Submit a new scan and poll until results are ready."""
    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    payload = {"url": url, "visibility": "unlisted"}

    try:
        resp = httpx.post(f"{URLSCAN_API_BASE}/scan/", json=payload, headers=headers, timeout=15)
        resp.raise_for_status()
        scan_data = resp.json()
        result_url = scan_data.get("api")
        scan_uuid = scan_data.get("uuid", "")

        if not result_url:
            logger.warning("urlscan.io did not return a result URL")
            return {}

        logger.info("urlscan.io scan submitted: %s (uuid=%s)", result_url, scan_uuid)

        # Poll for completion
        elapsed = 0
        while elapsed < _POLL_TIMEOUT:
            time.sleep(_POLL_INTERVAL)
            elapsed += _POLL_INTERVAL

            try:
                result_resp = httpx.get(result_url, timeout=15)
                if result_resp.status_code == 200:
                    return result_resp.json()
                elif result_resp.status_code == 404:
                    logger.debug("Scan not ready yet, retrying... (%ds)", elapsed)
                    continue
                else:
                    logger.warning("Unexpected status from urlscan.io: %d", result_resp.status_code)
                    break
            except httpx.TimeoutException:
                logger.debug("Poll timeout, retrying...")
                continue

        logger.warning("urlscan.io scan timed out after %ds", _POLL_TIMEOUT)
        return {}

    except httpx.HTTPStatusError as e:
        logger.warning("urlscan.io API error: HTTP %s", e.response.status_code)
        return {}
    except Exception as e:
        logger.warning("urlscan.io scan failed: %s", e)
        return {}


def _search_existing(url: str) -> dict[str, Any]:
    """Search urlscan.io for existing scans of the URL (no API key required)."""
    from urllib.parse import urlparse

    domain = urlparse(url).hostname or ""
    if not domain:
        return {}

    try:
        search_url = f"{URLSCAN_API_BASE}/search/?q=domain:{domain}&size=1"
        resp = httpx.get(search_url, timeout=15)
        resp.raise_for_status()
        results = resp.json().get("results", [])

        if not results:
            logger.info("No existing urlscan.io scans found for %s", domain)
            return {}

        # Fetch the full result for the most recent scan
        result_id = results[0].get("_id", "")
        if not result_id:
            return {}

        detail_resp = httpx.get(f"{URLSCAN_API_BASE}/result/{result_id}/", timeout=15)
        if detail_resp.status_code == 200:
            return detail_resp.json()

    except Exception as e:
        logger.warning("urlscan.io search failed: %s", e)

    return {}
