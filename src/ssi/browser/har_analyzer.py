"""HAR (HTTP Archive) analysis for extracting IOCs and suspicious patterns.

Parses HAR files captured during browser sessions to identify:
- Third-party tracking domains
- Suspicious request patterns (cryptocurrency wallets, credential exfil)
- Phishing-kit fingerprints (common resource paths)
- Content-type mismatches (executables disguised as images, etc.)
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ssi.models.investigation import ThreatIndicator

logger = logging.getLogger(__name__)

# Common phishing-kit resource patterns
_PHISHING_KIT_PATTERNS = [
    r"/wp-admin/",
    r"/wp-content/plugins/.*\.php",
    r"/\.well-known/",
    r"/cgi-bin/",
    r"/webmail/",
    r"panel\.php",
    r"gate\.php",
    r"post\.php",
    r"antibot",
    r"bot_check",
    r"blocker\.php",
]

# Suspicious content types that may indicate malware delivery
_SUSPICIOUS_CONTENT_TYPES = {
    "application/x-msdownload",
    "application/x-msdos-program",
    "application/x-executable",
    "application/x-dosexec",
    "application/vnd.microsoft.portable-executable",
    "application/java-archive",
    "application/x-shockwave-flash",
    "application/hta",
    "application/x-ms-shortcut",
}

# Patterns suggesting credential exfiltration
_EXFIL_PATTERNS = [
    r"password|passwd|pwd",
    r"credit.?card|cc.?num",
    r"ssn|social.?security",
    r"account.?num",
    r"routing.?num",
    r"bank.?account",
]

# Cryptocurrency address patterns
_CRYPTO_PATTERNS = {
    "bitcoin": r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
    "ethereum": r"\b0x[a-fA-F0-9]{40}\b",
    "monero": r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b",
}


def analyze_har(har_path: Path, target_domain: str = "") -> HarAnalysis:
    """Parse a HAR file and extract security-relevant findings.

    Args:
        har_path: Path to the HAR JSON file.
        target_domain: The primary domain being investigated (to identify
            third-party requests).

    Returns:
        An ``HarAnalysis`` with categorized findings.
    """
    if not har_path.is_file():
        logger.warning("HAR file not found: %s", har_path)
        return HarAnalysis()

    try:
        data = json.loads(har_path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to parse HAR file %s: %s", har_path, e)
        return HarAnalysis()

    entries = data.get("log", {}).get("entries", [])
    if not entries:
        return HarAnalysis()

    analysis = HarAnalysis()
    target = target_domain or ""

    for entry in entries:
        request = entry.get("request", {})
        response = entry.get("response", {})
        url = request.get("url", "")
        parsed = urlparse(url)
        domain = parsed.hostname or ""

        # Track third-party domains
        if target and domain and domain != target and not domain.endswith(f".{target}"):
            analysis.third_party_domains.add(domain)

        # Check for suspicious content types in responses
        resp_content_type = _get_content_type(response)
        if resp_content_type in _SUSPICIOUS_CONTENT_TYPES:
            analysis.suspicious_content_types.append(
                {"url": url, "content_type": resp_content_type, "domain": domain}
            )

        # Check for phishing-kit patterns in URLs
        for pattern in _PHISHING_KIT_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                analysis.phishing_kit_indicators.append(
                    {"url": url, "pattern": pattern, "domain": domain}
                )
                break  # One match per URL is enough

        # Check POST bodies for credential exfiltration patterns
        if request.get("method", "").upper() == "POST":
            post_data = _get_post_data(request)
            if post_data:
                for pattern in _EXFIL_PATTERNS:
                    if re.search(pattern, post_data, re.IGNORECASE):
                        analysis.exfil_indicators.append(
                            {"url": url, "pattern": pattern, "domain": domain}
                        )
                        break

        # Scan response body text for cryptocurrency addresses
        resp_text = _get_response_text(response)
        if resp_text:
            for crypto_name, crypto_pattern in _CRYPTO_PATTERNS.items():
                matches = re.findall(crypto_pattern, resp_text)
                for match in matches[:3]:  # Limit per type per entry
                    analysis.crypto_addresses.append(
                        {"type": crypto_name, "address": match, "source_url": url}
                    )

    analysis.total_requests = len(entries)
    return analysis


def har_to_threat_indicators(analysis: "HarAnalysis", source_url: str) -> list[ThreatIndicator]:
    """Convert HAR analysis findings into ThreatIndicator models.

    Args:
        analysis: Results from :func:`analyze_har`.
        source_url: The original investigated URL for attribution.

    Returns:
        List of ``ThreatIndicator`` objects.
    """
    indicators: list[ThreatIndicator] = []

    # Suspicious content types → might be malware delivery
    for item in analysis.suspicious_content_types:
        indicators.append(
            ThreatIndicator(
                indicator_type="url",
                value=item["url"][:200],
                context=f"Suspicious content-type: {item['content_type']}",
                source="har_analysis",
            )
        )

    # Phishing kit indicators
    for item in analysis.phishing_kit_indicators[:5]:
        indicators.append(
            ThreatIndicator(
                indicator_type="url",
                value=item["url"][:200],
                context=f"Phishing-kit pattern: {item['pattern']}",
                source="har_analysis",
            )
        )

    # Credential exfiltration patterns
    for item in analysis.exfil_indicators[:5]:
        indicators.append(
            ThreatIndicator(
                indicator_type="url",
                value=item["url"][:200],
                context=f"Possible credential exfiltration (matches: {item['pattern']})",
                source="har_analysis",
            )
        )

    # Cryptocurrency addresses
    for item in analysis.crypto_addresses[:10]:
        indicators.append(
            ThreatIndicator(
                indicator_type="crypto_wallet",
                value=item["address"],
                context=f"{item['type']} address found in page from {item['source_url'][:80]}",
                source="har_analysis",
            )
        )

    return indicators


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


class HarAnalysis:
    """Container for HAR analysis results."""

    def __init__(self) -> None:
        self.total_requests: int = 0
        self.third_party_domains: set[str] = set()
        self.suspicious_content_types: list[dict[str, str]] = []
        self.phishing_kit_indicators: list[dict[str, str]] = []
        self.exfil_indicators: list[dict[str, str]] = []
        self.crypto_addresses: list[dict[str, str]] = []

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-friendly dict."""
        return {
            "total_requests": self.total_requests,
            "third_party_domains": sorted(self.third_party_domains),
            "suspicious_content_types": self.suspicious_content_types,
            "phishing_kit_indicators": self.phishing_kit_indicators,
            "exfil_indicators": self.exfil_indicators,
            "crypto_addresses": self.crypto_addresses,
        }

    @property
    def has_findings(self) -> bool:
        """Return True if any suspicious findings were detected."""
        return bool(
            self.suspicious_content_types
            or self.phishing_kit_indicators
            or self.exfil_indicators
            or self.crypto_addresses
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_content_type(response: dict) -> str:
    """Extract the content-type header from a HAR response."""
    content = response.get("content", {})
    mime = content.get("mimeType", "")
    # Strip parameters (e.g., charset)
    return mime.split(";")[0].strip().lower()


def _get_post_data(request: dict) -> str:
    """Extract POST body text from a HAR request."""
    post = request.get("postData", {})
    return post.get("text", "")


def _get_response_text(response: dict) -> str:
    """Extract response body text from a HAR response, if available."""
    content = response.get("content", {})
    text = content.get("text", "")
    # Only process text-like content (don't scan binary blobs)
    mime = content.get("mimeType", "").lower()
    if any(t in mime for t in ("text/", "json", "javascript", "xml", "html")):
        return text[:50_000]  # Cap scan length
    return ""
