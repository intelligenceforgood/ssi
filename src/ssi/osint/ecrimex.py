"""eCrimeX (eCX) APWG data clearinghouse integration.

Provides :class:`ECXClient` for querying the eCX API and top-level
enrichment functions that are wired into the SSI investigation pipeline.

Phase 1 — Consume: query phish, malicious-domain, malicious-ip,
cryptocurrency-addresses, and report-phishing modules for enrichment.

Phase 2 — Contribute: submit investigation findings to eCX (TBD).

The client follows the SSI OSINT module pattern: settings-driven API key,
``@with_retries`` for transient errors, and graceful degradation when the
key is missing or a module is inaccessible.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

import httpx

from ssi.models.ecx import ECXCryptoRecord, ECXEnrichmentResult, ECXMalDomainRecord, ECXMalIPRecord, ECXPhishRecord
from ssi.osint import with_retries

logger = logging.getLogger(__name__)

T = TypeVar("T")

# ---------------------------------------------------------------------------
# camelCase → snake_case field normalisation
# ---------------------------------------------------------------------------

_FIELD_MAP: dict[str, str] = {
    "discoveredAt": "discovered_at",
    "createdAt": "created_at",
    "updatedAt": "updated_at",
    "submissionCount": "submission_count",
    "crimeCategory": "crime_category",
    "siteLink": "site_link",
    "actorCategory": "actor_category",
}

# Regex for generic camelCase → snake_case fallback
_CAMEL_RE = re.compile(r"(?<=[a-z0-9])([A-Z])")


def _normalize_keys(record: dict[str, Any]) -> dict[str, Any]:
    """Convert eCX camelCase keys to snake_case.

    Uses an explicit mapping for known fields, then falls back to a
    regex-based conversion for any unmapped camelCase keys.

    Args:
        record: Raw eCX API response dict.

    Returns:
        Dict with snake_case keys.
    """
    result: dict[str, Any] = {}
    for key, value in record.items():
        if key in _FIELD_MAP:
            result[_FIELD_MAP[key]] = value
        elif any(c.isupper() for c in key):
            result[_CAMEL_RE.sub(r"_\1", key).lower()] = value
        else:
            result[key] = value
    return result


# ---------------------------------------------------------------------------
# ECXClient
# ---------------------------------------------------------------------------


class ECXClient:
    """HTTP client for the eCrimeX API v1.1.

    Handles authentication, request/response mapping, retries, and
    rate limiting for all six eCX modules.

    Args:
        base_url: eCX API base URL (sandbox or production).
        api_key: Bearer token for authentication.
        attribution: Organisation name for submissions.
        timeout: HTTP request timeout in seconds.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        attribution: str = "IntelligenceForGood",
        timeout: int = 15,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._attribution = attribution
        self._timeout = timeout
        self._http = httpx.Client(
            base_url=self._base_url,
            timeout=self._timeout,
            headers=self._headers(),
        )

    def _headers(self) -> dict[str, str]:
        """Return default HTTP headers including Bearer auth."""
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

    @with_retries(
        max_retries=3,
        backoff_seconds=2.0,
        retryable_exceptions=(httpx.TransportError,),
    )
    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        """Execute an HTTP request with retry and error handling.

        Non-retryable HTTP errors (4xx except 429) are logged and
        re-raised so callers can handle them.  HTTP 429 and 5xx errors
        are retried with exponential backoff.

        Args:
            method: HTTP method (GET, POST, PUT).
            path: API path relative to base_url.
            **kwargs: Passed through to ``httpx.Client.request``.

        Returns:
            The HTTP response.

        Raises:
            httpx.HTTPStatusError: For non-retryable HTTP errors.
            httpx.TransportError: After max retries on transport failures.
        """
        resp = self._http.request(method, path, **kwargs)

        # Retry on rate limit and server errors
        if resp.status_code in (429, 500, 502, 503, 504):
            resp.raise_for_status()

        # Module access denied — log and let caller handle empty results
        if resp.status_code == 403:
            logger.warning("eCX module access denied for %s %s — skipping", method, path)
            resp.raise_for_status()

        resp.raise_for_status()
        return resp

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._http.close()

    # --- Phase 1: Search / Enrichment ---

    def search_phish(self, url: str, limit: int = 10) -> list[ECXPhishRecord]:
        """Search phish records by URL substring match.

        Args:
            url: URL or URL fragment to search for.
            limit: Maximum records to return.

        Returns:
            List of matching phish records.
        """
        body: dict[str, Any] = {
            "filters": {"url": url},
            "fields": [
                "id",
                "url",
                "brand",
                "confidence",
                "status",
                "discoveredAt",
                "ip",
                "asn",
                "tld",
                "createdAt",
            ],
            "limit": limit,
        }
        resp = self._request("POST", "/phish/search", json=body)
        data = resp.json().get("data", [])
        return [ECXPhishRecord(**_normalize_keys(r)) for r in data]

    def search_domain(self, domain: str, limit: int = 10) -> list[ECXMalDomainRecord]:
        """Search malicious domain records.

        Args:
            domain: Domain name to search for.
            limit: Maximum records to return.

        Returns:
            List of matching malicious domain records.
        """
        body: dict[str, Any] = {
            "filters": {"domain": domain},
            "fields": [
                "id",
                "domain",
                "classification",
                "confidence",
                "status",
                "discoveredAt",
            ],
            "limit": limit,
        }
        resp = self._request("POST", "/malicious-domain/search", json=body)
        data = resp.json().get("data", [])
        return [ECXMalDomainRecord(**_normalize_keys(r)) for r in data]

    def search_ip(self, ip: str, limit: int = 10) -> list[ECXMalIPRecord]:
        """Search malicious IP records.

        Args:
            ip: IP address to search for.
            limit: Maximum records to return.

        Returns:
            List of matching malicious IP records.
        """
        body: dict[str, Any] = {
            "filters": {"ip": ip},
            "fields": [
                "id",
                "ip",
                "brand",
                "description",
                "confidence",
                "status",
                "asn",
                "port",
                "discoveredAt",
            ],
            "limit": limit,
        }
        resp = self._request("POST", "/malicious-ip/search", json=body)
        data = resp.json().get("data", [])
        return [ECXMalIPRecord(**_normalize_keys(r)) for r in data]

    def search_crypto(self, address: str, limit: int = 10) -> list[ECXCryptoRecord]:
        """Search cryptocurrency address records.

        Args:
            address: Wallet address to search for.
            limit: Maximum records to return.

        Returns:
            List of matching cryptocurrency records.
        """
        body: dict[str, Any] = {
            "filters": {"address": address},
            "fields": [
                "id",
                "currency",
                "address",
                "crimeCategory",
                "siteLink",
                "price",
                "source",
                "procedure",
                "actorCategory",
                "confidence",
                "status",
                "discoveredAt",
            ],
            "limit": limit,
        }
        resp = self._request("POST", "/cryptocurrency-addresses/search", json=body)
        data = resp.json().get("data", [])
        return [ECXCryptoRecord(**_normalize_keys(r)) for r in data]

    def search_report_phishing(self, url: str, limit: int = 10) -> list[dict[str, Any]]:
        """Search the reportphishing email archive for a URL.

        Args:
            url: URL to search for in email bodies.
            limit: Maximum records to return.

        Returns:
            List of matching report-phishing records (raw dicts).
        """
        body: dict[str, Any] = {
            "filters": {"emailBody": url},
            "fields": [
                "id",
                "emailSubject",
                "senderEmail",
                "emailBody",
                "createdAt",
            ],
            "limit": limit,
        }
        resp = self._request("POST", "/report-phishing/search", json=body)
        data = resp.json().get("data", [])
        return [_normalize_keys(r) for r in data]

    # --- Phase 2: Submit ---

    def submit_phish(
        self,
        url: str,
        confidence: int,
        brand: str = "",
        ip: list[str] | None = None,
    ) -> int:
        """Submit a phishing URL to eCrimeX.

        Args:
            url: The phishing URL to report.
            confidence: Confidence score 0–100.
            brand: Impersonated brand name (empty if unknown).
            ip: Optional list of hosting IP addresses.

        Returns:
            eCX record ID assigned to the new submission.
        """
        body: dict[str, Any] = {
            "url": url,
            "confidence": confidence,
        }
        if brand:
            body["brand"] = brand
        if ip:
            body["ip"] = ip
        resp = self._request("POST", "/phish", json=body)
        return int(resp.json().get("id", 0))

    def submit_crypto(
        self,
        address: str,
        currency: str,
        confidence: int,
        crime_category: str = "fraud",
        site_link: str = "",
        procedure: str = "",
    ) -> int:
        """Submit a cryptocurrency address to eCrimeX.

        Args:
            address: Wallet address string.
            currency: eCX currency code (e.g. ``"BTC"``, ``"ETH"``).
            confidence: Confidence score 0–100.
            crime_category: eCX crime category (default ``"fraud"``).
            site_link: URL of the scam site using this address.
            procedure: Extraction procedure description.

        Returns:
            eCX record ID assigned to the new submission.
        """
        body: dict[str, Any] = {
            "address": address,
            "currency": currency,
            "confidence": confidence,
            "crimeCategory": crime_category,
        }
        if site_link:
            body["siteLink"] = site_link
        if procedure:
            body["procedure"] = procedure
        resp = self._request("POST", "/cryptocurrency-addresses", json=body)
        return int(resp.json().get("id", 0))

    def submit_domain(
        self,
        domain: str,
        classification: str,
        confidence: int,
    ) -> int:
        """Submit a malicious domain to eCrimeX.

        Args:
            domain: The hostname to report.
            classification: Domain classification label (e.g. ``"phishing"``).
            confidence: Confidence score 0–100.

        Returns:
            eCX record ID assigned to the new submission.
        """
        body: dict[str, Any] = {
            "domain": domain,
            "classification": classification,
            "confidence": confidence,
        }
        resp = self._request("POST", "/malicious-domain", json=body)
        return int(resp.json().get("id", 0))

    def submit_ip(
        self,
        ip: str,
        confidence: int,
        description: str = "",
    ) -> int:
        """Submit a malicious IP address to eCrimeX.

        Args:
            ip: IP address to report.
            confidence: Confidence score 0–100.
            description: Human-readable description of the malicious activity.

        Returns:
            eCX record ID assigned to the new submission.
        """
        body: dict[str, Any] = {
            "ip": ip,
            "confidence": confidence,
        }
        if description:
            body["description"] = description
        resp = self._request("POST", "/malicious-ip", json=body)
        return int(resp.json().get("id", 0))

    def add_note(self, module: str, record_id: int, description: str) -> None:
        """Append a note to an existing eCX record.

        Args:
            module: eCX module path (e.g. ``"phish"``, ``"malicious-domain"``).
            record_id: The eCX record to annotate.
            description: Note text.
        """
        body = {"description": description}
        self._request("POST", f"/{module}/{record_id}/note", json=body)

    def update_record(
        self,
        module: str,
        record_id: int,
        confidence: int | None = None,
        status: str | None = None,
    ) -> None:
        """Update confidence or status on an existing eCX record.

        Args:
            module: eCX module path (e.g. ``"phish"``).
            record_id: The eCX record to update.
            confidence: New confidence value (omitted if ``None``).
            status: New status string (omitted if ``None``).
        """
        body: dict[str, Any] = {}
        if confidence is not None:
            body["confidence"] = confidence
        if status is not None:
            body["status"] = status
        if body:
            self._request("PUT", f"/{module}/{record_id}", json=body)


# ---------------------------------------------------------------------------
# Singleton client accessor
# ---------------------------------------------------------------------------

_client_instance: ECXClient | None = None


def _get_client() -> ECXClient | None:
    """Return a singleton :class:`ECXClient` built from settings.

    Returns ``None`` when eCX is disabled or the API key is missing.
    """
    global _client_instance  # noqa: PLW0603
    if _client_instance is not None:
        return _client_instance

    from ssi.settings import get_settings

    settings = get_settings()
    if not settings.ecx.enabled:
        logger.debug("eCX integration is disabled")
        return None

    api_key = settings.ecx.api_key
    if not api_key:
        logger.info("eCX API key not configured — skipping eCX enrichment")
        return None

    _client_instance = ECXClient(
        base_url=settings.ecx.base_url,
        api_key=api_key,
        attribution=settings.ecx.attribution,
        timeout=settings.ecx.timeout,
    )
    return _client_instance


# ---------------------------------------------------------------------------
# Safe query wrapper
# ---------------------------------------------------------------------------


def _safe_query(
    fn: Callable[..., T],
    *args: Any,
    errors: list[str] | None = None,
) -> T | list:
    """Call *fn* and return its result, catching all exceptions.

    On failure, appends a message to *errors* (if provided) and returns
    an empty list so enrichment continues.

    Args:
        fn: The query function to call.
        *args: Positional arguments forwarded to *fn*.
        errors: Mutable list to collect error messages.

    Returns:
        The function result, or an empty list on failure.
    """
    try:
        return fn(*args)
    except httpx.HTTPStatusError as exc:
        msg = f"{fn.__name__}: HTTP {exc.response.status_code}"
        logger.warning("eCX query failed — %s", msg)
        if errors is not None:
            errors.append(msg)
    except Exception as exc:
        msg = f"{fn.__name__}: {type(exc).__name__}: {exc}"
        logger.warning("eCX query failed — %s", msg)
        if errors is not None:
            errors.append(msg)
    return []


# ---------------------------------------------------------------------------
# Top-level enrichment functions
# ---------------------------------------------------------------------------


def enrich_from_ecx(
    url: str,
    domain: str,
    ip: str | None = None,
) -> ECXEnrichmentResult:
    """Query eCrimeX for enrichment data across all accessible modules.

    Each module query is fault-tolerant — a failure in one module does not
    block the others.

    Args:
        url: The target URL being investigated.
        domain: Extracted domain from the URL.
        ip: Primary hosting IP (if resolved).

    Returns:
        Aggregated enrichment result (empty if eCX is disabled).
    """
    from ssi.settings import get_settings

    settings = get_settings()
    if not settings.ecx.enabled or not settings.ecx.enrichment_enabled:
        return ECXEnrichmentResult()

    client = _get_client()
    if client is None:
        return ECXEnrichmentResult()

    result = ECXEnrichmentResult()
    start = time.monotonic()

    result.phish_hits = _safe_query(client.search_phish, url, errors=result.errors)
    result.domain_hits = _safe_query(client.search_domain, domain, errors=result.errors)
    if ip:
        result.ip_hits = _safe_query(client.search_ip, ip, errors=result.errors)
    result.report_phishing_hits = _safe_query(client.search_report_phishing, url, errors=result.errors)

    result.query_count = 3 + (1 if ip else 0)
    result.total_hits = (
        len(result.phish_hits) + len(result.domain_hits) + len(result.ip_hits) + len(result.report_phishing_hits)
    )
    result.query_duration_ms = (time.monotonic() - start) * 1000

    if result.total_hits:
        logger.info(
            "eCX enrichment: %d hits across %d modules in %.0fms",
            result.total_hits,
            result.query_count,
            result.query_duration_ms,
        )
    else:
        logger.info("eCX enrichment: no hits (queried %d modules)", result.query_count)

    return result


def enrich_wallets_from_ecx(
    wallets: list[Any],
) -> dict[str, list[ECXCryptoRecord]]:
    """Cross-reference extracted wallets against eCX cryptocurrency-addresses.

    Args:
        wallets: Wallet entries extracted by the browser agent / regex.

    Returns:
        Dict mapping wallet address → list of eCX matches.
    """
    from ssi.settings import get_settings

    settings = get_settings()
    if not settings.ecx.enabled or not settings.ecx.enrichment_enabled:
        return {}

    client = _get_client()
    if client is None:
        return {}

    hits: dict[str, list[ECXCryptoRecord]] = {}
    for wallet in wallets:
        address = wallet.wallet_address if hasattr(wallet, "wallet_address") else str(wallet)
        records = _safe_query(client.search_crypto, address)
        if records:
            hits[address] = records

    if hits:
        logger.info("eCX wallet enrichment: %d/%d addresses had hits", len(hits), len(wallets))

    return hits


def load_currency_map() -> dict[str, str]:
    """Load the SSI token_symbol → eCX currency code mapping.

    Returns:
        Dict mapping uppercase SSI symbol (e.g. ``"BTC"``) to eCX currency code.
    """
    from ssi.settings import get_settings

    settings = get_settings()
    map_path = Path(settings.ecx.currency_map_path)
    if not map_path.is_file():
        logger.warning("eCX currency map not found at %s", map_path)
        return {}

    with open(map_path) as f:
        data = json.load(f)
    return data.get("mappings", {})
