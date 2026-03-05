"""eCrimeX sandbox integration tests.

These tests hit the live eCX sandbox API and require a valid API key.
Run with::

    SSI_ECX__API_KEY="your-key" pytest tests/integration/test_ecx_sandbox.py -v

All tests are marked with ``@pytest.mark.ecx_sandbox`` so they can be
selected or excluded with ``-m ecx_sandbox`` / ``-m "not ecx_sandbox"``.

Note: The eCX API may return 403 or 405 for modules your key does not
have access to. Tests that call individual search methods treat HTTP errors
as "module not accessible" and skip with a warning rather than failing.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx
import pytest

from ssi.models.ecx import ECXCryptoRecord, ECXEnrichmentResult, ECXMalDomainRecord, ECXMalIPRecord, ECXPhishRecord
from ssi.osint.ecrimex import ECXClient, enrich_from_ecx

logger = logging.getLogger(__name__)

# Skip the entire module if no API key is set
_API_KEY = os.environ.get("SSI_ECX__API_KEY", "")
pytestmark = [
    pytest.mark.ecx_sandbox,
    pytest.mark.skipif(not _API_KEY, reason="SSI_ECX__API_KEY not set — skipping eCX sandbox tests"),
]

# Well-known test values likely to return results in the sandbox.
_TEST_PHISH_URL = "paypal.com"
_TEST_DOMAIN = "paypal.com"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def ecx_client() -> ECXClient:
    """Build an ECXClient from environment variables."""
    return ECXClient(
        api_key=_API_KEY,
        base_url=os.environ.get("SSI_ECX__BASE_URL", "https://api.ecrimex.net"),
        attribution=os.environ.get("SSI_ECX__ATTRIBUTION", "i4g-ssi-test"),
        timeout=float(os.environ.get("SSI_ECX__TIMEOUT", "15")),
    )


# ---------------------------------------------------------------------------
# Helper: call a search method, tolerate module-access HTTP errors
# ---------------------------------------------------------------------------


def _try_search(callable_fn: Any, *args: Any) -> list[Any] | None:
    """Attempt a search; return results or None if the module is inaccessible."""
    try:
        return callable_fn(*args)
    except httpx.HTTPStatusError as exc:
        logger.warning("Module not accessible (%s) — %s", exc.response.status_code, exc.request.url)
        return None


# ---------------------------------------------------------------------------
# Client search methods — smoke tests against live API
# ---------------------------------------------------------------------------


class TestECXClientSandbox:
    """Smoke tests that verify the client can talk to the sandbox API.

    If a module returns an HTTP error (e.g. 403/405 for modules your
    key lacks access to), the test skips — it only fails on unexpected
    Python errors or malformed response parsing.
    """

    def test_search_phish(self, ecx_client: ECXClient) -> None:
        """search_phish should return a list of ECXPhishRecord (or module not accessible)."""
        results = _try_search(ecx_client.search_phish, _TEST_PHISH_URL, 3)
        if results is None:
            pytest.skip("phish module not accessible with this API key")
        assert isinstance(results, list)
        if results:
            assert isinstance(results[0], ECXPhishRecord)
            assert results[0].id is not None

    def test_search_domain(self, ecx_client: ECXClient) -> None:
        """search_domain should return a list of ECXMalDomainRecord."""
        results = _try_search(ecx_client.search_domain, _TEST_DOMAIN, 3)
        if results is None:
            pytest.skip("malicious-domain module not accessible with this API key")
        assert isinstance(results, list)
        if results:
            assert isinstance(results[0], ECXMalDomainRecord)

    def test_search_ip(self, ecx_client: ECXClient) -> None:
        """search_ip should return a list (possibly empty)."""
        results = _try_search(ecx_client.search_ip, "1.2.3.4", 3)
        if results is None:
            pytest.skip("malicious-ip module not accessible with this API key")
        assert isinstance(results, list)
        if results:
            assert isinstance(results[0], ECXMalIPRecord)

    def test_search_crypto(self, ecx_client: ECXClient) -> None:
        """search_crypto should return a list (possibly empty)."""
        results = _try_search(ecx_client.search_crypto, "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", 3)
        if results is None:
            pytest.skip("cryptocurrency-addresses module not accessible with this API key")
        assert isinstance(results, list)
        if results:
            assert isinstance(results[0], ECXCryptoRecord)

    def test_search_report_phishing(self, ecx_client: ECXClient) -> None:
        """search_report_phishing should return a list of dicts."""
        results = _try_search(ecx_client.search_report_phishing, _TEST_PHISH_URL, 3)
        if results is None:
            pytest.skip("report-phishing module not accessible with this API key")
        assert isinstance(results, list)
        if results:
            assert isinstance(results[0], dict)

    def test_search_phish_empty(self, ecx_client: ECXClient) -> None:
        """Searching for a nonsense URL should return an empty list."""
        results = _try_search(ecx_client.search_phish, "xyzzy-no-such-url-99999.invalid", 3)
        if results is None:
            pytest.skip("phish module not accessible with this API key")
        assert isinstance(results, list)
        assert len(results) == 0


# ---------------------------------------------------------------------------
# Enrichment pipeline — end-to-end against live API
# ---------------------------------------------------------------------------


class TestEnrichmentPipelineSandbox:
    """Verify the enrichment pipeline works end-to-end with the sandbox.

    The pipeline uses _safe_query() internally, so individual module
    errors are caught — the enrichment completes even if some modules
    return HTTP errors.
    """

    def test_enrich_from_ecx(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """enrich_from_ecx should aggregate results from available modules."""
        monkeypatch.setenv("SSI_ECX__ENABLED", "true")
        monkeypatch.setenv("SSI_ECX__API_KEY", _API_KEY)

        result = enrich_from_ecx(
            url=f"https://{_TEST_PHISH_URL}/login",
            domain=_TEST_DOMAIN,
            ip=None,
        )
        assert isinstance(result, ECXEnrichmentResult)
        assert result.query_count >= 1
        assert result.query_duration_ms > 0

    def test_enrich_from_ecx_with_ip(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """enrich_from_ecx with IP should query one extra module."""
        monkeypatch.setenv("SSI_ECX__ENABLED", "true")
        monkeypatch.setenv("SSI_ECX__API_KEY", _API_KEY)

        result = enrich_from_ecx(
            url=f"https://{_TEST_PHISH_URL}/login",
            domain=_TEST_DOMAIN,
            ip="1.2.3.4",
        )
        assert isinstance(result, ECXEnrichmentResult)
        # With IP, should query 4 modules (phish + domain + ip + report-phishing)
        assert result.query_count == 4


# ---------------------------------------------------------------------------
# Cache round-trip — persist + retrieve
# ---------------------------------------------------------------------------


class TestCacheRoundTripSandbox:
    """Verify cache persistence works with live enrichment data."""

    def test_cache_round_trip(self, tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        """Cache should persist enrichment results and retrieve them."""
        monkeypatch.setenv("SSI_ECX__ENABLED", "true")
        monkeypatch.setenv("SSI_ECX__API_KEY", _API_KEY)

        from ssi.store.scan_store import ScanStore

        store = ScanStore(db_path=tmp_path / "sandbox_cache.db")
        scan_id = store.create_scan(url=f"https://{_TEST_PHISH_URL}", domain=_TEST_DOMAIN)

        # Get live enrichment data
        result = enrich_from_ecx(
            url=f"https://{_TEST_PHISH_URL}/login",
            domain=_TEST_DOMAIN,
            ip=None,
        )

        if result.has_hits:
            count = store.cache_ecx_enrichments(scan_id, result, cache_ttl_hours=1)
            assert count > 0

            rows = store.get_ecx_enrichments(scan_id)
            assert len(rows) == count
            assert rows[0]["scan_id"] == scan_id
        else:
            # No hits from sandbox — cache should still work with zero rows
            count = store.cache_ecx_enrichments(scan_id, result, cache_ttl_hours=1)
            assert count == 0
