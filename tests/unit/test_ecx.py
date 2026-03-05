"""Unit tests for eCrimeX (eCX) integration.

Covers:
- ECX Pydantic models (validation, defaults, has_hits)
- Key normalisation (camelCase → snake_case)
- ECXClient HTTP methods (mocked httpx responses)
- Singleton client accessor (_get_client)
- Safe query wrapper (_safe_query)
- Enrichment aggregation (enrich_from_ecx, enrich_wallets_from_ecx)
- Currency map loading
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest

from ssi.models.ecx import (
    ECXCryptoRecord,
    ECXEnrichmentResult,
    ECXMalDomainRecord,
    ECXMalIPRecord,
    ECXPhishRecord,
    ECXSubmissionRecord,
)
from ssi.osint.ecrimex import ECXClient, _normalize_keys, _safe_query, load_currency_map

# ---------------------------------------------------------------------------
# Fixtures — sample eCX API response payloads (camelCase, as returned by API)
# ---------------------------------------------------------------------------


@pytest.fixture()
def raw_phish_response() -> dict[str, Any]:
    """Raw eCX /phish/search JSON (camelCase keys)."""
    return {
        "data": [
            {
                "id": 42,
                "url": "https://fake-bank.example.com/login",
                "brand": "ExampleBank",
                "confidence": 90,
                "status": "active",
                "discoveredAt": 1700000000,
                "createdAt": 1700000001,
                "ip": ["1.2.3.4"],
                "asn": [12345],
                "tld": "com",
            },
        ],
    }


@pytest.fixture()
def raw_domain_response() -> dict[str, Any]:
    """Raw eCX /malicious-domain/search JSON."""
    return {
        "data": [
            {
                "id": 101,
                "domain": "fake-bank.example.com",
                "classification": "phishing",
                "confidence": 85,
                "status": "active",
                "discoveredAt": 1700000000,
            },
        ],
    }


@pytest.fixture()
def raw_ip_response() -> dict[str, Any]:
    """Raw eCX /malicious-ip/search JSON."""
    return {
        "data": [
            {
                "id": 201,
                "ip": "1.2.3.4",
                "brand": "ExampleBank",
                "description": "Phish hosting server",
                "confidence": 80,
                "status": "active",
                "asn": [12345],
                "port": 443,
                "discoveredAt": 1700000000,
            },
        ],
    }


@pytest.fixture()
def raw_crypto_response() -> dict[str, Any]:
    """Raw eCX /cryptocurrency-addresses/search JSON."""
    return {
        "data": [
            {
                "id": 301,
                "currency": "bitcoin",
                "address": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
                "crimeCategory": "fraud",
                "siteLink": "https://scam.example.com",
                "price": 0,
                "source": "community",
                "procedure": "manual",
                "actorCategory": "pig-butchering",
                "confidence": 95,
                "status": "active",
                "discoveredAt": 1700000000,
            },
        ],
    }


# ---------------------------------------------------------------------------
# Model Tests
# ---------------------------------------------------------------------------


class TestECXModels:
    """Pydantic model validation and defaults."""

    def test_phish_record_from_normalized(self) -> None:
        """ECXPhishRecord should accept snake_case fields."""
        rec = ECXPhishRecord(
            id=1,
            url="https://evil.com",
            brand="SomeBank",
            confidence=90,
            status="active",
        )
        assert rec.id == 1
        assert rec.url == "https://evil.com"
        assert rec.ip == []  # default_factory
        assert rec.asn == []

    def test_crypto_record_defaults(self) -> None:
        """ECXCryptoRecord should fill defaults for optional fields."""
        rec = ECXCryptoRecord(id=5)
        assert rec.currency == ""
        assert rec.notes == []
        assert rec.metadata == {}

    def test_enrichment_result_has_hits_false(self) -> None:
        """Empty enrichment result should report no hits."""
        result = ECXEnrichmentResult()
        assert result.has_hits is False
        assert result.total_hits == 0

    def test_enrichment_result_has_hits_true(self) -> None:
        """Non-empty enrichment result should report hits."""
        result = ECXEnrichmentResult(
            phish_hits=[ECXPhishRecord(id=1)],
            total_hits=1,
        )
        assert result.has_hits is True

    def test_submission_record_defaults(self) -> None:
        """ECXSubmissionRecord should have sensible defaults."""
        rec = ECXSubmissionRecord()
        assert rec.status == "pending"
        assert rec.ecx_record_id is None

    def test_enrichment_result_serialization(self) -> None:
        """Enrichment results should round-trip to JSON."""
        result = ECXEnrichmentResult(
            phish_hits=[ECXPhishRecord(id=1, url="https://x.com", confidence=90)],
            query_count=1,
            total_hits=1,
        )
        data = result.model_dump(mode="json")
        recovered = ECXEnrichmentResult(**data)
        assert recovered.total_hits == 1
        assert len(recovered.phish_hits) == 1


# ---------------------------------------------------------------------------
# Key Normalisation Tests
# ---------------------------------------------------------------------------


class TestKeyNormalization:
    """camelCase → snake_case conversion."""

    def test_known_field_mapping(self) -> None:
        """discoveredAt should map to discovered_at."""
        result = _normalize_keys({"discoveredAt": 123, "crimeCategory": "fraud"})
        assert result == {"discovered_at": 123, "crime_category": "fraud"}

    def test_fallback_generic_camel(self) -> None:
        """Unknown camelCase keys should be converted via regex."""
        result = _normalize_keys({"someNewField": "val"})
        assert "some_new_field" in result

    def test_snake_case_passthrough(self) -> None:
        """Already-snake_case keys should be preserved."""
        result = _normalize_keys({"id": 1, "url": "https://x.com"})
        assert result == {"id": 1, "url": "https://x.com"}

    def test_empty_dict(self) -> None:
        """Empty dict should return empty dict."""
        assert _normalize_keys({}) == {}


# ---------------------------------------------------------------------------
# ECXClient Tests (mocked HTTP)
# ---------------------------------------------------------------------------


def _mock_response(data: dict[str, Any], status_code: int = 200) -> httpx.Response:
    """Build a mock httpx.Response."""
    return httpx.Response(
        status_code=status_code,
        json=data,
        request=httpx.Request("POST", "https://test.ecx/api/v1/phish/search"),
    )


class TestECXClient:
    """ECXClient search methods with mocked HTTP transport."""

    def _make_client(self) -> ECXClient:
        """Create a client for testing."""
        return ECXClient(
            base_url="https://test.ecx/api/v1",
            api_key="test-key-123",
        )

    def test_search_phish(self, raw_phish_response: dict[str, Any]) -> None:
        """search_phish should parse camelCase response into ECXPhishRecord."""
        client = self._make_client()
        with patch.object(client, "_request", return_value=_mock_response(raw_phish_response)):
            results = client.search_phish("https://fake-bank.example.com")
        assert len(results) == 1
        assert isinstance(results[0], ECXPhishRecord)
        assert results[0].id == 42
        assert results[0].discovered_at == 1700000000

    def test_search_domain(self, raw_domain_response: dict[str, Any]) -> None:
        """search_domain should return ECXMalDomainRecord list."""
        client = self._make_client()
        with patch.object(client, "_request", return_value=_mock_response(raw_domain_response)):
            results = client.search_domain("fake-bank.example.com")
        assert len(results) == 1
        assert isinstance(results[0], ECXMalDomainRecord)
        assert results[0].classification == "phishing"

    def test_search_ip(self, raw_ip_response: dict[str, Any]) -> None:
        """search_ip should return ECXMalIPRecord list."""
        client = self._make_client()
        with patch.object(client, "_request", return_value=_mock_response(raw_ip_response)):
            results = client.search_ip("1.2.3.4")
        assert len(results) == 1
        assert isinstance(results[0], ECXMalIPRecord)
        assert results[0].port == 443

    def test_search_crypto(self, raw_crypto_response: dict[str, Any]) -> None:
        """search_crypto should normalise camelCase crypto fields."""
        client = self._make_client()
        with patch.object(client, "_request", return_value=_mock_response(raw_crypto_response)):
            results = client.search_crypto("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh")
        assert len(results) == 1
        assert results[0].crime_category == "fraud"
        assert results[0].actor_category == "pig-butchering"

    def test_search_empty_data(self) -> None:
        """Empty data array should return empty list, not error."""
        client = self._make_client()
        with patch.object(client, "_request", return_value=_mock_response({"data": []})):
            results = client.search_phish("https://nothing.example.com")
        assert results == []

    def test_search_report_phishing(self) -> None:
        """search_report_phishing should return normalised dicts."""
        client = self._make_client()
        resp_data = {"data": [{"id": 501, "emailSubject": "Test", "createdAt": 123}]}
        with patch.object(client, "_request", return_value=_mock_response(resp_data)):
            results = client.search_report_phishing("https://test.com")
        assert len(results) == 1
        assert "email_subject" in results[0]
        assert "created_at" in results[0]

    def test_headers_include_bearer(self) -> None:
        """Client headers should contain the Bearer token."""
        client = self._make_client()
        headers = client._headers()
        assert headers["Authorization"] == "Bearer test-key-123"


# ---------------------------------------------------------------------------
# Singleton / _get_client Tests
# ---------------------------------------------------------------------------


class TestGetClient:
    """_get_client singleton factory."""

    def setup_method(self) -> None:
        """Reset the module-level singleton before each test."""
        import ssi.osint.ecrimex as mod

        mod._client_instance = None

    def test_returns_none_when_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Should return None when ecx.enabled is False."""
        monkeypatch.setenv("SSI_ECX__ENABLED", "false")
        from ssi.osint.ecrimex import _get_client

        assert _get_client() is None

    def test_returns_none_when_no_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Should return None when API key is empty."""
        monkeypatch.setenv("SSI_ECX__ENABLED", "true")
        monkeypatch.setenv("SSI_ECX__API_KEY", "")
        from ssi.osint.ecrimex import _get_client

        assert _get_client() is None

    def test_returns_client_when_configured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Should return an ECXClient when enabled with a key."""
        monkeypatch.setenv("SSI_ECX__ENABLED", "true")
        monkeypatch.setenv("SSI_ECX__API_KEY", "test-key")
        from ssi.osint.ecrimex import _get_client

        client = _get_client()
        assert isinstance(client, ECXClient)


# ---------------------------------------------------------------------------
# _safe_query Tests
# ---------------------------------------------------------------------------


class TestSafeQuery:
    """Fault-tolerant query wrapper."""

    def test_success_passthrough(self) -> None:
        """Successful call should return results."""
        fn = MagicMock(return_value=["result"])
        result = _safe_query(fn, "arg1")
        assert result == ["result"]

    def test_http_error_returns_empty(self) -> None:
        """HTTP errors should be caught and return []."""
        fn = MagicMock(
            __name__="mock_fn",
            side_effect=httpx.HTTPStatusError(
                "Not Found",
                request=httpx.Request("POST", "https://test.com"),
                response=httpx.Response(404),
            ),
        )
        errors: list[str] = []
        result = _safe_query(fn, "arg1", errors=errors)
        assert result == []
        assert len(errors) == 1
        assert "404" in errors[0]

    def test_generic_exception_returns_empty(self) -> None:
        """Unexpected exceptions should be caught and return []."""
        fn = MagicMock(__name__="mock_fn", side_effect=ValueError("boom"))
        errors: list[str] = []
        result = _safe_query(fn, "arg1", errors=errors)
        assert result == []
        assert "ValueError" in errors[0]

    def test_no_errors_list(self) -> None:
        """Should still return [] on error even without errors list."""
        fn = MagicMock(__name__="mock_fn", side_effect=RuntimeError("oops"))
        result = _safe_query(fn)
        assert result == []


# ---------------------------------------------------------------------------
# Enrichment Pipeline Tests
# ---------------------------------------------------------------------------


class TestEnrichFromECX:
    """enrich_from_ecx aggregation tests."""

    def setup_method(self) -> None:
        """Reset singleton."""
        import ssi.osint.ecrimex as mod

        mod._client_instance = None

    def test_returns_empty_when_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Should return empty result when eCX is disabled."""
        monkeypatch.setenv("SSI_ECX__ENABLED", "false")
        from ssi.osint.ecrimex import enrich_from_ecx

        result = enrich_from_ecx("https://x.com", "x.com")
        assert not result.has_hits
        assert result.query_count == 0

    def test_aggregates_hits(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Should aggregate hits from mocked client across modules."""
        monkeypatch.setenv("SSI_ECX__ENABLED", "true")
        monkeypatch.setenv("SSI_ECX__API_KEY", "test-key")
        monkeypatch.setenv("SSI_ECX__ENRICHMENT_ENABLED", "true")

        mock_client = MagicMock(spec=ECXClient)
        mock_client.search_phish.return_value = [ECXPhishRecord(id=1, confidence=90)]
        mock_client.search_domain.return_value = [ECXMalDomainRecord(id=2)]
        mock_client.search_ip.return_value = []
        mock_client.search_report_phishing.return_value = []

        with patch("ssi.osint.ecrimex._get_client", return_value=mock_client):
            from ssi.osint.ecrimex import enrich_from_ecx

            result = enrich_from_ecx("https://evil.com", "evil.com", ip="1.2.3.4")

        assert result.total_hits == 2
        assert len(result.phish_hits) == 1
        assert len(result.domain_hits) == 1
        assert result.query_count == 4  # phish + domain + ip + report-phishing

    def test_counts_without_ip(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """query_count should be 3 when no IP is provided."""
        monkeypatch.setenv("SSI_ECX__ENABLED", "true")
        monkeypatch.setenv("SSI_ECX__API_KEY", "test-key")
        monkeypatch.setenv("SSI_ECX__ENRICHMENT_ENABLED", "true")

        mock_client = MagicMock(spec=ECXClient)
        mock_client.search_phish.return_value = []
        mock_client.search_domain.return_value = []
        mock_client.search_report_phishing.return_value = []

        with patch("ssi.osint.ecrimex._get_client", return_value=mock_client):
            from ssi.osint.ecrimex import enrich_from_ecx

            result = enrich_from_ecx("https://x.com", "x.com")

        assert result.query_count == 3
        mock_client.search_ip.assert_not_called()


class TestEnrichWallets:
    """enrich_wallets_from_ecx tests."""

    def setup_method(self) -> None:
        """Reset singleton."""
        import ssi.osint.ecrimex as mod

        mod._client_instance = None

    def test_returns_empty_when_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Should return empty dict when eCX is disabled."""
        monkeypatch.setenv("SSI_ECX__ENABLED", "false")
        from ssi.osint.ecrimex import enrich_wallets_from_ecx

        result = enrich_wallets_from_ecx(["bc1qfake123"])
        assert result == {}

    def test_matches_wallet_addresses(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Should return hits keyed by address."""
        monkeypatch.setenv("SSI_ECX__ENABLED", "true")
        monkeypatch.setenv("SSI_ECX__API_KEY", "test-key")
        monkeypatch.setenv("SSI_ECX__ENRICHMENT_ENABLED", "true")

        mock_client = MagicMock(spec=ECXClient)
        mock_client.search_crypto.return_value = [
            ECXCryptoRecord(id=1, address="bc1qfake123", currency="bitcoin"),
        ]

        with patch("ssi.osint.ecrimex._get_client", return_value=mock_client):
            from ssi.osint.ecrimex import enrich_wallets_from_ecx

            result = enrich_wallets_from_ecx(["bc1qfake123"])

        assert "bc1qfake123" in result
        assert len(result["bc1qfake123"]) == 1


# ---------------------------------------------------------------------------
# Currency Map Tests
# ---------------------------------------------------------------------------


class TestCurrencyMap:
    """load_currency_map tests."""

    def test_loads_from_config(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Should load mapping from the default config path."""
        # Point to actual config file in repo
        config_path = Path(__file__).resolve().parents[2] / "config" / "ecx_currency_map.json"
        monkeypatch.setenv("SSI_ECX__CURRENCY_MAP_PATH", str(config_path))

        result = load_currency_map()
        assert isinstance(result, dict)
        assert result.get("BTC") == "bitcoin"
        assert result.get("ETH") == "ethereum"

    def test_returns_empty_for_missing_file(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Should return empty dict when file doesn't exist."""
        monkeypatch.setenv("SSI_ECX__CURRENCY_MAP_PATH", str(tmp_path / "nonexistent.json"))
        result = load_currency_map()
        assert result == {}


# ---------------------------------------------------------------------------
# ECXSettings Tests
# ---------------------------------------------------------------------------


class TestECXSettings:
    """ECX settings env-var overrides."""

    def test_default_disabled(self) -> None:
        """ECX should be disabled by default."""
        from ssi.settings.config import Settings

        s = Settings()
        assert s.ecx.enabled is False

    def test_env_override_enabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SSI_ECX__ENABLED should override to True."""
        monkeypatch.setenv("SSI_ECX__ENABLED", "true")
        from ssi.settings.config import Settings

        s = Settings()
        assert s.ecx.enabled is True

    def test_env_override_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SSI_ECX__API_KEY should be picked up."""
        monkeypatch.setenv("SSI_ECX__API_KEY", "my-secret-key")
        from ssi.settings.config import Settings

        s = Settings()
        assert s.ecx.api_key == "my-secret-key"

    def test_env_override_base_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SSI_ECX__BASE_URL should override the sandbox default."""
        monkeypatch.setenv("SSI_ECX__BASE_URL", "https://prod.ecx.example.com/api/v1")
        from ssi.settings.config import Settings

        s = Settings()
        assert s.ecx.base_url == "https://prod.ecx.example.com/api/v1"

    def test_cache_ttl_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SSI_ECX__CACHE_TTL_HOURS should override number field."""
        monkeypatch.setenv("SSI_ECX__CACHE_TTL_HOURS", "48")
        from ssi.settings.config import Settings

        s = Settings()
        assert s.ecx.cache_ttl_hours == 48


# ---------------------------------------------------------------------------
# Cache Layer Tests (1D)
# ---------------------------------------------------------------------------


class TestCacheLayer:
    """ecx_enrichments cache read/write/expiry in ScanStore."""

    @pytest.fixture()
    def store(self, tmp_path: Path) -> Any:
        """ScanStore backed by a temp SQLite DB."""
        from ssi.store.scan_store import ScanStore

        return ScanStore(db_path=tmp_path / "test_cache.db")

    def _create_scan(self, store: Any) -> str:
        """Helper to create a scan row for FK-free usage."""
        return store.create_scan(url="https://scam.example.com", domain="scam.example.com")

    def test_cache_ecx_enrichments_inserts(self, store: Any) -> None:
        """Should insert rows for each hit in the enrichment result."""
        scan_id = self._create_scan(store)
        result = ECXEnrichmentResult(
            phish_hits=[ECXPhishRecord(id=1, url="https://scam.example.com", confidence=90)],
            domain_hits=[ECXMalDomainRecord(id=2, domain="scam.example.com", confidence=85)],
            ip_hits=[ECXMalIPRecord(id=3, ip="1.2.3.4", confidence=80)],
            crypto_hits=[ECXCryptoRecord(id=4, address="bc1qfake", confidence=95)],
            query_count=4,
            total_hits=4,
        )
        count = store.cache_ecx_enrichments(scan_id, result, cache_ttl_hours=24)
        assert count == 4

    def test_get_ecx_enrichments(self, store: Any) -> None:
        """Should retrieve all cached rows for a scan."""
        scan_id = self._create_scan(store)
        result = ECXEnrichmentResult(
            phish_hits=[ECXPhishRecord(id=1, url="https://x.com", confidence=90)],
            query_count=1,
            total_hits=1,
        )
        store.cache_ecx_enrichments(scan_id, result)
        rows = store.get_ecx_enrichments(scan_id)
        assert len(rows) == 1
        assert rows[0]["query_module"] == "phish"
        assert rows[0]["ecx_record_id"] == 1

    def test_cache_empty_result_returns_zero(self, store: Any) -> None:
        """Empty enrichment result should insert nothing."""
        scan_id = self._create_scan(store)
        result = ECXEnrichmentResult()
        count = store.cache_ecx_enrichments(scan_id, result)
        assert count == 0

    def test_cache_invalid_type_returns_zero(self, store: Any) -> None:
        """Non-ECXEnrichmentResult should return 0."""
        scan_id = self._create_scan(store)
        count = store.cache_ecx_enrichments(scan_id, {"not": "a model"})
        assert count == 0

    def test_get_cached_ecx_enrichment_hit(self, store: Any) -> None:
        """Should return unexpired cached rows by module + value."""
        scan_id = self._create_scan(store)
        result = ECXEnrichmentResult(
            phish_hits=[ECXPhishRecord(id=10, url="https://phish.example.com", confidence=90)],
            query_count=1,
            total_hits=1,
        )
        store.cache_ecx_enrichments(scan_id, result, cache_ttl_hours=24)
        cached = store.get_cached_ecx_enrichment("phish", "https://phish.example.com")
        assert len(cached) == 1
        assert cached[0]["ecx_record_id"] == 10

    def test_get_cached_ecx_enrichment_miss(self, store: Any) -> None:
        """Should return empty list when no cached data exists."""
        cached = store.get_cached_ecx_enrichment("phish", "https://no-such-url.com")
        assert cached == []

    def test_cache_expiry(self, store: Any) -> None:
        """Expired cache entries should not be returned."""
        scan_id = self._create_scan(store)
        result = ECXEnrichmentResult(
            phish_hits=[ECXPhishRecord(id=99, url="https://expired.example.com", confidence=80)],
            query_count=1,
            total_hits=1,
        )
        # Cache with TTL of 0 hours — expires immediately
        store.cache_ecx_enrichments(scan_id, result, cache_ttl_hours=0)
        # The entry should still be there (cache_expires_at = now + 0 hours)
        # but get_cached_ecx_enrichment filters by cache_expires_at > now
        # With 0 hours TTL, the expires_at is set to now (equal, not greater)
        import time

        time.sleep(0.1)  # Ensure we're past the expiry
        cached = store.get_cached_ecx_enrichment("phish", "https://expired.example.com")
        assert cached == []

    def test_configurable_ttl(self, store: Any) -> None:
        """Cache entries with positive TTL should be retrievable."""
        scan_id = self._create_scan(store)
        result = ECXEnrichmentResult(
            domain_hits=[ECXMalDomainRecord(id=50, domain="test.example.com", confidence=85)],
            query_count=1,
            total_hits=1,
        )
        store.cache_ecx_enrichments(scan_id, result, cache_ttl_hours=48)
        cached = store.get_cached_ecx_enrichment("malicious-domain", "test.example.com")
        assert len(cached) == 1


# ---------------------------------------------------------------------------
# Report Rendering Tests (1E)
# ---------------------------------------------------------------------------


class TestReportECXRendering:
    """Report markdown rendering with eCX data."""

    def test_ecx_section_rendered(self) -> None:
        """Report should include eCX section when hits are present."""
        from ssi.models.investigation import InvestigationResult, InvestigationStatus
        from ssi.reports import render_markdown_report

        result = InvestigationResult(
            url="https://scam.example.com",
            status=InvestigationStatus.COMPLETED,
            success=True,
            duration_seconds=5.0,
            ecx_enrichment=ECXEnrichmentResult(
                phish_hits=[ECXPhishRecord(id=1, url="https://scam.example.com", brand="FakeBank", confidence=90)],
                query_count=3,
                total_hits=1,
                query_duration_ms=150.0,
            ),
        )
        md = render_markdown_report(result)
        assert "Community Intelligence (eCrimeX)" in md
        assert "FakeBank" in md
        assert "90" in md

    def test_ecx_section_absent_when_no_enrichment(self) -> None:
        """Report should omit eCX section when no enrichment data."""
        from ssi.models.investigation import InvestigationResult, InvestigationStatus
        from ssi.reports import render_markdown_report

        result = InvestigationResult(
            url="https://clean.example.com",
            status=InvestigationStatus.COMPLETED,
            success=True,
            duration_seconds=3.0,
        )
        md = render_markdown_report(result)
        assert "Community Intelligence (eCrimeX)" not in md

    def test_ecx_wallet_status_column(self) -> None:
        """Wallet table should show eCX status when crypto hits match."""
        from ssi.models.investigation import InvestigationResult, InvestigationStatus
        from ssi.reports import render_markdown_report
        from ssi.wallet.models import WalletEntry

        result = InvestigationResult(
            url="https://scam.example.com",
            status=InvestigationStatus.COMPLETED,
            success=True,
            duration_seconds=5.0,
            wallets=[
                WalletEntry(
                    token_symbol="BTC",
                    network_short="BTC",
                    wallet_address="bc1qfakeaddress",
                    source="regex_scan",
                    confidence=0.7,
                ),
            ],
            ecx_enrichment=ECXEnrichmentResult(
                crypto_hits=[ECXCryptoRecord(id=10, address="bc1qfakeaddress", currency="bitcoin", confidence=95)],
                query_count=1,
                total_hits=1,
            ),
        )
        md = render_markdown_report(result)
        assert "eCX Status" in md
        assert "Known" in md


# ---------------------------------------------------------------------------
# STIX Bundle eCX References Tests (1E)
# ---------------------------------------------------------------------------


class TestSTIXECXReferences:
    """STIX bundle should include eCX-sourced indicators."""

    def test_ecx_phish_indicators_in_bundle(self) -> None:
        """Bundle should contain eCX phish indicator SDOs."""
        from ssi.evidence.stix import investigation_to_stix_bundle
        from ssi.models.investigation import InvestigationResult, InvestigationStatus

        result = InvestigationResult(
            url="https://scam.example.com",
            status=InvestigationStatus.COMPLETED,
            success=True,
            duration_seconds=5.0,
            ecx_enrichment=ECXEnrichmentResult(
                phish_hits=[ECXPhishRecord(id=42, url="https://scam.example.com", brand="TestBrand", confidence=90)],
                query_count=1,
                total_hits=1,
            ),
        )
        bundle = investigation_to_stix_bundle(result)
        objects = bundle["objects"]

        ecx_indicators = [o for o in objects if o["type"] == "indicator" and "ecrimex" in o.get("labels", [])]
        assert len(ecx_indicators) >= 1
        ecx_ind = ecx_indicators[0]
        assert "eCrimeX" in ecx_ind["external_references"][0]["source_name"]
        assert ecx_ind["external_references"][0]["external_id"] == "42"

    def test_ecx_crypto_indicators_in_bundle(self) -> None:
        """Bundle should contain eCX crypto indicator SDOs."""
        from ssi.evidence.stix import investigation_to_stix_bundle
        from ssi.models.investigation import InvestigationResult, InvestigationStatus

        result = InvestigationResult(
            url="https://scam.example.com",
            status=InvestigationStatus.COMPLETED,
            success=True,
            duration_seconds=5.0,
            ecx_enrichment=ECXEnrichmentResult(
                crypto_hits=[
                    ECXCryptoRecord(
                        id=301,
                        address="bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
                        currency="bitcoin",
                        crime_category="fraud",
                        confidence=95,
                    )
                ],
                query_count=1,
                total_hits=1,
            ),
        )
        bundle = investigation_to_stix_bundle(result)
        objects = bundle["objects"]

        crypto_indicators = [o for o in objects if o["type"] == "indicator" and "cryptocurrency" in o.get("labels", [])]
        assert len(crypto_indicators) >= 1
        assert "cryptocurrency-wallet" in crypto_indicators[0]["pattern"]

    def test_no_ecx_indicators_when_no_enrichment(self) -> None:
        """Bundle should not contain eCX indicators when no enrichment."""
        from ssi.evidence.stix import investigation_to_stix_bundle
        from ssi.models.investigation import InvestigationResult, InvestigationStatus

        result = InvestigationResult(
            url="https://clean.example.com",
            status=InvestigationStatus.COMPLETED,
            success=True,
            duration_seconds=3.0,
        )
        bundle = investigation_to_stix_bundle(result)
        ecx_indicators = [o for o in bundle["objects"] if o["type"] == "indicator" and "ecrimex" in o.get("labels", [])]
        assert len(ecx_indicators) == 0


# ---------------------------------------------------------------------------
# CLI Command Tests (1F)
# ---------------------------------------------------------------------------


class TestCLICommands:
    """CLI command invocations with mocked client."""

    def test_search_phish_cli(self) -> None:
        """ssi ecx search phish should output results."""
        from typer.testing import CliRunner

        from ssi.cli.ecx_cmd import ecx_app

        runner = CliRunner()

        mock_client = MagicMock(spec=ECXClient)
        mock_client.search_phish.return_value = [
            ECXPhishRecord(id=1, url="https://evil.com", brand="TestBank", confidence=90, status="active"),
        ]

        with patch("ssi.cli.ecx_cmd._get_client", return_value=mock_client):
            result = runner.invoke(ecx_app, ["search", "phish", "https://evil.com"])
        assert result.exit_code == 0

    def test_search_domain_cli(self) -> None:
        """ssi ecx search domain should output results."""
        from typer.testing import CliRunner

        from ssi.cli.ecx_cmd import ecx_app

        runner = CliRunner()
        mock_client = MagicMock(spec=ECXClient)
        mock_client.search_domain.return_value = [
            ECXMalDomainRecord(id=1, domain="evil.com", classification="phishing", confidence=85, status="active"),
        ]

        with patch("ssi.cli.ecx_cmd._get_client", return_value=mock_client):
            result = runner.invoke(ecx_app, ["search", "domain", "evil.com"])
        assert result.exit_code == 0

    def test_search_ip_cli(self) -> None:
        """ssi ecx search ip should output results."""
        from typer.testing import CliRunner

        from ssi.cli.ecx_cmd import ecx_app

        runner = CliRunner()
        mock_client = MagicMock(spec=ECXClient)
        mock_client.search_ip.return_value = [
            ECXMalIPRecord(id=1, ip="1.2.3.4", confidence=80, status="active"),
        ]

        with patch("ssi.cli.ecx_cmd._get_client", return_value=mock_client):
            result = runner.invoke(ecx_app, ["search", "ip", "1.2.3.4"])
        assert result.exit_code == 0

    def test_search_crypto_cli(self) -> None:
        """ssi ecx search crypto should output results."""
        from typer.testing import CliRunner

        from ssi.cli.ecx_cmd import ecx_app

        runner = CliRunner()
        mock_client = MagicMock(spec=ECXClient)
        mock_client.search_crypto.return_value = [
            ECXCryptoRecord(id=1, address="bc1qfake", currency="bitcoin", confidence=95, status="active"),
        ]

        with patch("ssi.cli.ecx_cmd._get_client", return_value=mock_client):
            result = runner.invoke(ecx_app, ["search", "crypto", "bc1qfake"])
        assert result.exit_code == 0

    def test_search_json_output(self) -> None:
        """--json flag should output JSON."""
        from typer.testing import CliRunner

        from ssi.cli.ecx_cmd import ecx_app

        runner = CliRunner()
        mock_client = MagicMock(spec=ECXClient)
        mock_client.search_phish.return_value = [
            ECXPhishRecord(id=1, url="https://evil.com", confidence=90),
        ]

        with patch("ssi.cli.ecx_cmd._get_client", return_value=mock_client):
            result = runner.invoke(ecx_app, ["search", "phish", "https://evil.com", "--json"])
        assert result.exit_code == 0

    def test_search_no_client(self) -> None:
        """Should exit with error when eCX is not configured."""
        from typer.testing import CliRunner

        from ssi.cli.ecx_cmd import ecx_app

        runner = CliRunner()
        with patch("ssi.cli.ecx_cmd._get_client", return_value=None):
            result = runner.invoke(ecx_app, ["search", "phish", "https://x.com"])
        assert result.exit_code == 1

    def test_search_no_results(self) -> None:
        """Should handle empty results gracefully."""
        from typer.testing import CliRunner

        from ssi.cli.ecx_cmd import ecx_app

        runner = CliRunner()
        mock_client = MagicMock(spec=ECXClient)
        mock_client.search_phish.return_value = []

        with patch("ssi.cli.ecx_cmd._get_client", return_value=mock_client):
            result = runner.invoke(ecx_app, ["search", "phish", "https://nothing.com"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# API Endpoint Tests (1F)
# ---------------------------------------------------------------------------


class TestAPIEndpoints:
    """ECX API route tests with mocked client."""

    @pytest.fixture()
    def client(self) -> Any:
        """FastAPI test client."""
        from fastapi.testclient import TestClient

        from ssi.api.app import create_app

        app = create_app()
        return TestClient(app)

    def test_search_phish_endpoint(self, client: Any) -> None:
        """POST /ecx/search/phish should return results."""
        mock_ecx = MagicMock(spec=ECXClient)
        mock_ecx.search_phish.return_value = [
            ECXPhishRecord(id=1, url="https://evil.com", confidence=90),
        ]

        with patch("ssi.api.ecx_routes._require_client", return_value=mock_ecx):
            resp = client.post("/ecx/search/phish", json={"query": "https://evil.com"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["module"] == "phish"
        assert data["count"] == 1

    def test_search_domain_endpoint(self, client: Any) -> None:
        """POST /ecx/search/domain should return results."""
        mock_ecx = MagicMock(spec=ECXClient)
        mock_ecx.search_domain.return_value = [
            ECXMalDomainRecord(id=1, domain="evil.com", confidence=85),
        ]

        with patch("ssi.api.ecx_routes._require_client", return_value=mock_ecx):
            resp = client.post("/ecx/search/domain", json={"query": "evil.com"})
        assert resp.status_code == 200
        assert resp.json()["module"] == "malicious-domain"

    def test_search_ip_endpoint(self, client: Any) -> None:
        """POST /ecx/search/ip should return results."""
        mock_ecx = MagicMock(spec=ECXClient)
        mock_ecx.search_ip.return_value = [
            ECXMalIPRecord(id=1, ip="1.2.3.4", confidence=80),
        ]

        with patch("ssi.api.ecx_routes._require_client", return_value=mock_ecx):
            resp = client.post("/ecx/search/ip", json={"query": "1.2.3.4"})
        assert resp.status_code == 200
        assert resp.json()["module"] == "malicious-ip"

    def test_search_crypto_endpoint(self, client: Any) -> None:
        """POST /ecx/search/crypto should return results."""
        mock_ecx = MagicMock(spec=ECXClient)
        mock_ecx.search_crypto.return_value = [
            ECXCryptoRecord(id=1, address="bc1qfake", currency="bitcoin", confidence=95),
        ]

        with patch("ssi.api.ecx_routes._require_client", return_value=mock_ecx):
            resp = client.post("/ecx/search/crypto", json={"query": "bc1qfake"})
        assert resp.status_code == 200
        assert resp.json()["module"] == "cryptocurrency-addresses"

    def test_ecx_not_configured_returns_503(self, client: Any) -> None:
        """Should return 503 when eCX is not configured."""
        with patch("ssi.api.ecx_routes._require_client", side_effect=__import__("fastapi").HTTPException(503)):
            resp = client.post("/ecx/search/phish", json={"query": "test"})
        assert resp.status_code == 503

    def test_get_investigation_ecx(self, client: Any) -> None:
        """GET /ecx/investigate/{scan_id} should return cached enrichments."""
        mock_store = MagicMock()
        mock_store.get_scan.return_value = {"scan_id": "test-id", "url": "https://x.com"}
        mock_store.get_ecx_enrichments.return_value = [
            {"enrichment_id": "e1", "query_module": "phish", "query_value": "https://x.com", "ecx_record_id": 42},
        ]

        with patch("ssi.store.build_scan_store", return_value=mock_store):
            resp = client.get("/ecx/investigate/test-id")
        assert resp.status_code == 200
        data = resp.json()
        assert data["scan_id"] == "test-id"
        assert data["count"] == 1

    def test_get_investigation_ecx_not_found(self, client: Any) -> None:
        """GET /ecx/investigate/{scan_id} should return 404 for unknown scan."""
        mock_store = MagicMock()
        mock_store.get_scan.return_value = None

        with patch("ssi.store.build_scan_store", return_value=mock_store):
            resp = client.get("/ecx/investigate/nonexistent")
        assert resp.status_code == 404
