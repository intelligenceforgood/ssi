"""Unit tests for the eCrimeX Phase 3 inbound poller service.

Covers:
- ECXPoller.run_poll_cycle: full cycle across modules
- ECXPoller.poll_module: per-module polling with cursor management
- Filtering: confidence threshold, brand, TLD constraints
- Deduplication: skip records already in enrichment cache
- Investigation triggering: auto-trigger for qualifying phish records
- Polling state CRUD: get, upsert, list
- CLI poll command
- get_poller factory
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_ecx_settings(
    polling_enabled: bool = True,
    polling_modules: list[str] | None = None,
    polling_confidence_threshold: int = 50,
    polling_auto_investigate: bool = False,
    polling_brands: list[str] | None = None,
    polling_tlds: list[str] | None = None,
) -> MagicMock:
    """Build a mock settings.ecx object with polling config."""
    ecx = MagicMock()
    ecx.enabled = True
    ecx.api_key = "test-key"
    ecx.polling_enabled = polling_enabled
    ecx.polling_modules = polling_modules or ["phish"]
    ecx.polling_confidence_threshold = polling_confidence_threshold
    ecx.polling_auto_investigate = polling_auto_investigate
    ecx.polling_brands = polling_brands or []
    ecx.polling_tlds = polling_tlds or []
    settings = MagicMock()
    settings.ecx = ecx
    return settings


def _make_phish_records(ids: list[int], confidence: int = 80, brand: str = "ExampleBank") -> list[dict[str, Any]]:
    """Build a list of raw phish records as returned by _fetch_new_records."""
    return [
        {
            "id": record_id,
            "url": f"https://fake-bank-{record_id}.example.com/login",
            "brand": brand,
            "confidence": confidence,
            "status": "active",
            "discovered_at": 1700000000 + record_id,
            "tld": "com",
        }
        for record_id in ids
    ]


# ---------------------------------------------------------------------------
# Polling state store CRUD tests
# ---------------------------------------------------------------------------


class TestPollingStateCRUD:
    """Test ScanStore polling state methods."""

    def _build_store(self) -> Any:
        """Create a ScanStore with an in-memory SQLite database."""
        import sqlalchemy as sa
        from sqlalchemy.orm import sessionmaker

        from ssi.store import sql as sql_schema
        from ssi.store.scan_store import ScanStore

        engine = sa.create_engine("sqlite:///:memory:")
        sql_schema.METADATA.create_all(engine)
        return ScanStore(session_factory=sessionmaker(bind=engine))

    def test_get_polling_state_returns_none_for_unknown_module(self) -> None:
        store = self._build_store()
        assert store.get_polling_state("phish") is None

    def test_upsert_creates_new_state(self) -> None:
        store = self._build_store()
        store.upsert_polling_state("phish", last_polled_id=42, records_found=5)
        state = store.get_polling_state("phish")
        assert state is not None
        assert state["module"] == "phish"
        assert state["last_polled_id"] == 42
        assert state["records_found"] == 5

    def test_upsert_updates_existing_state(self) -> None:
        store = self._build_store()
        store.upsert_polling_state("phish", last_polled_id=42)
        store.upsert_polling_state("phish", last_polled_id=99, records_found=10, errors=1)
        state = store.get_polling_state("phish")
        assert state is not None
        assert state["last_polled_id"] == 99
        assert state["records_found"] == 10
        assert state["errors"] == 1

    def test_list_polling_states(self) -> None:
        store = self._build_store()
        store.upsert_polling_state("phish", last_polled_id=42)
        store.upsert_polling_state("malicious-domain", last_polled_id=10)
        states = store.list_polling_states()
        assert len(states) == 2
        modules = [s["module"] for s in states]
        assert "malicious-domain" in modules
        assert "phish" in modules


# ---------------------------------------------------------------------------
# ECXPoller core logic tests
# ---------------------------------------------------------------------------


class TestECXPoller:
    """Test the ECXPoller core logic with mocked eCX responses."""

    def _build_poller(self, store: Any = None) -> Any:
        """Create a poller with mocked client and optional real store."""
        import sqlalchemy as sa

        from ssi.ecx.poller import ECXPoller
        from ssi.store import sql as sql_schema
        from ssi.store.scan_store import ScanStore

        client = MagicMock()
        if store is None:
            from sqlalchemy.orm import sessionmaker

            engine = sa.create_engine("sqlite:///:memory:")
            sql_schema.METADATA.create_all(engine)
            store = ScanStore(session_factory=sessionmaker(bind=engine))
        return ECXPoller(client=client, store=store), client, store

    @patch("ssi.ecx.poller.ECXPoller._fetch_new_records")
    @patch("ssi.settings.get_settings")
    def test_poll_module_no_new_records(self, mock_settings: MagicMock, mock_fetch: MagicMock) -> None:
        """No new records → cursor unchanged, counts are zero."""
        mock_settings.return_value = _make_ecx_settings()
        mock_fetch.return_value = []

        poller, _, store = self._build_poller()
        result = poller.poll_module("phish")

        assert result["new"] == 0
        assert result["triggered"] == 0

    @patch("ssi.ecx.poller.ECXPoller._fetch_new_records")
    @patch("ssi.settings.get_settings")
    def test_poll_module_with_new_records(self, mock_settings: MagicMock, mock_fetch: MagicMock) -> None:
        """New records → cursor advances, counts are correct."""
        mock_settings.return_value = _make_ecx_settings()
        records = _make_phish_records([100, 101, 102])
        mock_fetch.return_value = records

        poller, _, store = self._build_poller()
        result = poller.poll_module("phish")

        assert result["new"] == 3
        assert result["last_id"] == 102

        # Verify cursor was updated
        state = store.get_polling_state("phish")
        assert state is not None
        assert state["last_polled_id"] == 102

    @patch("ssi.ecx.poller.ECXPoller._fetch_new_records")
    @patch("ssi.settings.get_settings")
    def test_poll_module_confidence_filter(self, mock_settings: MagicMock, mock_fetch: MagicMock) -> None:
        """Records below confidence threshold are filtered out."""
        mock_settings.return_value = _make_ecx_settings(polling_confidence_threshold=70)
        records = [
            {"id": 1, "url": "https://low.example.com", "confidence": 40, "tld": "com", "brand": ""},
            {"id": 2, "url": "https://high.example.com", "confidence": 90, "tld": "com", "brand": ""},
        ]
        mock_fetch.return_value = records

        poller, _, _ = self._build_poller()
        result = poller.poll_module("phish")

        assert result["new"] == 2
        assert result["filtered"] == 1  # The low-confidence one was filtered

    @patch("ssi.ecx.poller.ECXPoller._fetch_new_records")
    @patch("ssi.settings.get_settings")
    def test_poll_module_brand_filter(self, mock_settings: MagicMock, mock_fetch: MagicMock) -> None:
        """Only records matching configured brands pass through."""
        mock_settings.return_value = _make_ecx_settings(polling_brands=["ExampleBank"])
        records = [
            {"id": 1, "url": "https://a.com", "confidence": 80, "brand": "ExampleBank", "tld": "com"},
            {"id": 2, "url": "https://b.com", "confidence": 80, "brand": "OtherBank", "tld": "com"},
        ]
        mock_fetch.return_value = records

        poller, _, _ = self._build_poller()
        result = poller.poll_module("phish")

        assert result["filtered"] == 1  # OtherBank filtered

    @patch("ssi.ecx.poller.ECXPoller._fetch_new_records")
    @patch("ssi.settings.get_settings")
    def test_poll_module_tld_filter(self, mock_settings: MagicMock, mock_fetch: MagicMock) -> None:
        """Only records matching configured TLDs pass through."""
        mock_settings.return_value = _make_ecx_settings(polling_tlds=["com"])
        records = [
            {"id": 1, "url": "https://a.example.com", "confidence": 80, "brand": "", "tld": "com"},
            {"id": 2, "url": "https://b.example.org", "confidence": 80, "brand": "", "tld": "org"},
        ]
        mock_fetch.return_value = records

        poller, _, _ = self._build_poller()
        result = poller.poll_module("phish")

        assert result["filtered"] == 1  # .org filtered

    @patch("ssi.ecx.poller.ECXPoller._fetch_new_records")
    @patch("ssi.settings.get_settings")
    def test_poll_module_deduplication(self, mock_settings: MagicMock, mock_fetch: MagicMock) -> None:
        """Records already in the enrichment cache are skipped."""
        mock_settings.return_value = _make_ecx_settings()
        records = _make_phish_records([100])
        mock_fetch.return_value = records

        poller, _, store = self._build_poller()

        # Pre-populate enrichment cache for this URL

        from ssi.models.ecx import ECXEnrichmentResult, ECXPhishRecord

        enrichment = ECXEnrichmentResult(
            phish_hits=[ECXPhishRecord(id=100, url=records[0]["url"])],
            query_count=1,
            total_hits=1,
        )
        store.cache_ecx_enrichments("some-scan-id", enrichment)

        result = poller.poll_module("phish")
        # Record was deduped → no investigation triggered
        assert result["triggered"] == 0

    @patch("ssi.ecx.poller.ECXPoller._fetch_new_records")
    @patch("ssi.ecx.poller.ECXPoller._start_investigation")
    @patch("ssi.settings.get_settings")
    def test_poll_module_auto_investigate(
        self, mock_settings: MagicMock, mock_start: MagicMock, mock_fetch: MagicMock
    ) -> None:
        """When auto_investigate is on, qualifying phish records trigger investigations."""
        mock_settings.return_value = _make_ecx_settings(polling_auto_investigate=True)
        records = _make_phish_records([200, 201])
        mock_fetch.return_value = records

        poller, _, _ = self._build_poller()
        result = poller.poll_module("phish")

        assert result["triggered"] == 2
        assert mock_start.call_count == 2

    @patch("ssi.ecx.poller.ECXPoller._fetch_new_records")
    @patch("ssi.settings.get_settings")
    def test_poll_module_no_auto_investigate_by_default(self, mock_settings: MagicMock, mock_fetch: MagicMock) -> None:
        """Auto-investigate is off by default — no investigations triggered."""
        mock_settings.return_value = _make_ecx_settings(polling_auto_investigate=False)
        records = _make_phish_records([300])
        mock_fetch.return_value = records

        poller, _, _ = self._build_poller()
        result = poller.poll_module("phish")

        assert result["triggered"] == 0

    def test_poll_module_invalid_module(self) -> None:
        """Unsupported module raises ValueError."""
        poller, _, _ = self._build_poller()
        with pytest.raises(ValueError, match="Unsupported"):
            poller.poll_module("not-a-module")

    @patch("ssi.ecx.poller.ECXPoller.poll_module")
    @patch("ssi.settings.get_settings")
    def test_run_poll_cycle_multiple_modules(self, mock_settings: MagicMock, mock_poll: MagicMock) -> None:
        """Full cycle iterates all configured modules."""
        mock_settings.return_value = _make_ecx_settings(polling_modules=["phish", "malicious-domain"])
        mock_poll.side_effect = [
            {"new": 3, "filtered": 1, "triggered": 2, "last_id": 100},
            {"new": 1, "filtered": 0, "triggered": 0, "last_id": 50},
        ]

        poller, _, _ = self._build_poller()
        summary = poller.run_poll_cycle()

        assert summary["total_new"] == 4
        assert summary["total_triggered"] == 2
        assert len(summary["modules"]) == 2
        assert mock_poll.call_count == 2

    @patch("ssi.ecx.poller.ECXPoller.poll_module")
    @patch("ssi.settings.get_settings")
    def test_run_poll_cycle_handles_module_error(self, mock_settings: MagicMock, mock_poll: MagicMock) -> None:
        """Error in one module doesn't block others."""
        mock_settings.return_value = _make_ecx_settings(polling_modules=["phish", "malicious-domain"])
        mock_poll.side_effect = [
            RuntimeError("API down"),
            {"new": 1, "filtered": 0, "triggered": 0, "last_id": 50},
        ]

        poller, _, _ = self._build_poller()
        summary = poller.run_poll_cycle()

        assert len(summary["errors"]) == 1
        assert summary["total_new"] == 1  # Only the successful module counted
        assert "phish" in summary["modules"]
        assert "malicious-domain" in summary["modules"]


# ---------------------------------------------------------------------------
# ECXPoller._fetch_new_records tests
# ---------------------------------------------------------------------------


class TestFetchNewRecords:
    """Test the _fetch_new_records method."""

    def test_fetch_new_records_builds_correct_request(self) -> None:
        """Verify the idGt filter and field selection."""
        from ssi.ecx.poller import ECXPoller

        client = MagicMock()
        mock_response = MagicMock()
        mock_response.json.return_value = {"data": [{"id": 42, "url": "https://test.com", "confidence": 80}]}
        client._request.return_value = mock_response

        store = MagicMock()
        poller = ECXPoller(client=client, store=store)

        records = poller._fetch_new_records("phish", since_id=10)

        # Verify the request was made correctly
        client._request.assert_called_once()
        call_args = client._request.call_args
        assert call_args[0] == ("POST", "/phish/search")
        body = call_args[1]["json"]
        assert body["filters"]["idGt"] == 10
        assert body["limit"] == 100
        assert len(records) == 1


# ---------------------------------------------------------------------------
# ECXPoller filter logic tests
# ---------------------------------------------------------------------------


class TestApplyFilters:
    """Test the _apply_filters method."""

    def test_empty_filter_config_passes_all(self) -> None:
        """When no brands/TLDs configured, all records pass."""
        from ssi.ecx.poller import ECXPoller

        poller = ECXPoller(client=MagicMock(), store=MagicMock())
        settings = _make_ecx_settings(polling_confidence_threshold=0).ecx
        records = _make_phish_records([1, 2, 3], confidence=10)

        result = poller._apply_filters(records, settings)
        assert len(result) == 3

    def test_tld_filter_with_url_fallback(self) -> None:
        """TLD filter derives TLD from URL when record has no tld field."""
        from ssi.ecx.poller import ECXPoller

        poller = ECXPoller(client=MagicMock(), store=MagicMock())
        settings = _make_ecx_settings(polling_tlds=["io"]).ecx

        records = [
            {"id": 1, "url": "https://scam.example.io/login", "confidence": 80, "brand": ""},
            {"id": 2, "url": "https://scam.example.com/login", "confidence": 80, "brand": ""},
        ]
        result = poller._apply_filters(records, settings)
        assert len(result) == 1
        assert result[0]["id"] == 1


# ---------------------------------------------------------------------------
# get_poller factory tests
# ---------------------------------------------------------------------------


class TestGetPollerFactory:
    """Test the get_poller factory function."""

    @patch("ssi.osint.ecrimex.get_client")
    @patch("ssi.settings.get_settings")
    def test_returns_none_when_polling_disabled(self, mock_settings: MagicMock, mock_client: MagicMock) -> None:
        mock_settings.return_value = _make_ecx_settings(polling_enabled=False)
        from ssi.ecx.poller import get_poller

        assert get_poller() is None

    @patch("ssi.osint.ecrimex.get_client")
    @patch("ssi.settings.get_settings")
    def test_returns_none_when_client_unavailable(self, mock_settings: MagicMock, mock_client: MagicMock) -> None:
        mock_settings.return_value = _make_ecx_settings(polling_enabled=True)
        mock_client.return_value = None
        from ssi.ecx.poller import get_poller

        assert get_poller() is None

    @patch("ssi.store.build_scan_store")
    @patch("ssi.osint.ecrimex.get_client")
    @patch("ssi.settings.get_settings")
    def test_returns_poller_when_configured(
        self, mock_settings: MagicMock, mock_client: MagicMock, mock_store: MagicMock
    ) -> None:
        mock_settings.return_value = _make_ecx_settings(polling_enabled=True)
        mock_client.return_value = MagicMock()
        mock_store.return_value = MagicMock()
        from ssi.ecx.poller import ECXPoller, get_poller

        result = get_poller()
        assert isinstance(result, ECXPoller)


# ---------------------------------------------------------------------------
# CLI poll command tests
# ---------------------------------------------------------------------------


class TestPollCLI:
    """Test the CLI poll command."""

    @patch("ssi.ecx.poller.get_poller")
    def test_poll_exits_when_not_configured(self, mock_get_poller: MagicMock) -> None:
        """ssi ecx poll exits with code 1 when poller is not configured."""
        from typer.testing import CliRunner

        from ssi.cli.ecx_cmd import ecx_app

        mock_get_poller.return_value = None
        runner = CliRunner()
        result = runner.invoke(ecx_app, ["poll"])
        assert result.exit_code == 1
        assert "not configured" in result.output

    @patch("ssi.ecx.poller.get_poller")
    def test_poll_runs_full_cycle(self, mock_get_poller: MagicMock) -> None:
        """ssi ecx poll runs a full cycle and displays results."""
        from typer.testing import CliRunner

        from ssi.cli.ecx_cmd import ecx_app

        mock_poller = MagicMock()
        mock_poller.run_poll_cycle.return_value = {
            "modules": {"phish": {"new": 3, "filtered": 1, "triggered": 2, "last_id": 100}},
            "total_new": 3,
            "total_triggered": 2,
            "errors": [],
        }
        mock_get_poller.return_value = mock_poller

        runner = CliRunner()
        result = runner.invoke(ecx_app, ["poll"])
        assert result.exit_code == 0
        assert "3 new records" in result.output

    @patch("ssi.ecx.poller.get_poller")
    def test_poll_single_module(self, mock_get_poller: MagicMock) -> None:
        """ssi ecx poll --module phish polls only the specified module."""
        from typer.testing import CliRunner

        from ssi.cli.ecx_cmd import ecx_app

        mock_poller = MagicMock()
        mock_poller.poll_module.return_value = {"new": 1, "filtered": 0, "triggered": 0, "last_id": 50}
        mock_get_poller.return_value = mock_poller

        runner = CliRunner()
        result = runner.invoke(ecx_app, ["poll", "--module", "phish"])
        assert result.exit_code == 0
        mock_poller.poll_module.assert_called_once_with("phish")

    @patch("ssi.ecx.poller.get_poller")
    def test_poll_json_output(self, mock_get_poller: MagicMock) -> None:
        """ssi ecx poll --json emits JSON output."""
        from typer.testing import CliRunner

        from ssi.cli.ecx_cmd import ecx_app

        mock_poller = MagicMock()
        mock_poller.run_poll_cycle.return_value = {
            "modules": {},
            "total_new": 0,
            "total_triggered": 0,
            "errors": [],
        }
        mock_get_poller.return_value = mock_poller

        runner = CliRunner()
        result = runner.invoke(ecx_app, ["poll", "--json"])
        assert result.exit_code == 0
        assert "total_new" in result.output


# ---------------------------------------------------------------------------
# Extract query value tests
# ---------------------------------------------------------------------------


class TestExtractQueryValue:
    """Test _extract_query_value static method."""

    def test_phish(self) -> None:
        from ssi.ecx.poller import ECXPoller

        assert ECXPoller._extract_query_value({"url": "https://x.com"}, "phish") == "https://x.com"

    def test_domain(self) -> None:
        from ssi.ecx.poller import ECXPoller

        assert ECXPoller._extract_query_value({"domain": "x.com"}, "malicious-domain") == "x.com"

    def test_ip(self) -> None:
        from ssi.ecx.poller import ECXPoller

        assert ECXPoller._extract_query_value({"ip": "1.2.3.4"}, "malicious-ip") == "1.2.3.4"

    def test_crypto(self) -> None:
        from ssi.ecx.poller import ECXPoller

        assert ECXPoller._extract_query_value({"address": "0xabc"}, "cryptocurrency-addresses") == "0xabc"

    def test_unknown_module(self) -> None:
        from ssi.ecx.poller import ECXPoller

        assert ECXPoller._extract_query_value({}, "unknown") == ""
