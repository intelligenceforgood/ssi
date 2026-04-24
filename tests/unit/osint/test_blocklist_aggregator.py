"""Unit tests for ssi.osint.blocklist_aggregator."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import httpx
import pytest

from ssi.osint.blocklist_aggregator import _SOURCES, BlocklistRecord, _ingest_bucket, _record_id, scan

# ── Fixtures ──────────────────────────────────────────────────────────────────


def _make_mock_transport(responses: dict[str, tuple[int, str]]) -> httpx.MockTransport:
    """Build a MockTransport from a URL→(status, body) dict."""

    def handler(request: httpx.Request) -> httpx.Response:
        url_str = str(request.url)
        for key, (status, body) in responses.items():
            if key in url_str:
                return httpx.Response(status, content=body.encode())
        return httpx.Response(200, content=b"[]")

    return httpx.MockTransport(handler)


_METAMASK_JSON = json.dumps({"blacklist": ["evil.com", "scam.io"]})
_SCAMSNIFFER_JSON = json.dumps(["phish.net", "bad.xyz"])
_OPENPHISH_TEXT = "http://malware.example.com/\nhttps://phish2.com/path\n"
_PHISHDESTROY_JSON = json.dumps({"domains": ["destroydomain.com"]})
_POLKADOT_JSON = json.dumps({"deny": ["dot-scam.com"]})
_PLAINTEXT = "enkrypt-bad.com\nseal-scam.org\n"

_ALL_OK_RESPONSES: dict[str, tuple[int, str]] = {
    "MetaMask": (200, _METAMASK_JSON),
    "scamsniffer": (200, _SCAMSNIFFER_JSON),
    "openphish": (200, _OPENPHISH_TEXT),
    "security-alliance": (200, _PLAINTEXT),
    "enkryptcom": (200, _PLAINTEXT),
    "phishdestroy": (200, _PHISHDESTROY_JSON),
    "polkadot.js.org": (200, _POLKADOT_JSON),
    "CryptoFirewall": (200, _PLAINTEXT),
}


# ── Happy path ────────────────────────────────────────────────────────────────


class TestBlocklistAggregatorHappyPath:
    def test_returns_iterable_of_block_records(self, tmp_path: pytest.fixture) -> None:
        transport = _make_mock_transport(_ALL_OK_RESPONSES)
        client = httpx.Client(transport=transport)
        records = list(scan(http_client=client, cache_dir=tmp_path))
        assert len(records) > 0
        assert all(isinstance(r, BlocklistRecord) for r in records)

    def test_each_record_has_source_in_vocabulary(self, tmp_path: pytest.fixture) -> None:
        transport = _make_mock_transport(_ALL_OK_RESPONSES)
        client = httpx.Client(transport=transport)
        records = list(scan(http_client=client, cache_dir=tmp_path))
        allowed = set(_SOURCES.keys())
        for r in records:
            assert r.source in allowed, f"Unknown source: {r.source}"

    def test_all_eight_sources_attempted(self, tmp_path: pytest.fixture) -> None:
        transport = _make_mock_transport(_ALL_OK_RESPONSES)
        client = httpx.Client(transport=transport)
        records = list(scan(http_client=client, cache_dir=tmp_path))
        sources_seen = {r.source for r in records}
        assert sources_seen == set(_SOURCES.keys()), f"Missing sources: {set(_SOURCES.keys()) - sources_seen}"

    def test_provenance_shape_for_metamask(self, tmp_path: pytest.fixture) -> None:
        transport = _make_mock_transport(_ALL_OK_RESPONSES)
        client = httpx.Client(transport=transport)
        records = list(scan(http_client=client, cache_dir=tmp_path))
        mm_records = [r for r in records if r.source == "blocklist.metamask"]
        assert len(mm_records) > 0
        prov = mm_records[0].source_provenance
        # Required provenance fields per contract §1
        assert prov["source"] == "blocklist.metamask"
        assert isinstance(prov["commit_sha"], str) and len(prov["commit_sha"]) == 40
        assert prov["record_id"] == _record_id(mm_records[0].indicator, "blocklist.metamask")
        assert "ingested_at" in prov
        assert "ingest_job" in prov

    def test_indicators_are_normalized_lowercase(self, tmp_path: pytest.fixture) -> None:
        transport = _make_mock_transport(_ALL_OK_RESPONSES)
        client = httpx.Client(transport=transport)
        records = list(scan(http_client=client, cache_dir=tmp_path))
        for r in records:
            assert r.indicator == r.indicator.lower()
            assert not r.indicator.startswith("http")


# ── Circuit breaker ───────────────────────────────────────────────────────────


class TestCircuitBreaker:
    def test_source_skipped_after_3_consecutive_failures(self, tmp_path: pytest.fixture) -> None:
        """A source that always errors should not raise; circuit breaker trips at 3."""

        def handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if "MetaMask" in url_str:
                raise httpx.TransportError("simulated failure")
            # All other sources succeed
            if "scamsniffer" in url_str:
                return httpx.Response(200, content=_SCAMSNIFFER_JSON.encode())
            return httpx.Response(200, content=b"[]")

        transport = httpx.MockTransport(handler)
        client = httpx.Client(transport=transport)
        records = list(scan(http_client=client, cache_dir=tmp_path))
        # MetaMask should have 0 records due to failure
        mm_records = [r for r in records if r.source == "blocklist.metamask"]
        assert mm_records == []

    def test_circuit_breaker_does_not_stop_other_sources(self, tmp_path: pytest.fixture) -> None:
        """Failure of one source must not prevent other sources from being scanned."""
        fail_count: dict[str, int] = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if "MetaMask" in url_str:
                fail_count["n"] += 1
                return httpx.Response(500, content=b"error")
            if "scamsniffer" in url_str:
                return httpx.Response(200, content=_SCAMSNIFFER_JSON.encode())
            return httpx.Response(200, content=b"[]")

        transport = httpx.MockTransport(handler)
        client = httpx.Client(transport=transport)
        records = list(scan(http_client=client, cache_dir=tmp_path))
        scamsniffer_records = [r for r in records if r.source == "blocklist.scamsniffer"]
        assert len(scamsniffer_records) > 0


# ── Ingest bucket helper ──────────────────────────────────────────────────────


class TestIngestBucket:
    def test_bucket_rounds_to_6h_windows(self) -> None:
        t = datetime(2026, 4, 24, 7, 30, tzinfo=UTC)
        assert _ingest_bucket(t) == "2026-04-24-06h"

    def test_bucket_midnight(self) -> None:
        t = datetime(2026, 4, 24, 0, 0, tzinfo=UTC)
        assert _ingest_bucket(t) == "2026-04-24-00h"

    def test_bucket_exactly_12h(self) -> None:
        t = datetime(2026, 4, 24, 12, 0, tzinfo=UTC)
        assert _ingest_bucket(t) == "2026-04-24-12h"
