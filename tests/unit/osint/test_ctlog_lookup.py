"""Unit tests for ssi.osint.ctlog_lookup."""

from __future__ import annotations

import json
import time
from typing import Any

import httpx
import pytest

from ssi.osint.ctlog_lookup import CTLogEntry, _fetch_with_backoff, scan

# ── Fixtures ──────────────────────────────────────────────────────────────────

_SAMPLE_ROWS: list[dict[str, Any]] = [
    {
        "id": 12345,
        "name_value": "sub.example.com",
        "not_before": "2026-01-01T00:00:00",
        "issuer_name": "Let's Encrypt Authority X3",
    },
    {
        "id": 67890,
        "name_value": "other.example.com",
        "not_before": "2026-02-01T00:00:00",
        "issuer_name": "DigiCert SHA2 Secure Server CA",
    },
]


def _make_client(status: int, body: Any) -> httpx.Client:
    content = json.dumps(body).encode() if not isinstance(body, bytes) else body

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, content=content)

    return httpx.Client(transport=httpx.MockTransport(handler))


# ── Happy path ────────────────────────────────────────────────────────────────


class TestCTLogLookupHappyPath:
    def test_returns_list_of_ct_entries(self) -> None:
        client = _make_client(200, _SAMPLE_ROWS)
        entries = scan("example.com", http_client=client)
        assert len(entries) == 2
        assert all(isinstance(e, CTLogEntry) for e in entries)

    def test_entry_fields_populated(self) -> None:
        client = _make_client(200, _SAMPLE_ROWS)
        entries = scan("example.com", http_client=client)
        first = entries[0]
        assert first.entry_id == 12345
        assert first.domain == "sub.example.com"
        assert first.issuer == "Let's Encrypt Authority X3"

    def test_provenance_source_is_ctlog_crtsh(self) -> None:
        client = _make_client(200, _SAMPLE_ROWS)
        entries = scan("example.com", http_client=client)
        for e in entries:
            assert e.source_provenance["source"] == "ctlog.crtsh"

    def test_provenance_record_id_format(self) -> None:
        client = _make_client(200, _SAMPLE_ROWS)
        entries = scan("example.com", http_client=client)
        for e in entries:
            assert e.source_provenance["record_id"] == f"crtsh:{e.entry_id}"

    def test_deduplicates_by_entry_id(self) -> None:
        duplicated = _SAMPLE_ROWS + [_SAMPLE_ROWS[0]]  # entry 12345 appears twice
        client = _make_client(200, duplicated)
        entries = scan("example.com", http_client=client)
        ids = [e.entry_id for e in entries]
        assert len(ids) == len(set(ids)), "Duplicate entry_ids found"

    def test_returns_empty_on_empty_list(self) -> None:
        client = _make_client(200, [])
        entries = scan("example.com", http_client=client)
        assert entries == []

    def test_returns_empty_on_non_list_response(self) -> None:
        client = _make_client(200, {"error": "no results"})
        entries = scan("example.com", http_client=client)
        assert entries == []

    def test_returns_empty_on_network_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.TransportError("connection refused")

        client = httpx.Client(transport=httpx.MockTransport(handler))
        entries = scan("example.com", http_client=client)
        assert entries == []


# ── Rate-limit back-off ───────────────────────────────────────────────────────


class TestCTLogRateLimitBackoff:
    def test_retries_on_429_then_succeeds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """First call returns 429; second call returns 200 with data."""
        calls: list[int] = []
        sleep_calls: list[float] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(1)
            if len(calls) == 1:
                return httpx.Response(429, content=b"rate limited")
            return httpx.Response(200, content=json.dumps(_SAMPLE_ROWS).encode())

        monkeypatch.setattr(time, "sleep", lambda d: sleep_calls.append(d))
        client = httpx.Client(transport=httpx.MockTransport(handler))
        entries = scan("example.com", http_client=client)
        assert len(entries) == 2
        assert len(sleep_calls) == 1  # one sleep before the retry

    def test_backoff_delay_is_exponential(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Each 429 doubles the sleep delay: 1s, 2s, 4s, ..."""
        sleep_calls: list[float] = []
        call_count: list[int] = [0]

        def handler(request: httpx.Request) -> httpx.Response:
            call_count[0] += 1
            if call_count[0] <= 3:
                return httpx.Response(429, content=b"rate limited")
            return httpx.Response(200, content=json.dumps(_SAMPLE_ROWS).encode())

        monkeypatch.setattr(time, "sleep", lambda d: sleep_calls.append(d))
        client = httpx.Client(transport=httpx.MockTransport(handler))
        entries = scan("example.com", http_client=client)
        assert len(entries) == 2
        # Delays should be 1, 2, 4 (2^0, 2^1, 2^2)
        assert sleep_calls == [1, 2, 4]

    def test_backoff_is_capped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Delay is capped at the supplied cap_seconds.

        Uses _fetch_with_backoff directly with cap_seconds=5 and max_retries=4 so
        the sequence is: sleep(1), sleep(2), sleep(4), sleep(5) — the last value
        is capped from 2^3=8 to 5.
        """
        sleep_calls: list[float] = []
        call_count: list[int] = [0]

        def handler(request: httpx.Request) -> httpx.Response:
            call_count[0] += 1
            if call_count[0] <= 4:
                return httpx.Response(429, content=b"rate limited")
            return httpx.Response(200, content=json.dumps(_SAMPLE_ROWS).encode())

        monkeypatch.setattr(time, "sleep", lambda d: sleep_calls.append(d))
        client = httpx.Client(transport=httpx.MockTransport(handler))
        resp = _fetch_with_backoff("https://crt.sh/?q=example.com", client, cap_seconds=5, max_retries=4)
        assert resp.status_code == 200
        assert sleep_calls == [1, 2, 4, 5]  # last capped from 2^3=8 to 5
