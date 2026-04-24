"""Unit tests for ssi.osint.merklemap_client."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator

import httpx
import pytest

from ssi.osint.merklemap_client import DomainDiscovery, _parse_sse_event, tail
from ssi.providers.gate import ProviderGate, SkippedResult

# ── Helpers ───────────────────────────────────────────────────────────────────


def _sse_body(*events: dict) -> bytes:
    """Build a well-formed SSE response body from a list of data dicts."""
    parts = [f"data: {json.dumps(e)}\n\n" for e in events]
    return "".join(parts).encode()


class _AsyncBodyStream(httpx.AsyncByteStream):
    """Minimal async byte stream backed by a fixed bytes body."""

    def __init__(self, body: bytes) -> None:
        self._body = body

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield self._body


class _MockSSETransport(httpx.AsyncBaseTransport):
    """Async transport that serves a fixed SSE body then closes the stream."""

    def __init__(self, body: bytes, status: int = 200) -> None:
        self._body = body
        self._status = status

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            self._status,
            headers={"content-type": "text/event-stream"},
            stream=_AsyncBodyStream(self._body),
        )


class _MockSSETransportThenError(httpx.AsyncBaseTransport):
    """First request returns body; subsequent requests return another body after 1 error.

    Sequence:
      call 1 → body (stream the events)
      call 2 → TransportError (simulates drop)
      call 3+ → body (reconnect succeeds)
    """

    def __init__(self, body: bytes) -> None:
        self._body = body
        self._call_count = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self._call_count += 1
        if self._call_count == 2:
            raise httpx.TransportError("simulated stream drop")
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=_AsyncBodyStream(self._body),
        )


# ── SSE parse unit tests ──────────────────────────────────────────────────────


class TestParseSSEEvent:
    def test_parses_hostname_field(self) -> None:
        payload = json.dumps({"hostname": "evil.com"})
        result = _parse_sse_event(payload, "2026-04-24T00:00:00Z")
        assert result is not None
        assert result.domain == "evil.com"

    def test_normalizes_domain_to_lowercase(self) -> None:
        payload = json.dumps({"hostname": "Evil.COM"})
        result = _parse_sse_event(payload, "2026-04-24T00:00:00Z")
        assert result is not None
        assert result.domain == "evil.com"

    def test_provenance_source_is_merklemap_tail(self) -> None:
        payload = json.dumps({"hostname": "evil.com"})
        result = _parse_sse_event(payload, "2026-04-24T00:00:00Z")
        assert result is not None
        assert result.source_provenance["source"] == "merklemap.tail"

    def test_provenance_record_id_is_sha256(self) -> None:
        import hashlib

        payload = json.dumps({"hostname": "evil.com", "not_before": 1700000000})
        result = _parse_sse_event(payload, "2026-04-24T00:00:00Z")
        assert result is not None
        expected = hashlib.sha256(b"evil.com|1700000000").hexdigest()
        assert result.source_provenance["record_id"] == expected

    def test_returns_none_for_progress_event(self) -> None:
        payload = json.dumps({"progress_percentage": 42.0})
        result = _parse_sse_event(payload, "2026-04-24T00:00:00Z")
        assert result is None

    def test_returns_none_for_invalid_json(self) -> None:
        result = _parse_sse_event("not json {{{", "2026-04-24T00:00:00Z")
        assert result is None


# ── Gate-disabled behaviour ───────────────────────────────────────────────────


class TestMerklemapGateDisabled:
    @pytest.mark.anyio
    async def test_yields_skipped_result_when_gate_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SSI_PROVIDERS__MERKLEMAP__ENABLED", raising=False)
        monkeypatch.delenv("SSI_PROVIDERS__MERKLEMAP__API_KEY", raising=False)

        gate = ProviderGate("merklemap")
        events: list[DomainDiscovery | SkippedResult] = []
        async for event in tail(gate=gate):
            events.append(event)
            break  # should only emit one SkippedResult then stop

        assert len(events) == 1
        assert isinstance(events[0], SkippedResult)
        assert events[0].provider == "merklemap"
        assert events[0].reason == "quota_gated"


# ── Happy-path SSE streaming ──────────────────────────────────────────────────


class TestMerklemapSSEHappyPath:
    @pytest.mark.anyio
    async def test_yields_domain_discovery_events(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SSI_PROVIDERS__MERKLEMAP__ENABLED", "true")
        monkeypatch.setenv("SSI_PROVIDERS__MERKLEMAP__API_KEY", "test-key")
        gate = ProviderGate("merklemap")

        body = _sse_body(
            {"hostname": "phish1.com"},
            {"hostname": "phish2.net"},
        )
        transport = _MockSSETransport(body)
        client = httpx.AsyncClient(transport=transport)

        events: list[DomainDiscovery | SkippedResult] = []
        try:
            async for event in tail(gate=gate, http_client=client):
                events.append(event)
                if len(events) >= 2:
                    break
        except Exception:
            pass  # stream ends after our body; that's fine

        domains = [e.domain for e in events if isinstance(e, DomainDiscovery)]
        assert "phish1.com" in domains
        assert "phish2.net" in domains


# ── Reconnect on stream drop ──────────────────────────────────────────────────


class TestMerklemapReconnect:
    @pytest.mark.anyio
    async def test_reconnects_on_stream_drop(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """After a transport error the client should reconnect and continue yielding."""
        monkeypatch.setenv("SSI_PROVIDERS__MERKLEMAP__ENABLED", "true")
        monkeypatch.setenv("SSI_PROVIDERS__MERKLEMAP__API_KEY", "test-key")
        gate = ProviderGate("merklemap")

        sleep_calls: list[float] = []

        async def mock_sleep(d: float) -> None:
            sleep_calls.append(d)

        monkeypatch.setattr(asyncio, "sleep", mock_sleep)

        body = _sse_body({"hostname": "phish1.com"})
        # call 1 → body, call 2 → TransportError, call 3+ → body
        transport = _MockSSETransportThenError(body)
        client = httpx.AsyncClient(transport=transport)

        events: list[DomainDiscovery | SkippedResult] = []
        # Collect events from 2 separate successful connections (before and after the drop)
        async for event in tail(gate=gate, http_client=client):
            events.append(event)
            if len(events) >= 2:
                break

        # Two domain discoveries — one from before, one from after the reconnect
        domain_events = [e for e in events if isinstance(e, DomainDiscovery)]
        assert len(domain_events) >= 2
        # A sleep (back-off) was recorded for the error-triggered reconnect
        assert len(sleep_calls) >= 1
