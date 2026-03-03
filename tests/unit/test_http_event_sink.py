"""Unit tests for HttpEventSink — Phase 3B.

Tests cover:
* Event buffering and batch-size flush trigger.
* Screenshot throttling (excess events within the interval are dropped).
* ``flush()`` / ``flush_sync()`` drains the buffer.
* Screenshot JPEG compression via Pillow (and graceful fallback when Pillow
  is absent).
* HTTP POST payload shape sent to the core API.

Async methods are exercised via ``asyncio.run()`` so no external async test
plugin is required.
"""

from __future__ import annotations

import asyncio
import base64
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from ssi.monitoring.event_bus import Event, EventType
from ssi.monitoring.http_event_sink import HttpEventSink, _compress_screenshot

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

CORE_URL = "http://core.local"
SCAN_ID = "test-scan-001"


def _make_sink(**kwargs: object) -> HttpEventSink:
    """Return a sink with test-friendly defaults.

    Args:
        **kwargs: Keyword overrides for ``HttpEventSink.__init__``.

    Returns:
        Configured ``HttpEventSink``.
    """
    defaults: dict[str, object] = {
        "core_api_url": CORE_URL,
        "scan_id": SCAN_ID,
        "core_api_key": "test-token",
        "batch_size": 5,
        "flush_interval": 100.0,  # large so time-based flush doesn't trigger
        "screenshot_interval": 3.0,
        "timeout": 5.0,
    }
    defaults.update(kwargs)
    return HttpEventSink(**defaults)  # type: ignore[arg-type]


def _state_event(state: str = "navigating") -> Event:
    """Build a synthetic ``state_changed`` event.

    Args:
        state: Browser navigation state string.

    Returns:
        ``Event`` object.
    """
    return Event(
        event_type=EventType.STATE_CHANGED,
        investigation_id=SCAN_ID,
        data={"state": state},
    )


def _screenshot_event(b64: str = "") -> Event:
    """Build a synthetic ``screenshot_update`` event.

    Args:
        b64: Base64-encoded image payload.

    Returns:
        ``Event`` object.
    """
    return Event(
        event_type=EventType.SCREENSHOT_UPDATE,
        investigation_id=SCAN_ID,
        data={"screenshot_b64": b64 or _tiny_png_b64()},
    )


def _tiny_png_b64() -> str:
    """Return a minimal valid 1×1 PNG image as a base64 string."""
    import zlib

    def _chunk(tag: bytes, data: bytes) -> bytes:
        length = len(data).to_bytes(4, "big")
        crc = zlib.crc32(tag + data).to_bytes(4, "big")
        return length + tag + data + crc

    png = (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00")
        + _chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00"))
        + _chunk(b"IEND", b"")
    )
    return base64.b64encode(png).decode()


def _patched_post(captured_payloads: list) -> AsyncMock:
    """Return an ``httpx.AsyncClient.post`` mock that records call payloads."""

    async def _post(*args: object, **kwargs: object) -> MagicMock:
        captured_payloads.append(kwargs.get("json", {}))
        resp = MagicMock()
        resp.is_success = True
        return resp

    return AsyncMock(side_effect=_post)


# ---------------------------------------------------------------------------
# Buffering and batch-flush tests
# ---------------------------------------------------------------------------


class TestBuffering:
    """Verify event accumulation and batch-flush behaviour."""

    def test_events_buffered_until_batch_size(self) -> None:
        """Events accumulate in the buffer and flush only after batch_size."""
        sink = _make_sink(batch_size=3)
        posted_payloads: list[dict] = []

        async def _run() -> None:
            with patch.object(httpx.AsyncClient, "post", new=_patched_post(posted_payloads)):
                await sink.handle_event(_state_event("step-1"))
                await sink.handle_event(_state_event("step-2"))
                assert posted_payloads == [], "Should not flush before batch_size"
                await sink.handle_event(_state_event("step-3"))

        asyncio.run(_run())
        assert len(posted_payloads) == 1
        assert len(posted_payloads[0]["events"]) == 3

    def test_explicit_flush_drains_buffer(self) -> None:
        """Calling ``flush()`` sends partial batches immediately."""
        sink = _make_sink(batch_size=10)
        posted_payloads: list[dict] = []

        async def _run() -> None:
            with patch.object(httpx.AsyncClient, "post", new=_patched_post(posted_payloads)):
                await sink.handle_event(_state_event("a"))
                await sink.handle_event(_state_event("b"))
                assert posted_payloads == []
                await sink.flush()

        asyncio.run(_run())
        assert len(posted_payloads) == 1
        assert len(posted_payloads[0]["events"]) == 2

    def test_flush_on_empty_buffer_is_noop(self) -> None:
        """Flushing an empty buffer makes no HTTP calls."""
        sink = _make_sink()
        posted_payloads: list[dict] = []

        async def _run() -> None:
            with patch.object(httpx.AsyncClient, "post", new=_patched_post(posted_payloads)):
                await sink.flush()

        asyncio.run(_run())
        assert posted_payloads == []


# ---------------------------------------------------------------------------
# Screenshot throttling tests
# ---------------------------------------------------------------------------


class TestScreenshotThrottling:
    """Verify screenshot events are dropped when within the throttle window."""

    def test_first_screenshot_is_accepted(self) -> None:
        """The first screenshot event is always buffered."""
        sink = _make_sink(screenshot_interval=3.0, batch_size=100)
        asyncio.run(sink.handle_event(_screenshot_event()))
        assert len(sink._buffer) == 1

    def test_second_screenshot_within_interval_dropped(self) -> None:
        """A screenshot arriving before the throttle window elapses is dropped."""
        sink = _make_sink(screenshot_interval=3.0, batch_size=100)

        async def _run() -> None:
            await sink.handle_event(_screenshot_event())
            await sink.handle_event(_screenshot_event())

        asyncio.run(_run())
        assert len(sink._buffer) == 1, "Second screenshot within interval should be dropped"

    def test_screenshot_accepted_after_interval(self) -> None:
        """A screenshot arriving after the interval elapses is accepted."""
        sink = _make_sink(screenshot_interval=0.0, batch_size=100)

        async def _run() -> None:
            await sink.handle_event(_screenshot_event())
            await sink.handle_event(_screenshot_event())

        asyncio.run(_run())
        assert len(sink._buffer) == 2, "Both screenshots should be buffered with 0 s interval"

    def test_non_screenshot_events_not_throttled(self) -> None:
        """Non-screenshot events are never affected by the throttle."""
        sink = _make_sink(screenshot_interval=999.0, batch_size=100)

        async def _run() -> None:
            for _ in range(5):
                await sink.handle_event(_state_event())

        asyncio.run(_run())
        assert len(sink._buffer) == 5


# ---------------------------------------------------------------------------
# Payload shape test
# ---------------------------------------------------------------------------


class TestPayloadShape:
    """Verify the JSON payload sent to the core API matches the expected schema."""

    def test_payload_contains_event_type_and_data(self) -> None:
        """Flushed payload has ``events`` list with ``event_type`` and ``data``."""
        sink = _make_sink(batch_size=1)
        captured: list[dict] = []

        async def _run() -> None:
            with patch.object(httpx.AsyncClient, "post", new=_patched_post(captured)):
                await sink.handle_event(_state_event("idle"))

        asyncio.run(_run())
        assert captured
        ev = captured[0]["events"][0]
        assert ev["event_type"] == "state_changed"
        assert ev["data"]["state"] == "idle"
        assert ev["investigation_id"] == SCAN_ID

    def test_api_key_header(self) -> None:
        """API key is sent as X-API-KEY when no iap_audience is configured.

        This covers local / non-IAP deployments where core is not behind a
        Google IAP load balancer.  ``require_token`` checks ``X-API-KEY``
        before attempting JWT verification, so the raw key reaches FastAPI.
        """
        sink = _make_sink(core_api_key="my-secret", batch_size=1)
        captured_headers: list[dict] = []

        async def _post(*args: object, **kwargs: object) -> MagicMock:
            captured_headers.append(dict(kwargs.get("headers", {})))
            resp = MagicMock()
            resp.is_success = True
            return resp

        async def _run() -> None:
            with patch.object(httpx.AsyncClient, "post", new=AsyncMock(side_effect=_post)):
                await sink.handle_event(_state_event())

        asyncio.run(_run())
        assert captured_headers[0].get("X-API-KEY") == "my-secret"
        assert "Authorization" not in captured_headers[0]

    def test_direct_cloud_run_auth(self) -> None:
        """When core_events_url is set, both a Cloud Run OIDC Bearer token and
        X-API-KEY are sent.

        Direct Cloud Run invocation (bypassing IAP) requires:
        * ``Authorization: Bearer <OIDC>``  — passes the Cloud Run IAM gate;
          audience must equal the Cloud Run service URL.
        * ``X-API-KEY``  — satisfies FastAPI's ``require_token`` check.

        The OIDC audience is the ``core_events_url`` value, not the IAP client
        ID (which is only needed when going through the Google-managed LB).
        """
        events_url = "https://core-svc-xxx-uc.a.run.app"
        sink = _make_sink(
            core_api_key="my-secret",
            core_events_url=events_url,
            batch_size=1,
        )
        captured_headers: list[dict] = []

        async def _post(*args: object, **kwargs: object) -> MagicMock:
            captured_headers.append(dict(kwargs.get("headers", {})))
            resp = MagicMock()
            resp.is_success = True
            return resp

        fake_token = "fake-cloud-run-oidc-jwt"

        async def _run() -> None:
            with (
                patch(
                    "google.oauth2.id_token.fetch_id_token",
                    return_value=fake_token,
                ),
                patch(
                    "google.auth.transport.requests.Request",
                    return_value=MagicMock(),
                ),
                patch.object(httpx.AsyncClient, "post", new=AsyncMock(side_effect=_post)),
            ):
                await sink.handle_event(_state_event())

        asyncio.run(_run())
        assert captured_headers[0].get("Authorization") == f"Bearer {fake_token}"
        assert captured_headers[0].get("X-API-KEY") == "my-secret"


# ---------------------------------------------------------------------------
# Screenshot compression tests
# ---------------------------------------------------------------------------


class TestScreenshotCompression:
    """Verify the ``_compress_screenshot`` helper."""

    def test_compress_returns_string(self) -> None:
        """Compression always returns a non-empty base64 string."""
        result = _compress_screenshot(_tiny_png_b64())
        assert isinstance(result, str)
        assert result

    def test_compress_fallback_on_bad_data(self) -> None:
        """Invalid base64 input falls back to the original string."""
        bad = "not-valid-base64!!!"
        result = _compress_screenshot(bad)
        assert result == bad

    def test_compress_pillow_unavailable(self) -> None:
        """When Pillow cannot be imported, the original bytes are returned."""
        import ssi.monitoring.http_event_sink as sink_module

        original = sink_module._PILLOW_AVAILABLE
        try:
            sink_module._PILLOW_AVAILABLE = False
            b64 = _tiny_png_b64()
            result = _compress_screenshot(b64)
            assert result == b64
        finally:
            sink_module._PILLOW_AVAILABLE = original


# ---------------------------------------------------------------------------
# flush_sync test
# ---------------------------------------------------------------------------


class TestFlushSync:
    """Verify ``flush_sync`` bridges sync → async correctly."""

    def test_flush_sync_outside_event_loop(self) -> None:
        """``flush_sync`` drains the buffer when called from synchronous code."""
        sink = _make_sink(batch_size=100)
        # Manually pre-fill the buffer (bypass handle_event for speed).
        sink._buffer.append({"event_type": "log", "data": {}, "timestamp": "t", "investigation_id": SCAN_ID})

        posted: list[dict] = []

        async def _post(*args: object, **kwargs: object) -> MagicMock:
            posted.append(kwargs.get("json", {}))
            resp = MagicMock()
            resp.is_success = True
            return resp

        with patch.object(httpx.AsyncClient, "post", new=AsyncMock(side_effect=_post)):
            sink.flush_sync()

        assert posted, "flush_sync should have sent the buffered event"
        assert sink._buffer == [], "Buffer should be empty after flush_sync"
