"""HTTP event sink — forwards SSI investigation events to the core API.

Phase 3B of the Live Monitor redesign: SSI pushes events to
``POST /events/ssi/{scan_id}`` on core so the core SSE endpoint can
relay them to browser clients in cloud deployments where no direct
WebSocket path from the browser to the SSI service exists.

Usage::

    from ssi.monitoring.http_event_sink import HttpEventSink

    sink = HttpEventSink(
        core_api_url="https://api.example.com",
        scan_id="abc123",
        core_api_key="...",          # optional bearer token
        screenshot_interval=3.0,    # seconds between screenshot events
        batch_size=10,              # flush after this many events
        flush_interval=1.0,         # flush every N seconds regardless
    )
    bus.add_sink(sink)

Screenshot throttling
---------------------
``SCREENSHOT_UPDATE`` events are throttled to at most one every
``screenshot_interval`` seconds.  The screenshot payload is also
JPEG-compressed at 70 % quality and resized to a maximum width of 1024 px
before the base64 bytes are embedded in ``data_json``.

Batching
--------
Events are batched in memory and flushed either when the batch reaches
``batch_size`` or when ``flush_interval`` seconds elapse since the last
flush.  A synchronous ``flush()`` is also provided for end-of-investigation
teardown.
"""

from __future__ import annotations

import asyncio
import base64
import io
import logging
import time
from contextlib import suppress
from typing import Any

import httpx

from ssi.monitoring.event_bus import Event, EventType

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Screenshot compression helpers
# ---------------------------------------------------------------------------

_PILLOW_AVAILABLE: bool | None = None


def _compress_screenshot(b64_data: str, max_width: int = 1024, quality: int = 70) -> str:
    """Compress a base64 screenshot using Pillow (JPEG).

    Falls back to the original data if Pillow is not installed or
    compression fails.

    Args:
        b64_data: Base64-encoded PNG or JPEG image.
        max_width: Maximum pixel width after resizing.
        quality: JPEG quality (1–95).

    Returns:
        Base64-encoded JPEG string (or the original if compression fails).
    """
    global _PILLOW_AVAILABLE
    if _PILLOW_AVAILABLE is False:
        return b64_data  # fast path: skip import after first failure

    try:
        from PIL import Image  # type: ignore[import-untyped]

        _PILLOW_AVAILABLE = True
        raw = base64.b64decode(b64_data)
        img = Image.open(io.BytesIO(raw)).convert("RGB")
        if img.width > max_width:
            ratio = max_width / img.width
            img = img.resize((max_width, int(img.height * ratio)), Image.LANCZOS)
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=quality, optimize=True)
        return base64.b64encode(buf.getvalue()).decode()
    except ImportError:
        _PILLOW_AVAILABLE = False
        logger.debug("Pillow not installed — screenshots sent uncompressed")
        return b64_data
    except Exception as exc:
        logger.debug("Screenshot compression failed: %s", exc)
        return b64_data


# ---------------------------------------------------------------------------
# HttpEventSink
# ---------------------------------------------------------------------------


class HttpEventSink:
    """EventSink that POSTs investigation events to the core API.

    Events are queued locally and flushed in batches to reduce HTTP
    round-trips.  Screenshot events are throttled and compressed before
    being included in the batch.

    Args:
        core_api_url: Public base URL of the core API (IAP-protected LB).
            Used to build the endpoint when ``core_events_url`` is not set.
        scan_id: The SSI investigation scan ID (URL path component).
        core_api_key: Optional service API key (sent as ``X-API-KEY``).  Used
            for FastAPI's ``require_token`` check on the direct Cloud Run path.
        core_events_url: Direct Cloud Run service URL for core-svc (e.g.
            ``https://core-svc-xxx-uc.a.run.app``).  When set, the endpoint is
            built from this URL instead of ``core_api_url``, bypassing IAP
            entirely.  A Cloud Run OIDC token is fetched with this URL as the
            ``audience`` claim — the credential Cloud Run IAM requires at its
            outer gate.  ``sa-ssi`` must hold ``roles/run.invoker`` on
            ``core-svc``.
        screenshot_interval: Minimum seconds between screenshot events.
        batch_size: Flush the buffer after accumulating this many events.
        flush_interval: Flush at most every *N* seconds, regardless of batch size.
        timeout: HTTP request timeout in seconds.
    """

    def __init__(
        self,
        *,
        core_api_url: str,
        scan_id: str,
        core_api_key: str = "",
        core_events_url: str = "",
        screenshot_interval: float = 3.0,
        batch_size: int = 10,
        flush_interval: float = 1.0,
        timeout: float = 10.0,
    ) -> None:
        base = core_events_url.rstrip("/") if core_events_url else core_api_url.rstrip("/")
        self._endpoint = f"{base}/events/ssi/{scan_id}"
        self._scan_id = scan_id
        self._core_api_key = core_api_key
        self._core_events_url = core_events_url.rstrip("/") if core_events_url else ""
        self._screenshot_interval = screenshot_interval
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._timeout = timeout

        self._buffer: list[dict[str, Any]] = []
        self._last_screenshot_time: float = 0.0
        self._last_flush_time: float = time.monotonic()
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # EventSink protocol
    # ------------------------------------------------------------------

    async def handle_event(self, event: Event) -> None:
        """Process an event: throttle screenshots, buffer, then maybe flush.

        Args:
            event: The investigation event to process.
        """
        now = time.monotonic()

        # Screenshot throttling
        if event.event_type == EventType.SCREENSHOT_UPDATE:
            if now - self._last_screenshot_time < self._screenshot_interval:
                return  # drop — too frequent
            self._last_screenshot_time = now
            # Compress the screenshot before buffering.
            data = dict(event.data)
            if "screenshot_b64" in data and data["screenshot_b64"]:
                data["screenshot_b64"] = _compress_screenshot(data["screenshot_b64"])
        else:
            data = dict(event.data)

        async with self._lock:
            self._buffer.append(
                {
                    "event_type": event.event_type.value,
                    "timestamp": event.timestamp,
                    "investigation_id": event.investigation_id,
                    "data": data,
                }
            )

            should_flush = (
                len(self._buffer) >= self._batch_size or (now - self._last_flush_time) >= self._flush_interval
            )

        if should_flush:
            await self._flush()

    async def flush(self) -> None:
        """Flush all buffered events to the core API.

        Call explicitly at investigation teardown to ensure no events
        are lost.
        """
        await self._flush()

    def flush_sync(self) -> None:
        """Flush from synchronous / background-thread context.

        Bridges the sync/async gap using ``asyncio.run`` (safe to call
        from a thread that doesn't own an event loop).
        """
        try:
            loop = asyncio.get_running_loop()
            # We're inside a running loop — schedule and wait.
            future = asyncio.run_coroutine_threadsafe(self._flush(), loop)
            with suppress(Exception):
                future.result(timeout=self._timeout + 2)
        except RuntimeError:
            # No running loop — safe to use asyncio.run.
            asyncio.run(self._flush())

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _flush(self) -> None:
        """Send buffered events to core (best-effort, non-blocking on error)."""
        async with self._lock:
            if not self._buffer:
                return
            batch = list(self._buffer)
            self._buffer.clear()
            self._last_flush_time = time.monotonic()

        try:
            headers = self._build_headers()
            payload = {"events": batch}
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(self._endpoint, json=payload, headers=headers)
                if not resp.is_success:
                    logger.warning(
                        "HttpEventSink: core returned %s for scan %s: %s",
                        resp.status_code,
                        self._scan_id,
                        resp.text[:200],
                    )
        except Exception as exc:
            logger.warning(
                "HttpEventSink: failed to push %d events for scan %s: %s",
                len(batch),
                self._scan_id,
                exc,
            )
            # Re-buffer on network failure so the next flush retries.
            async with self._lock:
                self._buffer = batch + self._buffer

    def _build_headers(self) -> dict[str, str]:
        """Build HTTP headers for the core API request.

        Auth strategy:

        **Direct Cloud Run path** (``core_events_url`` is set — recommended):
          Cloud Run's outer IAM gate requires ``Authorization: Bearer <OIDC
          token>`` where the token's ``audience`` claim equals the Cloud Run
          service URL.  After Cloud Run lets the request through, FastAPI's
          ``require_token`` checks ``X-API-KEY`` first, so we include both.

        **Local / no-LB path** (only ``core_api_key`` is set):
          Send the key as ``X-API-KEY`` only — no Cloud Run IAM gate to pass.

        Returns:
            Headers dict.
        """
        if self._core_events_url:
            try:
                import google.auth.transport.requests  # type: ignore[import-untyped]
                import google.oauth2.id_token  # type: ignore[import-untyped]

                req = google.auth.transport.requests.Request()
                token = google.oauth2.id_token.fetch_id_token(req, audience=self._core_events_url)
                headers: dict[str, str] = {"Authorization": f"Bearer {token}"}
                if self._core_api_key:
                    headers["X-API-KEY"] = self._core_api_key
                return headers
            except Exception as exc:
                logger.warning(
                    "HttpEventSink: could not acquire Cloud Run OIDC token " "(audience=%s): %s",
                    self._core_events_url,
                    exc,
                )
                # Fall through to API-key-only as best-effort.

        if self._core_api_key:
            return {"X-API-KEY": self._core_api_key}

        return {}
