"""PhishDestroy merklemap SSE tail client.

Streams live domain discoveries from the Merklemap API using Server-Sent Events
(SSE) over httpx async streaming.  Reconnects on stream drop with exponential
back-off capped at 30 seconds.

Gate: requires ``SSI_PROVIDERS__MERKLEMAP__ENABLED=true`` AND a non-empty
``SSI_PROVIDERS__MERKLEMAP__API_KEY``.  When the gate is disabled, the
iterator yields a single ``SkippedResult`` and stops.

Entry point::

    import asyncio
    from ssi.osint.merklemap_client import tail

    async def main():
        async for event in tail():
            print(event)

    asyncio.run(main())

Upstream SSE path confirmed from merklemap-cli @ 550cb04aa633c000724c339ada085c59444d5b78.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx

from ssi.providers.gate import ProviderGate, SkippedResult

logger = logging.getLogger(__name__)

# Confirmed from merklemap-cli/src/lib.rs tail() @ 550cb04aa633c000724c339ada085c59444d5b78.
_DEFAULT_STREAM_URL = "https://api.merklemap.com/live-domains?no_throttle=true"
_RECONNECT_CAP_SECONDS = 30
_INGEST_JOB = "ssi.osint.merklemap_client"


@dataclass
class DomainDiscovery:
    """A single domain discovery emitted by the merklemap SSE stream."""

    domain: str
    first_seen_unix: int
    cert_issuer: str
    source_provenance: dict


# ── Internal helpers ──────────────────────────────────────────────────────────


def _record_id(domain: str, first_seen_unix: int) -> str:
    """Return deterministic record_id per provenance §2 for merklemap tail."""
    return hashlib.sha256(f"{domain}|{first_seen_unix}".encode()).hexdigest()


def _parse_sse_event(data: str, ingested_at: str) -> DomainDiscovery | None:
    """Parse a single SSE data payload into a ``DomainDiscovery``."""
    try:
        obj = json.loads(data)
    except json.JSONDecodeError:
        return None

    # TailEntry shape from merklemap-cli: {"hostname": "..."}.
    # The stream may also carry {"progress_percentage": ...} progress events.
    hostname = obj.get("hostname") or obj.get("domain")
    if not hostname:
        return None

    # Merklemap live stream does not include not_before; use current epoch as proxy.
    first_seen_unix = obj.get("not_before") or int(datetime.now(UTC).timestamp())
    cert_issuer = obj.get("subject_common_name") or obj.get("issuer") or ""

    return DomainDiscovery(
        domain=str(hostname).strip().lower(),
        first_seen_unix=int(first_seen_unix),
        cert_issuer=str(cert_issuer),
        source_provenance={
            "source": "merklemap.tail",
            "commit_sha": "550cb04aa633c000724c339ada085c59444d5b78",
            "record_id": _record_id(str(hostname).strip().lower(), int(first_seen_unix)),
            "ingested_at": ingested_at,
            "ingest_job": _INGEST_JOB,
        },
    )


async def _stream_sse(
    url: str,
    api_key: str,
    http_client: httpx.AsyncClient,
) -> AsyncIterator[DomainDiscovery]:
    """Yield ``DomainDiscovery`` objects from a single SSE connection."""
    headers = {"Authorization": f"Bearer {api_key}", "Accept": "text/event-stream"}
    buffer = ""

    async with http_client.stream("GET", url, headers=headers, timeout=None) as resp:
        resp.raise_for_status()
        async for chunk in resp.aiter_text():
            buffer += chunk
            while "\n\n" in buffer:
                event_block, buffer = buffer.split("\n\n", 1)
                for line in event_block.splitlines():
                    if line.startswith("data:"):
                        data = line[5:].strip()
                        ingested_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
                        discovery = _parse_sse_event(data, ingested_at)
                        if discovery is not None:
                            yield discovery


# ── Public entry point ────────────────────────────────────────────────────────


async def tail(
    *,
    gate: ProviderGate | None = None,
    http_client: httpx.AsyncClient | None = None,
) -> AsyncIterator[DomainDiscovery | SkippedResult]:
    """Yield live domain discoveries from the Merklemap SSE stream.

    Args:
        gate: Provider gate instance (default: ``ProviderGate("merklemap")``).
        http_client: Injected async HTTP client (use ``httpx.MockTransport`` in tests).

    Yields:
        ``DomainDiscovery`` on each parsed event, or a single ``SkippedResult``
        if the gate is disabled.
    """
    gate = gate or ProviderGate("merklemap")

    if not gate.enabled:
        yield gate.skip(reason="quota_gated", detail="merklemap provider disabled in settings")
        return

    url = _DEFAULT_STREAM_URL
    api_key = gate.api_key
    own_client = http_client is None
    client = http_client or httpx.AsyncClient()

    reconnect_attempt = 0

    try:
        while True:
            try:
                async for discovery in _stream_sse(url, api_key, client):
                    reconnect_attempt = 0  # reset on successful event
                    yield discovery
                # Stream ended cleanly — reconnect
                logger.info("merklemap SSE stream ended cleanly, reconnecting")
            except Exception as exc:
                reconnect_attempt += 1
                delay = min(2 ** (reconnect_attempt - 1), _RECONNECT_CAP_SECONDS)
                logger.warning(
                    "merklemap SSE stream error (attempt %d) — reconnecting in %.0fs: %s",
                    reconnect_attempt,
                    delay,
                    exc,
                )
                await asyncio.sleep(delay)
    finally:
        if own_client:
            await client.aclose()
