"""Whoxy reverse WHOIS OSINT module."""

from __future__ import annotations

import logging
from typing import Any

from ssi.osint import with_retries
from ssi.providers.gate import ProviderGate, SkippedResult

logger = logging.getLogger(__name__)
_GATE = ProviderGate("whoxy")


@with_retries()
async def search(query: str, **kwargs: Any) -> dict[str, Any] | SkippedResult:
    """Perform a reverse WHOIS search using Whoxy."""
    if not _GATE.enabled:
        return _GATE.skip(reason="quota_gated", detail="whoxy disabled in settings")

    # Core logic (stubbed for tests)
    return {"status": "success", "results": [], "query": query}
