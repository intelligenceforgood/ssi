"""Web Archive OSINT module."""

from __future__ import annotations

import logging
from typing import Any

from ssi.osint import phishdestroy_provider_enabled, with_retries
from ssi.providers.gate import SkippedResult

logger = logging.getLogger(__name__)


@with_retries()
async def fetch_snapshots(domain: str, **kwargs: Any) -> dict[str, Any] | SkippedResult:
    """Fetch snapshots from Archive.org CDX."""
    if not phishdestroy_provider_enabled("webarchive"):
        return SkippedResult(provider="webarchive", reason="disabled", detail="webarchive disabled in settings")

    # Core logic (stubbed for tests)
    return {"status": "success", "snapshots": [], "domain": domain}
