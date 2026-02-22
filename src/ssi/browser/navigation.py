"""Resilient page navigation with automatic wait-strategy fallback.

Many scam pages never reach ``networkidle`` due to persistent WebSocket
connections, long-polling analytics, or crypto-miner scripts.  This module
wraps Playwright's ``page.goto`` / ``page.reload`` with a two-stage
strategy: try ``networkidle`` first, then fall back to ``load`` on timeout.
"""

from __future__ import annotations

import logging
from typing import Literal

from playwright.sync_api import Page, Response, TimeoutError as PlaywrightTimeout

logger = logging.getLogger(__name__)

WaitUntil = Literal["commit", "domcontentloaded", "load", "networkidle"]

_FALLBACK_STRATEGY: list[WaitUntil] = ["networkidle", "load", "domcontentloaded"]


def resilient_goto(
    page: Page,
    url: str,
    *,
    timeout_ms: int = 30_000,
    wait_until: WaitUntil = "networkidle",
) -> Response | None:
    """Navigate to *url* with automatic wait-strategy fallback.

    Tries *wait_until* first (default ``networkidle``).  If that times out,
    retries with progressively less strict strategies (``load`` then
    ``domcontentloaded``) using the same timeout for each attempt.

    Args:
        page: Playwright page instance.
        url: Target URL to navigate to.
        timeout_ms: Timeout per attempt in milliseconds.
        wait_until: Preferred initial wait strategy.

    Returns:
        The Playwright ``Response`` for the main frame navigation,
        or ``None`` if the page did not produce a response.

    Raises:
        PlaywrightTimeout: If all fallback strategies also time out.
    """
    strategies = _build_fallback_chain(wait_until)

    last_error: PlaywrightTimeout | None = None
    for strategy in strategies:
        try:
            logger.debug("goto %s (wait_until=%s, timeout=%dms)", url, strategy, timeout_ms)
            return page.goto(url, wait_until=strategy, timeout=timeout_ms)
        except PlaywrightTimeout as exc:
            logger.warning(
                "Navigation to %s timed out with wait_until=%s — retrying with weaker strategy",
                url,
                strategy,
            )
            last_error = exc

    # All strategies exhausted — raise the last timeout
    raise last_error  # type: ignore[misc]


def resilient_reload(
    page: Page,
    *,
    timeout_ms: int = 15_000,
    wait_until: WaitUntil = "networkidle",
) -> Response | None:
    """Reload the current page with automatic wait-strategy fallback.

    Same fallback logic as :func:`resilient_goto` but for ``page.reload``.

    Args:
        page: Playwright page instance.
        timeout_ms: Timeout per attempt in milliseconds.
        wait_until: Preferred initial wait strategy.

    Returns:
        The Playwright ``Response``, or ``None``.

    Raises:
        PlaywrightTimeout: If all fallback strategies also time out.
    """
    strategies = _build_fallback_chain(wait_until)

    last_error: PlaywrightTimeout | None = None
    for strategy in strategies:
        try:
            logger.debug("reload (wait_until=%s, timeout=%dms)", strategy, timeout_ms)
            return page.reload(wait_until=strategy, timeout=timeout_ms)
        except PlaywrightTimeout as exc:
            logger.warning(
                "Reload timed out with wait_until=%s — retrying with weaker strategy",
                strategy,
            )
            last_error = exc

    raise last_error  # type: ignore[misc]


def _build_fallback_chain(preferred: WaitUntil) -> list[WaitUntil]:
    """Return the fallback chain starting from *preferred*.

    If *preferred* is in the default chain, returns from that point onward.
    Otherwise returns ``[preferred]`` followed by the full default chain.
    """
    if preferred in _FALLBACK_STRATEGY:
        idx = _FALLBACK_STRATEGY.index(preferred)
        return _FALLBACK_STRATEGY[idx:]
    return [preferred, *_FALLBACK_STRATEGY]
