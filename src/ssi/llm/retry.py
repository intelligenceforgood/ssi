"""Retrying LLM provider wrapper.

Wraps any ``LLMProvider`` with configurable exponential-backoff retry logic
so that transient network / provider errors do not kill an investigation.

Usage::

    from ssi.llm.factory import create_llm_provider
    from ssi.llm.retry import RetryingLLMProvider

    base = create_llm_provider()
    resilient = RetryingLLMProvider(base, max_retries=3, base_delay=1.0)
    result = resilient.chat(messages)
"""

from __future__ import annotations

import logging
import time

from ssi.llm.base import LLMProvider, LLMResult

logger = logging.getLogger(__name__)

# Exceptions that are safe to retry — transient network / rate-limit issues.
_RETRYABLE_EXCEPTION_NAMES = frozenset({
    "ConnectionError",
    "TimeoutError",
    "ReadTimeout",
    "ConnectTimeout",
    "RemoteProtocolError",
    "HTTPStatusError",
    "ServiceUnavailable",
    "TooManyRequests",
    "InternalServerError",
})


def _is_retryable(exc: Exception) -> bool:
    """Return True if *exc* looks like a transient error worth retrying."""
    name = type(exc).__name__
    if name in _RETRYABLE_EXCEPTION_NAMES:
        return True
    # httpx status-based errors
    status_code = getattr(exc, "status_code", None) or getattr(
        getattr(exc, "response", None), "status_code", None
    )
    if status_code and status_code in (429, 500, 502, 503, 504):
        return True
    return False


class RetryingLLMProvider(LLMProvider):
    """Transparent retry wrapper around any ``LLMProvider``.

    Args:
        delegate: The actual LLM provider to delegate calls to.
        max_retries: Number of retry attempts (0 = no retries, just pass through).
        base_delay: Base delay in seconds for exponential backoff.
        max_delay: Cap on the backoff delay.
    """

    def __init__(
        self,
        delegate: LLMProvider,
        *,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 30.0,
    ) -> None:
        self._delegate = delegate
        self._max_retries = max_retries
        self._base_delay = base_delay
        self._max_delay = max_delay

    # ------------------------------------------------------------------
    # Retry helper
    # ------------------------------------------------------------------

    def _call_with_retry(self, func, *args, **kwargs) -> LLMResult:  # type: ignore[no-untyped-def]
        """Invoke *func* with exponential-backoff retry on transient errors."""
        last_exc: Exception | None = None
        for attempt in range(1, self._max_retries + 2):  # attempt 1 = initial call
            try:
                return func(*args, **kwargs)
            except Exception as exc:
                last_exc = exc
                if attempt > self._max_retries or not _is_retryable(exc):
                    raise
                delay = min(self._base_delay * (2 ** (attempt - 1)), self._max_delay)
                logger.warning(
                    "LLM call failed (attempt %d/%d): %s — retrying in %.1fs",
                    attempt,
                    self._max_retries + 1,
                    type(exc).__name__,
                    delay,
                )
                time.sleep(delay)
        # Should not reach here, but satisfy the type checker
        raise last_exc  # type: ignore[misc]

    # ------------------------------------------------------------------
    # LLMProvider interface
    # ------------------------------------------------------------------

    def chat(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool = False,
    ) -> LLMResult:
        """Send a chat completion request with retry on transient errors."""
        return self._call_with_retry(
            self._delegate.chat,
            messages,
            temperature=temperature,
            max_tokens=max_tokens,
            json_mode=json_mode,
        )

    def chat_with_images(
        self,
        messages: list[dict],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        json_mode: bool = False,
    ) -> LLMResult:
        """Send a multimodal chat request with retry on transient errors."""
        return self._call_with_retry(
            self._delegate.chat_with_images,
            messages,
            temperature=temperature,
            max_tokens=max_tokens,
            json_mode=json_mode,
        )

    def check_connectivity(self) -> bool:
        """Delegate connectivity check (no retry — it does its own)."""
        return self._delegate.check_connectivity()

    def close(self) -> None:
        """Delegate cleanup."""
        self._delegate.close()
