"""OSINT modules for passive reconnaissance.

Provides a shared ``with_retries`` decorator for network-calling modules.
"""

from __future__ import annotations

import functools
import logging
import time
from typing import TypeVar

logger = logging.getLogger(__name__)

_DEFAULT_MAX_RETRIES = 2
_DEFAULT_BACKOFF_SECONDS = 1.0

F = TypeVar("F")


def with_retries(
    max_retries: int = _DEFAULT_MAX_RETRIES,
    backoff_seconds: float = _DEFAULT_BACKOFF_SECONDS,
    retryable_exceptions: tuple[type[BaseException], ...] = (Exception,),
):
    """Decorator that retries a function on transient errors with exponential backoff.

    Args:
        max_retries: Number of retry attempts after the initial call.
        backoff_seconds: Base delay between retries (doubled each attempt).
        retryable_exceptions: Tuple of exception types to catch and retry.

    Example::

        @with_retries(max_retries=2, backoff_seconds=1.0)
        def call_external_api(url: str) -> dict:
            ...
    """

    def decorator(func):  # type: ignore[no-untyped-def]
        @functools.wraps(func)
        def wrapper(*args, **kwargs):  # type: ignore[no-untyped-def]
            last_exc: BaseException | None = None
            for attempt in range(1, max_retries + 2):
                try:
                    return func(*args, **kwargs)
                except retryable_exceptions as exc:
                    last_exc = exc
                    if attempt > max_retries:
                        raise
                    delay = backoff_seconds * (2 ** (attempt - 1))
                    logger.warning(
                        "%s attempt %d/%d failed: %s — retrying in %.1fs",
                        func.__name__,
                        attempt,
                        max_retries + 1,
                        type(exc).__name__,
                        delay,
                    )
                    time.sleep(delay)
            raise last_exc  # type: ignore[misc]

        return wrapper

    return decorator
