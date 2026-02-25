"""Unit tests for Phase 8B hardening features.

Covers:
- BudgetExceededError / CostTracker.check_budget()
- ConcurrentLimitError
- RetryingLLMProvider
- OSINT with_retries decorator
- Concurrent investigation limit in API routes
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

from ssi.exceptions import BudgetExceededError, ConcurrentLimitError
from ssi.monitoring import CostTracker


# ---------------------------------------------------------------------------
# CostTracker.check_budget()
# ---------------------------------------------------------------------------


class TestCostBudgetAbort:
    """Verify CostTracker.check_budget() raises on budget exceeded."""

    def test_check_budget_within_budget(self) -> None:
        """No exception when within budget."""
        tracker = CostTracker(budget_usd=1.0)
        tracker.record_api_call("whois")
        tracker.check_budget()  # should not raise

    def test_check_budget_exceeded(self) -> None:
        """Raises BudgetExceededError when total meets or exceeds budget."""
        tracker = CostTracker(budget_usd=0.001)
        # Record enough cloud-model tokens to exceed budget
        tracker.record_llm_tokens("gemini-1.5-pro", input_tokens=10000, output_tokens=5000)
        assert tracker.budget_exceeded is True
        with pytest.raises(BudgetExceededError) as exc_info:
            tracker.check_budget()
        assert exc_info.value.budget_usd == 0.001
        assert exc_info.value.spent_usd > 0.001

    def test_check_budget_unlimited(self) -> None:
        """When budget is 0 (unlimited), check_budget() never raises."""
        tracker = CostTracker(budget_usd=0.0)
        tracker.record_llm_tokens("gemini-1.5-pro", input_tokens=1_000_000, output_tokens=500_000)
        assert tracker.budget_exceeded is False
        tracker.check_budget()  # should not raise


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------


class TestExceptions:
    """Basic exception construction."""

    def test_budget_exceeded_message(self) -> None:
        exc = BudgetExceededError(spent_usd=0.5, budget_usd=0.25)
        assert "0.5000" in str(exc)
        assert "0.2500" in str(exc)

    def test_concurrent_limit_message(self) -> None:
        exc = ConcurrentLimitError(limit=5)
        assert "5" in str(exc)
        assert exc.limit == 5


# ---------------------------------------------------------------------------
# RetryingLLMProvider
# ---------------------------------------------------------------------------


class TestRetryingLLMProvider:
    """Verify exponential-backoff retry on transient errors."""

    def test_succeeds_without_retry(self) -> None:
        from ssi.llm.base import LLMResult
        from ssi.llm.retry import RetryingLLMProvider

        delegate = MagicMock()
        delegate.chat.return_value = LLMResult(content="hello", model="mock")
        provider = RetryingLLMProvider(delegate, max_retries=3, base_delay=0.01)

        result = provider.chat([{"role": "user", "content": "hi"}])
        assert result.content == "hello"
        assert delegate.chat.call_count == 1

    def test_retries_on_connection_error(self) -> None:
        from ssi.llm.base import LLMResult
        from ssi.llm.retry import RetryingLLMProvider

        delegate = MagicMock()
        delegate.chat.side_effect = [
            ConnectionError("refused"),
            LLMResult(content="ok", model="mock"),
        ]
        provider = RetryingLLMProvider(delegate, max_retries=3, base_delay=0.01)

        result = provider.chat([{"role": "user", "content": "hi"}])
        assert result.content == "ok"
        assert delegate.chat.call_count == 2

    def test_raises_after_max_retries(self) -> None:
        from ssi.llm.retry import RetryingLLMProvider

        delegate = MagicMock()
        delegate.chat.side_effect = ConnectionError("always fails")
        provider = RetryingLLMProvider(delegate, max_retries=2, base_delay=0.01)

        with pytest.raises(ConnectionError, match="always fails"):
            provider.chat([{"role": "user", "content": "hi"}])
        assert delegate.chat.call_count == 3  # initial + 2 retries

    def test_no_retry_on_value_error(self) -> None:
        from ssi.llm.retry import RetryingLLMProvider

        delegate = MagicMock()
        delegate.chat.side_effect = ValueError("bad input")
        provider = RetryingLLMProvider(delegate, max_retries=3, base_delay=0.01)

        with pytest.raises(ValueError, match="bad input"):
            provider.chat([{"role": "user", "content": "hi"}])
        assert delegate.chat.call_count == 1  # no retries


# ---------------------------------------------------------------------------
# OSINT with_retries decorator
# ---------------------------------------------------------------------------


class TestOSINTRetryDecorator:
    """Verify the shared with_retries decorator."""

    def test_succeeds_without_retry(self) -> None:
        from ssi.osint import with_retries

        call_count = 0

        @with_retries(max_retries=2, backoff_seconds=0.01)
        def good_func() -> str:
            nonlocal call_count
            call_count += 1
            return "success"

        assert good_func() == "success"
        assert call_count == 1

    def test_retries_and_succeeds(self) -> None:
        from ssi.osint import with_retries

        call_count = 0

        @with_retries(max_retries=2, backoff_seconds=0.01)
        def flaky_func() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ConnectionError("transient")
            return "ok"

        assert flaky_func() == "ok"
        assert call_count == 2

    def test_raises_after_exhausting_retries(self) -> None:
        from ssi.osint import with_retries

        @with_retries(max_retries=1, backoff_seconds=0.01)
        def always_fails() -> str:
            raise RuntimeError("persistent")

        with pytest.raises(RuntimeError, match="persistent"):
            always_fails()

    def test_only_catches_specified_exceptions(self) -> None:
        from ssi.osint import with_retries

        call_count = 0

        @with_retries(max_retries=2, backoff_seconds=0.01, retryable_exceptions=(ConnectionError,))
        def raises_value_error() -> str:
            nonlocal call_count
            call_count += 1
            raise ValueError("not retryable")

        with pytest.raises(ValueError):
            raises_value_error()
        assert call_count == 1  # no retries


# ---------------------------------------------------------------------------
# Concurrent investigation limit (API routes)
# ---------------------------------------------------------------------------


class TestConcurrentLimit:
    """Verify the API rejects requests when at capacity."""

    def test_429_when_at_capacity(self) -> None:
        """Server returns 429 when max_concurrent_investigations is reached."""
        from fastapi.testclient import TestClient

        from ssi.api.app import create_app
        from ssi.api import routes

        # Save originals
        orig_active = routes._ACTIVE_INVESTIGATIONS

        try:
            # Set active to the limit
            with patch.object(routes, "_ACTIVE_INVESTIGATIONS", 5):
                app = create_app()
                with TestClient(app) as client:
                    resp = client.post("/investigate", json={"url": "https://example.com"})
                    assert resp.status_code == 429
                    assert "capacity" in resp.json()["detail"].lower()
        finally:
            routes._ACTIVE_INVESTIGATIONS = orig_active
