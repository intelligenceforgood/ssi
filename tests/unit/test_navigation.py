"""Unit tests for ssi.browser.navigation — resilient goto / reload."""

from __future__ import annotations

from unittest.mock import MagicMock, call, patch

import pytest
from playwright.sync_api import TimeoutError as PlaywrightTimeout

from ssi.browser.navigation import (
    _build_fallback_chain,
    resilient_goto,
    resilient_reload,
)


# ---------------------------------------------------------------------------
# _build_fallback_chain
# ---------------------------------------------------------------------------

class TestBuildFallbackChain:
    """Tests for the internal fallback-chain builder."""

    def test_networkidle_produces_full_chain(self) -> None:
        assert _build_fallback_chain("networkidle") == [
            "networkidle",
            "load",
            "domcontentloaded",
        ]

    def test_load_skips_networkidle(self) -> None:
        assert _build_fallback_chain("load") == ["load", "domcontentloaded"]

    def test_domcontentloaded_is_terminal(self) -> None:
        assert _build_fallback_chain("domcontentloaded") == ["domcontentloaded"]

    def test_unknown_strategy_prepends_to_chain(self) -> None:
        chain = _build_fallback_chain("commit")
        assert chain[0] == "commit"
        assert "networkidle" in chain


# ---------------------------------------------------------------------------
# resilient_goto
# ---------------------------------------------------------------------------

class TestResilientGoto:
    """Tests for resilient_goto."""

    def test_success_on_first_try(self) -> None:
        """Returns immediately when networkidle succeeds."""
        page = MagicMock()
        sentinel = MagicMock(name="response")
        page.goto.return_value = sentinel

        result = resilient_goto(page, "https://example.com", timeout_ms=5000)

        assert result is sentinel
        page.goto.assert_called_once_with(
            "https://example.com", wait_until="networkidle", timeout=5000
        )

    def test_fallback_to_load_on_timeout(self) -> None:
        """Falls back to 'load' when 'networkidle' times out."""
        page = MagicMock()
        sentinel = MagicMock(name="response")
        page.goto.side_effect = [
            PlaywrightTimeout("timeout"),
            sentinel,
        ]

        result = resilient_goto(page, "https://example.com", timeout_ms=5000)

        assert result is sentinel
        assert page.goto.call_count == 2
        page.goto.assert_any_call(
            "https://example.com", wait_until="networkidle", timeout=5000
        )
        page.goto.assert_any_call(
            "https://example.com", wait_until="load", timeout=5000
        )

    def test_fallback_to_domcontentloaded(self) -> None:
        """Falls through networkidle → load → domcontentloaded."""
        page = MagicMock()
        sentinel = MagicMock(name="response")
        page.goto.side_effect = [
            PlaywrightTimeout("timeout1"),
            PlaywrightTimeout("timeout2"),
            sentinel,
        ]

        result = resilient_goto(page, "https://example.com")

        assert result is sentinel
        assert page.goto.call_count == 3

    def test_raises_when_all_strategies_fail(self) -> None:
        """Raises PlaywrightTimeout if every strategy times out."""
        page = MagicMock()
        page.goto.side_effect = PlaywrightTimeout("all failed")

        with pytest.raises(PlaywrightTimeout):
            resilient_goto(page, "https://example.com")

        # Should have tried all 3 strategies
        assert page.goto.call_count == 3

    def test_custom_wait_until(self) -> None:
        """Respects a non-default wait_until preference."""
        page = MagicMock()
        page.goto.return_value = MagicMock()

        resilient_goto(page, "https://example.com", wait_until="load")

        page.goto.assert_called_once_with(
            "https://example.com", wait_until="load", timeout=30_000
        )


# ---------------------------------------------------------------------------
# resilient_reload
# ---------------------------------------------------------------------------

class TestResilientReload:
    """Tests for resilient_reload."""

    def test_success_on_first_try(self) -> None:
        page = MagicMock()
        sentinel = MagicMock(name="response")
        page.reload.return_value = sentinel

        result = resilient_reload(page, timeout_ms=10_000)

        assert result is sentinel
        page.reload.assert_called_once_with(
            wait_until="networkidle", timeout=10_000
        )

    def test_fallback_on_timeout(self) -> None:
        page = MagicMock()
        sentinel = MagicMock(name="response")
        page.reload.side_effect = [
            PlaywrightTimeout("timeout"),
            sentinel,
        ]

        result = resilient_reload(page, timeout_ms=10_000)

        assert result is sentinel
        assert page.reload.call_count == 2

    def test_raises_when_all_fail(self) -> None:
        page = MagicMock()
        page.reload.side_effect = PlaywrightTimeout("all failed")

        with pytest.raises(PlaywrightTimeout):
            resilient_reload(page)

        assert page.reload.call_count == 3
