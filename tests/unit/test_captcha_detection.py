"""CAPTCHA detection and handling tests — Task 1.4 of SSI roadmap Phase 1.

Validates:
  - ``detect_captcha()`` identifies reCAPTCHA v2/v3, hCaptcha, Turnstile,
    FunCaptcha, and text-based CAPTCHA phrases from fixture HTML.
  - ``handle_captcha()`` degrades gracefully under each strategy.
  - The pipeline continues with partial results when CAPTCHAs are encountered.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ssi.browser.captcha import (
    CaptchaDetection,
    CaptchaResult,
    CaptchaStrategy,
    CaptchaType,
    _CAPTCHA_SIGNATURES,
    detect_captcha,
    handle_captcha,
)

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "scam_sites"


# ---------------------------------------------------------------------------
# Helpers — mock Playwright Page that returns fixture HTML
# ---------------------------------------------------------------------------


def _mock_page_from_html(html_path: Path) -> MagicMock:
    """Create a mock Playwright Page whose DOM matches *html_path*.

    The mock supports ``page.locator(selector).count()`` and
    ``page.inner_text("body")``.
    """
    html = html_path.read_text() if html_path.exists() else ""
    page = MagicMock()
    page.url = f"file://{html_path}"

    def locator_factory(selector: str) -> MagicMock:
        loc = MagicMock()
        # Simple heuristic: check if the CSS selector's key substring
        # appears in the HTML source.
        key = _extract_selector_key(selector)
        loc.count.return_value = 1 if key and key in html else 0
        return loc

    page.locator.side_effect = locator_factory
    page.inner_text.return_value = _extract_body_text(html)
    return page


def _extract_selector_key(selector: str) -> str:
    """Extract the most unique substring from a CSS selector for matching.

    Examples:
        ``iframe[src*="hcaptcha.com"]`` → ``hcaptcha.com``
        ``.g-recaptcha`` → ``g-recaptcha``
        ``#funcaptcha`` → ``funcaptcha``
    """
    import re

    # iframe[src*="..."] → extract quoted substring
    m = re.search(r'src\*="([^"]+)"', selector)
    if m:
        return m.group(1)
    # .classname → strip leading dot
    if selector.startswith("."):
        return selector[1:]
    # #id → strip leading hash
    if selector.startswith("#"):
        return selector[1:]
    return selector


def _extract_body_text(html: str) -> str:
    """Cheaply extract text between <body> tags for phrase matching."""
    import re

    m = re.search(r"<body[^>]*>(.*)</body>", html, re.DOTALL | re.IGNORECASE)
    return m.group(1).lower() if m else html.lower()


# ---------------------------------------------------------------------------
# Task 1.4a — CAPTCHA detection from fixture HTML
# ---------------------------------------------------------------------------


class TestCaptchaDetectionFromFixtures:
    """Detect CAPTCHAs from fixture HTML files."""

    def test_detect_recaptcha(self) -> None:
        """reCAPTCHA v2 fixture contains g-recaptcha class."""
        page = _mock_page_from_html(FIXTURES_DIR / "captcha_recaptcha.html")
        detection = detect_captcha(page)
        assert detection.detected is True
        assert detection.captcha_type in (CaptchaType.RECAPTCHA_V2, CaptchaType.RECAPTCHA_V3)

    def test_detect_hcaptcha(self) -> None:
        """hCaptcha fixture contains h-captcha class."""
        page = _mock_page_from_html(FIXTURES_DIR / "captcha_hcaptcha.html")
        detection = detect_captcha(page)
        assert detection.detected is True
        assert detection.captcha_type == CaptchaType.HCAPTCHA

    def test_detect_turnstile(self) -> None:
        """Turnstile fixture contains cf-turnstile class."""
        page = _mock_page_from_html(FIXTURES_DIR / "captcha_turnstile.html")
        detection = detect_captcha(page)
        assert detection.detected is True
        assert detection.captcha_type == CaptchaType.CLOUDFLARE_TURNSTILE

    def test_no_captcha_on_plain_page(self) -> None:
        """A non-CAPTCHA scam page returns detected=False."""
        page = _mock_page_from_html(FIXTURES_DIR / "fake_shop.html")
        detection = detect_captcha(page)
        assert detection.detected is False
        assert detection.captcha_type == CaptchaType.UNKNOWN

    def test_text_captcha_phrase_fallback(self) -> None:
        """Falls back to text phrase matching when no DOM signature found."""
        page = MagicMock()
        page.url = "https://suspicious.example.com"
        page.locator.return_value.count.return_value = 0
        page.inner_text.return_value = "please verify you are human before continuing"

        detection = detect_captcha(page)
        assert detection.detected is True
        assert detection.captcha_type == CaptchaType.UNKNOWN

    def test_all_captcha_signatures_have_types(self) -> None:
        """Verify that every entry in _CAPTCHA_SIGNATURES has a valid type."""
        for selector, captcha_type in _CAPTCHA_SIGNATURES:
            assert isinstance(selector, str)
            assert isinstance(captcha_type, CaptchaType)
            assert captcha_type != CaptchaType.UNKNOWN


# ---------------------------------------------------------------------------
# Task 1.4b — handle_captcha() graceful degradation
# ---------------------------------------------------------------------------


class TestCaptchaHandling:
    """Verify handle_captcha() degrades gracefully under each strategy."""

    @pytest.fixture()
    def detected_recaptcha(self) -> CaptchaDetection:
        """A pre-built detection for reCAPTCHA v2."""
        return CaptchaDetection(
            detected=True,
            captcha_type=CaptchaType.RECAPTCHA_V2,
            element_selector=".g-recaptcha",
            page_url="https://scam.test/login",
        )

    @pytest.fixture()
    def detected_turnstile(self) -> CaptchaDetection:
        """A pre-built detection for Cloudflare Turnstile."""
        return CaptchaDetection(
            detected=True,
            captcha_type=CaptchaType.CLOUDFLARE_TURNSTILE,
            element_selector=".cf-turnstile",
            page_url="https://scam.test/verify",
        )

    def test_skip_strategy_returns_unsolved(self, detected_recaptcha: CaptchaDetection) -> None:
        """SKIP strategy logs and returns solved=False."""
        page = MagicMock()
        result = handle_captcha(page, detected_recaptcha, strategy=CaptchaStrategy.SKIP)

        assert result.strategy_used == CaptchaStrategy.SKIP
        assert result.solved is False
        assert result.error == ""

    def test_skip_captures_screenshot(
        self, detected_recaptcha: CaptchaDetection, tmp_path: Path
    ) -> None:
        """SKIP strategy still captures evidence screenshot."""
        page = MagicMock()
        result = handle_captcha(
            page,
            detected_recaptcha,
            strategy=CaptchaStrategy.SKIP,
            screenshot_dir=tmp_path,
        )
        page.screenshot.assert_called_once()

    def test_solver_without_api_key_falls_back(self, detected_recaptcha: CaptchaDetection) -> None:
        """SOLVER strategy without API key degrades to SKIP."""
        page = MagicMock()
        result = handle_captcha(
            page,
            detected_recaptcha,
            strategy=CaptchaStrategy.SOLVER,
            solver_api_key="",
        )
        assert result.strategy_used == CaptchaStrategy.SKIP
        assert result.solved is False
        assert "No solver API key" in result.error

    def test_solver_with_key_returns_stub_error(self, detected_recaptcha: CaptchaDetection) -> None:
        """SOLVER strategy with API key returns stub 'not implemented' error."""
        page = MagicMock()
        result = handle_captcha(
            page,
            detected_recaptcha,
            strategy=CaptchaStrategy.SOLVER,
            solver_api_key="test-key-123",
        )
        assert result.solved is False
        assert "not yet implemented" in result.error.lower()

    def test_no_captcha_returns_solved(self) -> None:
        """handle_captcha with detected=False returns solved=True immediately."""
        page = MagicMock()
        no_detection = CaptchaDetection(detected=False)
        result = handle_captcha(page, no_detection)
        assert result.solved is True

    @patch("time.sleep")
    def test_wait_strategy_rechecks(self, mock_sleep: MagicMock, detected_turnstile: CaptchaDetection) -> None:
        """WAIT strategy sleeps and rechecks for CAPTCHA resolution."""
        page = MagicMock()
        # After waiting, CAPTCHA is gone (locator returns 0)
        page.locator.return_value.count.return_value = 0
        page.inner_text.return_value = "Welcome to the site"
        page.url = "https://scam.test/verify"

        result = handle_captcha(
            page,
            detected_turnstile,
            strategy=CaptchaStrategy.WAIT,
            wait_seconds=5.0,
        )
        mock_sleep.assert_called_once_with(5.0)
        assert result.wait_seconds == 5.0
        assert result.solved is True

    @patch("time.sleep")
    def test_wait_strategy_captcha_persists(self, mock_sleep: MagicMock, detected_turnstile: CaptchaDetection) -> None:
        """WAIT strategy returns solved=False when CAPTCHA persists after wait."""
        page = MagicMock()
        # CAPTCHA still present after waiting
        page.locator.return_value.count.return_value = 1
        page.inner_text.return_value = "checking your browser"
        page.url = "https://scam.test/verify"

        result = handle_captcha(
            page,
            detected_turnstile,
            strategy=CaptchaStrategy.WAIT,
            wait_seconds=3.0,
        )
        assert result.solved is False


# ---------------------------------------------------------------------------
# Task 1.4c — CAPTCHA model validation
# ---------------------------------------------------------------------------


class TestCaptchaModels:
    """Verify CAPTCHA data models are correct."""

    def test_captcha_type_values(self) -> None:
        """All expected CaptchaType values exist."""
        expected = {"recaptcha_v2", "recaptcha_v3", "hcaptcha", "cloudflare_turnstile", "funcaptcha", "text_captcha", "unknown"}
        actual = {ct.value for ct in CaptchaType}
        assert expected == actual

    def test_captcha_strategy_values(self) -> None:
        """All expected CaptchaStrategy values exist."""
        expected = {"skip", "wait", "solver", "accessibility"}
        actual = {cs.value for cs in CaptchaStrategy}
        assert expected == actual

    def test_detection_defaults(self) -> None:
        """Default CaptchaDetection is not detected."""
        d = CaptchaDetection()
        assert d.detected is False
        assert d.captcha_type == CaptchaType.UNKNOWN

    def test_result_defaults(self) -> None:
        """Default CaptchaResult uses SKIP strategy."""
        r = CaptchaResult()
        assert r.strategy_used == CaptchaStrategy.SKIP
        assert r.solved is False
        assert r.wait_seconds == 0.0
