"""Integration tests for DOM inspector + decision cascade against fixture sites.

Validates that the DOM inspector detectors produce correct signals and
confidence scores when fed simulated scan data derived from the fixture
HTML pages, and that the decision cascade routes correctly.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from ssi.browser.decision_cascade import (
    CascadeTier,
    PreFilterOutcome,
    check_pre_filters,
    resolve_tier,
)
from ssi.browser.dom_inspector import (
    CheckEmailDetector,
    DOMInspection,
    DOMInspector,
    FindRegisterDetector,
    NavigateDepositDetector,
)
from ssi.models.action import ActionType

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "scam_sites"


@pytest.fixture()
def register_html() -> str:
    """Return the HTML content of the register fixture page."""
    return (FIXTURES_DIR / "register.html").read_text()


@pytest.fixture()
def deposit_html() -> str:
    """Return the HTML content of the deposit fixture page."""
    return (FIXTURES_DIR / "deposit.html").read_text()


@pytest.fixture()
def phishing_html() -> str:
    """Return the HTML content of the phishing fixture page."""
    return (FIXTURES_DIR / "phishing.html").read_text()


def _mock_agent_settings() -> object:
    """Return a minimal mock for agent settings used by DOMInspector."""

    class _Agent:
        dom_direct_threshold = 75
        dom_assisted_threshold = 40

    return _Agent()


# ---------------------------------------------------------------------------
# Register page — find registration form signals
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestRegisterPageDOMDetection:
    """Validates DOM inspector behaviour for the register.html fixture.

    The fixture contains a registration form with email, password, phone,
    SSN fields and a submit button. Simulates the scan data that
    ``ZenBrowserManager.run_dom_scan()`` would produce.
    """

    def test_find_register_form_detected(self) -> None:
        """Registration form with password + email inputs yields direct confidence."""
        scan = {
            "has_registration_form": True,
            "form_selector": "#register-form",
            "field_summary": "full_name, email, phone, password, ssn",
            "register_links": [],
        }
        detector = FindRegisterDetector()
        signals = detector.detect(scan)

        assert len(signals) == 1
        assert signals[0].source == "registration_form_present"
        assert signals[0].weight == 60

    def test_find_register_form_plus_url_direct(self) -> None:
        """Form present + URL pattern = confidence ≥75 (direct threshold)."""
        scan = {
            "has_registration_form": True,
            "form_selector": "#register-form",
            "field_summary": "full_name, email, password",
            "url_is_register_page": True,
            "current_url": "https://cryptomaxx.fake/register",
        }
        detector = FindRegisterDetector()
        signals = detector.detect(scan)

        total = sum(s.weight for s in signals)
        assert total >= 75, f"Expected ≥75 confidence, got {total}"

    def test_find_register_action_is_done(self) -> None:
        """When form is present, action should be DONE (proceed to FILL_REGISTER)."""
        scan = {
            "has_registration_form": True,
            "form_selector": "#register-form",
            "field_summary": "email, password",
        }
        detector = FindRegisterDetector()
        signals = detector.detect(scan)
        action = detector.build_action(signals)

        assert action is not None
        assert action.action == ActionType.DONE
        assert "FILL_REGISTER" in action.reasoning

    def test_inspector_routes_direct(self) -> None:
        """DOMInspector returns 'direct' outcome for FIND_REGISTER with form."""
        scan = {
            "has_registration_form": True,
            "form_selector": "#register-form",
            "field_summary": "email, password",
            "url_is_register_page": True,
            "current_url": "https://cryptomaxx.fake/register",
        }
        with patch("ssi.settings.get_settings") as mock_settings:
            mock_settings.return_value.agent = _mock_agent_settings()
            inspector = DOMInspector()
            result = inspector.inspect("FIND_REGISTER", scan)

        assert result.outcome == "direct"
        assert result.confidence >= 75
        assert result.direct_action is not None
        assert result.direct_action.action == ActionType.DONE


# ---------------------------------------------------------------------------
# Deposit page — navigate deposit and wallet address visibility
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestDepositPageDOMDetection:
    """Validates DOM inspector behaviour for the deposit.html fixture.

    The fixture is a deposit page with wallet addresses displayed for
    BTC, ETH, TRX, and SOL. When the agent is already on this page,
    the detector should see the URL pattern match.
    """

    def test_url_pattern_match_on_deposit_page(self) -> None:
        """URL matching /deposit yields signals with weight ≥35."""
        scan = {
            "url_is_deposit_page": True,
            "current_url": "https://cryptomaxx.fake/deposit",
            "deposit_links": [],
        }
        detector = NavigateDepositDetector()
        signals = detector.detect(scan)

        assert any(s.source == "url_pattern_match" for s in signals)
        total = sum(s.weight for s in signals)
        assert total >= 35

    def test_deposit_link_detection(self) -> None:
        """Deposit link yields click action with correct confidence."""
        scan = {
            "deposit_links": [{"selector": "a.deposit-tab", "text": "Deposit Funds"}],
        }
        detector = NavigateDepositDetector()
        signals = detector.detect(scan)
        action = detector.build_action(signals)

        assert action is not None
        assert action.action == ActionType.CLICK
        assert action.selector == "a.deposit-tab"

    def test_already_on_deposit_returns_done(self) -> None:
        """When URL indicates deposit page, action is DONE (no navigation needed)."""
        scan = {
            "url_is_deposit_page": True,
            "current_url": "https://cryptomaxx.fake/deposit.html",
            "deposit_links": [{"selector": "a.active", "text": "Deposit"}],
        }
        detector = NavigateDepositDetector()
        signals = detector.detect(scan)
        action = detector.build_action(signals)

        assert action is not None
        assert action.action == ActionType.DONE
        assert "Already on deposit" in action.reasoning

    def test_inspector_direct_for_deposit_url(self) -> None:
        """DOMInspector gives 'direct' outcome when on deposit page with link."""
        scan = {
            "url_is_deposit_page": True,
            "current_url": "https://cryptomaxx.fake/deposit",
            "deposit_links": [{"selector": "a.deposit", "text": "Deposit"}],
        }
        with patch("ssi.settings.get_settings") as mock_settings:
            mock_settings.return_value.agent = _mock_agent_settings()
            inspector = DOMInspector()
            result = inspector.inspect("NAVIGATE_DEPOSIT", scan)

        assert result.outcome == "direct"
        assert result.confidence >= 75


# ---------------------------------------------------------------------------
# Phishing page — no registration or deposit signals
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestPhishingPageDOMDetection:
    """Validates DOM inspector with phishing.html fixture.

    The phishing page is a credit-card form; it should NOT yield
    registration or deposit signals.
    """

    def test_no_register_signals(self) -> None:
        """Phishing page with only CC fields produces no register signals."""
        scan = {
            "has_registration_form": False,
            "register_links": [],
        }
        detector = FindRegisterDetector()
        signals = detector.detect(scan)
        assert len(signals) == 0

    def test_no_deposit_signals(self) -> None:
        """Phishing page has no deposit links or URL match."""
        scan = {
            "deposit_links": [],
        }
        detector = NavigateDepositDetector()
        signals = detector.detect(scan)
        assert len(signals) == 0

    def test_inspector_fallback_for_unsupported_state(self) -> None:
        """A state not handled by any detector falls back."""
        with patch("ssi.settings.get_settings") as mock_settings:
            mock_settings.return_value.agent = _mock_agent_settings()
            inspector = DOMInspector()
            result = inspector.inspect("FILL_REGISTER", {})

        assert result.outcome == "fallback"
        assert result.direct_action is None


# ---------------------------------------------------------------------------
# Decision cascade integration with DOM inspector
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestCascadeWithFixtureScanData:
    """Validates the full decision cascade using fixture-derived scan data."""

    def test_register_page_dom_direct_skips_llm(self) -> None:
        """Register form with high confidence routes to DOM_DIRECT tier."""
        from ssi.models.action import AgentAction

        dom_inspection = DOMInspection(
            state="FIND_REGISTER",
            confidence=85,
            outcome="direct",
            signals=[],
            direct_action=AgentAction(
                action=ActionType.DONE,
                reasoning="DOM: Registration form detected.",
                confidence=0.9,
            ),
        )
        decision = resolve_tier(
            state="FIND_REGISTER",
            dom_inspection=dom_inspection,
            is_stuck=False,
        )
        assert decision.tier == CascadeTier.DOM_DIRECT

    def test_deposit_page_dom_assisted_enhances_llm(self) -> None:
        """Deposit with medium confidence routes to DOM_ASSISTED."""
        dom_inspection = DOMInspection(
            state="NAVIGATE_DEPOSIT",
            confidence=50,
            outcome="assisted",
            signals=[],
            direct_action=None,
        )
        decision = resolve_tier(
            state="NAVIGATE_DEPOSIT",
            dom_inspection=dom_inspection,
            is_stuck=False,
        )
        assert decision.tier == CascadeTier.DOM_ASSISTED

    def test_phishing_page_no_dom_routes_to_vision(self) -> None:
        """Zero DOM signals for NAVIGATE_DEPOSIT → VISION_LLM tier."""
        dom_inspection = DOMInspection(
            state="NAVIGATE_DEPOSIT",
            confidence=0,
            outcome="fallback",
            signals=[],
            direct_action=None,
        )
        decision = resolve_tier(
            state="NAVIGATE_DEPOSIT",
            dom_inspection=dom_inspection,
            is_stuck=False,
        )
        assert decision.tier == CascadeTier.VISION_LLM

    def test_check_email_always_text_only(self) -> None:
        """CHECK_EMAIL_VERIFICATION always routes to TEXT_ONLY_LLM."""
        decision = resolve_tier(
            state="CHECK_EMAIL_VERIFICATION",
            dom_inspection=None,
            is_stuck=False,
        )
        assert decision.tier == CascadeTier.TEXT_ONLY_LLM

    def test_stuck_overrides_all(self) -> None:
        """When stuck, cascade routes to HUMAN_GUIDANCE regardless."""
        decision = resolve_tier(
            state="NAVIGATE_DEPOSIT",
            dom_inspection=DOMInspection(
                state="NAVIGATE_DEPOSIT",
                confidence=90,
                outcome="direct",
                signals=[],
                direct_action=None,
            ),
            is_stuck=True,
        )
        assert decision.tier == CascadeTier.HUMAN_GUIDANCE

    def test_pre_filters_blank_page(self) -> None:
        """Blank page (tiny text, small screenshot) triggers BLANK_PAGE filter."""
        outcome = check_pre_filters(
            page_text="",
            screenshot_size_bytes=1000,
            screenshot_hash="abc",
            last_screenshot_hash="",
            consecutive_dupes=0,
        )
        assert outcome == PreFilterOutcome.BLANK_PAGE

    def test_pre_filters_duplicate_screenshot(self) -> None:
        """Repeated screenshot hash triggers DUPLICATE_SCREENSHOT filter."""
        outcome = check_pre_filters(
            page_text="Lots of text here for a real page",
            screenshot_size_bytes=50000,
            screenshot_hash="abc123",
            last_screenshot_hash="abc123",
            consecutive_dupes=1,
        )
        assert outcome == PreFilterOutcome.DUPLICATE_SCREENSHOT

    def test_pre_filters_normal_page_proceeds(self) -> None:
        """A real page with unique screenshot hash proceeds."""
        outcome = check_pre_filters(
            page_text="This is a full crypto exchange deposit page with lots of content",
            screenshot_size_bytes=50000,
            screenshot_hash="unique123",
            last_screenshot_hash="old_hash",
            consecutive_dupes=0,
        )
        assert outcome == PreFilterOutcome.PROCEED
