"""Unit tests for the decision cascade routing logic.

Tests the formalized four-tier cascade: Playbook → DOM → Text-only LLM →
Vision LLM → Human Guidance, plus pre-filter checks (blank page,
screenshot dedup).
"""

from __future__ import annotations

import pytest

from ssi.browser.decision_cascade import (
    CascadeDecision,
    CascadeTier,
    PreFilterOutcome,
    check_pre_filters,
    resolve_tier,
)
from ssi.browser.dom_inspector import DOMInspection, DOMSignal
from ssi.models.action import ActionType, AgentAction


# ---------------------------------------------------------------------------
# Pre-filter tests
# ---------------------------------------------------------------------------


class TestPreFilters:
    """Tests for blank-page and screenshot-dedup pre-filters."""

    def test_blank_page_detected(self) -> None:
        """Page with minimal text and tiny screenshot triggers BLANK_PAGE."""
        result = check_pre_filters(
            page_text="   ",
            screenshot_size_bytes=3000,
            screenshot_hash="abc123",
            last_screenshot_hash="xyz789",
            consecutive_dupes=0,
        )
        assert result == PreFilterOutcome.BLANK_PAGE

    def test_non_blank_page_proceeds(self) -> None:
        """Page with sufficient text proceeds through the cascade."""
        result = check_pre_filters(
            page_text="Welcome to our trading platform. Register now!",
            screenshot_size_bytes=50000,
            screenshot_hash="abc123",
            last_screenshot_hash="xyz789",
            consecutive_dupes=0,
        )
        assert result == PreFilterOutcome.PROCEED

    def test_duplicate_screenshot_detected(self) -> None:
        """Unchanged screenshot hash triggers DUPLICATE_SCREENSHOT."""
        result = check_pre_filters(
            page_text="Some page content here",
            screenshot_size_bytes=50000,
            screenshot_hash="same_hash",
            last_screenshot_hash="same_hash",
            consecutive_dupes=1,
        )
        assert result == PreFilterOutcome.DUPLICATE_SCREENSHOT

    def test_different_screenshot_proceeds(self) -> None:
        """Changed screenshot hash allows normal cascade routing."""
        result = check_pre_filters(
            page_text="Some page content here",
            screenshot_size_bytes=50000,
            screenshot_hash="new_hash",
            last_screenshot_hash="old_hash",
            consecutive_dupes=0,
        )
        assert result == PreFilterOutcome.PROCEED

    def test_blank_page_text_boundary(self) -> None:
        """Exactly 20 chars of stripped text is NOT blank."""
        result = check_pre_filters(
            page_text="12345678901234567890",  # 20 chars
            screenshot_size_bytes=3000,
            screenshot_hash="abc",
            last_screenshot_hash="xyz",
            consecutive_dupes=0,
        )
        assert result == PreFilterOutcome.PROCEED

    def test_blank_page_screenshot_boundary(self) -> None:
        """Exactly 5000 bytes screenshot with short text is NOT blank."""
        result = check_pre_filters(
            page_text="hi",
            screenshot_size_bytes=5000,
            screenshot_hash="abc",
            last_screenshot_hash="xyz",
            consecutive_dupes=0,
        )
        assert result == PreFilterOutcome.PROCEED


# ---------------------------------------------------------------------------
# Cascade tier routing tests
# ---------------------------------------------------------------------------


class TestResolveTier:
    """Tests for the main cascade routing function."""

    def test_stuck_triggers_human_guidance(self) -> None:
        """When agent is stuck, the human guidance tier is selected."""
        decision = resolve_tier(state="FIND_REGISTER", is_stuck=True)
        assert decision.tier == CascadeTier.HUMAN_GUIDANCE
        assert "Stuck" in decision.reason

    def test_dom_direct_with_high_confidence(self) -> None:
        """DOM inspection with direct outcome selects DOM_DIRECT tier."""
        dom = DOMInspection(
            state="FIND_REGISTER",
            confidence=80,
            outcome="direct",
            signals=[DOMSignal(source="registration_form_present", weight=60, selector="form")],
            direct_action=AgentAction(action=ActionType.DONE, reasoning="Form found"),
        )
        decision = resolve_tier(
            state="FIND_REGISTER",
            dom_inspection=dom,
        )
        assert decision.tier == CascadeTier.DOM_DIRECT
        assert decision.include_screenshot is False
        assert "DOM direct" in decision.reason

    def test_dom_assisted_with_medium_confidence(self) -> None:
        """DOM inspection with assisted outcome injects context into LLM."""
        dom = DOMInspection(
            state="FIND_REGISTER",
            confidence=50,
            outcome="assisted",
            signals=[DOMSignal(source="register_link_found", weight=40, value="Sign Up")],
            direct_action=None,
            context_summary="DOM PRE-SCAN [FIND_REGISTER] confidence=50/100",
        )
        decision = resolve_tier(
            state="FIND_REGISTER",
            dom_inspection=dom,
        )
        assert decision.tier == CascadeTier.DOM_ASSISTED
        assert decision.include_screenshot is True
        assert decision.extra_context  # Has context summary

    def test_dom_fallback_with_low_confidence(self) -> None:
        """DOM inspection with fallback outcome routes to vision LLM."""
        dom = DOMInspection(
            state="FIND_REGISTER",
            confidence=10,
            outcome="fallback",
            signals=[],
            direct_action=None,
        )
        decision = resolve_tier(
            state="FIND_REGISTER",
            dom_inspection=dom,
        )
        assert decision.tier == CascadeTier.VISION_LLM

    def test_dom_skipped_when_disabled(self) -> None:
        """DOM inspection is skipped when disabled in settings."""
        dom = DOMInspection(
            state="FIND_REGISTER",
            confidence=90,
            outcome="direct",
            signals=[DOMSignal(source="form", weight=60)],
            direct_action=AgentAction(action=ActionType.DONE, reasoning="Form"),
        )
        decision = resolve_tier(
            state="FIND_REGISTER",
            dom_inspection=dom,
            dom_inspection_enabled=False,
        )
        assert decision.tier == CascadeTier.VISION_LLM

    def test_dom_skipped_for_non_inspectable_states(self) -> None:
        """DOM inspection is not attempted for states like FILL_REGISTER."""
        dom = DOMInspection(
            state="FILL_REGISTER",
            confidence=90,
            outcome="direct",
            signals=[],
            direct_action=AgentAction(action=ActionType.DONE, reasoning="x"),
        )
        decision = resolve_tier(
            state="FILL_REGISTER",
            dom_inspection=dom,
        )
        assert decision.tier == CascadeTier.VISION_LLM

    def test_check_email_is_text_only(self) -> None:
        """CHECK_EMAIL_VERIFICATION always uses text-only (no screenshot)."""
        decision = resolve_tier(state="CHECK_EMAIL_VERIFICATION")
        assert decision.tier == CascadeTier.TEXT_ONLY_LLM
        assert decision.include_screenshot is False

    def test_submit_register_text_only_after_first_action(self) -> None:
        """SUBMIT_REGISTER switches to text-only after the initial action."""
        decision = resolve_tier(state="SUBMIT_REGISTER", actions_in_state=1)
        assert decision.tier == CascadeTier.TEXT_ONLY_LLM
        assert decision.include_screenshot is False

    def test_submit_register_vision_on_first_action(self) -> None:
        """SUBMIT_REGISTER uses vision on the very first action."""
        decision = resolve_tier(state="SUBMIT_REGISTER", actions_in_state=0)
        assert decision.tier == CascadeTier.VISION_LLM

    def test_extract_wallets_text_only_with_js_wallets(self) -> None:
        """EXTRACT_WALLETS uses text-only when JS wallets were already found."""
        decision = resolve_tier(state="EXTRACT_WALLETS", js_wallets_found=True)
        assert decision.tier == CascadeTier.TEXT_ONLY_LLM

    def test_extract_wallets_vision_without_js_wallets(self) -> None:
        """EXTRACT_WALLETS uses vision when no JS wallets were found."""
        decision = resolve_tier(state="EXTRACT_WALLETS", js_wallets_found=False)
        assert decision.tier == CascadeTier.VISION_LLM

    def test_navigate_deposit_default_is_vision(self) -> None:
        """NAVIGATE_DEPOSIT defaults to full vision when DOM has no result."""
        decision = resolve_tier(state="NAVIGATE_DEPOSIT")
        assert decision.tier == CascadeTier.VISION_LLM
        assert decision.include_screenshot is True

    def test_navigate_deposit_dom_direct(self) -> None:
        """NAVIGATE_DEPOSIT with strong DOM signal uses direct action."""
        dom = DOMInspection(
            state="NAVIGATE_DEPOSIT",
            confidence=80,
            outcome="direct",
            signals=[DOMSignal(source="deposit_link_found", weight=40, selector="a.deposit")],
            direct_action=AgentAction(
                action=ActionType.CLICK, selector="a.deposit", reasoning="Deposit link"
            ),
        )
        decision = resolve_tier(state="NAVIGATE_DEPOSIT", dom_inspection=dom)
        assert decision.tier == CascadeTier.DOM_DIRECT

    def test_unknown_state_defaults_to_vision(self) -> None:
        """Unknown/new states default to full vision analysis."""
        decision = resolve_tier(state="SOME_FUTURE_STATE")
        assert decision.tier == CascadeTier.VISION_LLM

    def test_stuck_overrides_dom(self) -> None:
        """Stuck status takes precedence over a valid DOM inspection."""
        dom = DOMInspection(
            state="FIND_REGISTER",
            confidence=95,
            outcome="direct",
            signals=[DOMSignal(source="form", weight=60)],
            direct_action=AgentAction(action=ActionType.DONE, reasoning="Form found"),
        )
        decision = resolve_tier(
            state="FIND_REGISTER",
            dom_inspection=dom,
            is_stuck=True,
        )
        assert decision.tier == CascadeTier.HUMAN_GUIDANCE


# ---------------------------------------------------------------------------
# DOM Inspector detector tests
# ---------------------------------------------------------------------------


class TestDOMInspectorDetectors:
    """Tests for individual DOM detector components."""

    def test_find_register_form_present_high_confidence(self) -> None:
        """Registration form detection produces high confidence."""
        from ssi.browser.dom_inspector import DOMInspector

        inspector = DOMInspector()
        result = inspector.inspect(
            "FIND_REGISTER",
            {"has_registration_form": True, "form_selector": "form#register", "field_summary": "email, password"},
        )
        assert result.confidence >= 60
        assert result.outcome == "direct" or result.outcome == "assisted"

    def test_find_register_link_only_medium_confidence(self) -> None:
        """Register link without form produces medium confidence."""
        from ssi.browser.dom_inspector import DOMInspector

        inspector = DOMInspector()
        result = inspector.inspect(
            "FIND_REGISTER",
            {"register_links": [{"selector": "a.register", "text": "Register"}]},
        )
        assert 40 <= result.confidence < 75
        assert result.outcome == "assisted"

    def test_find_register_no_signals_fallback(self) -> None:
        """Empty scan data produces fallback outcome."""
        from ssi.browser.dom_inspector import DOMInspector

        inspector = DOMInspector()
        result = inspector.inspect("FIND_REGISTER", {})
        assert result.confidence == 0
        assert result.outcome == "fallback"

    def test_check_email_always_direct(self) -> None:
        """CHECK_EMAIL_VERIFICATION always returns a direct action."""
        from ssi.browser.dom_inspector import DOMInspector

        inspector = DOMInspector()
        result = inspector.inspect(
            "CHECK_EMAIL_VERIFICATION",
            {"dashboard_text_found": True, "dashboard_snippet": "Dashboard"},
        )
        assert result.outcome == "direct"
        assert result.direct_action is not None
        assert result.direct_action.action == ActionType.DONE

    def test_check_email_verify_required(self) -> None:
        """Email verification text triggers STUCK action."""
        from ssi.browser.dom_inspector import DOMInspector

        inspector = DOMInspector()
        result = inspector.inspect(
            "CHECK_EMAIL_VERIFICATION",
            {"email_verify_text_found": True, "email_verify_snippet": "Please verify your email"},
        )
        assert result.outcome == "direct"
        assert result.direct_action is not None
        assert result.direct_action.action == ActionType.STUCK

    def test_navigate_deposit_link_found(self) -> None:
        """Deposit link produces an assisted or direct action."""
        from ssi.browser.dom_inspector import DOMInspector

        inspector = DOMInspector()
        result = inspector.inspect(
            "NAVIGATE_DEPOSIT",
            {"deposit_links": [{"selector": "a.deposit", "text": "Deposit"}]},
        )
        assert result.confidence >= 40

    def test_unsupported_state_returns_fallback(self) -> None:
        """States without a detector return zero-confidence fallback."""
        from ssi.browser.dom_inspector import DOMInspector

        inspector = DOMInspector()
        result = inspector.inspect("FILL_REGISTER", {})
        assert result.confidence == 0
        assert result.outcome == "fallback"
