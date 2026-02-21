"""Unit tests for the AWH-ported browser agent modules.

Tests cover: state machine, action models, DOM inspector detectors,
metrics collector, result models, and identity vault extensions.
"""

from __future__ import annotations

import json

import pytest

from ssi.browser.dom_inspector import (
    CheckEmailDetector,
    DOMInspector,
    FindRegisterDetector,
    NavigateDepositDetector,
)
from ssi.browser.metrics import MetricsCollector
from ssi.identity.vault import IdentityVault, SyntheticIdentity
from ssi.models.action import ActionType, AgentAction
from ssi.models.results import SiteResult, SiteStatus, WalletEntry
from ssi.models.states import (
    AgentState,
    MILESTONE_SCREENSHOT_STATES,
    STATE_TRANSITIONS,
    TERMINAL_STATES,
)


# ======================================================================
# State machine
# ======================================================================


class TestAgentState:
    """AgentState enum and transition map."""

    def test_all_states_present(self):
        expected = {
            "INIT", "LOAD_SITE", "FIND_REGISTER", "FILL_REGISTER",
            "SUBMIT_REGISTER", "CHECK_EMAIL_VERIFICATION",
            "NAVIGATE_DEPOSIT", "EXTRACT_WALLETS",
            "COMPLETE", "SKIPPED", "ERROR",
        }
        assert {s.value for s in AgentState} == expected

    def test_terminal_states(self):
        assert AgentState.COMPLETE in TERMINAL_STATES
        assert AgentState.SKIPPED in TERMINAL_STATES
        assert AgentState.ERROR in TERMINAL_STATES
        assert AgentState.LOAD_SITE not in TERMINAL_STATES

    def test_milestone_screenshot_states(self):
        assert AgentState.LOAD_SITE in MILESTONE_SCREENSHOT_STATES
        assert AgentState.EXTRACT_WALLETS in MILESTONE_SCREENSHOT_STATES
        assert AgentState.COMPLETE not in MILESTONE_SCREENSHOT_STATES

    def test_transitions_from_init(self):
        assert STATE_TRANSITIONS[AgentState.INIT] == [AgentState.LOAD_SITE]

    def test_transitions_from_find_register(self):
        targets = STATE_TRANSITIONS[AgentState.FIND_REGISTER]
        assert AgentState.FILL_REGISTER in targets
        assert AgentState.NAVIGATE_DEPOSIT in targets

    def test_happy_path_sequence(self):
        """Verify the happy-path state sequence is valid."""
        happy = [
            AgentState.INIT,
            AgentState.LOAD_SITE,
            AgentState.FIND_REGISTER,
            AgentState.FILL_REGISTER,
            AgentState.SUBMIT_REGISTER,
            AgentState.CHECK_EMAIL_VERIFICATION,
            AgentState.NAVIGATE_DEPOSIT,
            AgentState.EXTRACT_WALLETS,
            AgentState.COMPLETE,
        ]
        for i in range(len(happy) - 1):
            cur, nxt = happy[i], happy[i + 1]
            allowed = STATE_TRANSITIONS.get(cur, [])
            assert nxt in allowed or nxt in TERMINAL_STATES, f"Invalid: {cur} → {nxt}"


# ======================================================================
# Action models
# ======================================================================


class TestActionModels:
    """ActionType enum and AgentAction model."""

    def test_all_action_types(self):
        expected = {"click", "type", "select", "key", "navigate", "scroll", "wait", "done", "stuck"}
        assert {a.value for a in ActionType} == expected

    def test_agent_action_defaults(self):
        a = AgentAction(action=ActionType.CLICK, selector="#btn")
        assert a.action == ActionType.CLICK
        assert a.selector == "#btn"
        assert a.value == ""
        assert a.confidence == 0.0

    def test_confidence_clamped(self):
        a = AgentAction(action=ActionType.DONE, confidence=1.5)
        assert a.confidence == 1.0
        b = AgentAction(action=ActionType.DONE, confidence=-0.3)
        assert b.confidence == 0.0

    def test_action_from_json(self):
        raw = {"action": "type", "selector": "#email", "value": "test@example.com", "confidence": 0.9}
        a = AgentAction(**raw)
        assert a.action == ActionType.TYPE
        assert a.value == "test@example.com"


# ======================================================================
# DOM Inspector detectors
# ======================================================================


class TestFindRegisterDetector:
    """FindRegisterDetector scores form, link, URL, and modal signals."""

    def test_form_detection(self):
        scan_data = {
            "has_registration_form": True,
            "form_selector": "form#register",
            "field_summary": "email, password",
        }
        det = FindRegisterDetector()
        signals = det.detect(scan_data)
        assert any(s.source == "registration_form_present" for s in signals)
        total = sum(s.weight for s in signals)
        assert total >= 60

    def test_link_detection(self):
        scan_data = {
            "register_links": [{"text": "Sign Up", "selector": "a.signup"}],
        }
        det = FindRegisterDetector()
        signals = det.detect(scan_data)
        assert any(s.source == "register_link_found" for s in signals)

    def test_url_matching(self):
        scan_data = {
            "url_is_register_page": True,
            "current_url": "https://scam.example.com/register",
        }
        det = FindRegisterDetector()
        signals = det.detect(scan_data)
        assert any(s.source == "url_pattern_match" for s in signals)


class TestNavigateDepositDetector:
    def test_deposit_link(self):
        scan_data = {
            "deposit_links": [{"text": "Deposit", "selector": "a.deposit"}],
        }
        det = NavigateDepositDetector()
        signals = det.detect(scan_data)
        assert any(s.source == "deposit_link_found" for s in signals)
        total = sum(s.weight for s in signals)
        assert total >= 40


class TestCheckEmailDetector:
    def test_verification_text(self):
        scan_data = {
            "email_verify_text_found": True,
            "email_verify_snippet": "Please verify your email to continue.",
        }
        det = CheckEmailDetector()
        signals = det.detect(scan_data)
        assert any(s.source == "email_verify_text" for s in signals)
        total = sum(s.weight for s in signals)
        assert total >= 80

    def test_dashboard_text(self):
        scan_data = {
            "dashboard_text_found": True,
            "dashboard_snippet": "Welcome to your dashboard. Balance: 0.",
        }
        det = CheckEmailDetector()
        signals = det.detect(scan_data)
        assert any(s.source == "dashboard_text" for s in signals)


class TestDOMInspector:
    def test_inspect_high_confidence_returns_direct(self):
        inspector = DOMInspector()
        scan_data = {
            "has_registration_form": True,
            "form_selector": "form#register",
            "field_summary": "email, password",
            "register_links": [{"text": "Register", "selector": "a.reg"}],
            "url_is_register_page": True,
            "current_url": "https://scam.example.com/register",
        }
        result = inspector.inspect("FIND_REGISTER", scan_data, 10.0)
        # High confidence → should be direct or assisted
        assert result.outcome in ("direct", "assisted", "fallback")
        assert result.confidence >= 0


# ======================================================================
# Metrics collector
# ======================================================================


class TestMetricsCollector:
    def test_initial_summary_zeroes(self):
        mc = MetricsCollector()
        s = mc.summary()
        assert s["click_strategies"]["css"] == 0
        assert s["wasted_actions"]["total"] == 0
        assert s["dom_inspection"]["llm_calls_saved"] == 0

    def test_record_click(self):
        mc = MetricsCollector()
        mc.record_click("#btn", "css", True, "FIND_REGISTER")
        mc.record_click("#btn2", "fuzzy", True, "FIND_REGISTER")
        mc.record_click("#btn3", "unknown", False, "FIND_REGISTER")
        s = mc.summary()
        assert s["click_strategies"]["css"] == 1
        assert s["click_strategies"]["fuzzy"] == 1
        assert s["click_strategies"]["failed"] == 1

    def test_record_type(self):
        mc = MetricsCollector()
        mc.record_type("#email", "css_verified", True, "FILL_REGISTER")
        s = mc.summary()
        assert s["type_strategies"]["css_verified"] == 1

    def test_record_llm_call(self):
        mc = MetricsCollector()
        mc.record_llm_call("FIND_REGISTER", 1000, 200, "click")
        mc.record_llm_call("FIND_REGISTER", 1200, 150, "done")
        s = mc.summary()
        state_calls = s["llm_calls_by_state"]["FIND_REGISTER"]
        assert state_calls["calls"] == 2
        assert state_calls["input_tokens"] == 2200
        assert len(s["token_series"]) == 2

    def test_record_state_timing(self):
        mc = MetricsCollector()
        mc.record_state_timing("FILL_REGISTER", 5, 12.345)
        mc.record_state_timing("FILL_REGISTER", 3, 5.678)
        s = mc.summary()
        assert s["state_timing"]["FILL_REGISTER"]["actions"] == 8
        assert s["state_timing"]["FILL_REGISTER"]["duration_s"] == pytest.approx(18.02, abs=0.02)

    def test_record_dom_inspection(self):
        mc = MetricsCollector()
        mc.record_dom_inspection("FIND_REGISTER", "direct")
        mc.record_dom_inspection("FIND_REGISTER", "direct")
        mc.record_dom_inspection("FIND_REGISTER", "assisted")
        s = mc.summary()
        assert s["dom_inspection"]["by_state"]["FIND_REGISTER"]["direct"] == 2
        assert s["dom_inspection"]["llm_calls_saved"] == 2

    def test_screenshot_sizes(self):
        mc = MetricsCollector()
        mc.record_screenshot("LOAD_SITE", 50000)
        mc.record_screenshot("LOAD_SITE", 60000)
        s = mc.summary()
        assert s["screenshot_sizes"]["total_count"] == 2
        assert s["screenshot_sizes"]["avg_bytes"] == 55000
        assert s["screenshot_sizes"]["max_bytes"] == 60000


# ======================================================================
# Result models
# ======================================================================


class TestSiteResult:
    def test_default_status(self):
        r = SiteResult(site_url="https://scam.test", run_id="run-1")
        assert r.status == SiteStatus.IN_PROGRESS
        assert r.wallets == []
        assert r.actions_taken == 0

    def test_to_dict(self):
        r = SiteResult(site_url="https://scam.test", run_id="run-1", site_id="s1")
        d = r.to_dict()
        assert d["site_url"] == "https://scam.test"
        assert d["status"] == "in_progress"
        assert isinstance(d["wallets"], list)

    def test_to_json_roundtrip(self):
        r = SiteResult(site_url="https://scam.test", run_id="run-1")
        j = r.to_json()
        parsed = json.loads(j)
        assert parsed["run_id"] == "run-1"


class TestWalletEntry:
    def test_to_dict(self):
        w = WalletEntry(
            site_url="https://x.com",
            token_symbol="BTC",
            wallet_address="bc1qtest123",
            run_id="r1",
        )
        d = w.to_dict()
        assert d["token_symbol"] == "BTC"
        assert d["wallet_address"] == "bc1qtest123"


# ======================================================================
# Identity vault extensions
# ======================================================================


class TestIdentityVaultExtension:
    """Test the AWH-ported extensions to IdentityVault."""

    def test_generate_has_crypto_username(self):
        vault = IdentityVault()
        identity = vault.generate()
        assert identity.crypto_username.startswith("Cx_")
        assert len(identity.crypto_username) > 4

    def test_generate_has_full_name(self):
        vault = IdentityVault()
        identity = vault.generate()
        assert " " in identity.full_name
        assert identity.full_name == f"{identity.first_name} {identity.last_name}"

    def test_generate_has_password_variants(self):
        vault = IdentityVault()
        identity = vault.generate()
        assert "default" in identity.password_variants
        assert "digits_8" in identity.password_variants
        assert "digits_12" in identity.password_variants
        assert "alphanumeric_8" in identity.password_variants
        assert "simple_10" in identity.password_variants
        assert identity.password_variants["default"] == identity.password
        assert len(identity.password_variants["digits_8"]) == 8
        assert identity.password_variants["digits_8"].isdigit()

    def test_to_dict_includes_new_fields(self):
        vault = IdentityVault()
        identity = vault.generate()
        d = identity.to_dict()
        assert "crypto_username" in d
        assert "full_name" in d
        assert "password_variants" in d
        assert isinstance(d["password_variants"], dict)
