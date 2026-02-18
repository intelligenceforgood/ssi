"""Unit tests for Phase 4 — Hardening & Scale modules.

Covers:
- Browser stealth (proxy pool, fingerprint randomization, stealth scripts)
- CAPTCHA detection and handling strategies
- Cost monitoring and budget enforcement
- Investigation feedback loop
"""

from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ssi.browser.captcha import (
    CaptchaDetection,
    CaptchaResult,
    CaptchaStrategy,
    CaptchaType,
    detect_captcha,
    handle_captcha,
)
from ssi.browser.stealth import (
    BrowserProfile,
    ProxyPool,
    apply_stealth_scripts,
    build_browser_profile,
)
from ssi.feedback import (
    FeedbackRecord,
    FeedbackStats,
    FeedbackStore,
    OutcomeType,
)
from ssi.monitoring import CostLineItem, CostSummary, CostTracker


# ===========================================================================
# Stealth tests
# ===========================================================================


class TestProxyPool:
    """ProxyPool round-robin and random selection."""

    def test_empty_pool_returns_none(self):
        pool = ProxyPool([])
        assert pool.next() is None

    def test_round_robin(self):
        urls = ["http://p1:8080", "http://p2:8080", "http://p3:8080"]
        pool = ProxyPool(urls, strategy="round_robin")
        assert pool.next() == "http://p1:8080"
        assert pool.next() == "http://p2:8080"
        assert pool.next() == "http://p3:8080"
        assert pool.next() == "http://p1:8080"  # wraps

    def test_random_selection(self):
        urls = ["http://p1:8080", "http://p2:8080"]
        pool = ProxyPool(urls, strategy="random")
        results = {pool.next() for _ in range(20)}
        assert results.issubset(set(urls))
        assert len(results) >= 1  # at least one picked

    def test_single_proxy(self):
        pool = ProxyPool(["http://only:8080"])
        assert pool.next() == "http://only:8080"
        assert pool.next() == "http://only:8080"

    def test_len(self):
        pool = ProxyPool(["a", "b", "c"])
        assert len(pool) == 3


class TestBuildBrowserProfile:
    """build_browser_profile produces correct Playwright args."""

    def test_default_headless(self):
        profile = build_browser_profile(headless=True)
        assert profile.launch_args["headless"] is True
        assert "proxy" not in profile.launch_args

    def test_explicit_proxy(self):
        profile = build_browser_profile(headless=True, explicit_proxy="http://my-proxy:3128")
        assert profile.launch_args["proxy"] == {"server": "http://my-proxy:3128"}

    def test_proxy_pool_overrides_explicit(self):
        pool = ProxyPool(["http://pool1:8080"])
        profile = build_browser_profile(
            headless=True,
            proxy_pool=pool,
            explicit_proxy="http://explicit:8080",
        )
        # Pool takes precedence
        assert profile.launch_args["proxy"]["server"] == "http://pool1:8080"

    def test_explicit_user_agent(self):
        profile = build_browser_profile(headless=True, explicit_user_agent="MyBot/1.0")
        assert profile.context_args["user_agent"] == "MyBot/1.0"

    def test_randomize_fingerprint_sets_fields(self):
        profile = build_browser_profile(headless=True, randomize_fingerprint=True)
        # A randomised profile should have user_agent, viewport, locale, timezone_id
        assert "user_agent" in profile.context_args
        assert "viewport" in profile.context_args
        assert "locale" in profile.context_args
        assert "timezone_id" in profile.context_args

    def test_no_fingerprint_randomization(self):
        profile = build_browser_profile(headless=True, randomize_fingerprint=False)
        # No fingerprint fields unless explicit user agent provided
        assert "viewport" not in profile.context_args
        assert "locale" not in profile.context_args
        assert "timezone_id" not in profile.context_args

    def test_har_and_video(self):
        profile = build_browser_profile(
            headless=True,
            record_har_path="/tmp/test.har",
            record_video_dir="/tmp/video",
        )
        assert profile.context_args["record_har_path"] == "/tmp/test.har"
        assert profile.context_args["record_video_dir"] == "/tmp/video"


class TestApplyStealthScripts:
    """apply_stealth_scripts injects JS via page.add_init_script."""

    def test_injects_scripts(self):
        mock_page = MagicMock()
        apply_stealth_scripts(mock_page)
        assert mock_page.add_init_script.call_count >= 1
        # The injected script should contain webdriver override
        script = mock_page.add_init_script.call_args_list[0][1].get(
            "script", mock_page.add_init_script.call_args_list[0][0][0] if mock_page.add_init_script.call_args_list[0][0] else ""
        )
        assert "webdriver" in script


# ===========================================================================
# CAPTCHA tests
# ===========================================================================


class TestCaptchaDetection:
    """detect_captcha scans DOM for CAPTCHA signatures."""

    def test_no_captcha_detected(self):
        mock_page = MagicMock()
        mock_page.url = "https://example.com"
        mock_locator = MagicMock()
        mock_locator.count.return_value = 0
        mock_page.locator.return_value = mock_locator
        mock_page.inner_text.return_value = "Normal page content"
        detection = detect_captcha(mock_page)
        assert detection.detected is False
        assert detection.captcha_type == CaptchaType.UNKNOWN

    def test_recaptcha_detected_via_selector(self):
        mock_page = MagicMock()
        mock_page.url = "https://example.com"

        def locator_side_effect(sel):
            mock_loc = MagicMock()
            if "recaptcha" in sel.lower():
                mock_loc.count.return_value = 1
            else:
                mock_loc.count.return_value = 0
            return mock_loc

        mock_page.locator.side_effect = locator_side_effect
        detection = detect_captcha(mock_page)
        assert detection.detected is True
        assert detection.captcha_type == CaptchaType.RECAPTCHA_V2

    def test_text_fallback_detection(self):
        mock_page = MagicMock()
        mock_page.url = "https://example.com"
        mock_locator = MagicMock()
        mock_locator.count.return_value = 0
        mock_page.locator.return_value = mock_locator
        mock_page.inner_text.return_value = "Please verify you are human to continue"
        detection = detect_captcha(mock_page)
        assert detection.detected is True
        assert detection.captcha_type == CaptchaType.UNKNOWN  # text fallback yields UNKNOWN


class TestCaptchaHandling:
    """handle_captcha responds with the configured strategy."""

    def test_skip_strategy(self):
        detection = CaptchaDetection(
            detected=True,
            captcha_type=CaptchaType.RECAPTCHA_V2,
            element_selector="iframe[src*='recaptcha']",
        )
        mock_page = MagicMock()
        result = handle_captcha(mock_page, detection, strategy=CaptchaStrategy.SKIP)
        assert result.solved is False
        assert result.strategy_used == CaptchaStrategy.SKIP

    def test_wait_strategy_timeout(self):
        detection = CaptchaDetection(
            detected=True,
            captcha_type=CaptchaType.CLOUDFLARE_TURNSTILE,
            element_selector="div.cf-turnstile",
        )
        mock_page = MagicMock()
        mock_page.url = "https://example.com"
        # After wait, CAPTCHA is still there via locator
        mock_locator = MagicMock()
        mock_locator.count.return_value = 1
        mock_page.locator.return_value = mock_locator
        mock_page.inner_text.return_value = ""
        result = handle_captcha(
            mock_page, detection, strategy=CaptchaStrategy.WAIT, wait_seconds=0.1
        )
        assert result.strategy_used == CaptchaStrategy.WAIT

    def test_not_detected_skips_handling(self):
        detection = CaptchaDetection(detected=False)
        mock_page = MagicMock()
        result = handle_captcha(mock_page, detection, strategy=CaptchaStrategy.SKIP)
        assert result.solved is True  # nothing to solve


# ===========================================================================
# Cost Monitoring tests
# ===========================================================================


class TestCostTracker:
    """CostTracker budget enforcement and pricing."""

    def test_empty_tracker(self):
        tracker = CostTracker(budget_usd=1.0)
        summary = tracker.summary()
        assert summary.total_usd == 0.0
        assert summary.budget_usd == 1.0
        assert summary.budget_exceeded is False

    def test_llm_token_pricing(self):
        tracker = CostTracker(budget_usd=10.0)
        tracker.record_llm_tokens("gemini-1.5-flash", input_tokens=1000, output_tokens=500)
        summary = tracker.summary()
        assert summary.llm_usd > 0.0
        assert summary.total_usd == summary.llm_usd + summary.api_usd + summary.compute_usd

    def test_ollama_is_free(self):
        tracker = CostTracker(budget_usd=1.0)
        tracker.record_llm_tokens("llama3.3", input_tokens=50_000, output_tokens=10_000)
        summary = tracker.summary()
        assert summary.llm_usd == 0.0

    def test_budget_exceeded(self):
        tracker = CostTracker(budget_usd=0.001)
        tracker.record_llm_tokens("gpt-4o", input_tokens=100_000, output_tokens=50_000)
        summary = tracker.summary()
        assert summary.budget_exceeded is True

    def test_api_call_recording(self):
        tracker = CostTracker()
        tracker.record_api_call("whois")
        tracker.record_api_call("whois")
        tracker.record_api_call("virustotal")
        summary = tracker.summary()
        assert summary.api_calls.get("whois", 0) == 2
        assert summary.api_calls.get("virustotal", 0) == 1

    def test_browser_seconds(self):
        tracker = CostTracker()
        tracker.record_browser_seconds(60.0)
        summary = tracker.summary()
        assert summary.browser_seconds == 60.0
        assert summary.compute_usd > 0.0

    def test_custom_api_cost(self):
        tracker = CostTracker(budget_usd=1.0)
        tracker.record_api_call("premium_api", cost_override=0.50)
        summary = tracker.summary()
        assert summary.api_usd == 0.50

    def test_line_items_present(self):
        tracker = CostTracker()
        tracker.record_llm_tokens("gemini-1.5-flash", input_tokens=1000, output_tokens=500)
        tracker.record_api_call("dns")
        tracker.record_browser_seconds(30.0)
        summary = tracker.summary()
        assert len(summary.line_items) >= 2  # at least LLM + compute

    def test_summary_model(self):
        """CostSummary is a proper Pydantic model."""
        tracker = CostTracker(budget_usd=5.0)
        tracker.record_llm_tokens("gemini-1.5-flash", input_tokens=100, output_tokens=50)
        summary = tracker.summary()
        data = summary.model_dump(mode="json")
        assert "total_usd" in data
        assert "budget_usd" in data
        restored = CostSummary(**data)
        assert restored.total_usd == summary.total_usd


# ===========================================================================
# Feedback Loop tests
# ===========================================================================


class TestFeedbackStore:
    """FeedbackStore SQLite persistence."""

    @pytest.fixture()
    def store(self, tmp_path: Path) -> FeedbackStore:
        return FeedbackStore(db_path=tmp_path / "test_feedback.db")

    def test_record_and_retrieve(self, store: FeedbackStore):
        feedback = FeedbackRecord(
            investigation_id="inv-001",
            outcome=OutcomeType.REFERRED_TO_LEA,
            notes="Sent to FBI IC3",
            lea_partner="FBI",
        )
        fid = store.record(feedback)
        assert fid == feedback.feedback_id

        records = store.get_feedback("inv-001")
        assert len(records) == 1
        assert records[0].outcome == OutcomeType.REFERRED_TO_LEA
        assert records[0].lea_partner == "FBI"

    def test_multiple_feedback_per_investigation(self, store: FeedbackStore):
        store.record(FeedbackRecord(investigation_id="inv-002", outcome=OutcomeType.REFERRED_TO_LEA))
        store.record(FeedbackRecord(investigation_id="inv-002", outcome=OutcomeType.PROSECUTION_INITIATED))
        records = store.get_feedback("inv-002")
        assert len(records) == 2

    def test_update_outcome(self, store: FeedbackStore):
        store.record(FeedbackRecord(investigation_id="inv-003", outcome=OutcomeType.PENDING))
        updated = store.update_outcome("inv-003", OutcomeType.TAKEDOWN_COMPLETED, notes="Domain seized")
        assert updated is True
        records = store.get_feedback("inv-003")
        assert any(r.outcome == OutcomeType.TAKEDOWN_COMPLETED for r in records)

    def test_update_nonexistent_returns_false(self, store: FeedbackStore):
        updated = store.update_outcome("no-such-inv", OutcomeType.NO_ACTION)
        assert updated is False

    def test_get_feedback_empty(self, store: FeedbackStore):
        records = store.get_feedback("no-such-inv")
        assert records == []

    def test_stats_empty(self, store: FeedbackStore):
        stats = store.get_stats()
        assert stats.total_investigations == 0
        assert stats.total_feedback == 0
        assert stats.prosecution_rate == 0.0

    def test_stats_with_data(self, store: FeedbackStore):
        store.record(FeedbackRecord(investigation_id="inv-a", outcome=OutcomeType.PROSECUTION_COMPLETED))
        store.record(FeedbackRecord(investigation_id="inv-b", outcome=OutcomeType.TAKEDOWN_COMPLETED))
        store.record(FeedbackRecord(investigation_id="inv-c", outcome=OutcomeType.FALSE_POSITIVE))
        store.record(FeedbackRecord(investigation_id="inv-d", outcome=OutcomeType.NO_ACTION))

        stats = store.get_stats()
        assert stats.total_investigations == 4
        assert stats.total_feedback == 4
        assert stats.prosecution_rate == pytest.approx(0.25)  # 1 prosecution / 4 inv
        assert stats.takedown_rate == pytest.approx(0.25)
        assert stats.false_positive_rate == pytest.approx(0.25)

    def test_metadata_roundtrip(self, store: FeedbackStore):
        feedback = FeedbackRecord(
            investigation_id="inv-meta",
            outcome=OutcomeType.INTEL_SHARED,
            metadata={"shared_with": "NCFTA", "iocs_count": 12},
        )
        store.record(feedback)
        records = store.get_feedback("inv-meta")
        assert records[0].metadata["shared_with"] == "NCFTA"
        assert records[0].metadata["iocs_count"] == 12


class TestFeedbackModels:
    """FeedbackRecord and OutcomeType model tests."""

    def test_default_pending(self):
        record = FeedbackRecord(investigation_id="test")
        assert record.outcome == OutcomeType.PENDING
        assert record.feedback_id  # auto-generated

    def test_outcome_enum_values(self):
        assert OutcomeType.PROSECUTION_COMPLETED.value == "prosecution_completed"
        assert OutcomeType.TAKEDOWN_REQUESTED.value == "takedown_requested"

    def test_serialization(self):
        record = FeedbackRecord(
            investigation_id="test",
            outcome=OutcomeType.REFERRED_TO_LEA,
            lea_partner="Interpol",
        )
        data = record.model_dump(mode="json")
        assert data["outcome"] == "referred_to_lea"
        restored = FeedbackRecord(**data)
        assert restored.lea_partner == "Interpol"


# ===========================================================================
# Settings integration tests
# ===========================================================================


class TestPhase4Settings:
    """Phase 4 settings sections load correctly."""

    def test_stealth_defaults(self):
        from ssi.settings.config import StealthSettings

        s = StealthSettings()
        assert s.proxy_urls == []
        assert s.rotation_strategy == "round_robin"
        assert s.randomize_fingerprint is True
        assert s.apply_stealth_scripts is True

    def test_captcha_defaults(self):
        from ssi.settings.config import CaptchaSettings

        s = CaptchaSettings()
        assert s.strategy == "skip"
        assert s.solver_api_key == ""
        assert s.wait_seconds == 15
        assert s.screenshot_on_detect is True

    def test_cost_defaults(self):
        from ssi.settings.config import CostSettings

        s = CostSettings()
        assert s.budget_per_investigation_usd == 1.0
        assert s.warn_at_pct == 80
        assert s.enabled is True

    def test_feedback_defaults(self):
        from ssi.settings.config import FeedbackSettings

        s = FeedbackSettings()
        assert s.db_path == "data/evidence/feedback.db"
        assert s.enabled is True


# ===========================================================================
# InvestigationResult model extension tests
# ===========================================================================


class TestInvestigationResultPhase4Fields:
    """New Phase 4 fields on InvestigationResult."""

    def test_cost_summary_default_none(self):
        from ssi.models.investigation import InvestigationResult

        result = InvestigationResult(url="https://example.com")
        assert result.cost_summary is None
        assert result.captcha_encountered is False

    def test_cost_summary_roundtrip(self):
        from ssi.models.investigation import InvestigationResult

        result = InvestigationResult(
            url="https://example.com",
            cost_summary={"total_usd": 0.05, "budget_usd": 1.0},
            captcha_encountered=True,
        )
        data = result.model_dump(mode="json")
        assert data["cost_summary"]["total_usd"] == 0.05
        assert data["captcha_encountered"] is True
        restored = InvestigationResult(**data)
        assert restored.cost_summary["total_usd"] == 0.05
