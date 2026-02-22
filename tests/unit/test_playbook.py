"""Unit tests for the playbook engine (Phase 4).

Covers:
  - PlaybookStep, Playbook model validation
  - PlaybookMatcher (register, match, remove, edge cases)
  - Template variable resolution
  - PlaybookExecutor step dispatch + retry + LLM fallback
  - PlaybookLoader (JSON file loading)
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

from ssi.identity.vault import SyntheticIdentity
from ssi.playbook.executor import PlaybookExecutor, resolve_template
from ssi.playbook.loader import load_playbook_from_file, load_playbooks_from_dir
from ssi.playbook.matcher import PlaybookMatcher
from ssi.playbook.models import (
    Playbook,
    PlaybookResult,
    PlaybookStep,
    PlaybookStepResult,
    PlaybookStepType,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_identity(**overrides: Any) -> SyntheticIdentity:
    """Create a test synthetic identity with sensible defaults."""
    defaults = {
        "first_name": "Jane",
        "last_name": "Doe",
        "full_name": "Jane Doe",
        "email": "jane.doe@fakeemail.test",
        "phone": "+15551234567",
        "username": "janedoe42",
        "crypto_username": "jd_crypto",
        "password": "TestPass123!",
        "password_variants": {
            "default": "TestPass123!",
            "digits_8": "12345678",
            "digits_12": "123456789012",
            "alphanumeric_8": "AbCd1234",
            "simple_10": "simplepass",
        },
        "street_address": "123 Fake St",
        "city": "Testville",
        "state": "TX",
        "zip_code": "12345",
        "country": "US",
        "date_of_birth": "1990-01-15",
        "ssn": "900-12-3456",
        "credit_card_number": "4111111111111111",
        "credit_card_expiry": "12/30",
        "credit_card_cvv": "123",
    }
    defaults.update(overrides)
    return SyntheticIdentity(**defaults)


def _make_step(**overrides: Any) -> PlaybookStep:
    """Create a test playbook step."""
    defaults = {
        "action": PlaybookStepType.CLICK,
        "selector": "Sign Up",
        "description": "Click sign up",
    }
    defaults.update(overrides)
    return PlaybookStep(**defaults)


def _make_playbook(**overrides: Any) -> Playbook:
    """Create a test playbook."""
    defaults = {
        "playbook_id": "test_playbook_v1",
        "url_pattern": r"example\.com",
        "description": "Test playbook",
        "steps": [_make_step()],
    }
    defaults.update(overrides)
    return Playbook(**defaults)


def _make_mock_browser() -> AsyncMock:
    """Create a mock ZenBrowserManager with default success returns."""
    browser = AsyncMock()
    browser.click = AsyncMock(return_value=True)
    browser.type_text = AsyncMock(return_value=(True, "typed_value"))
    browser.select_option = AsyncMock(return_value=True)
    browser.navigate = AsyncMock(return_value=True)
    browser.wait = AsyncMock()
    browser.scroll_down = AsyncMock()
    browser.extract_wallet_address = AsyncMock(return_value=[])
    return browser


# ===================================================================
# PlaybookStep model tests
# ===================================================================


class TestPlaybookStep:
    """Tests for PlaybookStep model validation."""

    def test_basic_step(self) -> None:
        """A step with required fields validates successfully."""
        step = PlaybookStep(action=PlaybookStepType.CLICK, selector="button#submit")
        assert step.action == PlaybookStepType.CLICK
        assert step.selector == "button#submit"
        assert step.retry_on_failure == 0
        assert step.fallback_to_llm is True

    def test_all_step_types(self) -> None:
        """Every PlaybookStepType value creates a valid step."""
        for stype in PlaybookStepType:
            step = PlaybookStep(action=stype, selector="x", value="v")
            assert step.action == stype

    def test_retry_bounds(self) -> None:
        """retry_on_failure is clamped to [0, 10]."""
        with pytest.raises(Exception):
            PlaybookStep(action=PlaybookStepType.CLICK, retry_on_failure=-1)
        with pytest.raises(Exception):
            PlaybookStep(action=PlaybookStepType.CLICK, retry_on_failure=11)

    def test_defaults(self) -> None:
        """Default values are applied correctly."""
        step = PlaybookStep(action=PlaybookStepType.WAIT)
        assert step.selector == ""
        assert step.value == ""
        assert step.description == ""
        assert step.fallback_to_llm is True


# ===================================================================
# Playbook model tests
# ===================================================================


class TestPlaybook:
    """Tests for Playbook model validation."""

    def test_valid_playbook(self) -> None:
        """A valid playbook passes validation."""
        pb = _make_playbook()
        assert pb.playbook_id == "test_playbook_v1"
        assert len(pb.steps) == 1
        assert pb.fallback_to_llm is True
        assert pb.enabled is True

    def test_empty_steps_rejected(self) -> None:
        """A playbook with no steps is rejected."""
        with pytest.raises(Exception):
            _make_playbook(steps=[])

    def test_invalid_regex_rejected(self) -> None:
        """An invalid url_pattern regex is rejected."""
        with pytest.raises(Exception):
            _make_playbook(url_pattern="[invalid(regex")

    def test_playbook_id_pattern(self) -> None:
        """playbook_id must be lowercase alphanumeric with underscores."""
        with pytest.raises(Exception):
            _make_playbook(playbook_id="Invalid-ID!")

    def test_max_duration_bounds(self) -> None:
        """max_duration_sec is clamped to [10, 600]."""
        pb = _make_playbook(max_duration_sec=10)
        assert pb.max_duration_sec == 10
        with pytest.raises(Exception):
            _make_playbook(max_duration_sec=5)
        with pytest.raises(Exception):
            _make_playbook(max_duration_sec=601)

    def test_metadata_fields(self) -> None:
        """Metadata fields are stored correctly."""
        pb = _make_playbook(
            author="test-author",
            version="2.0",
            tags=["crypto", "phishing"],
            tested_urls=["https://example.com"],
        )
        assert pb.author == "test-author"
        assert pb.version == "2.0"
        assert pb.tags == ["crypto", "phishing"]
        assert pb.tested_urls == ["https://example.com"]


# ===================================================================
# PlaybookMatcher tests
# ===================================================================


class TestPlaybookMatcher:
    """Tests for the URL → playbook matching engine."""

    def test_match_basic(self) -> None:
        """A simple regex pattern matches the expected URL."""
        matcher = PlaybookMatcher()
        pb = _make_playbook(url_pattern=r"example\.com")
        matcher.register(pb)
        assert matcher.match("https://example.com/page") is pb

    def test_no_match(self) -> None:
        """Non-matching URL returns None."""
        matcher = PlaybookMatcher()
        matcher.register(_make_playbook(url_pattern=r"example\.com"))
        assert matcher.match("https://other-site.net") is None

    def test_case_insensitive(self) -> None:
        """Matching is case-insensitive."""
        matcher = PlaybookMatcher()
        matcher.register(_make_playbook(url_pattern=r"EXAMPLE\.COM"))
        assert matcher.match("https://example.com") is not None

    def test_first_match_wins(self) -> None:
        """The first registered playbook that matches wins."""
        matcher = PlaybookMatcher()
        pb1 = _make_playbook(playbook_id="first_v1", url_pattern=r"example")
        pb2 = _make_playbook(playbook_id="second_v1", url_pattern=r"example\.com")
        matcher.register(pb1)
        matcher.register(pb2)
        assert matcher.match("https://example.com") is pb1

    def test_disabled_playbook_skipped(self) -> None:
        """Disabled playbooks are not matched."""
        matcher = PlaybookMatcher()
        pb = _make_playbook(enabled=False)
        matcher.register(pb)
        assert matcher.match("https://example.com") is None

    def test_register_many(self) -> None:
        """register_many adds multiple playbooks."""
        matcher = PlaybookMatcher()
        pbs = [
            _make_playbook(playbook_id="a_v1", url_pattern=r"site-a\.com"),
            _make_playbook(playbook_id="b_v1", url_pattern=r"site-b\.com"),
        ]
        count = matcher.register_many(pbs)
        assert count == 2
        assert matcher.count == 2

    def test_get_by_id(self) -> None:
        """Retrieve a playbook by its ID."""
        matcher = PlaybookMatcher()
        pb = _make_playbook(playbook_id="target_v1")
        matcher.register(pb)
        assert matcher.get("target_v1") is pb
        assert matcher.get("nonexistent") is None

    def test_remove(self) -> None:
        """Remove a playbook by ID."""
        matcher = PlaybookMatcher()
        pb = _make_playbook(playbook_id="removable_v1")
        matcher.register(pb)
        assert matcher.remove("removable_v1") is True
        assert matcher.count == 0
        assert matcher.remove("nonexistent") is False

    def test_clear(self) -> None:
        """Clear removes all playbooks."""
        matcher = PlaybookMatcher()
        matcher.register(_make_playbook(playbook_id="a_v1"))
        matcher.register(_make_playbook(playbook_id="b_v1"))
        matcher.clear()
        assert matcher.count == 0

    def test_complex_regex(self) -> None:
        """Complex regex patterns work correctly."""
        matcher = PlaybookMatcher()
        matcher.register(_make_playbook(url_pattern=r"(okdc|ok-dc|okx.*clone)"))
        assert matcher.match("https://okdc-exchange.com") is not None
        assert matcher.match("https://ok-dc.net/trade") is not None
        assert matcher.match("https://okx-clone.io") is not None
        assert matcher.match("https://binance.com") is None


# ===================================================================
# Template variable resolution tests
# ===================================================================


class TestTemplateResolution:
    """Tests for template variable resolution in playbook step values."""

    def test_identity_email(self) -> None:
        """Resolve {identity.email} to the identity's email."""
        identity = _make_identity(email="test@fake.test")
        result = resolve_template("{identity.email}", identity)
        assert result == "test@fake.test"

    def test_identity_password(self) -> None:
        """Resolve {identity.password} to the identity's password."""
        identity = _make_identity(password="MySecret!")
        result = resolve_template("{identity.password}", identity)
        assert result == "MySecret!"

    def test_password_variant(self) -> None:
        """Resolve {password_variants.digits_8} to the correct variant."""
        identity = _make_identity()
        result = resolve_template("{password_variants.digits_8}", identity)
        assert result == "12345678"

    def test_shorthand_resolution(self) -> None:
        """Resolve {email} as shorthand for {identity.email}."""
        identity = _make_identity(email="shorthand@test.dev")
        result = resolve_template("{email}", identity)
        assert result == "shorthand@test.dev"

    def test_multiple_variables(self) -> None:
        """Multiple variables in one string are resolved."""
        identity = _make_identity(first_name="Alice", last_name="Smith")
        result = resolve_template("{identity.first_name} {identity.last_name}", identity)
        assert result == "Alice Smith"

    def test_unresolved_left_as_is(self) -> None:
        """Unresolvable variables are left unchanged."""
        identity = _make_identity()
        result = resolve_template("{identity.nonexistent_field}", identity)
        assert result == "{identity.nonexistent_field}"

    def test_no_templates(self) -> None:
        """Strings without templates are returned unchanged."""
        identity = _make_identity()
        result = resolve_template("plain text", identity)
        assert result == "plain text"

    def test_empty_string(self) -> None:
        """Empty string is returned unchanged."""
        identity = _make_identity()
        result = resolve_template("", identity)
        assert result == ""

    def test_all_identity_fields(self) -> None:
        """All standard identity fields are resolvable."""
        identity = _make_identity()
        fields = [
            "first_name", "last_name", "full_name", "email", "phone",
            "username", "crypto_username", "password",
            "street_address", "city", "state", "zip_code", "country",
            "date_of_birth", "ssn",
            "credit_card_number", "credit_card_expiry", "credit_card_cvv",
        ]
        for field in fields:
            result = resolve_template(f"{{identity.{field}}}", identity)
            assert result != f"{{identity.{field}}}", f"Failed to resolve identity.{field}"


# ===================================================================
# PlaybookExecutor tests
# ===================================================================


class TestPlaybookExecutor:
    """Tests for step execution, retries, and LLM fallback."""

    @pytest.mark.anyio
    async def test_successful_execution(self) -> None:
        """All steps succeed → PlaybookResult.success is True."""
        browser = _make_mock_browser()
        identity = _make_identity()
        executor = PlaybookExecutor(browser=browser, identity=identity)

        pb = _make_playbook(steps=[
            _make_step(action=PlaybookStepType.CLICK, selector="Sign Up"),
            _make_step(action=PlaybookStepType.TYPE, selector="#email", value="{identity.email}"),
            _make_step(action=PlaybookStepType.WAIT, value="1"),
        ])

        result = await executor.execute(pb, "https://example.com")
        assert result.success is True
        assert result.completed_steps == 3
        assert result.total_steps == 3
        assert result.fell_back_to_llm is False

    @pytest.mark.anyio
    async def test_click_step(self) -> None:
        """CLICK step calls browser.click with the selector."""
        browser = _make_mock_browser()
        executor = PlaybookExecutor(browser=browser, identity=_make_identity())

        pb = _make_playbook(steps=[
            _make_step(action=PlaybookStepType.CLICK, selector="button.submit"),
        ])
        await executor.execute(pb, "https://example.com")
        browser.click.assert_called_once_with("button.submit")

    @pytest.mark.anyio
    async def test_type_step(self) -> None:
        """TYPE step calls browser.type_text with selector and resolved value."""
        browser = _make_mock_browser()
        identity = _make_identity(email="test@test.dev")
        executor = PlaybookExecutor(browser=browser, identity=identity)

        pb = _make_playbook(steps=[
            _make_step(action=PlaybookStepType.TYPE, selector="#email", value="{identity.email}"),
        ])
        await executor.execute(pb, "https://example.com")
        browser.type_text.assert_called_once_with("#email", "test@test.dev")

    @pytest.mark.anyio
    async def test_navigate_step(self) -> None:
        """NAVIGATE step calls browser.navigate with the resolved URL."""
        browser = _make_mock_browser()
        executor = PlaybookExecutor(browser=browser, identity=_make_identity())

        pb = _make_playbook(steps=[
            _make_step(action=PlaybookStepType.NAVIGATE, value="https://example.com/deposit"),
        ])
        await executor.execute(pb, "https://example.com")
        browser.navigate.assert_called_once_with("https://example.com/deposit")

    @pytest.mark.anyio
    async def test_wait_step(self) -> None:
        """WAIT step calls browser.wait with clamped seconds."""
        browser = _make_mock_browser()
        executor = PlaybookExecutor(browser=browser, identity=_make_identity())

        pb = _make_playbook(steps=[
            _make_step(action=PlaybookStepType.WAIT, value="5"),
        ])
        await executor.execute(pb, "https://example.com")
        browser.wait.assert_called_once_with(5.0)

    @pytest.mark.anyio
    async def test_wait_clamped_to_10(self) -> None:
        """WAIT step clamps seconds to at most 10."""
        browser = _make_mock_browser()
        executor = PlaybookExecutor(browser=browser, identity=_make_identity())

        pb = _make_playbook(steps=[
            _make_step(action=PlaybookStepType.WAIT, value="30"),
        ])
        await executor.execute(pb, "https://example.com")
        browser.wait.assert_called_once_with(10.0)

    @pytest.mark.anyio
    async def test_scroll_step(self) -> None:
        """SCROLL step calls browser.scroll_down."""
        browser = _make_mock_browser()
        executor = PlaybookExecutor(browser=browser, identity=_make_identity())

        pb = _make_playbook(steps=[
            _make_step(action=PlaybookStepType.SCROLL, value="500"),
        ])
        await executor.execute(pb, "https://example.com")
        browser.scroll_down.assert_called_once_with(500)

    @pytest.mark.anyio
    async def test_extract_step(self) -> None:
        """EXTRACT step calls browser.extract_wallet_address."""
        browser = _make_mock_browser()
        executor = PlaybookExecutor(browser=browser, identity=_make_identity())

        pb = _make_playbook(steps=[
            _make_step(action=PlaybookStepType.EXTRACT),
        ])
        await executor.execute(pb, "https://example.com")
        browser.extract_wallet_address.assert_called_once()

    @pytest.mark.anyio
    async def test_select_step(self) -> None:
        """SELECT step calls browser.select_option."""
        browser = _make_mock_browser()
        executor = PlaybookExecutor(browser=browser, identity=_make_identity())

        pb = _make_playbook(steps=[
            _make_step(action=PlaybookStepType.SELECT, selector="#currency", value="USD"),
        ])
        await executor.execute(pb, "https://example.com")
        browser.select_option.assert_called_once_with("#currency", "USD")

    @pytest.mark.anyio
    async def test_retry_on_failure(self) -> None:
        """A failing step retries the specified number of times."""
        browser = _make_mock_browser()
        # Fail twice, succeed on third attempt
        browser.click = AsyncMock(side_effect=[False, False, True])
        executor = PlaybookExecutor(browser=browser, identity=_make_identity())

        pb = _make_playbook(steps=[
            _make_step(
                action=PlaybookStepType.CLICK,
                selector="button",
                retry_on_failure=2,
            ),
        ])
        result = await executor.execute(pb, "https://example.com")
        assert result.success is True
        assert result.step_results[0].attempts == 3
        assert browser.click.call_count == 3

    @pytest.mark.anyio
    async def test_retry_exhausted_fallback_to_llm(self) -> None:
        """When retries are exhausted and fallback_to_llm is True, result shows fallback."""
        browser = _make_mock_browser()
        browser.click = AsyncMock(return_value=False)
        executor = PlaybookExecutor(browser=browser, identity=_make_identity())

        pb = _make_playbook(steps=[
            _make_step(
                action=PlaybookStepType.CLICK,
                selector="button",
                retry_on_failure=1,
                fallback_to_llm=True,
            ),
        ])
        result = await executor.execute(pb, "https://example.com")
        assert result.success is False
        assert result.fell_back_to_llm is True
        assert "failed" in result.fallback_reason.lower()

    @pytest.mark.anyio
    async def test_retry_exhausted_no_fallback(self) -> None:
        """When retries are exhausted and fallback_to_llm is False, playbook aborts."""
        browser = _make_mock_browser()
        browser.click = AsyncMock(return_value=False)
        executor = PlaybookExecutor(browser=browser, identity=_make_identity())

        pb = _make_playbook(steps=[
            _make_step(
                action=PlaybookStepType.CLICK,
                selector="button",
                retry_on_failure=0,
                fallback_to_llm=False,
            ),
        ])
        result = await executor.execute(pb, "https://example.com")
        assert result.success is False
        assert result.fell_back_to_llm is False
        assert result.error != ""

    @pytest.mark.anyio
    async def test_partial_execution(self) -> None:
        """If step 2 of 3 fails, completed_steps is 1."""
        browser = _make_mock_browser()
        browser.click = AsyncMock(side_effect=[True, False])
        executor = PlaybookExecutor(browser=browser, identity=_make_identity())

        pb = _make_playbook(steps=[
            _make_step(action=PlaybookStepType.CLICK, selector="a", fallback_to_llm=False),
            _make_step(action=PlaybookStepType.CLICK, selector="b", fallback_to_llm=False),
            _make_step(action=PlaybookStepType.CLICK, selector="c", fallback_to_llm=False),
        ])
        result = await executor.execute(pb, "https://example.com")
        assert result.success is False
        assert result.completed_steps == 1
        assert result.total_steps == 3

    @pytest.mark.anyio
    async def test_step_results_recorded(self) -> None:
        """Each step's result is recorded in step_results."""
        browser = _make_mock_browser()
        executor = PlaybookExecutor(browser=browser, identity=_make_identity())

        pb = _make_playbook(steps=[
            _make_step(action=PlaybookStepType.CLICK, selector="a"),
            _make_step(action=PlaybookStepType.WAIT, value="1"),
        ])
        result = await executor.execute(pb, "https://example.com")
        assert len(result.step_results) == 2
        assert result.step_results[0].action == PlaybookStepType.CLICK
        assert result.step_results[0].success is True
        assert result.step_results[1].action == PlaybookStepType.WAIT
        assert result.step_results[1].success is True

    @pytest.mark.anyio
    async def test_duration_tracked(self) -> None:
        """Execution duration is tracked."""
        browser = _make_mock_browser()
        executor = PlaybookExecutor(browser=browser, identity=_make_identity())

        pb = _make_playbook(steps=[_make_step(action=PlaybookStepType.WAIT, value="0")])
        result = await executor.execute(pb, "https://example.com")
        assert result.duration_sec >= 0
        assert result.completed_at is not None


# ===================================================================
# PlaybookLoader tests
# ===================================================================


class TestPlaybookLoader:
    """Tests for loading playbooks from JSON files."""

    def test_load_from_file(self, tmp_path: Path) -> None:
        """Load a single playbook from a JSON file."""
        data = {
            "playbook_id": "test_v1",
            "url_pattern": r"test\.com",
            "steps": [{"action": "click", "selector": "button"}],
        }
        pb_file = tmp_path / "test_v1.json"
        pb_file.write_text(json.dumps(data), encoding="utf-8")

        pb = load_playbook_from_file(pb_file)
        assert pb.playbook_id == "test_v1"
        assert len(pb.steps) == 1

    def test_load_from_dir(self, tmp_path: Path) -> None:
        """Load all playbooks from a directory."""
        for i in range(3):
            data = {
                "playbook_id": f"pb_{i}_v1",
                "url_pattern": f"site-{i}\\.com",
                "steps": [{"action": "click", "selector": "x"}],
            }
            (tmp_path / f"pb_{i}.json").write_text(json.dumps(data), encoding="utf-8")

        playbooks = load_playbooks_from_dir(tmp_path)
        assert len(playbooks) == 3

    def test_load_from_nonexistent_dir(self, tmp_path: Path) -> None:
        """Loading from a non-existent directory returns empty list."""
        playbooks = load_playbooks_from_dir(tmp_path / "nonexistent")
        assert playbooks == []

    def test_invalid_json_skipped(self, tmp_path: Path) -> None:
        """Invalid JSON files are skipped without raising."""
        (tmp_path / "bad.json").write_text("not valid json", encoding="utf-8")
        data = {
            "playbook_id": "good_v1",
            "url_pattern": r"good\.com",
            "steps": [{"action": "click", "selector": "x"}],
        }
        (tmp_path / "good.json").write_text(json.dumps(data), encoding="utf-8")

        playbooks = load_playbooks_from_dir(tmp_path)
        assert len(playbooks) == 1
        assert playbooks[0].playbook_id == "good_v1"

    def test_invalid_schema_skipped(self, tmp_path: Path) -> None:
        """Files with invalid schemas are skipped without raising."""
        # Missing required fields
        (tmp_path / "bad_schema.json").write_text(
            json.dumps({"playbook_id": "bad"}),
            encoding="utf-8",
        )

        playbooks = load_playbooks_from_dir(tmp_path)
        assert len(playbooks) == 0

    def test_load_sample_playbooks(self) -> None:
        """Validate that all sample playbooks in config/playbooks/ load correctly."""
        playbook_dir = Path(__file__).parents[2] / "config" / "playbooks"
        if not playbook_dir.exists():
            pytest.skip("config/playbooks/ not found")

        playbooks = load_playbooks_from_dir(playbook_dir)
        assert len(playbooks) >= 1, "Expected at least one sample playbook"
        for pb in playbooks:
            assert pb.playbook_id
            assert len(pb.steps) >= 1
            # Verify regex compiles
            re.compile(pb.url_pattern)


# ===================================================================
# PlaybookResult model tests
# ===================================================================


class TestPlaybookResult:
    """Tests for PlaybookResult and PlaybookStepResult."""

    def test_step_result_fields(self) -> None:
        """PlaybookStepResult stores expected fields."""
        sr = PlaybookStepResult(
            step_index=0,
            action=PlaybookStepType.CLICK,
            selector="button",
            success=True,
            attempts=2,
            duration_sec=1.5,
        )
        assert sr.step_index == 0
        assert sr.success is True
        assert sr.attempts == 2

    def test_result_defaults(self) -> None:
        """PlaybookResult has sensible defaults."""
        r = PlaybookResult(playbook_id="test_v1", url="https://example.com", success=False)
        assert r.completed_steps == 0
        assert r.total_steps == 0
        assert r.fell_back_to_llm is False
        assert r.step_results == []
        assert r.started_at is not None
