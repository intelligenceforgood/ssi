"""Tests for module status tracking in investigation models and orchestrator."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ssi.models.investigation import InvestigationResult, ModuleOutcome, ModuleStatus

# ---------------------------------------------------------------------------
# Phase 1 — Model tests
# ---------------------------------------------------------------------------


class TestModuleStatus:
    """Test the ModuleStatus enum values and string representation."""

    def test_enum_values(self) -> None:
        assert ModuleStatus.SUCCESS == "success"
        assert ModuleStatus.DISABLED == "disabled"
        assert ModuleStatus.SKIPPED == "skipped"
        assert ModuleStatus.FAILED == "failed"
        assert ModuleStatus.MOCKED == "mocked"

    def test_all_members(self) -> None:
        assert set(ModuleStatus) == {
            ModuleStatus.SUCCESS,
            ModuleStatus.DISABLED,
            ModuleStatus.SKIPPED,
            ModuleStatus.FAILED,
            ModuleStatus.MOCKED,
        }


class TestModuleOutcome:
    """Test ModuleOutcome model serialization and defaults."""

    def test_required_status(self) -> None:
        outcome = ModuleOutcome(status=ModuleStatus.SUCCESS)
        assert outcome.status == ModuleStatus.SUCCESS
        assert outcome.message == ""
        assert outcome.duration_ms == 0.0
        assert outcome.error_type == ""

    def test_full_construction(self) -> None:
        outcome = ModuleOutcome(
            status=ModuleStatus.FAILED,
            message="DNS resolution failed (NXDOMAIN)",
            duration_ms=42.5,
            error_type="socket.gaierror",
        )
        assert outcome.status == ModuleStatus.FAILED
        assert "NXDOMAIN" in outcome.message
        assert outcome.duration_ms == 42.5
        assert outcome.error_type == "socket.gaierror"

    def test_json_round_trip(self) -> None:
        outcome = ModuleOutcome(
            status=ModuleStatus.DISABLED,
            message="Sec-Gemini integration disabled in config",
        )
        data = outcome.model_dump(mode="json")
        assert data["status"] == "disabled"
        assert data["message"] == "Sec-Gemini integration disabled in config"

        restored = ModuleOutcome.model_validate(data)
        assert restored.status == ModuleStatus.DISABLED
        assert restored.message == outcome.message

    def test_missing_status_raises(self) -> None:
        with pytest.raises(Exception):  # noqa: B017 — Pydantic ValidationError
            ModuleOutcome()  # type: ignore[call-arg]


class TestInvestigationResultModuleStatuses:
    """Test the module_statuses field on InvestigationResult."""

    def test_defaults_to_empty_dict(self) -> None:
        result = InvestigationResult(url="https://example.com")
        assert result.module_statuses == {}

    def test_add_module_status(self) -> None:
        result = InvestigationResult(url="https://example.com")
        result.module_statuses["whois"] = ModuleOutcome(status=ModuleStatus.SUCCESS, duration_ms=150.0)
        assert "whois" in result.module_statuses
        assert result.module_statuses["whois"].status == ModuleStatus.SUCCESS

    def test_backward_compatibility_missing_field(self) -> None:
        """Deserializing old JSON without module_statuses should default to empty dict."""
        old_json = {
            "url": "https://example.com",
            "investigation_id": "00000000-0000-0000-0000-000000000001",
        }
        result = InvestigationResult.model_validate(old_json)
        assert result.module_statuses == {}

    def test_json_round_trip_with_statuses(self) -> None:
        result = InvestigationResult(url="https://example.com")
        result.module_statuses["dns"] = ModuleOutcome(
            status=ModuleStatus.SKIPPED,
            message="Domain does not resolve (NXDOMAIN)",
        )
        result.module_statuses["sec_gemini"] = ModuleOutcome(
            status=ModuleStatus.DISABLED,
            message="Sec-Gemini integration disabled in config",
        )

        data = result.model_dump(mode="json")
        assert "module_statuses" in data
        assert data["module_statuses"]["dns"]["status"] == "skipped"
        assert data["module_statuses"]["sec_gemini"]["status"] == "disabled"

        restored = InvestigationResult.model_validate(data)
        assert restored.module_statuses["dns"].status == ModuleStatus.SKIPPED
        assert restored.module_statuses["sec_gemini"].status == ModuleStatus.DISABLED


# ---------------------------------------------------------------------------
# Phase 2 — Orchestrator helper tests
# ---------------------------------------------------------------------------


class TestSanitizeError:
    """Test the _sanitize_error helper in the orchestrator."""

    def test_simple_error(self) -> None:
        from ssi.investigator.orchestrator import _sanitize_error

        err = ValueError("Something went wrong")
        assert _sanitize_error(err) == "Something went wrong"

    def test_multiline_error_takes_first_line(self) -> None:
        from ssi.investigator.orchestrator import _sanitize_error

        err = RuntimeError("Line one\nLine two\nLine three")
        assert _sanitize_error(err) == "Line one"

    def test_empty_message_returns_class_name(self) -> None:
        from ssi.investigator.orchestrator import _sanitize_error

        err = RuntimeError()
        assert _sanitize_error(err) == "RuntimeError"

    def test_long_message_truncated(self) -> None:
        from ssi.investigator.orchestrator import _sanitize_error

        err = ValueError("x" * 500)
        assert len(_sanitize_error(err)) == 200


class TestRecordStatus:
    """Test the _record_status helper in the orchestrator."""

    def test_record_success(self) -> None:
        from ssi.investigator.orchestrator import _record_status

        result = InvestigationResult(url="https://example.com")
        _record_status(result, "whois", ModuleStatus.SUCCESS, duration_ms=42.0)

        assert "whois" in result.module_statuses
        outcome = result.module_statuses["whois"]
        assert outcome.status == ModuleStatus.SUCCESS
        assert outcome.duration_ms == 42.0
        assert outcome.error_type == ""

    def test_record_failure_with_error(self) -> None:
        from ssi.investigator.orchestrator import _record_status

        result = InvestigationResult(url="https://example.com")
        err = ConnectionError("Connection refused")
        _record_status(result, "dns", ModuleStatus.FAILED, error=err, duration_ms=10.0)

        outcome = result.module_statuses["dns"]
        assert outcome.status == ModuleStatus.FAILED
        assert outcome.message == "Connection refused"
        assert outcome.error_type == "ConnectionError"
        assert outcome.duration_ms == 10.0

    def test_record_disabled_with_message(self) -> None:
        from ssi.investigator.orchestrator import _record_status

        result = InvestigationResult(url="https://example.com")
        _record_status(
            result,
            "sec_gemini",
            ModuleStatus.DISABLED,
            message="Sec-Gemini integration disabled in config",
        )

        outcome = result.module_statuses["sec_gemini"]
        assert outcome.status == ModuleStatus.DISABLED
        assert "disabled in config" in outcome.message

    def test_message_overrides_error_sanitization(self) -> None:
        from ssi.investigator.orchestrator import _record_status

        result = InvestigationResult(url="https://example.com")
        err = ValueError("raw traceback stuff")
        _record_status(
            result,
            "geoip",
            ModuleStatus.FAILED,
            message="Custom message",
            error=err,
        )

        # When both message and error are provided, message wins
        outcome = result.module_statuses["geoip"]
        assert outcome.message == "Custom message"
        assert outcome.error_type == "ValueError"

    def test_overwrites_existing_status(self) -> None:
        from ssi.investigator.orchestrator import _record_status

        result = InvestigationResult(url="https://example.com")
        _record_status(result, "whois", ModuleStatus.SKIPPED, message="first")
        _record_status(result, "whois", ModuleStatus.SUCCESS, message="second")

        assert result.module_statuses["whois"].status == ModuleStatus.SUCCESS
        assert result.module_statuses["whois"].message == "second"


class TestSecGeminiStatusResolution:
    """Verify that run_investigation records correct status for sec_gemini based on outcome."""

    @patch("ssi.investigator.orchestrator._check_domain_resolution", return_value=True)
    @patch("ssi.investigator.orchestrator._run_whois", return_value=None)
    @patch("ssi.investigator.orchestrator._run_dns", return_value=None)
    @patch("ssi.investigator.orchestrator._run_ssl", return_value=None)
    @patch("ssi.investigator.orchestrator._run_geoip", return_value=None)
    @patch("ssi.investigator.orchestrator._run_browser_capture", return_value=None)
    @patch("ssi.investigator.orchestrator._run_virustotal", return_value=None)
    @patch("ssi.investigator.orchestrator._run_urlscan", return_value=None)
    def test_sec_gemini_status_resolution(
        self,
        _mock_urlscan: MagicMock,
        _mock_vt: MagicMock,
        _mock_capture: MagicMock,
        _mock_geoip: MagicMock,
        _mock_ssl: MagicMock,
        _mock_dns: MagicMock,
        _mock_whois: MagicMock,
        _mock_domain: MagicMock,
        tmp_path: Path,
    ) -> None:
        from ssi.investigator.orchestrator import run_investigation

        mock_settings = MagicMock()
        mock_settings.storage.persist_scans = False
        mock_settings.cost.enabled = False

        # 1. Success case
        def _mock_enrich_success(url, result):
            result.sec_gemini_analysis = {"raw_agent_response": "Successful response content"}

        with (
            patch("ssi.settings.get_settings", return_value=mock_settings),
            patch("ssi.investigator.orchestrator._run_sec_gemini_enrichment", side_effect=_mock_enrich_success),
        ):
            res = run_investigation(
                url="https://scam.example.com",
                output_dir=tmp_path,
                scan_type="passive",
                skip_whois=True,
                skip_screenshot=True,
                skip_virustotal=True,
                skip_urlscan=True,
            )
            assert res.module_statuses["sec_gemini"].status == ModuleStatus.SUCCESS

        # 2. Failed case
        def _mock_enrich_failed(url, result):
            result.sec_gemini_analysis = {"raw_agent_response": "ERROR: Session timed out"}

        with (
            patch("ssi.settings.get_settings", return_value=mock_settings),
            patch("ssi.investigator.orchestrator._run_sec_gemini_enrichment", side_effect=_mock_enrich_failed),
        ):
            res = run_investigation(
                url="https://scam.example.com",
                output_dir=tmp_path,
                scan_type="passive",
                skip_whois=True,
                skip_screenshot=True,
                skip_virustotal=True,
                skip_urlscan=True,
            )
            assert res.module_statuses["sec_gemini"].status == ModuleStatus.FAILED
            assert res.module_statuses["sec_gemini"].message == "Session timed out"

        # 3. Mocked case
        def _mock_enrich_mocked(url, result):
            result.sec_gemini_analysis = {"raw_agent_response": "MOCK_RESPONSE: local development mock"}

        with (
            patch("ssi.settings.get_settings", return_value=mock_settings),
            patch("ssi.investigator.orchestrator._run_sec_gemini_enrichment", side_effect=_mock_enrich_mocked),
        ):
            res = run_investigation(
                url="https://scam.example.com",
                output_dir=tmp_path,
                scan_type="passive",
                skip_whois=True,
                skip_screenshot=True,
                skip_virustotal=True,
                skip_urlscan=True,
            )
            assert res.module_statuses["sec_gemini"].status == ModuleStatus.MOCKED
            assert res.module_statuses["sec_gemini"].message == "Mock fallback used"
