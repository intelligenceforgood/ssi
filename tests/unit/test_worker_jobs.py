"""Unit tests for SSI Cloud Run Job runner."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from ssi.worker.jobs import _configure_logging, main


class TestConfigureLogging:
    def test_sets_up_logging(self):
        """Verify logging is configured without errors."""
        _configure_logging()


class TestMain:
    def test_requires_url(self, monkeypatch):
        """Job exits with code 1 when SSI_JOB__URL is missing."""
        monkeypatch.delenv("SSI_JOB__URL", raising=False)
        assert main() == 1

    def test_requires_non_empty_url(self, monkeypatch):
        """Job exits with code 1 when SSI_JOB__URL is whitespace."""
        monkeypatch.setenv("SSI_JOB__URL", "   ")
        assert main() == 1

    @patch("ssi.settings.get_settings")
    @patch("ssi.investigator.orchestrator.run_investigation")
    def test_successful_investigation(self, mock_run, mock_settings, monkeypatch):
        """Happy path: successful investigation returns 0."""
        monkeypatch.setenv("SSI_JOB__URL", "https://scam.example.com")

        mock_settings_instance = MagicMock()
        mock_settings_instance.evidence.output_dir = "/tmp/ssi-test"
        mock_settings.return_value = mock_settings_instance

        mock_result = MagicMock()
        mock_result.success = True
        mock_result.investigation_id = "test-123"
        mock_result.status.value = "complete"
        mock_result.taxonomy_result = None
        mock_result.error = None
        mock_run.return_value = mock_result

        assert main() == 0
        mock_run.assert_called_once()
        call_kwargs = mock_run.call_args
        assert call_kwargs[1]["url"] == "https://scam.example.com"
        assert call_kwargs[1]["passive_only"] is False

    @patch("ssi.settings.get_settings")
    @patch("ssi.investigator.orchestrator.run_investigation")
    def test_passive_only_flag(self, mock_run, mock_settings, monkeypatch):
        """SSI_JOB__PASSIVE_ONLY=true sets passive_only."""
        monkeypatch.setenv("SSI_JOB__URL", "https://scam.example.com")
        monkeypatch.setenv("SSI_JOB__PASSIVE_ONLY", "true")

        mock_settings_instance = MagicMock()
        mock_settings_instance.evidence.output_dir = "/tmp/ssi-test"
        mock_settings.return_value = mock_settings_instance

        mock_result = MagicMock()
        mock_result.success = True
        mock_result.investigation_id = "test-123"
        mock_result.status.value = "complete"
        mock_result.taxonomy_result = None
        mock_run.return_value = mock_result

        assert main() == 0
        assert mock_run.call_args[1]["passive_only"] is True

    @patch("ssi.settings.get_settings")
    @patch("ssi.investigator.orchestrator.run_investigation")
    def test_failed_investigation(self, mock_run, mock_settings, monkeypatch):
        """Failed investigation returns exit code 1."""
        monkeypatch.setenv("SSI_JOB__URL", "https://scam.example.com")

        mock_settings_instance = MagicMock()
        mock_settings_instance.evidence.output_dir = "/tmp/ssi-test"
        mock_settings.return_value = mock_settings_instance

        mock_result = MagicMock()
        mock_result.success = False
        mock_result.investigation_id = "test-fail"
        mock_result.status.value = "failed"
        mock_result.taxonomy_result = None
        mock_result.error = "Connection refused"
        mock_run.return_value = mock_result

        assert main() == 1

    @patch("ssi.settings.get_settings")
    @patch("ssi.investigator.orchestrator.run_investigation")
    def test_exception_returns_1(self, mock_run, mock_settings, monkeypatch):
        """Unhandled exception returns exit code 1."""
        monkeypatch.setenv("SSI_JOB__URL", "https://scam.example.com")

        mock_settings_instance = MagicMock()
        mock_settings_instance.evidence.output_dir = "/tmp/ssi-test"
        mock_settings.return_value = mock_settings_instance

        mock_run.side_effect = RuntimeError("boom")
        assert main() == 1

    @patch("ssi.worker.jobs._push_to_core")
    @patch("ssi.settings.get_settings")
    @patch("ssi.investigator.orchestrator.run_investigation")
    def test_push_to_core_when_enabled(self, mock_run, mock_settings, mock_push, monkeypatch):
        """SSI_JOB__PUSH_TO_CORE=true triggers core push."""
        monkeypatch.setenv("SSI_JOB__URL", "https://scam.example.com")
        monkeypatch.setenv("SSI_JOB__PUSH_TO_CORE", "true")
        monkeypatch.setenv("SSI_JOB__TRIGGER_DOSSIER", "true")
        monkeypatch.setenv("SSI_JOB__DATASET", "custom-ds")

        mock_settings_instance = MagicMock()
        mock_settings_instance.evidence.output_dir = "/tmp/ssi-test"
        mock_settings.return_value = mock_settings_instance

        mock_result = MagicMock()
        mock_result.success = True
        mock_result.investigation_id = "test-push"
        mock_result.status.value = "complete"
        mock_result.taxonomy_result = None
        mock_run.return_value = mock_result

        assert main() == 0
        mock_push.assert_called_once_with(mock_result, dataset="custom-ds", trigger_dossier=True)

    @patch("ssi.worker.jobs._push_to_core")
    @patch("ssi.settings.get_settings")
    @patch("ssi.investigator.orchestrator.run_investigation")
    def test_no_push_when_disabled(self, mock_run, mock_settings, mock_push, monkeypatch):
        """SSI_JOB__PUSH_TO_CORE=false (default) does not push."""
        monkeypatch.setenv("SSI_JOB__URL", "https://scam.example.com")

        mock_settings_instance = MagicMock()
        mock_settings_instance.evidence.output_dir = "/tmp/ssi-test"
        mock_settings.return_value = mock_settings_instance

        mock_result = MagicMock()
        mock_result.success = True
        mock_result.investigation_id = "test-nopush"
        mock_result.status.value = "complete"
        mock_result.taxonomy_result = None
        mock_run.return_value = mock_result

        assert main() == 0
        mock_push.assert_not_called()
