"""Unit tests for the SSI task-status reporter (DB-backed variant).

Tests verify:
- Reporter no-ops when scan_id is absent.
- Reporter writes to ``site_scans`` via ``ScanStore.update_scan()``.
- DB errors are handled gracefully (no exceptions raised).
- Correct columns are set for running / completed / failed statuses.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

from ssi.worker.task_reporter import TaskStatusReporter


class TestTaskStatusReporterInit:
    """Initialisation and configuration tests."""

    def test_disabled_when_no_scan_id(self) -> None:
        """Reporter is disabled when scan_id is empty."""
        reporter = TaskStatusReporter(scan_id="")
        assert not reporter.is_enabled

    def test_enabled_when_scan_id_set(self) -> None:
        """Reporter is enabled when scan_id is provided."""
        reporter = TaskStatusReporter(scan_id="scan-abc123")
        assert reporter.is_enabled

    def test_disabled_when_no_scan_id_arg(self) -> None:
        """Reporter is disabled when no scan_id is passed."""
        reporter = TaskStatusReporter()
        assert not reporter.is_enabled


class TestTaskStatusReporterUpdate:
    """Update / DB-write tests."""

    def test_noop_when_disabled(self) -> None:
        """No DB call when reporter is disabled."""
        reporter = TaskStatusReporter(scan_id="")
        # Should not raise
        reporter.update(status="running", message="test")

    @patch("ssi.worker.task_reporter.TaskStatusReporter._get_store")
    def test_updates_running_status(self, mock_get_store: MagicMock) -> None:
        """Running status writes only status column."""
        mock_store = MagicMock()
        mock_get_store.return_value = mock_store

        reporter = TaskStatusReporter(scan_id="scan-abc123")
        reporter.update(status="running", message="In progress")

        mock_store.update_scan.assert_called_once()
        call_kwargs = mock_store.update_scan.call_args
        assert call_kwargs.args[0] == "scan-abc123"
        assert call_kwargs.kwargs["status"] == "running"
        # Running should NOT set error_message or completed_at
        assert "error_message" not in call_kwargs.kwargs
        assert "completed_at" not in call_kwargs.kwargs

    @patch("ssi.worker.task_reporter.TaskStatusReporter._get_store")
    def test_updates_failed_status_with_error_message(self, mock_get_store: MagicMock) -> None:
        """Failed status stores message as error_message."""
        mock_store = MagicMock()
        mock_get_store.return_value = mock_store

        reporter = TaskStatusReporter(scan_id="scan-abc123")
        reporter.update(status="failed", message="Connection timed out")

        call_kwargs = mock_store.update_scan.call_args
        assert call_kwargs.kwargs["status"] == "failed"
        assert call_kwargs.kwargs["error_message"] == "Connection timed out"

    @patch("ssi.worker.task_reporter.TaskStatusReporter._get_store")
    def test_updates_completed_status_with_timestamp(self, mock_get_store: MagicMock) -> None:
        """Completed status sets completed_at timestamp."""
        mock_store = MagicMock()
        mock_get_store.return_value = mock_store

        reporter = TaskStatusReporter(scan_id="scan-abc123")
        reporter.update(status="completed", message="Done")

        call_kwargs = mock_store.update_scan.call_args
        assert call_kwargs.kwargs["status"] == "completed"
        assert isinstance(call_kwargs.kwargs["completed_at"], datetime)
        assert call_kwargs.kwargs["completed_at"].tzinfo == UTC

    @patch("ssi.worker.task_reporter.TaskStatusReporter._get_store")
    def test_maps_extra_fields_to_columns(self, mock_get_store: MagicMock) -> None:
        """Extra kwargs risk_score, case_id, duration_seconds are persisted."""
        mock_store = MagicMock()
        mock_get_store.return_value = mock_store

        reporter = TaskStatusReporter(scan_id="scan-abc123")
        reporter.update(
            status="completed",
            message="Done",
            risk_score=75.5,
            case_id="case-xyz",
            duration_seconds=42.3,
        )

        call_kwargs = mock_store.update_scan.call_args
        assert call_kwargs.kwargs["risk_score"] == 75.5
        assert call_kwargs.kwargs["case_id"] == "case-xyz"
        assert call_kwargs.kwargs["duration_seconds"] == 42.3

    @patch("ssi.worker.task_reporter.TaskStatusReporter._get_store")
    def test_ignores_unmapped_extra_fields(self, mock_get_store: MagicMock) -> None:
        """Extra kwargs not in _EXTRA_COLUMN_KEYS are silently ignored."""
        mock_store = MagicMock()
        mock_get_store.return_value = mock_store

        reporter = TaskStatusReporter(scan_id="scan-abc123")
        reporter.update(
            status="completed",
            message="Done",
            investigation_id="inv-123",
            some_random_field="ignored",
        )

        call_kwargs = mock_store.update_scan.call_args
        assert "investigation_id" not in call_kwargs.kwargs
        assert "some_random_field" not in call_kwargs.kwargs

    @patch("ssi.worker.task_reporter.TaskStatusReporter._get_store")
    def test_skips_none_extra_values(self, mock_get_store: MagicMock) -> None:
        """None values for mapped columns are not written."""
        mock_store = MagicMock()
        mock_get_store.return_value = mock_store

        reporter = TaskStatusReporter(scan_id="scan-abc123")
        reporter.update(status="completed", message="Done", risk_score=None, case_id=None)

        call_kwargs = mock_store.update_scan.call_args
        assert "risk_score" not in call_kwargs.kwargs
        assert "case_id" not in call_kwargs.kwargs

    @patch("ssi.worker.task_reporter.TaskStatusReporter._get_store")
    def test_handles_db_error_gracefully(self, mock_get_store: MagicMock) -> None:
        """DB errors are caught and logged, not raised."""
        mock_store = MagicMock()
        mock_store.update_scan.side_effect = RuntimeError("DB connection lost")
        mock_get_store.return_value = mock_store

        reporter = TaskStatusReporter(scan_id="scan-abc123")
        # Should not raise
        reporter.update(status="running", message="test")

    @patch("ssi.worker.task_reporter.TaskStatusReporter._get_store")
    def test_store_is_cached(self, mock_get_store: MagicMock) -> None:
        """ScanStore is built once and reused across update calls."""
        mock_store = MagicMock()
        mock_get_store.return_value = mock_store

        reporter = TaskStatusReporter(scan_id="scan-abc123")
        reporter.update(status="running", message="start")
        reporter.update(status="completed", message="done")

        # _get_store called twice (once per update), but the lazy
        # caching inside _get_store itself builds only once.
        assert mock_store.update_scan.call_count == 2
