"""Unit tests for the SSI task-status reporter (Phase 3: 3.2).

Tests verify:
- Reporter no-ops when env vars are absent.
- Reporter posts to the correct URL with auth headers.
- HTTP errors are handled gracefully (no exceptions raised).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from ssi.worker.task_reporter import TaskStatusReporter


class TestTaskStatusReporterInit:
    """Initialisation and configuration tests."""

    def test_disabled_when_no_env_vars(self) -> None:
        """Reporter is disabled when neither task_id nor endpoint is set."""
        reporter = TaskStatusReporter(task_id="", endpoint="")
        assert not reporter.is_enabled

    def test_disabled_when_task_id_missing(self) -> None:
        """Reporter is disabled when task_id is empty."""
        reporter = TaskStatusReporter(task_id="", endpoint="https://api.example.com/tasks")
        assert not reporter.is_enabled

    def test_disabled_when_endpoint_missing(self) -> None:
        """Reporter is disabled when endpoint is empty."""
        reporter = TaskStatusReporter(task_id="ssi-abc123", endpoint="")
        assert not reporter.is_enabled

    def test_enabled_when_both_set(self) -> None:
        """Reporter is enabled when both task_id and endpoint are set."""
        reporter = TaskStatusReporter(
            task_id="ssi-abc123",
            endpoint="https://api.example.com/tasks",
        )
        assert reporter.is_enabled

    def test_reads_from_env_vars(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Reporter reads configuration from environment variables."""
        monkeypatch.setenv("I4G_TASK_ID", "ssi-from-env")
        monkeypatch.setenv("I4G_TASK_STATUS_URL", "https://core.example.com/tasks")
        monkeypatch.setenv("SSI_INTEGRATION__CORE_API_KEY", "test-key-123")

        reporter = TaskStatusReporter()
        assert reporter.task_id == "ssi-from-env"
        assert reporter.endpoint == "https://core.example.com/tasks"
        assert reporter.is_enabled


class TestTaskStatusReporterUpdate:
    """Update posting tests."""

    def test_noop_when_disabled(self) -> None:
        """No HTTP call when reporter is disabled."""
        reporter = TaskStatusReporter(task_id="", endpoint="")
        # Should not raise
        reporter.update(status="running", message="test")

    @patch("ssi.worker.task_reporter.httpx.post")
    def test_posts_to_correct_url(self, mock_post: MagicMock) -> None:
        """Reporter posts to {endpoint}/{task_id}/update."""
        mock_post.return_value = MagicMock(status_code=200, raise_for_status=MagicMock())

        reporter = TaskStatusReporter(
            task_id="ssi-abc123",
            endpoint="https://api.example.com/tasks",
            api_key="test-key",
        )
        reporter.update(status="running", message="In progress")

        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert call_args.args[0] == "https://api.example.com/tasks/ssi-abc123/update"
        assert call_args.kwargs["json"]["status"] == "running"
        assert call_args.kwargs["json"]["message"] == "In progress"

    @patch("ssi.worker.task_reporter.httpx.post")
    def test_includes_api_key_header(self, mock_post: MagicMock) -> None:
        """API key is sent as X-API-KEY header."""
        mock_post.return_value = MagicMock(status_code=200, raise_for_status=MagicMock())

        reporter = TaskStatusReporter(
            task_id="ssi-abc123",
            endpoint="https://api.example.com/tasks",
            api_key="my-secret-key",
        )
        reporter.update(status="completed", message="Done")

        headers = mock_post.call_args.kwargs["headers"]
        assert headers.get("X-API-KEY") == "my-secret-key"

    @patch("ssi.worker.task_reporter.httpx.post")
    def test_includes_extra_fields(self, mock_post: MagicMock) -> None:
        """Extra keyword args are included in the POST body."""
        mock_post.return_value = MagicMock(status_code=200, raise_for_status=MagicMock())

        reporter = TaskStatusReporter(
            task_id="ssi-abc123",
            endpoint="https://api.example.com/tasks",
        )
        reporter.update(
            status="completed",
            message="Done",
            investigation_id="inv-123",
            risk_score=75.5,
        )

        body = mock_post.call_args.kwargs["json"]
        assert body["investigation_id"] == "inv-123"
        assert body["risk_score"] == 75.5

    @patch("ssi.worker.task_reporter.httpx.post")
    def test_handles_http_error_gracefully(self, mock_post: MagicMock) -> None:
        """HTTP errors are caught and logged, not raised."""
        import httpx

        mock_post.side_effect = httpx.ConnectError("Connection refused")

        reporter = TaskStatusReporter(
            task_id="ssi-abc123",
            endpoint="https://api.example.com/tasks",
        )
        # Should not raise
        reporter.update(status="running", message="test")

    @patch("ssi.worker.task_reporter.httpx.post")
    def test_strips_trailing_slash_from_endpoint(self, mock_post: MagicMock) -> None:
        """Trailing slash on endpoint is stripped before building URL."""
        mock_post.return_value = MagicMock(status_code=200, raise_for_status=MagicMock())

        reporter = TaskStatusReporter(
            task_id="ssi-abc123",
            endpoint="https://api.example.com/tasks/",
        )
        reporter.update(status="running", message="test")

        url = mock_post.call_args.args[0]
        assert "/tasks//ssi" not in url
        assert url == "https://api.example.com/tasks/ssi-abc123/update"
