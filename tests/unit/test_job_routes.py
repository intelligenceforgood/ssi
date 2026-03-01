"""Unit tests for the SSI job HTTP endpoint (Phase 3.0: task 3.0.1).

Tests verify:
- ``POST /jobs/investigate`` returns 202 with scan_id and status.
- Request validation rejects missing required fields.
- Background task is spawned with correct parameters.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from ssi.api.app import create_app

app = create_app()
client = TestClient(app)


class TestJobsInvestigateEndpoint:
    """Tests for POST /jobs/investigate."""

    @patch("ssi.api.job_routes._run_investigation_job")
    def test_returns_202_accepted(self, mock_run: MagicMock) -> None:
        """Endpoint returns 202 with scan_id and 'accepted' status."""
        resp = client.post(
            "/jobs/investigate",
            json={"url": "https://scam.example.com", "scan_id": "scan-abc"},
        )
        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] == "accepted"
        assert data["scan_id"] == "scan-abc"

    @patch("ssi.api.job_routes._run_investigation_job")
    def test_spawns_background_task(self, mock_run: MagicMock) -> None:
        """Background task is spawned with correct investigation parameters."""
        resp = client.post(
            "/jobs/investigate",
            json={
                "url": "https://scam.example.com",
                "scan_type": "passive",
                "scan_id": "scan-123",
                "push_to_core": False,
                "dataset": "tutorial",
            },
        )
        assert resp.status_code == 202

        # FastAPI BackgroundTasks runs the task after the response is sent.
        # In the test client, background tasks run synchronously.
        mock_run.assert_called_once_with(
            url="https://scam.example.com",
            scan_type="passive",
            scan_id="scan-123",
            push_to_core=False,
            dataset="tutorial",
        )

    @patch("ssi.api.job_routes._run_investigation_job")
    def test_defaults_applied(self, mock_run: MagicMock) -> None:
        """Default values are applied for optional fields."""
        resp = client.post(
            "/jobs/investigate",
            json={"url": "https://scam.example.com"},
        )
        assert resp.status_code == 202

        call_kwargs = mock_run.call_args.kwargs
        assert call_kwargs["scan_type"] == "full"
        assert call_kwargs["push_to_core"] is True
        assert call_kwargs["dataset"] == "ssi"
        assert call_kwargs["scan_id"] is None

    def test_requires_url(self) -> None:
        """Request without URL returns 422."""
        resp = client.post("/jobs/investigate", json={})
        assert resp.status_code == 422

    @patch("ssi.api.job_routes._run_investigation_job")
    def test_rejects_invalid_scan_type(self, mock_run: MagicMock) -> None:
        """Invalid scan_type values are rejected."""
        resp = client.post(
            "/jobs/investigate",
            json={"url": "https://scam.example.com", "scan_type": "invalid"},
        )
        assert resp.status_code == 422

    @patch("ssi.api.job_routes._run_investigation_job")
    def test_scan_id_none_when_omitted(self, mock_run: MagicMock) -> None:
        """scan_id is None when not provided in the request."""
        resp = client.post(
            "/jobs/investigate",
            json={"url": "https://scam.example.com"},
        )
        assert resp.status_code == 202
        data = resp.json()
        assert data["scan_id"] is None
