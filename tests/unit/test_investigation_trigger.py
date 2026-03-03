"""Unit tests for SSI investigation trigger endpoints.

Tests verify:
- ``POST /trigger/investigate`` returns 202 with scan_id and status.
- ``POST /trigger/batch`` returns 202 with entry count.
- Request validation rejects missing required fields.
- Background task is spawned with correct parameters.
"""

from __future__ import annotations

from unittest.mock import ANY, MagicMock, patch

from fastapi.testclient import TestClient

from ssi.api.app import create_app

app = create_app()
client = TestClient(app)


class TestInvestigateEndpoint:
    """Tests for POST /trigger/investigate."""

    @patch("ssi.api.investigation_routes._run_investigation")
    def test_returns_202_accepted(self, mock_run: MagicMock) -> None:
        """Endpoint returns 202 with scan_id and 'accepted' status."""
        resp = client.post(
            "/trigger/investigate",
            json={"url": "https://scam.example.com", "scan_id": "scan-abc"},
        )
        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] == "accepted"
        assert data["scan_id"] == "scan-abc"

    @patch("ssi.api.investigation_routes._run_investigation")
    def test_spawns_background_task(self, mock_run: MagicMock) -> None:
        """Background task is spawned with correct investigation parameters."""
        resp = client.post(
            "/trigger/investigate",
            json={
                "url": "https://scam.example.com",
                "scan_type": "passive",
                "scan_id": "scan-123",
                "push_to_core": False,
                "dataset": "tutorial",
            },
        )
        assert resp.status_code == 202

        # FastAPI BackgroundTasks runs the task synchronously in the test client.
        mock_run.assert_called_once_with(
            url="https://scam.example.com",
            scan_type="passive",
            scan_id="scan-123",
            push_to_core=False,
            dataset="tutorial",
            event_bus=ANY,
        )

    @patch("ssi.api.investigation_routes._run_investigation")
    def test_defaults_applied(self, mock_run: MagicMock) -> None:
        """Default values are applied for optional fields."""
        resp = client.post(
            "/trigger/investigate",
            json={"url": "https://scam.example.com"},
        )
        assert resp.status_code == 202

        call_kwargs = mock_run.call_args.kwargs
        assert call_kwargs["scan_type"] == "full"
        assert call_kwargs["push_to_core"] is True
        assert call_kwargs["dataset"] == "ssi"
        # scan_id is auto-generated when not provided
        assert isinstance(call_kwargs["scan_id"], str) and call_kwargs["scan_id"]

    def test_requires_url(self) -> None:
        """Request without URL returns 422."""
        resp = client.post("/trigger/investigate", json={})
        assert resp.status_code == 422

    @patch("ssi.api.investigation_routes._run_investigation")
    def test_rejects_invalid_scan_type(self, mock_run: MagicMock) -> None:
        """Invalid scan_type values are rejected."""
        resp = client.post(
            "/trigger/investigate",
            json={"url": "https://scam.example.com", "scan_type": "invalid"},
        )
        assert resp.status_code == 422

    @patch("ssi.api.investigation_routes._run_investigation")
    def test_scan_id_generated_when_omitted(self, mock_run: MagicMock) -> None:
        """scan_id is auto-generated when not provided in the request."""
        resp = client.post(
            "/trigger/investigate",
            json={"url": "https://scam.example.com"},
        )
        assert resp.status_code == 202
        data = resp.json()
        # scan_id must be a non-empty string (auto-generated UUID hex)
        assert isinstance(data["scan_id"], str) and data["scan_id"]


class TestBatchInvestigateEndpoint:
    """Tests for POST /trigger/batch."""

    @patch("ssi.api.investigation_routes._run_batch_investigation")
    def test_inline_manifest_returns_202(self, mock_run: MagicMock) -> None:
        """Inline manifest returns 202 with correct entry count."""
        resp = client.post(
            "/trigger/batch",
            json={
                "manifest": [
                    {"url": "https://scam1.example.com"},
                    {"url": "https://scam2.example.com"},
                ],
            },
        )
        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] == "accepted"
        assert data["entry_count"] == 2

    @patch("ssi.api.investigation_routes._run_batch_investigation")
    def test_manifest_uri_dispatches(self, mock_run: MagicMock) -> None:
        """A manifest_uri dispatches to batch loader."""
        with patch("ssi.worker.batch.load_manifest") as mock_load:
            mock_load.return_value = [{"url": "https://example.com"}]
            resp = client.post(
                "/trigger/batch",
                json={"manifest_uri": "gs://bucket/manifest.json"},
            )
        assert resp.status_code == 202

    def test_requires_manifest_or_uri(self) -> None:
        """Request without manifest or manifest_uri returns 422."""
        resp = client.post("/trigger/batch", json={})
        assert resp.status_code == 422
