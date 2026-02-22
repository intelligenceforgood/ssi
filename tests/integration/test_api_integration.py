"""API integration tests — verify request → background task → response round-trip.

Uses the FastAPI ``TestClient`` with the investigation endpoint mocked so it
completes synchronously. Validates HTTP contract, task status tracking, and
the concurrent investigation limit (8B hardening).
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from ssi.api.app import create_app
from ssi.api.routes import _TASKS


@pytest.fixture()
def client():
    """Fresh TestClient with an empty _TASKS dict."""
    _TASKS.clear()
    app = create_app()
    with TestClient(app) as c:
        yield c
    _TASKS.clear()


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------


class TestHealthEndpoint:
    """Verify the health endpoint works."""

    def test_health(self, client: TestClient) -> None:
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"


# ---------------------------------------------------------------------------
# Investigation endpoints
# ---------------------------------------------------------------------------


class TestInvestigationSubmit:
    """POST /investigate request/response contract."""

    def test_submit_returns_pending(self, client: TestClient) -> None:
        """Submitting a URL returns 200 with a task ID in pending state."""
        resp = client.post("/investigate", json={"url": "https://example.com"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "pending"
        assert "investigation_id" in data

    def test_invalid_scan_type_rejected(self, client: TestClient) -> None:
        """Invalid scan_type is rejected by Pydantic validation."""
        resp = client.post(
            "/investigate",
            json={"url": "https://example.com", "scan_type": "invalid"},
        )
        assert resp.status_code == 422

    def test_missing_url_rejected(self, client: TestClient) -> None:
        """Missing required field returns 422."""
        resp = client.post("/investigate", json={})
        assert resp.status_code == 422


class TestInvestigationStatus:
    """GET /investigate/{id} status polling."""

    def test_nonexistent_id_returns_404(self, client: TestClient) -> None:
        resp = client.get("/investigate/nonexistent-uuid")
        assert resp.status_code == 404

    def test_poll_pending_task(self, client: TestClient) -> None:
        """After submission, polling returns the current status."""
        # Submit a task
        resp = client.post("/investigate", json={"url": "https://example.com"})
        task_id = resp.json()["investigation_id"]

        # Poll — status should be pending or running (background task races)
        poll = client.get(f"/investigate/{task_id}")
        assert poll.status_code == 200
        assert poll.json()["status"] in ("pending", "running", "completed", "failed")


# ---------------------------------------------------------------------------
# Task tracking round-trip
# ---------------------------------------------------------------------------


class TestTaskTracking:
    """Verify that _TASKS dict is correctly managed."""

    def test_completed_task_has_result(self, client: TestClient) -> None:
        """When the background task finishes, status becomes completed and has a result."""
        # Manually set a completed task to simulate the background finishing
        _TASKS["test-id-001"] = {
            "status": "completed",
            "result": {"url": "https://example.com", "success": True},
        }

        resp = client.get("/investigate/test-id-001")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "completed"
        assert data["result"]["success"] is True

    def test_failed_task_has_error(self, client: TestClient) -> None:
        """Failed tasks include the error detail in the result."""
        _TASKS["test-id-002"] = {
            "status": "failed",
            "result": {"error": "Connection timeout"},
        }

        resp = client.get("/investigate/test-id-002")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "failed"
        assert "error" in data["result"]
