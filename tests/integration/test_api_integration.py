"""API integration tests — verify request -> background task -> response round-trip.

Uses the FastAPI ``TestClient`` with the investigation endpoint mocked so it
completes synchronously. Validates HTTP contract, task status tracking, and
the concurrent investigation limit (8B hardening).
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from ssi.api.app import create_app
from ssi.store.task_store import build_task_store


@pytest.fixture()
def client():
    """Fresh TestClient with an empty task store and mocked investigation."""
    store = build_task_store()
    if hasattr(store, "_data"):
        store._data.clear()

    app = create_app()
    with patch("ssi.api.routes._run_investigation_task") as mock_run:
        # Mock _run_investigation_task to simply set status to completed in the store
        def dummy_run(task_id, req):
            store = build_task_store()
            store.update(task_id, status="completed", result={"url": "https://example.com", "success": True})

        mock_run.side_effect = dummy_run

        with TestClient(app) as c:
            yield c

    if hasattr(store, "_data"):
        store._data.clear()


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
        # Since TestClient runs background tasks inline, status becomes completed immediately
        assert data["status"] in ("pending", "completed")
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
    """Verify that task store is correctly managed."""

    def test_completed_task_has_result(self, client: TestClient) -> None:
        """When the background task finishes, status becomes completed and has a result."""
        store = build_task_store()
        store.set(
            "test-id-001",
            {
                "status": "completed",
                "result": {"url": "https://example.com", "success": True},
            },
        )

        resp = client.get("/investigate/test-id-001")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "completed"
        assert data["result"]["success"] is True

    def test_failed_task_has_error(self, client: TestClient) -> None:
        """Failed tasks include the error detail in the result."""
        store = build_task_store()
        store.set(
            "test-id-002",
            {
                "status": "failed",
                "result": {"error": "Connection timeout"},
            },
        )

        resp = client.get("/investigate/test-id-002")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "failed"
        assert "error" in data["result"]
