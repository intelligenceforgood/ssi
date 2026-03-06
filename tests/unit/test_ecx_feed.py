"""Unit tests for eCX Phase 3 intelligence feed and polling status API endpoints."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ssi.api.ecx_routes import ecx_router

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def app() -> FastAPI:
    """Create a minimal FastAPI app with the eCX router."""
    _app = FastAPI()
    _app.include_router(ecx_router)
    return _app


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    """Test client for the eCX router."""
    return TestClient(app)


def _mock_ecx_response(records: list[dict[str, Any]]) -> MagicMock:
    """Build a mock httpx.Response with eCX-style JSON."""
    resp = MagicMock()
    resp.json.return_value = {"data": records, "current_page": 1, "total": len(records)}
    resp.status_code = 200
    return resp


# ---------------------------------------------------------------------------
# GET /ecx/feed
# ---------------------------------------------------------------------------


class TestFeedEndpoint:
    """Tests for the intelligence feed endpoint."""

    def test_feed_returns_records(self, client: TestClient) -> None:
        """Feed returns eCX records for the specified module."""
        mock_client = MagicMock()
        mock_client._request.return_value = _mock_ecx_response(
            [
                {"id": 100, "url": "https://scam.example.com", "brand": "Acme", "confidence": 90},
                {"id": 101, "url": "https://phish.example.com", "brand": "BigCo", "confidence": 70},
            ]
        )

        with patch("ssi.api.ecx_routes._require_client", return_value=mock_client):
            resp = client.get("/ecx/feed?module=phish&limit=50")

        assert resp.status_code == 200
        data = resp.json()
        assert data["module"] == "phish"
        assert data["count"] == 2
        assert len(data["records"]) == 2

    def test_feed_filters_by_confidence(self, client: TestClient) -> None:
        """Records below confidence_min are excluded."""
        mock_client = MagicMock()
        mock_client._request.return_value = _mock_ecx_response(
            [
                {"id": 100, "url": "https://a.example.com", "confidence": 90},
                {"id": 101, "url": "https://b.example.com", "confidence": 30},
            ]
        )

        with patch("ssi.api.ecx_routes._require_client", return_value=mock_client):
            resp = client.get("/ecx/feed?module=phish&confidence_min=50")

        data = resp.json()
        assert data["count"] == 1
        assert data["records"][0]["id"] == 100

    def test_feed_filters_by_brand(self, client: TestClient) -> None:
        """Brand filter is case-insensitive substring match."""
        mock_client = MagicMock()
        mock_client._request.return_value = _mock_ecx_response(
            [
                {"id": 100, "brand": "Rakuten", "confidence": 80},
                {"id": 101, "brand": "PayPal", "confidence": 80},
                {"id": 102, "brand": "rakuten Bank", "confidence": 80},
            ]
        )

        with patch("ssi.api.ecx_routes._require_client", return_value=mock_client):
            resp = client.get("/ecx/feed?module=phish&brand=rakuten")

        data = resp.json()
        assert data["count"] == 2

    def test_feed_since_id_forwarded(self, client: TestClient) -> None:
        """The since_id parameter is passed to eCX as idGt filter."""
        mock_client = MagicMock()
        mock_client._request.return_value = _mock_ecx_response([])

        with patch("ssi.api.ecx_routes._require_client", return_value=mock_client):
            client.get("/ecx/feed?module=phish&since_id=500")

        call_args = mock_client._request.call_args
        body = call_args.kwargs.get("json") or call_args[1].get("json")
        assert body["filters"]["idGt"] == 500

    def test_feed_invalid_module_rejected(self, client: TestClient) -> None:
        """Invalid module name returns 400."""
        mock_client = MagicMock()
        with patch("ssi.api.ecx_routes._require_client", return_value=mock_client):
            resp = client.get("/ecx/feed?module=invalid-module")

        assert resp.status_code == 400
        assert "Invalid module" in resp.json()["detail"]

    def test_feed_ecx_disabled_returns_503(self, client: TestClient) -> None:
        """When eCX is not configured, feed returns 503."""
        with patch(
            "ssi.api.ecx_routes._require_client", side_effect=__import__("fastapi").HTTPException(503, "not configured")
        ):
            resp = client.get("/ecx/feed?module=phish")

        assert resp.status_code == 503

    def test_feed_default_module_is_phish(self, client: TestClient) -> None:
        """Default module is phish when not specified."""
        mock_client = MagicMock()
        mock_client._request.return_value = _mock_ecx_response([])

        with patch("ssi.api.ecx_routes._require_client", return_value=mock_client):
            resp = client.get("/ecx/feed")

        assert resp.status_code == 200
        assert resp.json()["module"] == "phish"


# ---------------------------------------------------------------------------
# GET /ecx/polling-status
# ---------------------------------------------------------------------------


class TestPollingStatusEndpoint:
    """Tests for the polling status endpoint."""

    def test_returns_all_module_states(self, client: TestClient) -> None:
        """Polling status returns state for all modules."""
        mock_store = MagicMock()
        mock_store.list_polling_states.return_value = [
            {"module": "phish", "last_polled_id": 1000, "records_found": 5, "errors": 0},
            {"module": "malicious-domain", "last_polled_id": 200, "records_found": 2, "errors": 1},
        ]

        with patch("ssi.store.build_scan_store", return_value=mock_store):
            resp = client.get("/ecx/polling-status")

        assert resp.status_code == 200
        data = resp.json()
        assert len(data["modules"]) == 2
        assert data["modules"][0]["module"] == "phish"

    def test_returns_empty_when_no_polling(self, client: TestClient) -> None:
        """Polling status returns empty list when no modules have been polled."""
        mock_store = MagicMock()
        mock_store.list_polling_states.return_value = []

        with patch("ssi.store.build_scan_store", return_value=mock_store):
            resp = client.get("/ecx/polling-status")

        assert resp.status_code == 200
        assert resp.json()["modules"] == []
