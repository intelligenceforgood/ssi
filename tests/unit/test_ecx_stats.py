"""Tests for eCX statistics / trend API endpoints."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from ssi.api.app import app


@pytest.fixture()
def client() -> TestClient:
    return TestClient(app)


class TestPhishByBrand:
    """Tests for GET /ecx/stats/phish-by-brand."""

    @patch("ssi.store.build_scan_store")
    def test_returns_brand_series(self, mock_build: MagicMock, client: TestClient) -> None:
        mock_store = MagicMock()
        mock_store.stats_submissions_by_brand.return_value = [
            {"brand": "BankCo", "date": "2025-06-01", "count": 5},
            {"brand": "BankCo", "date": "2025-06-02", "count": 3},
            {"brand": "FinApp", "date": "2025-06-01", "count": 2},
        ]
        mock_build.return_value = mock_store

        resp = client.get("/ecx/stats/phish-by-brand")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["series"]) == 3
        assert data["series"][0]["brand"] == "BankCo"

    @patch("ssi.store.build_scan_store")
    def test_accepts_days_param(self, mock_build: MagicMock, client: TestClient) -> None:
        mock_store = MagicMock()
        mock_store.stats_submissions_by_brand.return_value = []
        mock_build.return_value = mock_store

        resp = client.get("/ecx/stats/phish-by-brand?days=7")
        assert resp.status_code == 200
        mock_store.stats_submissions_by_brand.assert_called_once_with(days=7)

    def test_rejects_invalid_days(self, client: TestClient) -> None:
        resp = client.get("/ecx/stats/phish-by-brand?days=0")
        assert resp.status_code == 422

    @patch("ssi.store.build_scan_store")
    def test_returns_empty_when_no_data(self, mock_build: MagicMock, client: TestClient) -> None:
        mock_store = MagicMock()
        mock_store.stats_submissions_by_brand.return_value = []
        mock_build.return_value = mock_store

        resp = client.get("/ecx/stats/phish-by-brand")
        assert resp.status_code == 200
        assert resp.json()["series"] == []


class TestWalletHeatmap:
    """Tests for GET /ecx/stats/wallet-heatmap."""

    @patch("ssi.store.build_scan_store")
    def test_returns_top_wallets_and_breakdown(self, mock_build: MagicMock, client: TestClient) -> None:
        mock_store = MagicMock()
        mock_store.stats_wallet_heatmap.return_value = [
            {"token_symbol": "ETH", "network_short": "ethereum", "wallet_address": "0xabc123", "count": 15},
        ]
        mock_store.stats_wallet_currency_breakdown.return_value = [
            {"token_symbol": "ETH", "count": 20},
            {"token_symbol": "BTC", "count": 10},
        ]
        mock_build.return_value = mock_store

        resp = client.get("/ecx/stats/wallet-heatmap")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["top_wallets"]) == 1
        assert data["top_wallets"][0]["wallet_address"] == "0xabc123"
        assert len(data["currency_breakdown"]) == 2

    @patch("ssi.store.build_scan_store")
    def test_accepts_limit_param(self, mock_build: MagicMock, client: TestClient) -> None:
        mock_store = MagicMock()
        mock_store.stats_wallet_heatmap.return_value = []
        mock_store.stats_wallet_currency_breakdown.return_value = []
        mock_build.return_value = mock_store

        resp = client.get("/ecx/stats/wallet-heatmap?limit=5")
        assert resp.status_code == 200
        mock_store.stats_wallet_heatmap.assert_called_once_with(limit=5)


class TestGeoInfrastructure:
    """Tests for GET /ecx/stats/geo-infrastructure."""

    @patch("ssi.store.build_scan_store")
    def test_returns_distribution(self, mock_build: MagicMock, client: TestClient) -> None:
        mock_store = MagicMock()
        mock_store.stats_geo_infrastructure.return_value = [
            {"country": "US", "count": 50},
            {"country": "RU", "count": 30},
            {"country": "CN", "count": 20},
        ]
        mock_build.return_value = mock_store

        resp = client.get("/ecx/stats/geo-infrastructure")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["distribution"]) == 3
        assert data["distribution"][0]["country"] == "US"

    @patch("ssi.store.build_scan_store")
    def test_accepts_days_param(self, mock_build: MagicMock, client: TestClient) -> None:
        mock_store = MagicMock()
        mock_store.stats_geo_infrastructure.return_value = []
        mock_build.return_value = mock_store

        resp = client.get("/ecx/stats/geo-infrastructure?days=60")
        assert resp.status_code == 200
        mock_store.stats_geo_infrastructure.assert_called_once_with(days=60)

    @patch("ssi.store.build_scan_store")
    def test_returns_empty_when_no_data(self, mock_build: MagicMock, client: TestClient) -> None:
        mock_store = MagicMock()
        mock_store.stats_geo_infrastructure.return_value = []
        mock_build.return_value = mock_store

        resp = client.get("/ecx/stats/geo-infrastructure")
        assert resp.status_code == 200
        assert resp.json()["distribution"] == []
