"""Unit tests for the CoreBridge integration module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from ssi.integration.core_bridge import CoreBridge, _IOC_TYPE_TO_ENTITY
from ssi.models.investigation import (
    FraudTaxonomyResult,
    InvestigationResult,
    TaxonomyScoredLabel,
    ThreatIndicator,
)


@pytest.fixture()
def bridge():
    """Create a CoreBridge with a mocked HTTP client."""
    b = CoreBridge(core_api_url="http://test-core:8000")
    b._client = MagicMock(spec=httpx.Client)
    return b


@pytest.fixture()
def basic_result():
    """Minimal investigation result for testing."""
    return InvestigationResult(url="https://scam.example.com")


class TestCoreBridgeInit:
    def test_strips_trailing_slash(self):
        b = CoreBridge(core_api_url="http://core:8000/")
        assert b.core_api_url == "http://core:8000"
        b.close()

    def test_default_timeout(self):
        b = CoreBridge(core_api_url="http://core:8000")
        assert b.timeout == 60.0
        b.close()


class TestHealthCheck:
    def test_healthy(self, bridge):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        bridge._client.get.return_value = mock_resp
        assert bridge.health_check() is True
        bridge._client.get.assert_called_once_with("/health")

    def test_unhealthy(self, bridge):
        bridge._client.get.side_effect = httpx.ConnectError("refused")
        assert bridge.health_check() is False


class TestCreateCase:
    def test_creates_case_and_returns_id(self, bridge, basic_result):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"case_id": "case-abc"}
        mock_resp.raise_for_status = MagicMock()
        bridge._client.post.return_value = mock_resp

        case_id = bridge._create_case(basic_result, dataset="ssi")
        assert case_id == "case-abc"

        call_args = bridge._client.post.call_args
        assert call_args[0][0] == "/cases"
        payload = call_args[1]["json"]
        assert payload["dataset"] == "ssi"
        assert payload["source_type"] == "ssi_investigation"
        assert payload["source_url"] == "https://scam.example.com"

    def test_includes_classification_when_present(self, bridge, basic_result):
        basic_result.taxonomy_result = FraudTaxonomyResult(
            intent=[TaxonomyScoredLabel(label="INTENT.SHOPPING", confidence=0.85, explanation="test")],
            risk_score=65.0,
        )
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"case_id": "case-xyz"}
        mock_resp.raise_for_status = MagicMock()
        bridge._client.post.return_value = mock_resp

        bridge._create_case(basic_result, dataset="ssi")
        payload = bridge._client.post.call_args[1]["json"]
        assert "classification_result" in payload
        assert payload["risk_score"] == 65.0


class TestStoreClassification:
    def test_stores_classification(self, bridge, basic_result):
        basic_result.taxonomy_result = FraudTaxonomyResult(risk_score=75.0)
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        bridge._client.patch.return_value = mock_resp

        bridge._store_classification("case-123", basic_result)
        bridge._client.patch.assert_called_once()
        call_args = bridge._client.patch.call_args
        assert call_args[0][0] == "/cases/case-123"
        assert call_args[1]["json"]["risk_score"] == 75.0

    def test_skips_when_no_taxonomy(self, bridge, basic_result):
        bridge._store_classification("case-123", basic_result)
        bridge._client.patch.assert_not_called()


class TestCreateEntities:
    def test_creates_entities_from_indicators(self, bridge, basic_result):
        basic_result.threat_indicators = [
            ThreatIndicator(indicator_type="ip", value="1.2.3.4", context="hosting", source="dns"),
            ThreatIndicator(indicator_type="domain", value="scam.example.com", context="target", source="url"),
        ]
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        bridge._client.post.return_value = mock_resp

        bridge._create_entities("case-123", basic_result)
        bridge._client.post.assert_called_once()
        call_args = bridge._client.post.call_args
        assert call_args[0][0] == "/cases/case-123/entities/batch"
        entities = call_args[1]["json"]["entities"]
        assert len(entities) == 2
        assert entities[0]["entity_type"] == "ip_address"
        assert entities[1]["entity_type"] == "domain"

    def test_skips_when_no_indicators(self, bridge, basic_result):
        bridge._create_entities("case-123", basic_result)
        bridge._client.post.assert_not_called()


class TestTriggerDossier:
    def test_queues_dossier(self, bridge, basic_result):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        bridge._client.post.return_value = mock_resp

        bridge._trigger_dossier("case-123", basic_result)
        bridge._client.post.assert_called_once()
        call_args = bridge._client.post.call_args
        assert call_args[0][0] == "/dossier/queue"
        assert "case-123" in call_args[1]["json"]["case_ids"]


class TestPushInvestigation:
    def test_full_push_without_dossier(self, bridge, basic_result):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"case_id": "case-full"}
        mock_resp.raise_for_status = MagicMock()
        bridge._client.post.return_value = mock_resp
        bridge._client.patch.return_value = mock_resp

        case_id = bridge.push_investigation(basic_result)
        assert case_id == "case-full"
        # post called for /cases (no evidence or entity calls because result is minimal)
        assert bridge._client.post.call_count >= 1

    def test_full_push_with_dossier(self, bridge, basic_result):
        basic_result.threat_indicators = [
            ThreatIndicator(indicator_type="ip", value="1.2.3.4", context="a", source="dns"),
        ]
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"case_id": "case-dossier"}
        mock_resp.raise_for_status = MagicMock()
        bridge._client.post.return_value = mock_resp
        bridge._client.patch.return_value = mock_resp

        case_id = bridge.push_investigation(basic_result, trigger_dossier=True)
        assert case_id == "case-dossier"

        # Verify dossier queue was called
        post_calls = bridge._client.post.call_args_list
        dossier_calls = [c for c in post_calls if c[0][0] == "/dossier/queue"]
        assert len(dossier_calls) == 1


class TestIOCTypeMapping:
    @pytest.mark.parametrize(
        "ioc_type,expected",
        [
            ("ip", "ip_address"),
            ("ipv4", "ip_address"),
            ("ipv6", "ip_address"),
            ("domain", "domain"),
            ("email", "email"),
            ("url", "url"),
            ("crypto_wallet", "crypto_wallet"),
            ("phone", "phone"),
            ("sha256", "file_hash"),
            ("md5", "file_hash"),
        ],
    )
    def test_mapping(self, ioc_type, expected):
        assert _IOC_TYPE_TO_ENTITY[ioc_type] == expected
