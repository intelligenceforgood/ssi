"""Unit tests for the CoreBridge integration module."""

from __future__ import annotations

from datetime import datetime, timezone
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


class TestBuildAuthHeaders:
    """Verify IAP auth: OIDC token (IAP gate) + API key (app fallback)."""

    def test_https_sends_oidc_with_iap_audience_and_api_key(self):
        with (
            patch("ssi.settings.get_settings") as mock_settings,
            patch("ssi.integration.core_bridge._get_oidc_token", return_value="oidc-tok-123") as mock_oidc,
        ):
            mock_settings.return_value.integration.core_api_key = "key-abc"
            mock_settings.return_value.integration.iap_audience = "my-iap-client-id.apps.googleusercontent.com"
            b = CoreBridge(core_api_url="https://api.example.org")
            headers = b._client.headers
            assert headers["X-API-KEY"] == "key-abc"
            assert headers["Authorization"] == "Bearer oidc-tok-123"
            # Must use IAP audience, not the URL
            mock_oidc.assert_called_once_with("my-iap-client-id.apps.googleusercontent.com")
            b.close()

    def test_http_skips_both(self):
        b = CoreBridge(core_api_url="http://localhost:8000")
        headers = b._client.headers
        assert "X-API-KEY" not in headers
        assert "Authorization" not in headers
        b.close()

    def test_https_without_oidc_still_sends_api_key(self):
        with (
            patch("ssi.settings.get_settings") as mock_settings,
            patch("ssi.integration.core_bridge._get_oidc_token", return_value=None),
        ):
            mock_settings.return_value.integration.core_api_key = "key-abc"
            mock_settings.return_value.integration.iap_audience = "my-iap-client-id"
            b = CoreBridge(core_api_url="https://api.example.org")
            headers = b._client.headers
            assert headers["X-API-KEY"] == "key-abc"
            assert "Authorization" not in headers
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


class TestCreateTimelineEvents:
    """Tests for ``CoreBridge._create_timeline_events``."""

    def test_posts_timeline_events_for_complete_result(self, bridge):
        """A fully-populated result generates multiple timeline events."""
        result = InvestigationResult(
            url="https://scam.example.com",
            started_at=datetime(2026, 2, 28, 10, 0, 0, tzinfo=timezone.utc),
            completed_at=datetime(2026, 2, 28, 10, 5, 0, tzinfo=timezone.utc),
            taxonomy_result=FraudTaxonomyResult(
                intent=[TaxonomyScoredLabel(label="INTENT.INVESTMENT_SCAM", confidence=0.9, explanation="test")],
                risk_score=85.0,
            ),
            threat_indicators=[
                ThreatIndicator(indicator_type="crypto_wallet", value="0xabc", context="ETH", source="dom"),
                ThreatIndicator(indicator_type="crypto_wallet", value="bc1q", context="BTC", source="dom"),
            ],
        )
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        bridge._client.post.return_value = mock_resp

        bridge._create_timeline_events("case-123", result)

        # Find the timeline POST call
        timeline_calls = [
            c for c in bridge._client.post.call_args_list if c[0][0] == "/cases/case-123/timeline"
        ]
        assert len(timeline_calls) == 1
        events = timeline_calls[0][1]["json"]["events"]

        # Should have: submitted, classification, wallets, case_created (at minimum)
        event_types = [e["type"] for e in events]
        assert "investigation_submitted" in event_types
        assert "classification_completed" in event_types
        assert "wallets_harvested" in event_types
        assert "case_created" in event_types

        # Verify description content
        submitted = next(e for e in events if e["type"] == "investigation_submitted")
        assert "scam.example.com" in submitted["description"]
        assert submitted["actor"] == "ssi-agent"

        classified = next(e for e in events if e["type"] == "classification_completed")
        assert "Investment Scam" in classified["description"]
        assert "85" in classified["description"]

        wallets = next(e for e in events if e["type"] == "wallets_harvested")
        assert "2 wallet addresses" in wallets["description"]

    def test_minimal_result_still_creates_case_created_event(self, bridge, basic_result):
        """Even a minimal result generates at least a case_created event."""
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        bridge._client.post.return_value = mock_resp

        bridge._create_timeline_events("case-minimal", basic_result)

        timeline_calls = [
            c for c in bridge._client.post.call_args_list if c[0][0] == "/cases/case-minimal/timeline"
        ]
        assert len(timeline_calls) == 1
        events = timeline_calls[0][1]["json"]["events"]
        event_types = [e["type"] for e in events]
        assert "case_created" in event_types

    def test_handles_http_error_gracefully(self, bridge, basic_result):
        """HTTP errors are logged but don't raise exceptions."""
        bridge._client.post.side_effect = httpx.HTTPStatusError(
            "500", request=MagicMock(), response=MagicMock()
        )
        # Should not raise
        bridge._create_timeline_events("case-fail", basic_result)

    def test_push_investigation_calls_timeline(self, bridge, basic_result):
        """push_investigation() now includes a call to _create_timeline_events."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"case_id": "case-tl"}
        mock_resp.raise_for_status = MagicMock()
        bridge._client.post.return_value = mock_resp
        bridge._client.patch.return_value = mock_resp

        bridge.push_investigation(basic_result)

        # Verify that /timeline was called
        post_urls = [c[0][0] for c in bridge._client.post.call_args_list]
        assert any("/timeline" in url for url in post_urls)


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
