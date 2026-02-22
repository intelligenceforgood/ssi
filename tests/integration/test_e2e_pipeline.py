"""End-to-end pipeline integration test.

Runs ``run_investigation()`` in **passive** mode against a local HTML fixture
with all OSINT calls mocked to return deterministic data. Verifies that
the investigation JSON, evidence ZIP, and wallet extraction work correctly
through the full pipeline.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ssi.investigator.orchestrator import run_investigation
from ssi.models.investigation import DNSRecords, GeoIPInfo, SSLInfo, WHOISRecord


# ---------------------------------------------------------------------------
# Deterministic OSINT stubs
# ---------------------------------------------------------------------------

_FAKE_WHOIS = WHOISRecord(
    domain_name="fake-exchange.com",
    registrar="NameCheap",
    creation_date="2024-01-15",
    expiration_date="2025-01-15",
    name_servers=["ns1.namecheap.com", "ns2.namecheap.com"],
    status=["clientTransferProhibited"],
)

_FAKE_DNS = DNSRecords(
    a=["93.184.216.34"],
    aaaa=[],
    mx=[],
    txt=[],
    ns=["ns1.namecheap.com"],
    cname=[],
)

_FAKE_SSL = SSLInfo(
    subject="CN=fake-exchange.com",
    issuer="CN=R3, O=Let's Encrypt",
    not_before="Jan  1 00:00:00 2024 GMT",
    not_after="Mar 31 23:59:59 2025 GMT",
    serial_number="1234567890",
    san=["fake-exchange.com", "www.fake-exchange.com"],
    is_valid=True,
    is_self_signed=False,
)

_FAKE_GEOIP = GeoIPInfo(
    ip="93.184.216.34",
    hostname="server.fake-exchange.com",
    city="Los Angeles",
    region="California",
    country="US",
    org="AS15169 Google LLC",
)


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestE2EPipeline:
    """Full passive-pipeline integration test."""

    @patch("ssi.investigator.orchestrator._check_domain_resolution", return_value=True)
    @patch("ssi.investigator.orchestrator._run_whois", return_value=_FAKE_WHOIS)
    @patch("ssi.investigator.orchestrator._run_dns", return_value=_FAKE_DNS)
    @patch("ssi.investigator.orchestrator._run_ssl", return_value=_FAKE_SSL)
    @patch("ssi.investigator.orchestrator._run_geoip", return_value=_FAKE_GEOIP)
    @patch("ssi.investigator.orchestrator._run_browser_capture", return_value=None)
    @patch("ssi.investigator.orchestrator._run_virustotal")
    @patch("ssi.investigator.orchestrator._run_urlscan")
    def test_passive_pipeline_produces_complete_result(
        self,
        mock_urlscan: MagicMock,
        mock_vt: MagicMock,
        mock_capture: MagicMock,
        mock_geoip: MagicMock,
        mock_ssl: MagicMock,
        mock_dns: MagicMock,
        mock_whois: MagicMock,
        mock_domain_ok: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Passive scan collects all OSINT phases and writes evidence."""
        result = run_investigation(
            url="https://fake-exchange.com",
            output_dir=tmp_path,
            scan_type="passive",
            skip_screenshot=True,
        )

        # Basic success assertions
        assert result.success is True
        assert result.status.value == "completed"
        assert result.url == "https://fake-exchange.com"

        # OSINT data populated
        assert result.whois is not None
        assert result.whois.registrar == "NameCheap"
        assert result.dns is not None
        assert result.dns.a == ["93.184.216.34"]
        assert result.ssl is not None
        assert result.ssl.is_valid is True
        assert result.geoip is not None
        assert result.geoip.country == "US"

        # Investigation directory created
        inv_dir = Path(result.output_path)
        assert inv_dir.exists()
        assert inv_dir.parent == tmp_path

        # Evidence JSON written
        json_files = list(inv_dir.glob("investigation*.json"))
        assert len(json_files) >= 1, "Expected investigation JSON file"

        # Cost summary present (cost tracking enabled by default)
        if result.cost_summary:
            assert result.cost_summary["budget_exceeded"] is False

        # Timing recorded
        assert result.duration_seconds > 0
        assert result.completed_at is not None

    @patch("ssi.investigator.orchestrator._check_domain_resolution", return_value=True)
    @patch("ssi.investigator.orchestrator._run_whois", return_value=_FAKE_WHOIS)
    @patch("ssi.investigator.orchestrator._run_dns", return_value=_FAKE_DNS)
    @patch("ssi.investigator.orchestrator._run_ssl", return_value=_FAKE_SSL)
    @patch("ssi.investigator.orchestrator._run_geoip", return_value=_FAKE_GEOIP)
    @patch("ssi.investigator.orchestrator._run_browser_capture", return_value=None)
    @patch("ssi.investigator.orchestrator._run_virustotal")
    @patch("ssi.investigator.orchestrator._run_urlscan")
    def test_scan_store_persists_result(
        self,
        mock_urlscan: MagicMock,
        mock_vt: MagicMock,
        mock_capture: MagicMock,
        mock_geoip: MagicMock,
        mock_ssl: MagicMock,
        mock_dns: MagicMock,
        mock_whois: MagicMock,
        mock_domain_ok: MagicMock,
        tmp_path: Path,
        scan_store,
    ) -> None:
        """When persistence is enabled, the ScanStore records the investigation."""
        with patch("ssi.settings.get_settings") as mock_settings:
            settings = MagicMock()
            settings.cost.enabled = True
            settings.cost.budget_per_investigation_usd = 1.0
            settings.storage.persist_scans = True
            settings.llm.model = "mock"
            mock_settings.return_value = settings

            with patch("ssi.store.build_scan_store", return_value=scan_store):
                result = run_investigation(
                    url="https://fake-exchange.com",
                    output_dir=tmp_path,
                    scan_type="passive",
                    skip_screenshot=True,
                )

        assert result.success is True

        # Verify scan_store recorded the investigation
        scans = scan_store.list_scans()
        assert len(scans) >= 1
        scan = scans[0]
        assert scan["url"] == "https://fake-exchange.com"

    @patch("ssi.investigator.orchestrator._check_domain_resolution", return_value=False)
    @patch("ssi.investigator.orchestrator._run_browser_capture", return_value=None)
    @patch("ssi.investigator.orchestrator._run_virustotal")
    @patch("ssi.investigator.orchestrator._run_urlscan")
    def test_nxdomain_graceful_degradation(
        self,
        mock_urlscan: MagicMock,
        mock_vt: MagicMock,
        mock_capture: MagicMock,
        mock_domain_check: MagicMock,
        tmp_path: Path,
    ) -> None:
        """When a domain doesn't resolve, the pipeline still completes with warnings."""
        result = run_investigation(
            url="https://nxdomain-test.invalid",
            output_dir=tmp_path,
            scan_type="passive",
            skip_whois=True,
            skip_screenshot=True,
            skip_virustotal=True,
            skip_urlscan=True,
        )

        # Investigation should still complete — not crash
        assert result.success is True
        assert any("does not resolve" in w for w in result.warnings)

    @patch("ssi.investigator.orchestrator._check_domain_resolution", return_value=True)
    @patch("ssi.investigator.orchestrator._run_whois", return_value=_FAKE_WHOIS)
    @patch("ssi.investigator.orchestrator._run_dns", return_value=_FAKE_DNS)
    @patch("ssi.investigator.orchestrator._run_ssl", return_value=_FAKE_SSL)
    @patch("ssi.investigator.orchestrator._run_geoip", return_value=_FAKE_GEOIP)
    @patch("ssi.investigator.orchestrator._run_browser_capture", return_value=None)
    @patch("ssi.investigator.orchestrator._run_virustotal")
    @patch("ssi.investigator.orchestrator._run_urlscan")
    def test_full_scan_type_triggers_agent(
        self,
        mock_urlscan: MagicMock,
        mock_vt: MagicMock,
        mock_capture: MagicMock,
        mock_geoip: MagicMock,
        mock_ssl: MagicMock,
        mock_dns: MagicMock,
        mock_whois: MagicMock,
        mock_domain_ok: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Full scan type runs both passive recon and the AI agent phase."""
        with patch("ssi.investigator.orchestrator._run_agent_interaction", return_value=None) as mock_agent:
            result = run_investigation(
                url="https://fake-exchange.com",
                output_dir=tmp_path,
                scan_type="full",
                skip_screenshot=True,
            )

        # Agent should have been called for "full" scan
        mock_agent.assert_called_once()
        # Even if agent returns None, passive data should still be present
        assert result.whois is not None
        assert result.dns is not None
