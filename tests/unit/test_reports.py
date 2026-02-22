"""Unit tests for the markdown report generator."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from ssi.models.investigation import (
    DNSRecords,
    FormField,
    GeoIPInfo,
    InvestigationResult,
    InvestigationStatus,
    PageSnapshot,
    SSLInfo,
    ThreatIndicator,
    WHOISRecord,
)
from ssi.reports import render_markdown_report


@pytest.fixture()
def minimal_result() -> InvestigationResult:
    """A bare-minimum investigation result."""
    return InvestigationResult(
        url="https://suspicious.example.com",
        status=InvestigationStatus.COMPLETED,
        success=True,
        duration_seconds=2.5,
    )


@pytest.fixture()
def full_result() -> InvestigationResult:
    """A fully-populated investigation result with all sections."""
    return InvestigationResult(
        url="https://phishing.example.com/login",
        status=InvestigationStatus.COMPLETED,
        success=True,
        duration_seconds=8.3,
        whois=WHOISRecord(
            domain="phishing.example.com",
            registrar="Shady Registrar LLC",
            creation_date="2026-01-15",
            expiration_date="2027-01-15",
            registrant_country="RU",
            name_servers=["ns1.evil.net", "ns2.evil.net"],
        ),
        dns=DNSRecords(
            a=["198.51.100.42"],
            mx=["mail.phishing.example.com"],
            ns=["ns1.evil.net", "ns2.evil.net"],
            txt=["v=spf1 -all"],
        ),
        ssl=SSLInfo(
            issuer="Let's Encrypt",
            subject="phishing.example.com",
            not_before="2026-01-15",
            not_after="2026-04-15",
            is_valid=True,
            fingerprint_sha256="ABCD1234",
        ),
        geoip=GeoIPInfo(
            ip="198.51.100.42",
            country="NL",
            city="Amsterdam",
            org="BulletProof Hosting",
            asn="AS12345",
            as_name="BadHost",
        ),
        page_snapshot=PageSnapshot(
            url="https://phishing.example.com/login",
            final_url="https://phishing.example.com/login",
            status_code=200,
            title="Secure Banking Login",
            screenshot_path="/tmp/screenshot.png",
            dom_snapshot_path="/tmp/dom.html",
            har_path="/tmp/network.har",
            redirect_chain=["https://phishing.example.com/"],
            form_fields=[
                FormField(field_type="text", name="username", label="Username", required=True),
                FormField(field_type="password", name="password", label="Password", required=True),
                FormField(field_type="text", name="ssn", label="Social Security Number"),
            ],
            external_resources=["https://cdn.evil.net/tracking.js"],
        ),
        threat_indicators=[
            ThreatIndicator(
                indicator_type="url",
                value="https://phishing.example.com/login",
                context="VirusTotal: 15 malicious detections",
                source="virustotal",
            ),
            ThreatIndicator(
                indicator_type="ip",
                value="198.51.100.42",
                context="Contacted IP during page load",
                source="urlscan.io",
            ),
        ],
        brand_impersonation="Impersonates First National Bank",
        report_path="/tmp/investigation.json",
    )


class TestRenderMarkdownReport:
    """Test markdown report rendering."""

    def test_minimal_report(self, minimal_result):
        md = render_markdown_report(minimal_result)
        assert "suspicious.example.com" in md
        assert "COMPLETED" in md
        assert "Investigation ID" in md

    def test_full_report_sections(self, full_result):
        md = render_markdown_report(full_result)

        # Summary section
        assert "phishing.example.com" in md
        assert "Secure Banking Login" in md

        # WHOIS section
        assert "WHOIS" in md
        assert "Shady Registrar LLC" in md
        assert "2026-01-15" in md

        # DNS section
        assert "198.51.100.42" in md
        assert "ns1.evil.net" in md

        # SSL section
        assert "Let's Encrypt" in md
        assert "ABCD1234" in md

        # GeoIP section
        assert "Amsterdam" in md
        assert "BadHost" in md

        # Form fields
        assert "Form Fields Detected" in md
        assert "username" in md
        assert "Social Security Number" in md

        # Threat indicators
        assert "Threat Indicators" in md
        assert "malicious" in md
        assert "urlscan.io" in md

        # Brand impersonation
        assert "First National Bank" in md

        # Evidence artifacts
        assert "Evidence Artifacts" in md

    def test_report_written_to_file(self, minimal_result, tmp_path):
        output_path = tmp_path / "report.md"
        md = render_markdown_report(minimal_result, output_path=output_path)

        assert output_path.exists()
        content = output_path.read_text()
        assert content == md
        assert "suspicious.example.com" in content

    def test_report_creates_parent_dirs(self, minimal_result, tmp_path):
        output_path = tmp_path / "nested" / "dir" / "report.md"
        render_markdown_report(minimal_result, output_path=output_path)
        assert output_path.exists()

    def test_redirect_chain_rendered(self, full_result):
        md = render_markdown_report(full_result)
        assert "Redirect Chain" in md
        assert "hop(s)" in md

    def test_external_resources_rendered(self, full_result):
        md = render_markdown_report(full_result)
        assert "External Resources" in md
        assert "cdn.evil.net" in md

    def test_no_whois_section_when_absent(self, minimal_result):
        md = render_markdown_report(minimal_result)
        assert "WHOIS" not in md or "Registrar" not in md

    def test_agent_steps_rendered(self, full_result):
        full_result.agent_steps = [
            {
                "step": 0,
                "action": "type",
                "element": 0,
                "value": "test@example.com",
                "reasoning": "Fill email field",
                "tokens": 500,
                "duration_ms": 1200,
                "error": "",
            },
        ]
        full_result.token_usage = 500
        full_result.passive_only = False
        full_result.scan_type = "active"

        md = render_markdown_report(full_result)
        assert "AI Agent Interaction" in md
        assert "type" in md
        assert "Fill email" in md
