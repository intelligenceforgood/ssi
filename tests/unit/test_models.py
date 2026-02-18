"""Unit tests for SSI domain models."""

from __future__ import annotations

from ssi.models.investigation import (
    DNSRecords,
    FormField,
    GeoIPInfo,
    InvestigationResult,
    InvestigationStatus,
    PageSnapshot,
    ScamClassification,
    SSLInfo,
    ThreatIndicator,
    WHOISRecord,
)


class TestInvestigationResult:
    def test_default_values(self):
        result = InvestigationResult(url="https://example.com")
        assert result.url == "https://example.com"
        assert result.status == InvestigationStatus.PENDING
        assert result.success is False
        assert result.passive_only is True
        assert result.investigation_id is not None

    def test_serialization_roundtrip(self):
        result = InvestigationResult(
            url="https://scam.example.com",
            status=InvestigationStatus.COMPLETED,
            success=True,
            whois=WHOISRecord(domain="scam.example.com", registrar="Cheap Registrar"),
            dns=DNSRecords(a=["1.2.3.4"]),
            ssl=SSLInfo(issuer="Let's Encrypt", is_valid=True),
            geoip=GeoIPInfo(ip="1.2.3.4", country="US"),
            classification=ScamClassification(scam_type="phishing", confidence=0.92),
            threat_indicators=[ThreatIndicator(indicator_type="ip", value="1.2.3.4", source="dns")],
        )
        data = result.model_dump(mode="json")
        restored = InvestigationResult.model_validate(data)
        assert restored.url == result.url
        assert restored.whois.registrar == "Cheap Registrar"
        assert len(restored.threat_indicators) == 1


class TestFormField:
    def test_pii_category_default(self):
        f = FormField(tag="input", field_type="text", name="ssn")
        assert f.pii_category == ""


class TestScamClassification:
    def test_taxonomy_fields(self):
        c = ScamClassification(
            scam_type="investment_scam",
            confidence=0.85,
            intent="financial_theft",
            channel="website",
            technique="social_engineering",
            action="credential_harvest",
            persona="authority_figure",
        )
        assert c.intent == "financial_theft"
