"""Unit tests for SSI domain models."""

from __future__ import annotations

from ssi.models.investigation import (
    ChainOfCustody,
    DNSRecords,
    EvidenceArtifact,
    FormField,
    FraudTaxonomyResult,
    GeoIPInfo,
    InvestigationResult,
    InvestigationStatus,
    PageSnapshot,
    ScamClassification,
    SSLInfo,
    TaxonomyScoredLabel,
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


class TestTaxonomyScoredLabel:
    def test_defaults(self):
        lbl = TaxonomyScoredLabel()
        assert lbl.label == ""
        assert lbl.confidence == 0.0
        assert lbl.explanation == ""

    def test_with_values(self):
        lbl = TaxonomyScoredLabel(label="INTENT.IMPOSTER", confidence=0.95, explanation="Pretends to be IRS")
        assert lbl.label == "INTENT.IMPOSTER"
        assert lbl.confidence == 0.95


class TestFraudTaxonomyResult:
    def test_defaults(self):
        result = FraudTaxonomyResult()
        assert result.intent == []
        assert result.channel == []
        assert result.techniques == []
        assert result.actions == []
        assert result.persona == []
        assert result.risk_score == 0.0
        assert result.taxonomy_version == "1.0"

    def test_serialization(self):
        result = FraudTaxonomyResult(
            intent=[TaxonomyScoredLabel(label="INTENT.SHOPPING", confidence=0.8)],
            risk_score=55.0,
            explanation="Fake shopping site",
        )
        data = result.model_dump(mode="json")
        restored = FraudTaxonomyResult.model_validate(data)
        assert restored.intent[0].label == "INTENT.SHOPPING"
        assert restored.risk_score == 55.0


class TestEvidenceArtifact:
    def test_basic(self):
        art = EvidenceArtifact(
            file="screenshot.png",
            sha256="abc123",
            size_bytes=1024,
            description="Homepage screenshot",
            mime_type="image/png",
        )
        assert art.file == "screenshot.png"
        assert art.sha256 == "abc123"


class TestChainOfCustody:
    def test_defaults(self):
        coc = ChainOfCustody(
            investigation_id="test-001",
            target_url="https://scam.example.com",
        )
        assert coc.investigation_id == "test-001"
        assert coc.artifacts == []
        assert coc.total_artifacts == 0
        assert coc.hash_algorithm == "SHA-256"

    def test_with_artifacts(self):
        artifacts = [
            EvidenceArtifact(file="a.png", sha256="aaa", size_bytes=100),
            EvidenceArtifact(file="b.json", sha256="bbb", size_bytes=200),
        ]
        coc = ChainOfCustody(
            investigation_id="test-002",
            target_url="https://scam.example.com",
            artifacts=artifacts,
            total_artifacts=2,
            total_size_bytes=300,
        )
        data = coc.model_dump(mode="json")
        assert len(data["artifacts"]) == 2
        assert data["total_size_bytes"] == 300


class TestInvestigationResultPhase3Fields:
    def test_taxonomy_result_default_none(self):
        result = InvestigationResult(url="https://example.com")
        assert result.taxonomy_result is None
        assert result.chain_of_custody is None

    def test_taxonomy_result_roundtrip(self):
        result = InvestigationResult(
            url="https://example.com",
            taxonomy_result=FraudTaxonomyResult(
                intent=[TaxonomyScoredLabel(label="INTENT.IMPOSTER", confidence=0.9)],
                risk_score=72.0,
            ),
        )
        data = result.model_dump(mode="json")
        restored = InvestigationResult.model_validate(data)
        assert restored.taxonomy_result is not None
        assert restored.taxonomy_result.risk_score == 72.0
