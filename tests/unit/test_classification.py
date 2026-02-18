"""Unit tests for the fraud taxonomy classifier."""

from __future__ import annotations

import json

import pytest

from ssi.classification.classifier import (
    FraudTaxonomyResult,
    ScoredLabel,
    _build_evidence_text,
    _calculate_risk_score,
    _parse_llm_response,
)
from ssi.models.investigation import (
    FormField,
    GeoIPInfo,
    InvestigationResult,
    PageSnapshot,
    ScamClassification,
    SSLInfo,
    ThreatIndicator,
    WHOISRecord,
)


class TestScoredLabel:
    def test_clamps_confidence(self):
        lbl = ScoredLabel("INTENT.IMPOSTER", 1.5)
        assert lbl.confidence == 1.0

        lbl2 = ScoredLabel("INTENT.IMPOSTER", -0.2)
        assert lbl2.confidence == 0.0

    def test_to_dict(self):
        lbl = ScoredLabel("INTENT.IMPOSTER", 0.95, "Test explanation")
        d = lbl.to_dict()
        assert d == {"label": "INTENT.IMPOSTER", "confidence": 0.95, "explanation": "Test explanation"}


class TestFraudTaxonomyResult:
    def test_default_empty(self):
        result = FraudTaxonomyResult()
        assert result.intent == []
        assert result.channel == []
        assert result.risk_score == 0.0
        assert result.taxonomy_version == "1.0"

    def test_to_dict(self):
        result = FraudTaxonomyResult(
            intent=[ScoredLabel("INTENT.IMPOSTER", 0.9)],
            channel=[ScoredLabel("CHANNEL.WEB", 1.0)],
            explanation="Test",
        )
        d = result.to_dict()
        assert len(d["intent"]) == 1
        assert d["intent"][0]["label"] == "INTENT.IMPOSTER"
        assert d["explanation"] == "Test"

    def test_to_scam_classification(self):
        result = FraudTaxonomyResult(
            intent=[ScoredLabel("INTENT.SHOPPING", 0.85)],
            channel=[ScoredLabel("CHANNEL.WEB", 1.0)],
            techniques=[ScoredLabel("SE.URGENCY", 0.7)],
            actions=[ScoredLabel("ACTION.PROVIDE_PII", 0.9)],
            persona=[ScoredLabel("PERSONA.MARKETPLACE", 0.8)],
            explanation="Fake shopping site",
        )
        cls = result.to_scam_classification()
        assert isinstance(cls, ScamClassification)
        assert cls.scam_type == "INTENT.SHOPPING"
        assert cls.confidence == 0.85
        assert cls.channel == "CHANNEL.WEB"
        assert cls.summary == "Fake shopping site"


class TestCalculateRiskScore:
    def test_empty_taxonomy(self):
        result = FraudTaxonomyResult()
        assert _calculate_risk_score(result) == 0.0

    def test_high_risk(self):
        result = FraudTaxonomyResult(
            intent=[ScoredLabel("INTENT.EXTORTION", 0.95)],
            actions=[ScoredLabel("ACTION.CRYPTO", 0.9)],
            techniques=[ScoredLabel("SE.FEAR", 0.85)],
        )
        score = _calculate_risk_score(result)
        assert score > 50.0
        assert score <= 100.0

    def test_capped_at_100(self):
        result = FraudTaxonomyResult(
            intent=[ScoredLabel("INTENT.EXTORTION", 1.0), ScoredLabel("INTENT.INVESTMENT", 1.0)],
            actions=[ScoredLabel("ACTION.CRYPTO", 1.0), ScoredLabel("ACTION.SEND_MONEY", 1.0)],
            techniques=[ScoredLabel("SE.FEAR", 1.0), ScoredLabel("SE.URGENCY", 1.0)],
        )
        assert _calculate_risk_score(result) == 100.0


class TestParseLLMResponse:
    def test_valid_json(self):
        raw = json.dumps(
            {
                "intent": [{"label": "INTENT.SHOPPING", "confidence": 0.85, "explanation": "Fake store"}],
                "channel": [{"label": "CHANNEL.WEB", "confidence": 1.0, "explanation": "Website"}],
                "techniques": [{"label": "SE.URGENCY", "confidence": 0.7, "explanation": "Limited time"}],
                "actions": [{"label": "ACTION.PROVIDE_PII", "confidence": 0.9, "explanation": "Asks for PII"}],
                "persona": [{"label": "PERSONA.MARKETPLACE", "confidence": 0.8, "explanation": "Fake store"}],
                "explanation": "This appears to be a fake shopping site.",
            }
        )
        result = _parse_llm_response(raw)
        assert len(result.intent) == 1
        assert result.intent[0].label == "INTENT.SHOPPING"
        assert result.risk_score > 0

    def test_strips_markdown_fences(self):
        raw = '```json\n{"intent": [], "channel": [], "techniques": [], "actions": [], "persona": [], "explanation": "test"}\n```'
        result = _parse_llm_response(raw)
        assert result.explanation == "test"

    def test_invalid_json_raises(self):
        with pytest.raises(json.JSONDecodeError):
            _parse_llm_response("not json")


class TestBuildEvidenceText:
    def test_minimal_result(self):
        result = InvestigationResult(url="https://scam.example.com")
        text = _build_evidence_text(result)
        assert "https://scam.example.com" in text
        assert "None found." in text

    def test_with_full_data(self):
        result = InvestigationResult(
            url="https://scam.example.com",
            whois=WHOISRecord(domain="scam.example.com", registrar="Shady Registrar", creation_date="2025-01-01"),
            ssl=SSLInfo(issuer="Let's Encrypt", is_valid=True),
            geoip=GeoIPInfo(ip="1.2.3.4", city="Mumbai", region="MH", country="IN", org="HostingCo"),
            page_snapshot=PageSnapshot(
                url="https://scam.example.com",
                title="Free iPhone Giveaway",
                form_fields=[
                    FormField(tag="input", field_type="text", name="email", label="Email", pii_category="email"),
                ],
                technologies=["WordPress"],
            ),
            threat_indicators=[ThreatIndicator(indicator_type="ip", value="1.2.3.4", context="hosting", source="dns")],
        )
        text = _build_evidence_text(result)
        assert "Shady Registrar" in text
        assert "Let's Encrypt" in text
        assert "Mumbai" in text
        assert "Free iPhone Giveaway" in text
        assert "email" in text
        assert "1.2.3.4" in text
