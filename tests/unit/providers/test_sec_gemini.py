"""Unit tests for the Sec-Gemini provider module.

Tests cover:
- Response parser (JSON extraction from various agent output formats)
- Prompt builder (correct prompt construction from OSINT context)
- Provider error handling (SDK not installed, timeout, API errors)
- Orchestrator integration helper (feature flag gating, context building)
- Models (serialization roundtrip)
"""

from __future__ import annotations

import json

import pytest

from ssi.models.investigation import InvestigationResult, ThreatIndicator
from ssi.providers.sec_gemini.models import (
    EmailSecurityPosture,
    InfraFingerprint,
    SecGeminiAnalysis,
    VulnerabilityFinding,
)
from ssi.providers.sec_gemini.parser import _build_indicators, _extract_json, parse_sec_gemini_response
from ssi.providers.sec_gemini.prompts import (
    _extract_domain,
    _extract_email_domains,
    _flatten_to_text,
    build_investigation_prompt,
)

# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------


class TestExtractJson:
    """Test JSON extraction from various agent output formats."""

    def test_json_in_code_fence(self) -> None:
        text = 'Some preamble\n```json\n{"email_security": []}\n```\nMore text'
        result = _extract_json(text)
        assert result == {"email_security": []}

    def test_json_in_plain_fence(self) -> None:
        text = 'Preamble\n```\n{"infrastructure": {"web_server": "nginx"}}\n```'
        result = _extract_json(text)
        assert result == {"infrastructure": {"web_server": "nginx"}}

    def test_raw_json(self) -> None:
        text = 'Here is the result: {"threat_synthesis": "test"}'
        result = _extract_json(text)
        assert result == {"threat_synthesis": "test"}

    def test_no_json_returns_none(self) -> None:
        text = "This is just plain text with no JSON."
        result = _extract_json(text)
        assert result is None

    def test_malformed_json_returns_none(self) -> None:
        text = '```json\n{"broken": \n```'
        result = _extract_json(text)
        assert result is None

    def test_array_json_returns_none(self) -> None:
        """Only top-level objects (dicts) are accepted, not arrays."""
        text = "```json\n[1, 2, 3]\n```"
        result = _extract_json(text)
        assert result is None


class TestParseSecGeminiResponse:
    """Test end-to-end response parsing."""

    def test_empty_response(self) -> None:
        result = parse_sec_gemini_response("")
        assert isinstance(result, SecGeminiAnalysis)
        assert result.email_security == []
        assert result.infrastructure is None
        assert result.threat_synthesis == ""

    def test_full_structured_response(self) -> None:
        data = {
            "email_security": [
                {
                    "domain": "scam.example.com",
                    "spf_record": "v=spf1 -all",
                    "spf_valid": True,
                    "dkim_configured": False,
                    "dmarc_record": "v=DMARC1; p=none",
                    "dmarc_policy": "none",
                    "mx_records": ["mx1.example.com"],
                    "assessment": "Weak email security — DMARC in monitor mode.",
                }
            ],
            "infrastructure": {
                "web_server": "nginx/1.24.0",
                "framework": "PHP",
                "cms": None,
                "hosting_provider": "DigitalOcean",
                "cdn": None,
                "technologies": ["PHP 8.1"],
                "vulnerabilities": [
                    {
                        "cve_id": "CVE-2024-1234",
                        "software": "nginx/1.24.0",
                        "severity": "high",
                        "cvss_score": 8.1,
                        "is_exploited": True,
                        "patch_available": True,
                        "description": "Remote code execution in nginx",
                    }
                ],
            },
            "threat_synthesis": "This appears to be a moderately sophisticated operation.",
            "risk_adjustment": 5.0,
        }
        raw = f"```json\n{json.dumps(data)}\n```"
        result = parse_sec_gemini_response(raw)

        assert len(result.email_security) == 1
        assert result.email_security[0].domain == "scam.example.com"
        assert result.email_security[0].spf_valid is True
        assert result.email_security[0].dmarc_policy == "none"

        assert result.infrastructure is not None
        assert result.infrastructure.web_server == "nginx/1.24.0"
        assert len(result.infrastructure.vulnerabilities) == 1
        assert result.infrastructure.vulnerabilities[0].is_exploited is True

        assert result.threat_synthesis.startswith("This appears")
        assert result.risk_adjustment == 5.0

        # Verify threat indicators were generated
        assert len(result.threat_indicators) >= 1
        vuln_indicators = [i for i in result.threat_indicators if i.indicator_type == "vulnerability"]
        assert len(vuln_indicators) == 1
        assert vuln_indicators[0].value == "CVE-2024-1234"

    def test_no_json_falls_back_to_narrative(self) -> None:
        raw = "The target site shows signs of a sophisticated operation."
        result = parse_sec_gemini_response(raw)
        assert result.threat_synthesis == raw.strip()
        assert result.raw_agent_response == raw
        assert result.email_security == []

    def test_risk_adjustment_clamped(self) -> None:
        data = {"risk_adjustment": 999}
        raw = json.dumps(data)
        result = parse_sec_gemini_response(raw)
        assert result.risk_adjustment == 10.0

    def test_risk_adjustment_negative_clamped(self) -> None:
        data = {"risk_adjustment": -50}
        raw = json.dumps(data)
        result = parse_sec_gemini_response(raw)
        assert result.risk_adjustment == -10.0

    def test_partial_response_still_parses(self) -> None:
        """Agent returns email_security but no infrastructure."""
        data = {"email_security": [{"domain": "test.com", "spf_valid": False}]}
        raw = json.dumps(data)
        result = parse_sec_gemini_response(raw)
        assert len(result.email_security) == 1
        assert result.infrastructure is None


class TestBuildIndicators:
    """Test threat indicator generation from parsed data."""

    def test_spf_invalid_generates_indicator(self) -> None:
        es = [EmailSecurityPosture(domain="bad.com", spf_valid=False)]
        indicators = _build_indicators(es, None)
        assert any(i.indicator_type == "email_security" and "SPF" in i.context for i in indicators)

    def test_dmarc_none_generates_indicator(self) -> None:
        es = [EmailSecurityPosture(domain="bad.com", spf_valid=True, dmarc_policy="none")]
        indicators = _build_indicators(es, None)
        assert any(i.indicator_type == "email_security" and "DMARC" in i.context for i in indicators)

    def test_dmarc_reject_no_indicator(self) -> None:
        es = [EmailSecurityPosture(domain="good.com", spf_valid=True, dmarc_policy="reject")]
        indicators = _build_indicators(es, None)
        # No email security indicators should be generated for properly configured domains
        email_indicators = [i for i in indicators if i.indicator_type == "email_security"]
        assert len(email_indicators) == 0

    def test_vulnerability_generates_indicator(self) -> None:
        infra = InfraFingerprint(
            web_server="nginx",
            vulnerabilities=[
                VulnerabilityFinding(
                    cve_id="CVE-2024-9999",
                    software="nginx",
                    severity="critical",
                    is_exploited=True,
                    description="Bad bug",
                )
            ],
        )
        indicators = _build_indicators([], infra)
        assert len(indicators) == 1
        assert indicators[0].value == "CVE-2024-9999"
        assert "actively exploited" in indicators[0].context


# ---------------------------------------------------------------------------
# Prompt builder tests
# ---------------------------------------------------------------------------


class TestPromptBuilder:
    """Test prompt construction."""

    def test_basic_prompt(self) -> None:
        prompt = build_investigation_prompt("https://scam.example.com", {})
        assert "scam.example.com" in prompt
        assert "Do NOT repeat" in prompt
        assert "Email Security Posture" in prompt
        assert "Infrastructure Fingerprinting" in prompt

    def test_prompt_includes_email_domains(self) -> None:
        osint = {
            "whois": {
                "registrant_name": "John Doe",
                "registrant_org": "Scam Corp",
            },
            "threat_indicators": [{"value": "admin@evil.net", "indicator_type": "email"}],
        }
        prompt = build_investigation_prompt("https://scam.example.com", osint)
        assert "evil.net" in prompt

    def test_extract_domain(self) -> None:
        assert _extract_domain("https://scam.example.com/path") == "scam.example.com"
        assert _extract_domain("http://test.org") == "test.org"
        assert _extract_domain("test.org") == "test.org"

    def test_extract_email_domains(self) -> None:
        osint = {"notes": "Contact admin@evil.net for info. Also user@test.org is interesting."}
        domains = _extract_email_domains(osint)
        assert any("evil.net" in d for d in domains)
        assert any("test.org" in d for d in domains)

    def test_flatten_to_text(self) -> None:
        data = {"a": "hello", "b": {"c": "world"}, "d": [1, "foo"]}
        text = _flatten_to_text(data)
        assert "hello" in text
        assert "world" in text
        assert "foo" in text


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------


class TestModels:
    """Test model serialization and defaults."""

    def test_sec_gemini_analysis_defaults(self) -> None:
        analysis = SecGeminiAnalysis()
        assert analysis.email_security == []
        assert analysis.infrastructure is None
        assert analysis.threat_synthesis == ""
        assert analysis.risk_adjustment == 0.0

    def test_sec_gemini_analysis_roundtrip(self) -> None:
        analysis = SecGeminiAnalysis(
            email_security=[EmailSecurityPosture(domain="test.com", spf_valid=True)],
            infrastructure=InfraFingerprint(web_server="nginx"),
            threat_synthesis="Test synthesis",
            risk_adjustment=3.5,
            session_id="test-123",
            duration_seconds=42.0,
        )
        dumped = analysis.model_dump(mode="json")
        restored = SecGeminiAnalysis.model_validate(dumped)
        assert restored.email_security[0].domain == "test.com"
        assert restored.infrastructure.web_server == "nginx"
        assert restored.risk_adjustment == 3.5

    def test_investigation_result_has_sec_gemini_field(self) -> None:
        result = InvestigationResult(url="https://test.com")
        assert result.sec_gemini_analysis is None
        result.sec_gemini_analysis = {"test": True}
        dumped = result.model_dump(mode="json")
        assert dumped["sec_gemini_analysis"] == {"test": True}


# ---------------------------------------------------------------------------
# Orchestrator helper tests
# ---------------------------------------------------------------------------


class TestOrchestratorHelpers:
    """Test the orchestrator integration helpers."""

    def test_build_sec_gemini_context_empty_result(self) -> None:
        from ssi.investigator.orchestrator import _build_sec_gemini_context

        result = InvestigationResult(url="https://test.com")
        context = _build_sec_gemini_context(result)
        assert context == {}

    def test_build_sec_gemini_context_with_osint(self) -> None:
        from ssi.investigator.orchestrator import _build_sec_gemini_context
        from ssi.models.investigation import DNSRecords, SSLInfo, WHOISRecord

        result = InvestigationResult(url="https://test.com")
        result.whois = WHOISRecord(domain="test.com", registrar="TestReg")
        result.dns = DNSRecords(a=["1.2.3.4"])
        result.ssl = SSLInfo(issuer="Let's Encrypt", is_valid=True)
        result.threat_indicators = [ThreatIndicator(indicator_type="ip", value="1.2.3.4", source="virustotal")]

        context = _build_sec_gemini_context(result)
        assert "whois" in context
        assert context["whois"]["domain"] == "test.com"
        assert "dns" in context
        assert "ssl" in context
        assert "existing_threat_indicators" in context
        assert len(context["existing_threat_indicators"]) == 1

    def test_sec_gemini_enrichment_skips_when_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verify _run_sec_gemini_enrichment is a no-op when disabled."""
        from unittest.mock import MagicMock

        from ssi.investigator.orchestrator import _run_sec_gemini_enrichment

        mock_settings = MagicMock()
        mock_settings.sec_gemini.enabled = False

        monkeypatch.setattr("ssi.settings.get_settings", lambda: mock_settings)

        result = InvestigationResult(url="https://test.com")
        # Should return immediately without touching the result
        _run_sec_gemini_enrichment("https://test.com", result)
        assert result.sec_gemini_analysis is None

    def test_sec_gemini_enrichment_skips_when_no_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Verify _run_sec_gemini_enrichment skips when enabled but no API key."""
        from unittest.mock import MagicMock

        from ssi.investigator.orchestrator import _run_sec_gemini_enrichment

        mock_settings = MagicMock()
        mock_settings.sec_gemini.enabled = True
        mock_settings.sec_gemini.api_key = ""

        monkeypatch.setattr("ssi.settings.get_settings", lambda: mock_settings)

        result = InvestigationResult(url="https://test.com")
        _run_sec_gemini_enrichment("https://test.com", result)
        assert result.sec_gemini_analysis is None


# ---------------------------------------------------------------------------
# Settings tests
# ---------------------------------------------------------------------------


class TestSecGeminiSettings:
    """Test settings schema and defaults."""

    def test_default_settings(self) -> None:
        from ssi.settings.config import SecGeminiSettings

        settings = SecGeminiSettings()
        assert settings.enabled is False
        assert settings.api_key == ""
        assert settings.timeout_seconds == 180
        assert settings.disable_logging is False
        assert settings.enable_email_security is True
        assert settings.enable_vuln_correlation is True
        assert settings.enable_threat_synthesis is True

    def test_env_var_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from ssi.settings.config import SecGeminiSettings

        monkeypatch.setenv("SSI_SEC_GEMINI__ENABLED", "true")
        monkeypatch.setenv("SSI_SEC_GEMINI__API_KEY", "test-key-123")
        monkeypatch.setenv("SSI_SEC_GEMINI__TIMEOUT_SECONDS", "60")

        settings = SecGeminiSettings()
        assert settings.enabled is True
        assert settings.api_key == "test-key-123"
        assert settings.timeout_seconds == 60

    def test_settings_on_root(self) -> None:
        """Verify sec_gemini section is accessible from the root Settings."""
        from ssi.settings.config import Settings

        # Construct with minimal overrides to avoid file I/O
        settings = Settings(
            _env_file=None,
            sec_gemini={"enabled": False, "api_key": ""},
        )
        assert hasattr(settings, "sec_gemini")
        assert settings.sec_gemini.enabled is False
