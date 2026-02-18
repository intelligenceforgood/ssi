"""Unit tests for STIX 2.1 evidence export."""

from __future__ import annotations

import pytest

from ssi.evidence.stix import (
    _create_indicator_sdo,
    _create_infrastructure_sdo,
    _indicator_to_pattern,
    _make_stix_id,
    investigation_to_stix_bundle,
)
from ssi.models.investigation import (
    DownloadArtifact,
    GeoIPInfo,
    InvestigationResult,
    SSLInfo,
    ThreatIndicator,
    WHOISRecord,
)


class TestMakeStixId:
    def test_deterministic(self):
        id1 = _make_stix_id("indicator", "ip:1.2.3.4")
        id2 = _make_stix_id("indicator", "ip:1.2.3.4")
        assert id1 == id2
        assert id1.startswith("indicator--")

    def test_different_values(self):
        id1 = _make_stix_id("indicator", "ip:1.2.3.4")
        id2 = _make_stix_id("indicator", "ip:5.6.7.8")
        assert id1 != id2


class TestIndicatorToPattern:
    @pytest.mark.parametrize(
        "itype,value,expected",
        [
            ("ip", "1.2.3.4", "[ipv4-addr:value = '1.2.3.4']"),
            ("ipv4", "10.0.0.1", "[ipv4-addr:value = '10.0.0.1']"),
            ("ipv6", "::1", "[ipv6-addr:value = '::1']"),
            ("domain", "scam.example.com", "[domain-name:value = 'scam.example.com']"),
            ("email", "bad@evil.com", "[email-addr:value = 'bad@evil.com']"),
            ("url", "https://evil.com/payload", "[url:value = 'https://evil.com/payload']"),
            ("crypto_wallet", "bc1qxy2k", "[artifact:payload_bin = 'bc1qxy2k']"),
            ("sha256", "abcdef123456", "[file:hashes.'SHA-256' = 'abcdef123456']"),
            ("md5", "d41d8cd", "[file:hashes.MD5 = 'd41d8cd']"),
            ("unknown_type", "somevalue", "[artifact:payload_bin = 'somevalue']"),
        ],
    )
    def test_pattern(self, itype, value, expected):
        ti = ThreatIndicator(indicator_type=itype, value=value, context="test", source="unit")
        assert _indicator_to_pattern(ti) == expected


class TestCreateIndicatorSdo:
    def test_creates_valid_sdo(self):
        ti = ThreatIndicator(indicator_type="ip", value="1.2.3.4", context="Hosting IP", source="dns")
        sdo = _create_indicator_sdo(ti, "https://scam.example.com")
        assert sdo["type"] == "indicator"
        assert sdo["spec_version"] == "2.1"
        assert sdo["pattern"] == "[ipv4-addr:value = '1.2.3.4']"
        assert sdo["pattern_type"] == "stix"
        assert "scam-infrastructure" in sdo["labels"]
        assert sdo["indicator_types"] == ["malicious-activity"]
        assert sdo["external_references"][0]["url"] == "https://scam.example.com"


class TestCreateInfrastructureSdo:
    def test_creates_infra_sdo(self):
        result = InvestigationResult(
            url="https://fakeshop.example.com",
            whois=WHOISRecord(domain="fakeshop.example.com", registrar="GoDaddy"),
            geoip=GeoIPInfo(ip="1.2.3.4", country="US", org="HostingCo"),
            ssl=SSLInfo(issuer="Let's Encrypt", is_valid=True),
        )
        sdo = _create_infrastructure_sdo(result)
        assert sdo is not None
        assert sdo["type"] == "infrastructure"
        assert sdo["infrastructure_types"] == ["phishing"]
        assert "GoDaddy" in sdo["description"]
        assert "HostingCo" in sdo["description"]
        assert "Let's Encrypt" in sdo["description"]

    def test_no_url_returns_none(self):
        result = InvestigationResult(url="")
        assert _create_infrastructure_sdo(result) is None


class TestInvestigationToStixBundle:
    def test_minimal_bundle(self):
        result = InvestigationResult(url="https://scam.example.com")
        bundle = investigation_to_stix_bundle(result)
        assert bundle["type"] == "bundle"
        assert bundle["id"].startswith("bundle--")
        # Should have at least identity + infrastructure
        types = [o["type"] for o in bundle["objects"]]
        assert "identity" in types
        assert "infrastructure" in types

    def test_deduplicates_indicators(self):
        result = InvestigationResult(
            url="https://scam.example.com",
            threat_indicators=[
                ThreatIndicator(indicator_type="ip", value="1.2.3.4", context="a", source="dns"),
                ThreatIndicator(indicator_type="ip", value="1.2.3.4", context="b", source="whois"),  # duplicate
                ThreatIndicator(indicator_type="domain", value="scam.example.com", context="c", source="dns"),
            ],
        )
        bundle = investigation_to_stix_bundle(result)
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        # Should only have 2 indicators (ip + domain), not 3
        assert len(indicators) == 2

    def test_malware_from_downloads(self):
        result = InvestigationResult(
            url="https://scam.example.com",
            downloads=[
                DownloadArtifact(
                    url="https://scam.example.com/trojan.exe",
                    filename="trojan.exe",
                    sha256="abc123def456",
                    md5="deadbeef",
                    is_malicious=True,
                    vt_detections=15,
                    vt_total_engines=70,
                ),
                DownloadArtifact(
                    url="https://scam.example.com/clean.pdf",
                    filename="clean.pdf",
                    sha256="ffeedd",
                    is_malicious=False,
                ),
            ],
        )
        bundle = investigation_to_stix_bundle(result)
        malware = [o for o in bundle["objects"] if o["type"] == "malware"]
        # Only the malicious download should produce a malware SDO
        assert len(malware) == 1
        assert malware[0]["name"] == "trojan.exe"
        assert malware[0]["hashes"]["SHA-256"] == "abc123def456"
        assert malware[0]["hashes"]["MD5"] == "deadbeef"

    def test_relationships_link_indicators_to_infrastructure(self):
        result = InvestigationResult(
            url="https://scam.example.com",
            threat_indicators=[
                ThreatIndicator(indicator_type="ip", value="1.2.3.4", context="a", source="dns"),
            ],
        )
        bundle = investigation_to_stix_bundle(result)
        rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
        assert len(rels) == 1
        assert rels[0]["relationship_type"] == "indicates"

        # Verify source is indicator, target is infrastructure
        infra = [o for o in bundle["objects"] if o["type"] == "infrastructure"][0]
        indicator = [o for o in bundle["objects"] if o["type"] == "indicator"][0]
        assert rels[0]["source_ref"] == indicator["id"]
        assert rels[0]["target_ref"] == infra["id"]
