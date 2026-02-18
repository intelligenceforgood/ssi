"""Unit tests for the urlscan.io module."""

from __future__ import annotations

from ssi.osint.urlscan import extract_threat_indicators, get_page_metadata


class TestExtractThreatIndicators:
    """Test extract_threat_indicators from urlscan.io result dicts."""

    def test_empty_result(self):
        indicators = extract_threat_indicators({}, "https://example.com")
        assert indicators == []

    def test_none_result(self):
        indicators = extract_threat_indicators({}, "https://example.com")
        assert indicators == []

    def test_malicious_verdict(self):
        result = {
            "verdicts": {
                "overall": {"malicious": True, "score": 100},
            },
            "lists": {"ips": [], "domains": [], "certificates": []},
        }
        indicators = extract_threat_indicators(result, "https://evil.example.com")
        assert len(indicators) == 1
        assert indicators[0].indicator_type == "url"
        assert "malicious" in indicators[0].context
        assert indicators[0].source == "urlscan.io"

    def test_non_malicious_verdict(self):
        result = {
            "verdicts": {
                "overall": {"malicious": False, "score": 0},
            },
            "lists": {"ips": [], "domains": [], "certificates": []},
        }
        indicators = extract_threat_indicators(result, "https://safe.example.com")
        assert len(indicators) == 0

    def test_contacted_ips(self):
        result = {
            "verdicts": {"overall": {}},
            "lists": {
                "ips": ["1.2.3.4", "5.6.7.8"],
                "domains": [],
                "certificates": [],
            },
        }
        indicators = extract_threat_indicators(result, "https://example.com")
        ip_indicators = [i for i in indicators if i.indicator_type == "ip"]
        assert len(ip_indicators) == 2
        assert ip_indicators[0].value == "1.2.3.4"

    def test_contacted_domains_exclude_target(self):
        result = {
            "verdicts": {"overall": {}},
            "lists": {
                "ips": [],
                "domains": ["example.com", "cdn.badsite.com", "tracker.evil.net"],
                "certificates": [],
            },
        }
        indicators = extract_threat_indicators(result, "https://example.com/phish")
        domain_indicators = [i for i in indicators if i.indicator_type == "domain"]
        # Should exclude example.com (the target domain itself)
        assert len(domain_indicators) == 2
        values = [i.value for i in domain_indicators]
        assert "example.com" not in values
        assert "cdn.badsite.com" in values

    def test_certificates(self):
        result = {
            "verdicts": {"overall": {}},
            "lists": {
                "ips": [],
                "domains": [],
                "certificates": [
                    {"issuer": "Let's Encrypt", "subjectName": "*.badsite.com"},
                ],
            },
        }
        indicators = extract_threat_indicators(result, "https://example.com")
        cert_indicators = [i for i in indicators if "certificate" in i.context.lower()]
        assert len(cert_indicators) == 1
        assert cert_indicators[0].value == "*.badsite.com"

    def test_ip_limit(self):
        """Only first 10 IPs should be included."""
        result = {
            "verdicts": {"overall": {}},
            "lists": {
                "ips": [f"10.0.0.{i}" for i in range(20)],
                "domains": [],
                "certificates": [],
            },
        }
        indicators = extract_threat_indicators(result, "https://example.com")
        ip_indicators = [i for i in indicators if i.indicator_type == "ip"]
        assert len(ip_indicators) == 10


class TestGetPageMetadata:
    """Test page metadata extraction from urlscan.io results."""

    def test_empty_result(self):
        meta = get_page_metadata({})
        assert meta == {}

    def test_full_page_metadata(self):
        result = {
            "page": {
                "server": "nginx",
                "domain": "example.com",
                "ip": "93.184.216.34",
                "country": "US",
                "asn": "AS15133",
                "asnname": "Edgecast",
                "title": "Example Domain",
                "status": 200,
                "mimeType": "text/html",
            },
            "stats": {
                "resourceStats": [{"count": 15}],
                "uniqCountries": 3,
            },
        }
        meta = get_page_metadata(result)
        assert meta["server"] == "nginx"
        assert meta["domain"] == "example.com"
        assert meta["country"] == "US"
        assert meta["status_code"] == 200
        assert meta["total_resources"] == 15
        assert meta["unique_countries"] == 3

    def test_missing_page_fields(self):
        result = {"page": {}, "stats": {}}
        meta = get_page_metadata(result)
        assert meta["server"] == ""
        assert meta["domain"] == ""
