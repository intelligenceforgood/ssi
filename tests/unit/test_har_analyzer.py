"""Unit tests for the HAR analysis module."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ssi.browser.har_analyzer import (
    HarAnalysis,
    analyze_har,
    har_to_threat_indicators,
)


def _make_har_entry(
    url: str = "https://example.com/page",
    method: str = "GET",
    response_mime: str = "text/html",
    response_text: str = "",
    post_data: str = "",
) -> dict:
    """Build a minimal HAR entry for testing."""
    entry: dict = {
        "request": {
            "url": url,
            "method": method,
        },
        "response": {
            "content": {
                "mimeType": response_mime,
                "text": response_text,
            },
        },
    }
    if post_data:
        entry["request"]["postData"] = {"text": post_data}
    return entry


def _write_har(tmp_path: Path, entries: list[dict]) -> Path:
    """Write a HAR file with the given entries."""
    har = {"log": {"entries": entries}}
    har_path = tmp_path / "test.har"
    har_path.write_text(json.dumps(har))
    return har_path


class TestAnalyzeHar:
    """Tests for the analyze_har function."""

    def test_missing_file(self, tmp_path):
        result = analyze_har(tmp_path / "nonexistent.har")
        assert result.total_requests == 0

    def test_empty_entries(self, tmp_path):
        har_path = _write_har(tmp_path, [])
        result = analyze_har(har_path)
        assert result.total_requests == 0

    def test_basic_request_count(self, tmp_path):
        entries = [
            _make_har_entry("https://example.com/page1"),
            _make_har_entry("https://example.com/page2"),
            _make_har_entry("https://cdn.example.com/style.css"),
        ]
        har_path = _write_har(tmp_path, entries)
        result = analyze_har(har_path, target_domain="example.com")
        assert result.total_requests == 3

    def test_third_party_domains(self, tmp_path):
        entries = [
            _make_har_entry("https://example.com/page"),
            _make_har_entry("https://tracker.evil.net/pixel.gif"),
            _make_har_entry("https://cdn.example.com/lib.js"),
        ]
        har_path = _write_har(tmp_path, entries)
        result = analyze_har(har_path, target_domain="example.com")

        assert "tracker.evil.net" in result.third_party_domains
        # Subdomain of target should also be third-party (different host)
        # cdn.example.com ends with .example.com, so it's excluded
        assert "cdn.example.com" not in result.third_party_domains

    def test_suspicious_content_type(self, tmp_path):
        entries = [
            _make_har_entry(
                "https://example.com/update.exe",
                response_mime="application/x-msdownload",
            ),
        ]
        har_path = _write_har(tmp_path, entries)
        result = analyze_har(har_path)

        assert len(result.suspicious_content_types) == 1
        assert result.suspicious_content_types[0]["content_type"] == "application/x-msdownload"

    def test_phishing_kit_pattern(self, tmp_path):
        entries = [
            _make_har_entry("https://example.com/wp-admin/gate.php"),
        ]
        har_path = _write_har(tmp_path, entries)
        result = analyze_har(har_path)

        assert len(result.phishing_kit_indicators) == 1

    def test_exfil_indicator_post(self, tmp_path):
        entries = [
            _make_har_entry(
                "https://evil.com/collect",
                method="POST",
                post_data="username=test&password=secret123",
            ),
        ]
        har_path = _write_har(tmp_path, entries)
        result = analyze_har(har_path)

        assert len(result.exfil_indicators) == 1
        assert "password" in result.exfil_indicators[0]["pattern"]

    def test_crypto_address_detection(self, tmp_path):
        btc_address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        entries = [
            _make_har_entry(
                "https://example.com/donate",
                response_text=f"Send BTC to {btc_address}",
                response_mime="text/html",
            ),
        ]
        har_path = _write_har(tmp_path, entries)
        result = analyze_har(har_path)

        assert len(result.crypto_addresses) == 1
        assert result.crypto_addresses[0]["type"] == "bitcoin"
        assert result.crypto_addresses[0]["address"] == btc_address

    def test_ethereum_address_detection(self, tmp_path):
        eth_address = "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD10"
        entries = [
            _make_har_entry(
                "https://example.com/page",
                response_text=f"Wallet: {eth_address}",
                response_mime="text/html",
            ),
        ]
        har_path = _write_har(tmp_path, entries)
        result = analyze_har(har_path)

        assert len(result.crypto_addresses) == 1
        assert result.crypto_addresses[0]["type"] == "ethereum"

    def test_invalid_json(self, tmp_path):
        har_path = tmp_path / "bad.har"
        har_path.write_text("not json at all")
        result = analyze_har(har_path)
        assert result.total_requests == 0


class TestHarAnalysis:
    """Tests for the HarAnalysis container."""

    def test_has_findings_empty(self):
        a = HarAnalysis()
        assert a.has_findings is False

    def test_has_findings_with_suspicious_content(self):
        a = HarAnalysis()
        a.suspicious_content_types.append({"url": "test", "content_type": "bad", "domain": "x"})
        assert a.has_findings is True

    def test_to_dict(self):
        a = HarAnalysis()
        a.total_requests = 5
        a.third_party_domains = {"a.com", "b.com"}
        d = a.to_dict()
        assert d["total_requests"] == 5
        assert sorted(d["third_party_domains"]) == ["a.com", "b.com"]


class TestHarToThreatIndicators:
    """Tests for converting HAR analysis to ThreatIndicator models."""

    def test_empty_analysis(self):
        a = HarAnalysis()
        indicators = har_to_threat_indicators(a, "https://example.com")
        assert indicators == []

    def test_suspicious_content_type_indicator(self):
        a = HarAnalysis()
        a.suspicious_content_types.append({
            "url": "https://evil.com/malware.exe",
            "content_type": "application/x-msdownload",
            "domain": "evil.com",
        })
        indicators = har_to_threat_indicators(a, "https://evil.com")
        assert len(indicators) == 1
        assert indicators[0].indicator_type == "url"
        assert "application/x-msdownload" in indicators[0].context

    def test_crypto_wallet_indicator(self):
        a = HarAnalysis()
        a.crypto_addresses.append({
            "type": "bitcoin",
            "address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "source_url": "https://example.com/page",
        })
        indicators = har_to_threat_indicators(a, "https://example.com")
        assert len(indicators) == 1
        assert indicators[0].indicator_type == "crypto_wallet"
        assert "bitcoin" in indicators[0].context
