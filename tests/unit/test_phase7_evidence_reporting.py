"""Unit tests for Phase 7 — Evidence & Reporting Enhancements.

Covers:
- Wallet manifest generation in evidence ZIP
- STIX 2.1 bundle wallet indicators
- PII exposure in reports
- Markdown / LEA report wallet sections
- Investigation model schema updates
- Wallet XLSX/CSV export API endpoint
- PDF embedded evidence (screenshot/DOM)
"""

from __future__ import annotations

import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

from ssi.evidence.stix import (
    _create_wallet_indicator_sdo,
    _indicator_to_pattern,
    investigation_to_stix_bundle,
)
from ssi.investigator.orchestrator import _create_evidence_zip, _write_wallet_manifest
from ssi.models.investigation import (
    InvestigationResult,
    InvestigationStatus,
    PageSnapshot,
    PiiExposure,
    ScanType,
    ThreatIndicator,
)
from ssi.reports import render_markdown_report
from ssi.wallet.models import WalletEntry


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_wallet(
    token: str = "USDT",
    network: str = "trx",
    address: str = "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb",
    source: str = "js",
    confidence: float = 0.9,
) -> WalletEntry:
    """Create a sample WalletEntry for tests."""
    return WalletEntry(
        site_url="https://scam.example.com",
        token_label=f"{token} ({network.upper()})",
        token_symbol=token,
        network_label=f"{network.upper()} Network",
        network_short=network,
        wallet_address=address,
        source=source,
        confidence=confidence,
        run_id="test-run-001",
    )


def _make_pii_exposure(
    field_type: str = "email",
    label: str = "Email Address",
    required: bool = True,
    submitted: bool = False,
) -> PiiExposure:
    """Create a sample PiiExposure for tests."""
    return PiiExposure(
        field_type=field_type,
        field_label=label,
        form_action="https://scam.example.com/submit",
        page_url="https://scam.example.com/register",
        is_required=required,
        was_submitted=submitted,
    )


@pytest.fixture()
def result_with_wallets() -> InvestigationResult:
    """An investigation result populated with wallets and PII exposures."""
    return InvestigationResult(
        url="https://scam.example.com",
        status=InvestigationStatus.COMPLETED,
        success=True,
        scan_type=ScanType.FULL,
        duration_seconds=15.0,
        wallets=[
            _make_wallet("USDT", "trx", "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb"),
            _make_wallet("ETH", "eth", "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28"),
            _make_wallet("BTC", "btc", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"),
        ],
        pii_exposures=[
            _make_pii_exposure("email", "Email Address", required=True, submitted=True),
            _make_pii_exposure("password", "Password", required=True, submitted=True),
            _make_pii_exposure("text", "Full Name", required=False, submitted=False),
        ],
        threat_indicators=[
            ThreatIndicator(indicator_type="ip", value="198.51.100.42", context="Hosting IP", source="dns"),
            ThreatIndicator(
                indicator_type="crypto_wallet",
                value="T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb",
                context="USDT wallet on TRC-20",
                source="wallet_extraction",
            ),
        ],
    )


@pytest.fixture()
def inv_dir_with_wallets(tmp_path: Path, result_with_wallets: InvestigationResult) -> tuple[InvestigationResult, Path]:
    """Populated investigation directory for evidence ZIP tests."""
    inv_dir = tmp_path / "inv_wallet_test"
    inv_dir.mkdir()
    (inv_dir / "investigation.json").write_text('{"url": "https://scam.example.com"}')
    (inv_dir / "screenshot.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
    return result_with_wallets, inv_dir


# ---------------------------------------------------------------------------
# Wallet Manifest Tests
# ---------------------------------------------------------------------------


class TestWalletManifest:
    """Tests for _write_wallet_manifest."""

    def test_manifest_created(self, inv_dir_with_wallets: tuple[InvestigationResult, Path]) -> None:
        result, inv_dir = inv_dir_with_wallets
        _write_wallet_manifest(result, inv_dir)

        manifest_path = inv_dir / "wallet_manifest.json"
        assert manifest_path.exists()
        assert result.wallet_manifest_path == str(manifest_path)

    def test_manifest_content(self, inv_dir_with_wallets: tuple[InvestigationResult, Path]) -> None:
        result, inv_dir = inv_dir_with_wallets
        _write_wallet_manifest(result, inv_dir)

        manifest = json.loads((inv_dir / "wallet_manifest.json").read_text())
        assert manifest["investigation_id"] == str(result.investigation_id)
        assert manifest["target_url"] == "https://scam.example.com"
        assert manifest["wallet_count"] == 3
        assert len(manifest["wallets"]) == 3
        assert set(manifest["unique_networks"]) == {"btc", "eth", "trx"}
        assert set(manifest["unique_tokens"]) == {"BTC", "ETH", "USDT"}

    def test_manifest_wallet_fields(self, inv_dir_with_wallets: tuple[InvestigationResult, Path]) -> None:
        result, inv_dir = inv_dir_with_wallets
        _write_wallet_manifest(result, inv_dir)

        manifest = json.loads((inv_dir / "wallet_manifest.json").read_text())
        wallet = manifest["wallets"][0]
        assert "token_symbol" in wallet
        assert "network_short" in wallet
        assert "wallet_address" in wallet
        assert "source" in wallet
        assert "confidence" in wallet
        assert "harvested_at" in wallet
        assert "site_url" in wallet

    def test_manifest_in_evidence_zip(self, inv_dir_with_wallets: tuple[InvestigationResult, Path]) -> None:
        result, inv_dir = inv_dir_with_wallets
        _write_wallet_manifest(result, inv_dir)
        _create_evidence_zip(result, inv_dir)

        with zipfile.ZipFile(inv_dir / "evidence.zip", "r") as zf:
            assert "wallet_manifest.json" in zf.namelist()
            wallet_data = json.loads(zf.read("wallet_manifest.json"))
            assert wallet_data["wallet_count"] == 3

    def test_manifest_not_created_when_no_wallets(self, tmp_path: Path) -> None:
        inv_dir = tmp_path / "no_wallets"
        inv_dir.mkdir()
        result = InvestigationResult(
            url="https://clean.example.com",
            status=InvestigationStatus.COMPLETED,
        )
        # _write_wallet_manifest should not be called (it's guarded in orchestrator),
        # but even if called directly it should not fail
        _write_wallet_manifest(result, inv_dir)
        manifest_path = inv_dir / "wallet_manifest.json"
        assert manifest_path.exists()
        manifest = json.loads(manifest_path.read_text())
        assert manifest["wallet_count"] == 0

    def test_manifest_has_description_in_zip(
        self, inv_dir_with_wallets: tuple[InvestigationResult, Path]
    ) -> None:
        """Evidence ZIP manifest.json should have a description for wallet_manifest.json."""
        result, inv_dir = inv_dir_with_wallets
        _write_wallet_manifest(result, inv_dir)
        _create_evidence_zip(result, inv_dir)

        with zipfile.ZipFile(inv_dir / "evidence.zip", "r") as zf:
            chain = json.loads(zf.read("manifest.json"))

        wallet_art = next((a for a in chain["artifacts"] if a["file"] == "wallet_manifest.json"), None)
        assert wallet_art is not None
        assert wallet_art["description"] != ""
        assert "wallet" in wallet_art["description"].lower()


# ---------------------------------------------------------------------------
# STIX Bundle Wallet Indicator Tests
# ---------------------------------------------------------------------------


class TestStixWalletIndicators:
    """Tests for STIX 2.1 wallet indicator SDOs."""

    def test_wallet_indicator_sdo_created(self) -> None:
        wallet = _make_wallet()
        sdo = _create_wallet_indicator_sdo(wallet, "https://scam.example.com")

        assert sdo["type"] == "indicator"
        assert sdo["spec_version"] == "2.1"
        assert "cryptocurrency-wallet" in sdo["pattern"]
        assert wallet.wallet_address in sdo["pattern"]
        assert sdo["pattern_type"] == "stix"
        assert "cryptocurrency" in sdo["labels"]
        assert wallet.network_short in sdo["labels"]

    def test_wallet_indicator_has_descriptive_name(self) -> None:
        wallet = _make_wallet("ETH", "eth", "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28")
        sdo = _create_wallet_indicator_sdo(wallet, "https://scam.example.com")

        assert "ETH" in sdo["name"]
        assert "eth" in sdo["name"]
        assert "0x742d35" in sdo["name"]

    def test_bundle_includes_wallet_indicators(self, result_with_wallets: InvestigationResult) -> None:
        bundle = investigation_to_stix_bundle(result_with_wallets)
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]

        # Should have: 1 IP indicator + 3 wallet indicators (2 from result.wallets not in threat_indicators,
        # plus the one overlapping with threat_indicators which is created from threat_indicators section)
        wallet_indicators = [i for i in indicators if "cryptocurrency-wallet" in i["pattern"]]
        assert len(wallet_indicators) >= 2, f"Expected >=2 wallet indicators, got {len(wallet_indicators)}"

    def test_wallet_addresses_deduplicated(self) -> None:
        """Wallets that already appear in threat_indicators should not produce duplicate SDOs."""
        result = InvestigationResult(
            url="https://scam.example.com",
            threat_indicators=[
                ThreatIndicator(
                    indicator_type="crypto_wallet",
                    value="T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb",
                    context="USDT wallet",
                    source="wallet_extraction",
                ),
            ],
            wallets=[
                _make_wallet("USDT", "trx", "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb"),
            ],
        )
        bundle = investigation_to_stix_bundle(result)
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        # Should only have 1 indicator (the wallet from threat_indicators), not 2
        wallet_indicators = [i for i in indicators if "cryptocurrency-wallet" in i["pattern"]]
        assert len(wallet_indicators) == 1

    def test_wallet_relationships_link_to_infrastructure(self, result_with_wallets: InvestigationResult) -> None:
        bundle = investigation_to_stix_bundle(result_with_wallets)
        rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
        infra = [o for o in bundle["objects"] if o["type"] == "infrastructure"]
        wallet_indicators = [
            o for o in bundle["objects"] if o["type"] == "indicator" and "cryptocurrency-wallet" in o["pattern"]
        ]

        assert len(infra) == 1
        # Each wallet indicator should have a relationship to infrastructure
        rel_sources = {r["source_ref"] for r in rels}
        for wi in wallet_indicators:
            assert wi["id"] in rel_sources

    def test_crypto_wallet_pattern_updated(self) -> None:
        """crypto_wallet type should now use cryptocurrency-wallet SCO pattern."""
        ti = ThreatIndicator(indicator_type="crypto_wallet", value="0xABC123", context="test", source="unit")
        pattern = _indicator_to_pattern(ti)
        assert "cryptocurrency-wallet:address" in pattern
        assert "artifact:payload_bin" not in pattern

    def test_infrastructure_sdo_mentions_wallets(self, result_with_wallets: InvestigationResult) -> None:
        bundle = investigation_to_stix_bundle(result_with_wallets)
        infra = [o for o in bundle["objects"] if o["type"] == "infrastructure"][0]
        assert "wallet" in infra["description"].lower()
        assert "3" in infra["description"]  # 3 wallet addresses


# ---------------------------------------------------------------------------
# PII Exposure Model Tests
# ---------------------------------------------------------------------------


class TestPiiExposureModel:
    """Tests for the PiiExposure model and its integration in InvestigationResult."""

    def test_pii_exposure_defaults(self) -> None:
        pii = PiiExposure()
        assert pii.field_type == ""
        assert pii.field_label == ""
        assert pii.is_required is False
        assert pii.was_submitted is False

    def test_pii_exposure_with_values(self) -> None:
        pii = _make_pii_exposure("password", "Password", required=True, submitted=True)
        assert pii.field_type == "password"
        assert pii.field_label == "Password"
        assert pii.is_required is True
        assert pii.was_submitted is True

    def test_investigation_result_has_pii_exposures(self, result_with_wallets: InvestigationResult) -> None:
        assert len(result_with_wallets.pii_exposures) == 3
        assert result_with_wallets.pii_exposures[0].field_type == "email"

    def test_pii_exposures_serialized_in_json(self, result_with_wallets: InvestigationResult) -> None:
        data = result_with_wallets.model_dump(mode="json")
        assert "pii_exposures" in data
        assert len(data["pii_exposures"]) == 3
        assert data["pii_exposures"][0]["field_type"] == "email"
        assert data["pii_exposures"][1]["was_submitted"] is True


# ---------------------------------------------------------------------------
# Investigation Model Schema Update Tests
# ---------------------------------------------------------------------------


class TestInvestigationSchemaUpdates:
    """Tests for the updated InvestigationResult schema."""

    def test_wallet_manifest_path_field(self) -> None:
        result = InvestigationResult(url="https://test.com")
        assert result.wallet_manifest_path == ""

    def test_wallet_manifest_path_set(self) -> None:
        result = InvestigationResult(
            url="https://test.com",
            wallet_manifest_path="/tmp/wallet_manifest.json",
        )
        assert result.wallet_manifest_path == "/tmp/wallet_manifest.json"

    def test_full_model_serialization(self, result_with_wallets: InvestigationResult) -> None:
        data = result_with_wallets.model_dump(mode="json")
        assert "wallets" in data
        assert "pii_exposures" in data
        assert "wallet_manifest_path" in data
        assert len(data["wallets"]) == 3
        assert len(data["pii_exposures"]) == 3


# ---------------------------------------------------------------------------
# Markdown Report Tests (Wallet + PII Sections)
# ---------------------------------------------------------------------------


class TestMarkdownReportWallets:
    """Tests for wallet and PII exposure sections in the markdown report."""

    def test_wallet_section_rendered(self, result_with_wallets: InvestigationResult) -> None:
        md = render_markdown_report(result_with_wallets)
        assert "Cryptocurrency Wallets" in md
        assert "USDT" in md
        assert "ETH" in md
        assert "BTC" in md
        assert "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb" in md

    def test_wallet_section_has_summary_table(self, result_with_wallets: InvestigationResult) -> None:
        md = render_markdown_report(result_with_wallets)
        assert "Total Addresses" in md
        assert "Unique Networks" in md
        assert "Unique Tokens" in md

    def test_wallet_manifest_referenced(self, result_with_wallets: InvestigationResult) -> None:
        md = render_markdown_report(result_with_wallets)
        assert "wallet_manifest.json" in md

    def test_pii_exposure_section_rendered(self, result_with_wallets: InvestigationResult) -> None:
        md = render_markdown_report(result_with_wallets)
        assert "PII Exposure Analysis" in md
        assert "Email Address" in md
        assert "Password" in md

    def test_pii_exposure_shows_count(self, result_with_wallets: InvestigationResult) -> None:
        md = render_markdown_report(result_with_wallets)
        assert "3 PII field(s)" in md or "3 fields" in md.lower()

    def test_no_pii_section_when_empty(self) -> None:
        result = InvestigationResult(
            url="https://clean.example.com",
            status=InvestigationStatus.COMPLETED,
        )
        md = render_markdown_report(result)
        assert "PII Exposure Analysis" not in md

    def test_no_wallet_section_when_empty(self) -> None:
        result = InvestigationResult(
            url="https://clean.example.com",
            status=InvestigationStatus.COMPLETED,
        )
        md = render_markdown_report(result)
        assert "Cryptocurrency Wallets" not in md

    def test_evidence_artifacts_includes_wallet_manifest(self, result_with_wallets: InvestigationResult) -> None:
        md = render_markdown_report(result_with_wallets)
        assert "Wallet Manifest" in md
        assert "wallet_manifest.json" in md

    def test_evidence_artifacts_includes_stix(self, result_with_wallets: InvestigationResult) -> None:
        md = render_markdown_report(result_with_wallets)
        assert "STIX IOC Bundle" in md
        assert "stix_bundle.json" in md

    def test_screenshot_rendered_inline(self) -> None:
        """Template includes a clickable link to appendix-screenshot."""
        result = InvestigationResult(
            url="https://scam.example.com",
            status=InvestigationStatus.COMPLETED,
            page_snapshot=PageSnapshot(
                url="https://scam.example.com",
                screenshot_path="/path/to/screenshot.png",
            ),
        )
        md = render_markdown_report(result)
        assert "[screenshot.png](#appendix-screenshot)" in md

    def test_dom_link_to_appendix(self) -> None:
        """Template includes a clickable link to appendix-dom."""
        result = InvestigationResult(
            url="https://scam.example.com",
            status=InvestigationStatus.COMPLETED,
            page_snapshot=PageSnapshot(
                url="https://scam.example.com",
                dom_snapshot_path="/path/to/dom.html",
            ),
        )
        md = render_markdown_report(result)
        assert "[dom.html](#appendix-dom)" in md

    def test_toc_marker_present(self) -> None:
        """Template includes the [TOC] marker for auto-generated table of contents."""
        result = InvestigationResult(
            url="https://scam.example.com",
            status=InvestigationStatus.COMPLETED,
        )
        md = render_markdown_report(result)
        assert "[TOC]" in md

    def test_evidence_artifacts_has_anchor(self) -> None:
        """Evidence Artifacts heading has the id anchor for back-links."""
        result = InvestigationResult(
            url="https://scam.example.com",
            status=InvestigationStatus.COMPLETED,
        )
        md = render_markdown_report(result)
        assert "{: #evidence-artifacts}" in md


class TestLeoReportWallets:
    """Tests for wallet and PII exposure sections in the LEA report."""

    def test_leo_wallet_section_rendered(self, result_with_wallets: InvestigationResult) -> None:
        md = render_markdown_report(result_with_wallets, template_name="leo_report.md.j2")
        assert "Cryptocurrency Wallet Addresses" in md
        assert "Blockchain Intelligence" in md
        assert "USDT" in md
        assert "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb" in md

    def test_leo_wallet_section_has_recommended_actions(self, result_with_wallets: InvestigationResult) -> None:
        md = render_markdown_report(result_with_wallets, template_name="leo_report.md.j2")
        assert "Recommended Actions" in md
        assert "Chainalysis" in md or "blockchain analytics" in md

    def test_leo_pii_exposure_detail(self, result_with_wallets: InvestigationResult) -> None:
        md = render_markdown_report(result_with_wallets, template_name="leo_report.md.j2")
        assert "PII Exposure Detail" in md
        assert "Email Address" in md

    def test_leo_no_wallet_section_when_empty(self) -> None:
        result = InvestigationResult(
            url="https://clean.example.com",
            status=InvestigationStatus.COMPLETED,
        )
        md = render_markdown_report(result, template_name="leo_report.md.j2")
        assert "No cryptocurrency wallet addresses" in md


# ---------------------------------------------------------------------------
# PDF Embedded Evidence Tests
# ---------------------------------------------------------------------------


class TestPdfEmbeddedEvidence:
    """Tests for embedded screenshots and DOM snapshots in PDF."""

    def test_inline_local_images_with_screenshot(self, tmp_path: Path) -> None:
        """Screenshot <img> tags are base64-inlined by _inline_local_images."""
        from ssi.reports.pdf import _inline_local_images

        screenshot = tmp_path / "screenshot.png"
        screenshot.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 50)

        result = InvestigationResult(
            url="https://scam.example.com",
            output_path=str(tmp_path),
            page_snapshot=PageSnapshot(
                url="https://scam.example.com",
                screenshot_path=str(screenshot),
            ),
        )
        html_in = f'<img src="{screenshot}" alt="screenshot" />'
        html_out = _inline_local_images(html_in, result)
        assert "data:image/png;base64," in html_out
        assert str(screenshot) not in html_out

    def test_inline_local_images_skips_data_uris(self, tmp_path: Path) -> None:
        """Already-inlined data URIs are not re-processed."""
        from ssi.reports.pdf import _inline_local_images

        result = InvestigationResult(url="https://scam.example.com")
        html_in = '<img src="data:image/png;base64,ABC123" alt="already" />'
        html_out = _inline_local_images(html_in, result)
        assert html_out == html_in

    def test_inline_local_images_skips_http_urls(self, tmp_path: Path) -> None:
        """External HTTP URLs are not inlined."""
        from ssi.reports.pdf import _inline_local_images

        result = InvestigationResult(url="https://scam.example.com")
        html_in = '<img src="https://cdn.example.com/logo.png" alt="logo" />'
        html_out = _inline_local_images(html_in, result)
        assert html_out == html_in

    def test_appendices_include_screenshot(self, tmp_path: Path) -> None:
        """Screenshot appendix has anchor ID and back-link."""
        from ssi.reports.pdf import _build_evidence_appendices_html

        screenshot = tmp_path / "screenshot.png"
        screenshot.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 50)

        result = InvestigationResult(
            url="https://scam.example.com",
            page_snapshot=PageSnapshot(
                url="https://scam.example.com",
                screenshot_path=str(screenshot),
            ),
        )
        html = _build_evidence_appendices_html(result)
        assert 'id="appendix-screenshot"' in html
        assert "Appendix A: Screenshot" in html
        assert f'src="{screenshot}"' in html
        assert 'href="#evidence-artifacts"' in html

    def test_appendices_include_dom(self, tmp_path: Path) -> None:
        """DOM appendix has anchor ID, content, and back-link."""
        from ssi.reports.pdf import _build_evidence_appendices_html

        dom = tmp_path / "dom.html"
        dom.write_text("<html><body><p>Test scam page</p></body></html>")

        result = InvestigationResult(
            url="https://scam.example.com",
            page_snapshot=PageSnapshot(
                url="https://scam.example.com",
                dom_snapshot_path=str(dom),
            ),
        )
        html = _build_evidence_appendices_html(result)
        assert 'id="appendix-dom"' in html
        assert "Appendix B: DOM Snapshot" in html
        assert "Test scam page" in html
        assert 'href="#evidence-artifacts"' in html

    def test_no_screenshot_or_dom_appendices_when_no_snapshots(self) -> None:
        """Screenshot/DOM appendices absent when page_snapshot is None.

        Investigation JSON appendix (C) is always generated.
        """
        from ssi.reports.pdf import _build_evidence_appendices_html

        result = InvestigationResult(url="https://scam.example.com")
        html = _build_evidence_appendices_html(result)
        assert 'id="appendix-screenshot"' not in html
        assert 'id="appendix-dom"' not in html
        # Appendix C (investigation JSON) is always present
        assert 'id="appendix-investigation-json"' in html

    def test_dom_truncation(self, tmp_path: Path) -> None:
        """DOM appendix is truncated to 500 lines for large pages."""
        from ssi.reports.pdf import _build_evidence_appendices_html

        dom = tmp_path / "dom.html"
        lines = [f"<p>Line {i}</p>" for i in range(600)]
        dom.write_text("\n".join(lines))

        result = InvestigationResult(
            url="https://scam.example.com",
            page_snapshot=PageSnapshot(
                url="https://scam.example.com",
                dom_snapshot_path=str(dom),
            ),
        )
        html = _build_evidence_appendices_html(result)
        assert "truncated" in html
        assert "first 500 lines" in html

    def test_legacy_aliases_exist(self) -> None:
        """Legacy function names alias to _build_evidence_appendices_html."""
        from ssi.reports.pdf import (
            _build_dom_appendix_html,
            _build_embedded_evidence_html,
            _build_evidence_appendices_html,
        )

        assert _build_embedded_evidence_html is _build_evidence_appendices_html
        assert _build_dom_appendix_html is _build_evidence_appendices_html

    def test_resolve_evidence_path_absolute(self, tmp_path: Path) -> None:
        from ssi.reports.pdf import _resolve_evidence_path

        screenshot = tmp_path / "shot.png"
        screenshot.write_bytes(b"\x89PNG")

        result = InvestigationResult(
            url="https://test.com",
            page_snapshot=PageSnapshot(url="https://test.com", screenshot_path=str(screenshot)),
        )
        resolved = _resolve_evidence_path(result, "screenshot_path")
        assert resolved == screenshot

    def test_resolve_evidence_path_none_when_no_snapshot(self) -> None:
        from ssi.reports.pdf import _resolve_evidence_path

        result = InvestigationResult(url="https://test.com")
        assert _resolve_evidence_path(result, "screenshot_path") is None

    def test_appendices_include_investigation_json(self) -> None:
        """Investigation JSON appendix (C) is always generated with anchor and back-link."""
        from ssi.reports.pdf import _build_evidence_appendices_html

        result = InvestigationResult(
            url="https://scam.example.com",
            status=InvestigationStatus.COMPLETED,
        )
        html = _build_evidence_appendices_html(result)
        assert 'id="appendix-investigation-json"' in html
        assert "Appendix C: Investigation Summary" in html
        assert 'href="#evidence-artifacts"' in html
        assert "scam.example.com" in html

    def test_investigation_json_truncation(self) -> None:
        """Investigation JSON appendix is truncated for very large results."""
        from ssi.reports.pdf import _append_investigation_json_appendix

        result = InvestigationResult(
            url="https://scam.example.com",
            warnings=[f"warning-{i}" for i in range(500)],
        )
        sections: list[str] = []
        _append_investigation_json_appendix(sections, result)
        assert len(sections) == 1
        assert "truncated at 300 lines" in sections[0]

    def test_appendices_include_har_summary(self, tmp_path: Path) -> None:
        """HAR summary appendix (D) is generated with anchor, stats, and request table."""
        from ssi.reports.pdf import _build_evidence_appendices_html

        har_path = tmp_path / "network.har"
        har_data = {
            "log": {
                "entries": [
                    {
                        "request": {"method": "GET", "url": "https://scam.example.com/"},
                        "response": {"status": 200, "content": {"size": 5000, "mimeType": "text/html"}},
                    },
                    {
                        "request": {"method": "GET", "url": "https://cdn.example.com/style.css"},
                        "response": {"status": 200, "content": {"size": 1200, "mimeType": "text/css"}},
                    },
                ]
            }
        }
        har_path.write_text(json.dumps(har_data))

        result = InvestigationResult(
            url="https://scam.example.com",
            page_snapshot=PageSnapshot(
                url="https://scam.example.com",
                har_path=str(har_path),
            ),
        )
        html = _build_evidence_appendices_html(result)
        assert 'id="appendix-har-summary"' in html
        assert "Appendix D: Network Activity" in html
        assert "Total Requests" in html
        assert 'href="#evidence-artifacts"' in html
        assert "scam.example.com" in html
        assert "cdn.example.com" in html

    def test_no_har_appendix_when_no_har(self) -> None:
        """HAR appendix is absent when no HAR file exists."""
        from ssi.reports.pdf import _build_evidence_appendices_html

        result = InvestigationResult(url="https://scam.example.com")
        html = _build_evidence_appendices_html(result)
        assert 'id="appendix-har-summary"' not in html

    def test_appendices_include_wallet_manifest(self) -> None:
        """Wallet manifest appendix (E) is generated when wallets are present."""
        from ssi.reports.pdf import _build_evidence_appendices_html

        result = InvestigationResult(
            url="https://scam.example.com",
            wallets=[_make_wallet()],
        )
        html = _build_evidence_appendices_html(result)
        assert 'id="appendix-wallet-manifest"' in html
        assert "Appendix E: Wallet Manifest" in html
        assert 'href="#evidence-artifacts"' in html
        assert "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb" in html
        assert "USDT" in html

    def test_no_wallet_appendix_when_no_wallets(self) -> None:
        """Wallet appendix is absent when no wallets extracted."""
        from ssi.reports.pdf import _build_evidence_appendices_html

        result = InvestigationResult(url="https://scam.example.com")
        html = _build_evidence_appendices_html(result)
        assert 'id="appendix-wallet-manifest"' not in html

    def test_appendices_include_stix_bundle(self) -> None:
        """STIX bundle appendix (F) is generated when threat indicators present."""
        from ssi.reports.pdf import _build_evidence_appendices_html

        result = InvestigationResult(
            url="https://scam.example.com",
            threat_indicators=[
                ThreatIndicator(
                    indicator_type="domain",
                    value="scam.example.com",
                    context="target site",
                    source="dns",
                )
            ],
        )
        html = _build_evidence_appendices_html(result)
        assert 'id="appendix-stix-bundle"' in html
        assert "Appendix F: STIX" in html
        assert 'href="#evidence-artifacts"' in html

    def test_no_stix_appendix_when_no_indicators(self) -> None:
        """STIX appendix is absent when no threat indicators."""
        from ssi.reports.pdf import _build_evidence_appendices_html

        result = InvestigationResult(url="https://scam.example.com")
        html = _build_evidence_appendices_html(result)
        assert 'id="appendix-stix-bundle"' not in html

    def test_page_analysis_screenshot_linked(self) -> None:
        """Page Analysis section links screenshot to appendix."""
        result = InvestigationResult(
            url="https://scam.example.com",
            status=InvestigationStatus.COMPLETED,
            page_snapshot=PageSnapshot(
                url="https://scam.example.com",
                screenshot_path="/path/to/screenshot.png",
            ),
        )
        md = render_markdown_report(result)
        # Should appear in the Page Analysis table
        assert "[screenshot.png](#appendix-screenshot)" in md
        # Should NOT have backtick-wrapped plain text
        assert "| **Screenshot** | `screenshot.png` |" not in md

    def test_evidence_table_investigation_json_always_present(self) -> None:
        """Investigation Summary is always in the evidence table (no condition)."""
        result = InvestigationResult(
            url="https://scam.example.com",
            status=InvestigationStatus.COMPLETED,
        )
        md = render_markdown_report(result)
        assert "[investigation.json](#appendix-investigation-json)" in md

    def test_evidence_table_har_linked(self) -> None:
        """HAR file in evidence table links to appendix."""
        result = InvestigationResult(
            url="https://scam.example.com",
            status=InvestigationStatus.COMPLETED,
            page_snapshot=PageSnapshot(
                url="https://scam.example.com",
                har_path="/path/to/network.har",
            ),
        )
        md = render_markdown_report(result)
        assert "[network.har](#appendix-har-summary)" in md

    def test_evidence_table_wallet_linked(self) -> None:
        """Wallet manifest in evidence table links to appendix."""
        result = InvestigationResult(
            url="https://scam.example.com",
            status=InvestigationStatus.COMPLETED,
            wallets=[_make_wallet()],
            threat_indicators=[ThreatIndicator(
                indicator_type="crypto_wallet",
                value="T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb",
                context="wallet",
                source="js",
            )],
        )
        md = render_markdown_report(result)
        assert "[wallet_manifest.json](#appendix-wallet-manifest)" in md

    def test_evidence_table_stix_linked(self) -> None:
        """STIX bundle in evidence table links to appendix."""
        result = InvestigationResult(
            url="https://scam.example.com",
            status=InvestigationStatus.COMPLETED,
            threat_indicators=[ThreatIndicator(
                indicator_type="domain",
                value="scam.example.com",
                context="target",
                source="dns",
            )],
        )
        md = render_markdown_report(result)
        assert "[stix_bundle.json](#appendix-stix-bundle)" in md

    def test_evidence_table_video_not_linked(self) -> None:
        """Agent video shows a note instead of a file link."""
        result = InvestigationResult(
            url="https://scam.example.com",
            status=InvestigationStatus.COMPLETED,
            scan_type=ScanType.ACTIVE,
        )
        md = render_markdown_report(result)
        assert "see evidence ZIP" in md


# ---------------------------------------------------------------------------
# Wallet Export API Endpoint Tests
# ---------------------------------------------------------------------------


class TestWalletExportEndpoint:
    """Tests for the wallet XLSX/CSV export API endpoints."""

    def test_export_wallets_xlsx_route_exists(self) -> None:
        from ssi.api.investigation_routes import investigation_router

        paths = [r.path for r in investigation_router.routes]
        assert "/investigations/{scan_id}/wallets.xlsx" in paths

    def test_export_wallets_csv_route_exists(self) -> None:
        from ssi.api.investigation_routes import investigation_router

        paths = [r.path for r in investigation_router.routes]
        assert "/investigations/{scan_id}/wallets.csv" in paths

    @patch("ssi.api.investigation_routes.build_scan_store")
    def test_export_wallets_xlsx_not_found(self, mock_build: MagicMock) -> None:
        from fastapi.testclient import TestClient

        from ssi.api.investigation_routes import investigation_router

        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(investigation_router)
        client = TestClient(app)

        mock_store = MagicMock()
        mock_store.get_scan.return_value = None
        mock_build.return_value = mock_store

        response = client.get("/investigations/nonexistent/wallets.xlsx")
        assert response.status_code == 404

    @patch("ssi.api.investigation_routes.build_scan_store")
    def test_export_wallets_xlsx_no_wallets(self, mock_build: MagicMock) -> None:
        from fastapi.testclient import TestClient

        from ssi.api.investigation_routes import investigation_router

        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(investigation_router)
        client = TestClient(app)

        mock_store = MagicMock()
        mock_store.get_scan.return_value = {"scan_id": "test-123", "url": "https://test.com"}
        mock_store.get_wallets.return_value = []
        mock_build.return_value = mock_store

        response = client.get("/investigations/test-123/wallets.xlsx")
        assert response.status_code == 404

    @patch("ssi.api.investigation_routes.build_scan_store")
    def test_export_wallets_xlsx_success(self, mock_build: MagicMock) -> None:
        from fastapi.testclient import TestClient

        from ssi.api.investigation_routes import investigation_router

        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(investigation_router)
        client = TestClient(app)

        mock_store = MagicMock()
        mock_store.get_scan.return_value = {"scan_id": "test-123", "url": "https://scam.com"}
        mock_store.get_wallets.return_value = [
            {
                "wallet_address": "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb",
                "token_symbol": "USDT",
                "network_short": "trx",
                "source": "js",
                "confidence": 0.9,
                "site_url": "https://scam.com",
            }
        ]
        mock_build.return_value = mock_store

        response = client.get("/investigations/test-123/wallets.xlsx")
        assert response.status_code == 200
        assert "spreadsheetml" in response.headers.get("content-type", "")

    @patch("ssi.api.investigation_routes.build_scan_store")
    def test_export_wallets_csv_success(self, mock_build: MagicMock) -> None:
        from fastapi.testclient import TestClient

        from ssi.api.investigation_routes import investigation_router

        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(investigation_router)
        client = TestClient(app)

        mock_store = MagicMock()
        mock_store.get_scan.return_value = {"scan_id": "test-456", "url": "https://scam.com"}
        mock_store.get_wallets.return_value = [
            {
                "wallet_address": "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28",
                "token_symbol": "ETH",
                "network_short": "eth",
                "source": "llm",
                "confidence": 0.8,
                "site_url": "https://scam.com",
            }
        ]
        mock_build.return_value = mock_store

        response = client.get("/investigations/test-456/wallets.csv")
        assert response.status_code == 200
