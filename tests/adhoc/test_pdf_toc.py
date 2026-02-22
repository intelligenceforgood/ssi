"""Adhoc smoke test: verify PDF generation with ToC, anchors, and all appendix links."""

import json
import os
import tempfile
from pathlib import Path

from ssi.models.investigation import InvestigationResult, PageSnapshot, ThreatIndicator
from ssi.reports.pdf import render_pdf_report, _build_evidence_appendices_html
from ssi.wallet.models import WalletEntry


def main() -> None:
    tmpdir = tempfile.mkdtemp()

    # Create fake evidence files
    screenshot = Path(tmpdir) / "screenshot.png"
    screenshot.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 50)
    dom = Path(tmpdir) / "dom.html"
    dom.write_text("<html><body>Scam test page</body></html>")
    har = Path(tmpdir) / "network.har"
    har.write_text(json.dumps({
        "log": {
            "entries": [
                {
                    "request": {"method": "GET", "url": "https://scam-test.example.com/"},
                    "response": {"status": 200, "content": {"size": 4000, "mimeType": "text/html"}},
                },
                {
                    "request": {"method": "GET", "url": "https://cdn.example.com/style.css"},
                    "response": {"status": 200, "content": {"size": 1200, "mimeType": "text/css"}},
                },
            ]
        }
    }))

    result = InvestigationResult(
        url="https://scam-test.example.com",
        output_path=tmpdir,
        page_snapshot=PageSnapshot(
            url="https://scam-test.example.com",
            screenshot_path=str(screenshot),
            dom_snapshot_path=str(dom),
            har_path=str(har),
        ),
        wallets=[
            WalletEntry(
                site_url="https://scam-test.example.com",
                token_symbol="USDT",
                token_label="USDT (TRX)",
                network_short="trx",
                network_label="Tron",
                wallet_address="T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb",
                source="js",
                confidence=0.9,
                run_id="test",
            )
        ],
        threat_indicators=[
            ThreatIndicator(
                indicator_type="domain",
                value="scam-test.example.com",
                context="target",
                source="dns",
            )
        ],
    )

    pdf_path = Path(result.output_path) / "test_report.pdf"
    render_pdf_report(result, pdf_path)
    size = os.path.getsize(pdf_path)
    print(f"PDF generated: {pdf_path} ({size:,} bytes)")

    # Verify appendix HTML features
    appendix_html = _build_evidence_appendices_html(result)
    appendix_checks = {
        "Appendix A (screenshot)": 'id="appendix-screenshot"' in appendix_html,
        "Appendix B (DOM)": 'id="appendix-dom"' in appendix_html,
        "Appendix C (JSON)": 'id="appendix-investigation-json"' in appendix_html,
        "Appendix D (HAR)": 'id="appendix-har-summary"' in appendix_html,
        "Appendix E (wallets)": 'id="appendix-wallet-manifest"' in appendix_html,
        "Appendix F (STIX)": 'id="appendix-stix-bundle"' in appendix_html,
        "All back-links present": appendix_html.count('href="#evidence-artifacts"') == 6,
    }

    # Verify markdown template
    import markdown
    from ssi.reports import render_markdown_report

    md_content = render_markdown_report(result)
    md_checks = {
        "[TOC] in markdown": "[TOC]" in md_content,
        "evidence-artifacts attr": "{: #evidence-artifacts}" in md_content,
        "screenshot link": "[screenshot.png](#appendix-screenshot)" in md_content,
        "dom link": "[dom.html](#appendix-dom)" in md_content,
        "investigation JSON link": "[investigation.json](#appendix-investigation-json)" in md_content,
        "HAR link": "[network.har](#appendix-har-summary)" in md_content,
        "wallet manifest link": "[wallet_manifest.json](#appendix-wallet-manifest)" in md_content,
        "STIX link": "[stix_bundle.json](#appendix-stix-bundle)" in md_content,
        "Page Analysis screenshot linked": "[screenshot.png](#appendix-screenshot)" in md_content,
    }

    # Verify HTML ToC
    html = markdown.markdown(
        md_content,
        extensions=["tables", "fenced_code", "attr_list", "toc"],
        extension_configs={"toc": {"title": "Table of Contents", "toc_depth": "2"}},
    )
    html_checks = {
        "TOC div": '<div class="toc">' in html,
        "evidence-artifacts id": 'id="evidence-artifacts"' in html,
    }

    all_checks = {**appendix_checks, **md_checks, **html_checks}
    for name, ok in all_checks.items():
        print(f"  {name}: {'PASS' if ok else 'FAIL'}")

    all_ok = all(all_checks.values())
    print(f"\nOverall: {'ALL PASS' if all_ok else 'SOME FAILED'}")


if __name__ == "__main__":
    main()
