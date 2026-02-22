"""PDF report generation for SSI investigations.

Renders an investigation result to a styled PDF using markdown → HTML → PDF
pipeline with ``markdown`` and ``weasyprint`` libraries.

Features:

- **Table of Contents**: Auto-generated from ``[TOC]`` marker in the
  markdown template, with clickable links to each section.
- **Evidence appendices**: Screenshots and DOM snapshots are embedded as
  appendix pages with bidirectional anchor links to the Evidence Artifacts
  table in the report body.
- **Self-contained output**: Local ``<img>`` tags are resolved to
  ``data:`` base64 URIs so the PDF works without external file references.
"""

from __future__ import annotations

import base64
import html as html_mod
import json
import logging
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ssi.models.investigation import InvestigationResult

logger = logging.getLogger(__name__)

# CSS for the PDF report — professional, clean layout
_PDF_CSS = """\
@page {
    size: A4;
    margin: 2cm 2.5cm;
    @bottom-center {
        content: "SSI Investigation Report — Confidential";
        font-size: 8pt;
        color: #999;
    }
    @bottom-right {
        content: "Page " counter(page) " of " counter(pages);
        font-size: 8pt;
        color: #999;
    }
}

body {
    font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
    font-size: 10pt;
    line-height: 1.5;
    color: #1a1a1a;
}

h1 {
    font-size: 18pt;
    color: #1a3a5c;
    border-bottom: 2pt solid #1a3a5c;
    padding-bottom: 6pt;
    margin-top: 0;
}

h2 {
    font-size: 14pt;
    color: #2c5f8a;
    border-bottom: 1pt solid #ddd;
    padding-bottom: 4pt;
    margin-top: 18pt;
}

h3 {
    font-size: 11pt;
    color: #444;
    margin-top: 14pt;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin: 10pt 0;
    font-size: 9pt;
}

th {
    background-color: #f0f4f8;
    font-weight: 600;
    text-align: left;
    padding: 6pt 8pt;
    border: 1pt solid #ddd;
}

td {
    padding: 5pt 8pt;
    border: 1pt solid #eee;
    vertical-align: top;
}

tr:nth-child(even) td {
    background-color: #fafbfc;
}

code {
    font-family: 'Courier New', monospace;
    font-size: 8.5pt;
    background-color: #f5f5f5;
    padding: 1pt 3pt;
    border-radius: 2pt;
}

blockquote {
    border-left: 3pt solid #2c5f8a;
    padding-left: 12pt;
    margin-left: 0;
    color: #444;
    font-size: 9.5pt;
}

.risk-high { color: #c0392b; font-weight: bold; }
.risk-medium { color: #e67e22; font-weight: bold; }
.risk-low { color: #27ae60; font-weight: bold; }

hr {
    border: none;
    border-top: 1pt solid #ddd;
    margin: 16pt 0;
}

img {
    max-width: 100%;
    border: 1px solid #ddd;
    margin: 8pt 0;
}

/* Table of Contents */
.toc {
    background: #f8f9fa;
    border: 1pt solid #ddd;
    border-radius: 4pt;
    padding: 12pt 16pt 12pt 16pt;
    margin: 12pt 0 16pt 0;
}

.toc .toctitle {
    font-size: 12pt;
    font-weight: 600;
    color: #1a3a5c;
    margin-bottom: 6pt;
}

.toc ul {
    list-style: none;
    padding-left: 14pt;
    margin: 3pt 0;
}

.toc > ul {
    padding-left: 0;
}

.toc li {
    margin: 2pt 0;
    font-size: 9.5pt;
    line-height: 1.4;
}

.toc a {
    color: #2c5f8a;
    text-decoration: none;
}

/* Appendix back-link */
.back-link {
    font-size: 8.5pt;
    color: #666;
    text-decoration: none;
    float: right;
    margin-top: 4pt;
}
"""


def render_pdf_report(
    result: InvestigationResult,
    output_path: Path,
    markdown_content: str | None = None,
    *,
    embed_evidence: bool = True,
) -> Path:
    """Render an investigation result to a styled PDF.

    If ``markdown_content`` is provided, it is used directly. Otherwise,
    the markdown report is generated from the Jinja2 template first.

    When ``embed_evidence`` is True and the investigation directory is
    available, screenshots and DOM snapshots are inlined as base64 images
    and appendix pages so the PDF is fully self-contained when printed
    (e.g. for law enforcement submission).

    Args:
        result: The investigation result to render.
        output_path: Path for the output PDF file.
        markdown_content: Pre-rendered markdown (optional).
        embed_evidence: Inline screenshots and DOM snapshots in the PDF.

    Returns:
        The path to the written PDF file.
    """
    import markdown
    from weasyprint import CSS, HTML

    if markdown_content is None:
        from ssi.reports import render_markdown_report

        markdown_content = render_markdown_report(result)

    # Convert markdown to HTML with ToC support.
    # The ``toc`` extension auto-generates heading IDs and replaces the
    # ``[TOC]`` marker in the template with a clickable table of contents.
    html_body = markdown.markdown(
        markdown_content,
        extensions=[
            "tables",
            "fenced_code",
            "attr_list",
            "toc",
        ],
        extension_configs={
            "toc": {
                "title": "Table of Contents",
                "toc_depth": "2-2",
            },
        },
    )

    # Optionally embed evidence appendices and inline local images
    appendix_html = ""
    if embed_evidence:
        appendix_html = _build_evidence_appendices_html(result)

    # Combine body + appendices, then inline all local <img> paths
    combined = html_body + "\n" + appendix_html
    if embed_evidence:
        combined = _inline_local_images(combined, result)

    full_html = f"""\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>SSI Investigation Report — {result.investigation_id}</title>
</head>
<body>
{combined}
</body>
</html>
"""

    output_path.parent.mkdir(parents=True, exist_ok=True)

    HTML(string=full_html).write_pdf(
        str(output_path),
        stylesheets=[CSS(string=_PDF_CSS)],
    )

    logger.info("PDF report written to %s", output_path)
    return output_path


def _inline_local_images(html_body: str, result: InvestigationResult) -> str:
    """Resolve local ``<img>`` ``src`` paths to ``data:`` base64 URIs.

    Scans the rendered HTML for ``<img>`` tags whose ``src`` points to a
    local file path (absolute or relative to the investigation directory).
    Each matching file is base64-encoded in-place so the screenshot
    appears exactly where it was referenced in the template.

    Args:
        html_body: HTML string from the markdown renderer.
        result: The investigation result (provides ``output_path``).

    Returns:
        HTML string with local images replaced by data URIs.
    """
    img_pattern = re.compile(r'(<img\s[^>]*src=")([^"]+)("[^>]*>)', re.IGNORECASE)

    def _replace_src(match: re.Match[str]) -> str:
        """Replace a single <img> src with its base64-encoded data URI."""
        prefix, src, suffix = match.group(1), match.group(2), match.group(3)
        # Skip already-inlined data URIs
        if src.startswith("data:"):
            return match.group(0)
        path = _resolve_local_path(src, result)
        if path is None:
            return match.group(0)
        try:
            b64 = base64.b64encode(path.read_bytes()).decode("ascii")
            ext = path.suffix.lstrip(".")
            mime = f"image/{ext}" if ext in ("png", "jpeg", "jpg", "webp", "gif") else "image/png"
            logger.debug("Inlined local image %s (%d KB)", path.name, path.stat().st_size // 1024)
            return f'{prefix}data:{mime};base64,{b64}{suffix}'
        except Exception as exc:
            logger.warning("Failed to inline image %s: %s", src, exc)
            return match.group(0)

    return img_pattern.sub(_replace_src, html_body)


def _build_evidence_appendices_html(result: InvestigationResult) -> str:
    """Build appendix pages for all embeddable evidence artifacts.

    Each appendix has:

    - A stable ``id`` anchor so the Evidence Artifacts table can link to it.
    - A "↑ Back to Evidence Artifacts" link to return to the main report.
    - A page-break before each appendix for clean pagination.

    Appendices generated (when data is available):

    - **A** — Screenshot
    - **B** — DOM Snapshot
    - **C** — Investigation Summary (JSON)
    - **D** — Network Activity (HAR summary)
    - **E** — Wallet Manifest
    - **F** — STIX IOC Bundle

    Args:
        result: The investigation result with evidence paths.

    Returns:
        HTML string to append after the main report body.
    """
    sections: list[str] = []

    _append_screenshot_appendix(sections, result)
    _append_dom_appendix(sections, result)
    _append_investigation_json_appendix(sections, result)
    _append_har_summary_appendix(sections, result)
    _append_wallet_manifest_appendix(sections, result)
    _append_stix_bundle_appendix(sections, result)

    return "\n".join(sections)


def _append_screenshot_appendix(
    sections: list[str], result: InvestigationResult
) -> None:
    """Appendix A: Full-page screenshot of the target site."""
    screenshot_path = _resolve_evidence_path(result, "screenshot_path")
    if not screenshot_path or not screenshot_path.exists():
        return
    size_kb = screenshot_path.stat().st_size / 1024
    sections.append(
        '<div style="page-break-before: always;" id="appendix-screenshot">'
        '<a class="back-link" href="#evidence-artifacts">↑ Back to Evidence Artifacts</a>'
        "<h2>Appendix A: Screenshot</h2>"
        f"<p><em>Full-page screenshot of target site ({size_kb:.0f} KB)</em></p>"
        f'<img src="{screenshot_path}" '
        f'style="max-width:100%; border:1px solid #ddd;" '
        f'alt="Screenshot of {result.url}" />'
        "</div>"
    )
    logger.debug("Added screenshot appendix (%s KB)", f"{size_kb:.0f}")


def _append_dom_appendix(
    sections: list[str], result: InvestigationResult
) -> None:
    """Appendix B: DOM snapshot (HTML source at time of capture)."""
    dom_path = _resolve_evidence_path(result, "dom_snapshot_path")
    if not dom_path or not dom_path.exists():
        return
    try:
        dom_text = dom_path.read_text(errors="replace")
        dom_lines = dom_text.splitlines()
        truncated = len(dom_lines) > 500
        if truncated:
            dom_lines = dom_lines[:500]
            dom_text = (
                "\n".join(dom_lines)
                + "\n\n… (truncated — see dom_snapshot.html in evidence ZIP)"
            )
        else:
            dom_text = "\n".join(dom_lines)

        dom_escaped = html_mod.escape(dom_text)
        sections.append(
            '<div style="page-break-before: always;" id="appendix-dom">'
            '<a class="back-link" href="#evidence-artifacts">↑ Back to Evidence Artifacts</a>'
            "<h2>Appendix B: DOM Snapshot</h2>"
            "<p><em>Complete DOM of target page at time of capture"
            f'{" (first 500 lines)" if truncated else ""}'
            "</em></p>"
            '<pre style="font-size:7pt; line-height:1.3; white-space:pre-wrap; '
            'word-break:break-all; border:1px solid #ddd; padding:8pt; '
            f'background:#fafafa;">{dom_escaped}</pre>'
            "</div>"
        )
        logger.debug("Added DOM appendix (%d lines)", len(dom_lines))
    except Exception as exc:
        logger.warning("Failed to embed DOM snapshot in PDF: %s", exc)


def _append_investigation_json_appendix(
    sections: list[str], result: InvestigationResult
) -> None:
    """Appendix C: Investigation result serialized as JSON.

    Renders the full ``InvestigationResult`` model as pretty-printed JSON,
    capped at 300 lines to keep the PDF manageable.
    """
    try:
        data = result.model_dump(mode="json")
        # Remove bulky fields that are already shown in other appendices
        for key in ("agent_steps", "cost_summary"):
            data.pop(key, None)
        json_str = json.dumps(data, indent=2, default=str)
        json_lines = json_str.splitlines()
        truncated = len(json_lines) > 300
        if truncated:
            json_str = (
                "\n".join(json_lines[:300])
                + "\n\n… (truncated at 300 lines — full file in evidence ZIP)"
            )
        json_escaped = html_mod.escape(json_str)
        sections.append(
            '<div style="page-break-before: always;" id="appendix-investigation-json">'
            '<a class="back-link" href="#evidence-artifacts">↑ Back to Evidence Artifacts</a>'
            "<h2>Appendix C: Investigation Summary (JSON)</h2>"
            "<p><em>Machine-readable investigation result"
            f'{" (first 300 lines)" if truncated else ""}'
            "</em></p>"
            '<pre style="font-size:7pt; line-height:1.3; white-space:pre-wrap; '
            'word-break:break-all; border:1px solid #ddd; padding:8pt; '
            f'background:#fafafa;">{json_escaped}</pre>'
            "</div>"
        )
        logger.debug("Added investigation JSON appendix")
    except Exception as exc:
        logger.warning("Failed to build investigation JSON appendix: %s", exc)


def _append_har_summary_appendix(
    sections: list[str], result: InvestigationResult
) -> None:
    """Appendix D: Network activity summary from HAR capture.

    Parses the HAR file and renders a summary table of HTTP requests
    rather than the raw (potentially very large) HAR JSON.
    """
    har_path = _resolve_evidence_path(result, "har_path")
    if not har_path or not har_path.exists():
        return
    try:
        har_data = json.loads(har_path.read_text(errors="replace"))
        entries = har_data.get("log", {}).get("entries", [])
        if not entries:
            return

        # Aggregate stats
        domains: dict[str, int] = {}
        total_size = 0
        status_groups: dict[str, int] = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "other": 0}

        for entry in entries:
            req = entry.get("request", {})
            resp = entry.get("response", {})
            url = req.get("url", "")
            try:
                domain = urlparse(url).netloc
            except Exception:
                domain = "unknown"
            domains[domain] = domains.get(domain, 0) + 1
            size = resp.get("content", {}).get("size", 0)
            if isinstance(size, (int, float)) and size > 0:
                total_size += int(size)
            status = resp.get("status", 0)
            if 200 <= status < 300:
                status_groups["2xx"] += 1
            elif 300 <= status < 400:
                status_groups["3xx"] += 1
            elif 400 <= status < 500:
                status_groups["4xx"] += 1
            elif status >= 500:
                status_groups["5xx"] += 1
            else:
                status_groups["other"] += 1

        # Build summary HTML
        summary_rows = (
            f"<tr><td><strong>Total Requests</strong></td><td>{len(entries)}</td></tr>"
            f"<tr><td><strong>Unique Domains</strong></td><td>{len(domains)}</td></tr>"
            f"<tr><td><strong>Total Response Size</strong></td><td>{total_size:,} bytes</td></tr>"
            f'<tr><td><strong>Status Codes</strong></td><td>'
            f'{status_groups["2xx"]} ok, {status_groups["3xx"]} redirect, '
            f'{status_groups["4xx"]} client err, {status_groups["5xx"]} server err'
            f"</td></tr>"
        )

        # Domain breakdown
        sorted_domains = sorted(domains.items(), key=lambda x: x[1], reverse=True)[:15]
        domain_rows = "".join(
            f"<tr><td><code>{html_mod.escape(d)}</code></td><td>{c}</td></tr>"
            for d, c in sorted_domains
        )
        if len(domains) > 15:
            domain_rows += (
                f'<tr><td colspan="2"><em>… and {len(domains) - 15} more domains</em></td></tr>'
            )

        # First 30 request entries
        entry_rows = ""
        for i, entry in enumerate(entries[:30]):
            req = entry.get("request", {})
            resp = entry.get("response", {})
            method = html_mod.escape(req.get("method", "?"))
            url_raw = req.get("url", "")
            url_display = html_mod.escape(url_raw[:80] + ("…" if len(url_raw) > 80 else ""))
            status = resp.get("status", 0)
            size = resp.get("content", {}).get("size", 0)
            size_display = f"{size:,}" if isinstance(size, (int, float)) and size > 0 else "—"
            entry_rows += (
                f"<tr><td>{i + 1}</td><td>{method}</td><td><code>{url_display}</code></td>"
                f"<td>{status}</td><td>{size_display}</td></tr>"
            )
        if len(entries) > 30:
            entry_rows += (
                f'<tr><td colspan="5"><em>… and {len(entries) - 30} more requests '
                f"(see network.har in evidence ZIP)</em></td></tr>"
            )

        sections.append(
            '<div style="page-break-before: always;" id="appendix-har-summary">'
            '<a class="back-link" href="#evidence-artifacts">↑ Back to Evidence Artifacts</a>'
            "<h2>Appendix D: Network Activity</h2>"
            "<p><em>Summary of HTTP traffic captured during investigation</em></p>"
            f'<table><tr><th>Metric</th><th>Value</th></tr>{summary_rows}</table>'
            "<h3>Domains Contacted</h3>"
            f'<table><tr><th>Domain</th><th>Requests</th></tr>{domain_rows}</table>'
            "<h3>Request Log</h3>"
            f'<table><tr><th>#</th><th>Method</th><th>URL</th><th>Status</th><th>Size</th></tr>'
            f"{entry_rows}</table>"
            "</div>"
        )
        logger.debug("Added HAR summary appendix (%d entries)", len(entries))
    except Exception as exc:
        logger.warning("Failed to build HAR summary appendix: %s", exc)


def _append_wallet_manifest_appendix(
    sections: list[str], result: InvestigationResult
) -> None:
    """Appendix E: Wallet manifest (structured JSON of extracted wallets).

    Constructs the same manifest data that the orchestrator writes to
    ``wallet_manifest.json``, so the appendix is available even before
    the file has been written to disk.
    """
    if not result.wallets:
        return
    try:
        networks: set[str] = set()
        tokens: set[str] = set()
        wallets_data: list[dict[str, Any]] = []
        for w in result.wallets:
            wallets_data.append({
                "token_symbol": w.token_symbol,
                "token_label": w.token_label,
                "network_short": w.network_short,
                "network_label": w.network_label,
                "wallet_address": w.wallet_address,
                "source": w.source,
                "confidence": w.confidence,
                "harvested_at": w.harvested_at.isoformat() if w.harvested_at else None,
                "site_url": w.site_url,
            })
            if w.network_short:
                networks.add(w.network_short)
            if w.token_symbol:
                tokens.add(w.token_symbol)

        manifest = {
            "investigation_id": str(result.investigation_id),
            "target_url": result.url,
            "wallet_count": len(wallets_data),
            "unique_networks": sorted(networks),
            "unique_tokens": sorted(tokens),
            "wallets": wallets_data,
        }
        json_str = json.dumps(manifest, indent=2, default=str)
        json_escaped = html_mod.escape(json_str)
        sections.append(
            '<div style="page-break-before: always;" id="appendix-wallet-manifest">'
            '<a class="back-link" href="#evidence-artifacts">↑ Back to Evidence Artifacts</a>'
            "<h2>Appendix E: Wallet Manifest</h2>"
            f"<p><em>Machine-readable manifest of {len(wallets_data)} cryptocurrency wallet(s) "
            "extracted during investigation</em></p>"
            '<pre style="font-size:7pt; line-height:1.3; white-space:pre-wrap; '
            'word-break:break-all; border:1px solid #ddd; padding:8pt; '
            f'background:#fafafa;">{json_escaped}</pre>'
            "</div>"
        )
        logger.debug("Added wallet manifest appendix (%d wallets)", len(wallets_data))
    except Exception as exc:
        logger.warning("Failed to build wallet manifest appendix: %s", exc)


def _append_stix_bundle_appendix(
    sections: list[str], result: InvestigationResult
) -> None:
    """Appendix F: STIX 2.1 IOC bundle for threat intelligence sharing.

    Generates the STIX bundle from the investigation result (same data
    the orchestrator writes to ``stix_bundle.json``), formatted as JSON
    and capped at 300 lines.
    """
    if not result.threat_indicators:
        return
    try:
        from ssi.evidence.stix import investigation_to_stix_bundle

        bundle = investigation_to_stix_bundle(result)
        json_str = json.dumps(bundle, indent=2, default=str)
        json_lines = json_str.splitlines()
        truncated = len(json_lines) > 300
        if truncated:
            json_str = (
                "\n".join(json_lines[:300])
                + "\n\n… (truncated at 300 lines — full file in evidence ZIP)"
            )
        json_escaped = html_mod.escape(json_str)
        obj_count = len(bundle.get("objects", []))
        sections.append(
            '<div style="page-break-before: always;" id="appendix-stix-bundle">'
            '<a class="back-link" href="#evidence-artifacts">↑ Back to Evidence Artifacts</a>'
            "<h2>Appendix F: STIX 2.1 IOC Bundle</h2>"
            f"<p><em>Threat intelligence bundle with {obj_count} STIX object(s)"
            f'{" (first 300 lines)" if truncated else ""}'
            "</em></p>"
            '<pre style="font-size:7pt; line-height:1.3; white-space:pre-wrap; '
            'word-break:break-all; border:1px solid #ddd; padding:8pt; '
            f'background:#fafafa;">{json_escaped}</pre>'
            "</div>"
        )
        logger.debug("Added STIX bundle appendix (%d objects)", obj_count)
    except ImportError:
        logger.debug("STIX module not available — skipping appendix")
    except Exception as exc:
        logger.warning("Failed to build STIX bundle appendix: %s", exc)


# Keep legacy names for backwards compatibility
_build_embedded_evidence_html = _build_evidence_appendices_html
_build_dom_appendix_html = _build_evidence_appendices_html


def _resolve_local_path(src: str, result: InvestigationResult) -> Path | None:
    """Resolve a local file path from an ``<img>`` ``src`` attribute.

    Checks whether ``src`` is an absolute path that exists or can be
    resolved relative to the investigation's output directory.

    Args:
        src: The ``src`` attribute value (file path or URL).
        result: The investigation result (provides ``output_path``).

    Returns:
        Resolved ``Path`` if the file exists locally, else ``None``.
    """
    # Ignore URLs
    if src.startswith(("http://", "https://", "data:")):
        return None

    path = Path(src)
    if path.is_absolute() and path.exists():
        return path

    if result.output_path:
        candidate = Path(result.output_path) / path
        if candidate.exists():
            return candidate

    return path if path.exists() else None


def _resolve_evidence_path(result: InvestigationResult, attr: str) -> Path | None:
    """Resolve an evidence file path from the result's page snapshot.

    Tries the attribute on ``page_snapshot``, then checks if the path is
    absolute or relative to the investigation output directory.

    Args:
        result: The investigation result.
        attr: Attribute name on ``page_snapshot`` (e.g. ``"screenshot_path"``).

    Returns:
        Resolved ``Path`` or ``None`` if not available.
    """
    if not result.page_snapshot:
        return None

    raw_path = getattr(result.page_snapshot, attr, "")
    if not raw_path:
        return None

    return _resolve_local_path(raw_path, result)
