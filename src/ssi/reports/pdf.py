"""PDF report generation for SSI investigations.

Renders an investigation result to a styled PDF using markdown → HTML → PDF
pipeline with ``markdown`` and ``weasyprint`` libraries.
"""

from __future__ import annotations

import logging
from pathlib import Path

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
"""


def render_pdf_report(
    result: InvestigationResult,
    output_path: Path,
    markdown_content: str | None = None,
) -> Path:
    """Render an investigation result to a styled PDF.

    If ``markdown_content`` is provided, it is used directly. Otherwise,
    the markdown report is generated from the Jinja2 template first.

    Args:
        result: The investigation result to render.
        output_path: Path for the output PDF file.
        markdown_content: Pre-rendered markdown (optional).

    Returns:
        The path to the written PDF file.
    """
    import markdown
    from weasyprint import CSS, HTML

    if markdown_content is None:
        from ssi.reports import render_markdown_report

        markdown_content = render_markdown_report(result)

    # Convert markdown to HTML
    html_body = markdown.markdown(
        markdown_content,
        extensions=["tables", "fenced_code", "attr_list"],
    )

    full_html = f"""\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>SSI Investigation Report — {result.investigation_id}</title>
</head>
<body>
{html_body}
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
