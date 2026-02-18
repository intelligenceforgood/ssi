#!/usr/bin/env python3
"""Phase 2 Campaign Runner — Systematic investigation across scam URL types.

Executes investigations against a curated set of test URLs organized by
scam type.  Produces per-URL evidence directories, an aggregate summary,
and a campaign report suitable for go/no-go decisions.

Usage:
    # Run all safe test URLs (default — no real scam sites)
    conda run -n i4g-ssi python scripts/campaign_runner.py

    # Run a single URL
    conda run -n i4g-ssi python scripts/campaign_runner.py --url "https://example.com"

    # Run with active agent (requires Ollama)
    conda run -n i4g-ssi python scripts/campaign_runner.py --active

    # Load URLs from a file
    conda run -n i4g-ssi python scripts/campaign_runner.py --url-file urls.txt

    # Only run a specific scam category
    conda run -n i4g-ssi python scripts/campaign_runner.py --category phishing

Prerequisites:
    - Playwright browsers: playwright install chromium
    - For active mode: Ollama running with llama3.3
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from ssi.investigator.orchestrator import run_investigation

console = Console()

# ---------------------------------------------------------------------------
# Curated test URL catalog — organized by scam type
# ---------------------------------------------------------------------------
# NOTE: These are SAFE, legitimate sites used to validate investigator
# behavior.  They simulate scam-like patterns (forms, redirects, downloads)
# without actually being malicious.  Real scam URLs should be loaded from
# an external file (--url-file) and handled with appropriate caution.

SCAM_TYPE_CATALOG: dict[str, list[dict[str, str]]] = {
    "phishing": [
        {
            "url": "https://the-internet.herokuapp.com/login",
            "description": "Login form — simulates credential phishing",
        },
        {
            "url": "https://httpbin.org/forms/post",
            "description": "Multi-field form — simulates data harvesting",
        },
        {
            "url": "https://www.phishtank.com/",
            "description": "PhishTank homepage — validates domain recon",
        },
    ],
    "tech_support": [
        {
            "url": "https://the-internet.herokuapp.com/javascript_alerts",
            "description": "JS alerts — simulates tech-support popup scam",
        },
        {
            "url": "https://the-internet.herokuapp.com/windows",
            "description": "Multiple windows — simulates popup chains",
        },
    ],
    "fake_shopping": [
        {
            "url": "https://demoqa.com/automation-practice-form",
            "description": "Complex form — simulates fake checkout flow",
        },
        {
            "url": "https://demoqa.com/text-box",
            "description": "Personal info form — simulates PII harvesting",
        },
    ],
    "investment_crypto": [
        {
            "url": "https://httpbin.org/anything",
            "description": "Echo endpoint — validates request capture",
        },
        {
            "url": "https://the-internet.herokuapp.com/redirect",
            "description": "Redirect chain — simulates redirect laundering",
        },
    ],
    "download_malware": [
        {
            "url": "https://the-internet.herokuapp.com/download",
            "description": "File download page — validates download interception",
        },
        {
            "url": "https://httpbin.org/response-headers?Content-Disposition=attachment;filename=test.txt",
            "description": "Header-triggered download — tests content-disposition detection",
        },
    ],
    "redirect_chains": [
        {
            "url": "https://the-internet.herokuapp.com/redirector",
            "description": "Multi-hop redirect — validates chain tracking",
        },
        {
            "url": "https://httpbin.org/redirect/3",
            "description": "3-hop redirect — validates redirect counting",
        },
    ],
    "form_harvesting": [
        {
            "url": "https://demoqa.com/automation-practice-form",
            "description": "Full PII form — validates form field inventory",
        },
        {
            "url": "https://the-internet.herokuapp.com/forgot_password",
            "description": "Email form — simulates account recovery phish",
        },
        {
            "url": "https://the-internet.herokuapp.com/inputs",
            "description": "Number input — validates diverse field types",
        },
        {
            "url": "https://demoqa.com/text-box",
            "description": "Text box form — validates label extraction",
        },
    ],
}


def get_all_urls(category: str | None = None) -> list[dict[str, str]]:
    """Return all URLs from the catalog, optionally filtered by category."""
    if category:
        urls = SCAM_TYPE_CATALOG.get(category, [])
        for u in urls:
            u["category"] = category
        return urls

    all_urls = []
    for cat, urls in SCAM_TYPE_CATALOG.items():
        for u in urls:
            u["category"] = cat
        all_urls.extend(urls)
    return all_urls


def run_campaign(
    urls: list[dict[str, str]],
    output_dir: Path,
    passive_only: bool = True,
    skip_whois: bool = True,
    skip_virustotal: bool = True,
    skip_urlscan: bool = True,
) -> dict:
    """Execute investigations for all URLs and produce a campaign summary.

    Args:
        urls: List of URL dicts with ``url``, ``description``, ``category`` keys.
        output_dir: Root directory for campaign evidence.
        passive_only: Skip AI agent interaction when True.
        skip_whois: Skip WHOIS lookups (faster for batch testing).
        skip_virustotal: Skip VirusTotal checks.
        skip_urlscan: Skip urlscan.io checks.

    Returns:
        Campaign summary dict.
    """
    campaign_id = str(uuid4())[:8]
    campaign_dir = output_dir / f"campaign_{campaign_id}"
    campaign_dir.mkdir(parents=True, exist_ok=True)

    results = []
    start_time = time.monotonic()

    console.print(Panel(f"[bold]SSI Campaign[/bold] — {len(urls)} URLs", title="Campaign", border_style="blue"))

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        for i, url_entry in enumerate(urls, 1):
            url = url_entry["url"]
            category = url_entry.get("category", "unknown")
            task = progress.add_task(f"[{i}/{len(urls)}] {category}: {url[:60]}...", total=None)

            try:
                result = run_investigation(
                    url=url,
                    output_dir=campaign_dir,
                    passive_only=passive_only,
                    skip_whois=skip_whois,
                    skip_virustotal=skip_virustotal,
                    skip_urlscan=skip_urlscan,
                    report_format="both",
                )

                results.append({
                    "url": url,
                    "category": category,
                    "description": url_entry.get("description", ""),
                    "status": result.status.value,
                    "success": result.success,
                    "duration_s": round(result.duration_seconds, 1),
                    "threat_indicators": len(result.threat_indicators),
                    "downloads": len(result.downloads),
                    "form_fields": (
                        len(result.page_snapshot.form_fields) if result.page_snapshot else 0
                    ),
                    "redirect_hops": (
                        len(result.page_snapshot.redirect_chain) if result.page_snapshot else 0
                    ),
                    "investigation_id": str(result.investigation_id),
                    "error": result.error,
                })

            except Exception as e:
                results.append({
                    "url": url,
                    "category": category,
                    "description": url_entry.get("description", ""),
                    "status": "error",
                    "success": False,
                    "duration_s": 0,
                    "threat_indicators": 0,
                    "downloads": 0,
                    "form_fields": 0,
                    "redirect_hops": 0,
                    "investigation_id": "",
                    "error": str(e),
                })

            progress.update(task, completed=True)

    total_time = time.monotonic() - start_time

    # Build summary
    summary = {
        "campaign_id": campaign_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_urls": len(urls),
        "successful": sum(1 for r in results if r["success"]),
        "failed": sum(1 for r in results if not r["success"]),
        "total_duration_s": round(total_time, 1),
        "passive_only": passive_only,
        "results": results,
    }

    # Write summary JSON
    summary_path = campaign_dir / "campaign_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2))

    # Print results table
    _print_summary_table(summary)

    return summary


def _print_summary_table(summary: dict) -> None:
    """Print a rich table summarizing campaign results."""
    table = Table(title=f"Campaign {summary['campaign_id']} — Results")
    table.add_column("#", style="dim")
    table.add_column("Category", style="cyan")
    table.add_column("URL", max_width=45)
    table.add_column("Status", justify="center")
    table.add_column("Time", justify="right")
    table.add_column("Indicators", justify="center")
    table.add_column("Forms", justify="center")
    table.add_column("Downloads", justify="center")

    for i, r in enumerate(summary["results"], 1):
        status_style = "green" if r["success"] else "red"
        table.add_row(
            str(i),
            r["category"],
            r["url"][:45],
            f"[{status_style}]{r['status']}[/{status_style}]",
            f"{r['duration_s']}s",
            str(r["threat_indicators"]),
            str(r["form_fields"]),
            str(r["downloads"]),
        )

    console.print(table)
    console.print(
        f"\n[bold]Summary:[/bold] {summary['successful']}/{summary['total_urls']} succeeded "
        f"in {summary['total_duration_s']}s"
    )

    pass_rate = summary["successful"] / max(summary["total_urls"], 1)
    threshold = 0.6
    if pass_rate >= threshold:
        console.print(f"[green bold]GO[/green bold] — Pass rate {pass_rate:.0%} ≥ {threshold:.0%} threshold")
    else:
        console.print(f"[red bold]NO-GO[/red bold] — Pass rate {pass_rate:.0%} < {threshold:.0%} threshold")


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="SSI Phase 2 Campaign Runner")
    parser.add_argument("--url", help="Single URL to investigate")
    parser.add_argument("--url-file", help="File with URLs (one per line, optional #comment)")
    parser.add_argument("--category", help="Only run URLs from this scam category")
    parser.add_argument("--active", action="store_true", help="Enable AI agent (requires Ollama)")
    parser.add_argument("--output", default="data/evidence/campaigns", help="Output directory")
    parser.add_argument("--with-whois", action="store_true", help="Enable WHOIS lookups")
    parser.add_argument("--with-virustotal", action="store_true", help="Enable VirusTotal checks")
    parser.add_argument("--with-urlscan", action="store_true", help="Enable urlscan.io checks")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    # Build URL list
    if args.url:
        urls = [{"url": args.url, "description": "Ad-hoc URL", "category": "adhoc"}]
    elif args.url_file:
        url_path = Path(args.url_file)
        if not url_path.exists():
            console.print(f"[red]File not found:[/red] {url_path}")
            sys.exit(1)
        urls = []
        for line in url_path.read_text().splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                parts = stripped.split("|", 2)
                url = parts[0].strip()
                category = parts[1].strip() if len(parts) > 1 else "unknown"
                desc = parts[2].strip() if len(parts) > 2 else ""
                urls.append({"url": url, "description": desc, "category": category})
        console.print(f"Loaded {len(urls)} URLs from {url_path}")
    else:
        urls = get_all_urls(category=args.category)

    if not urls:
        console.print("[yellow]No URLs to investigate.[/yellow]")
        sys.exit(0)

    console.print(f"[bold]{len(urls)} URLs[/bold] across categories: "
                   f"{', '.join(sorted({u.get('category', '?') for u in urls}))}")

    run_campaign(
        urls=urls,
        output_dir=Path(args.output),
        passive_only=not args.active,
        skip_whois=not args.with_whois,
        skip_virustotal=not args.with_virustotal,
        skip_urlscan=not args.with_urlscan,
    )


if __name__ == "__main__":
    main()
