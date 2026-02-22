"""CLI commands for investigating suspicious URLs."""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Any, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

investigate_app = typer.Typer(help="Investigate suspicious URLs for scam intelligence.")
console = Console()


@investigate_app.command("url")
def investigate_url(
    url: str = typer.Argument(..., help="The suspicious URL to investigate."),
    output_dir: Optional[Path] = typer.Option(None, "--output", "-o", help="Directory for evidence output."),
    passive_only: bool = typer.Option(False, "--passive", help="Run passive reconnaissance only (no site interaction)."),
    skip_whois: bool = typer.Option(False, "--skip-whois", help="Skip WHOIS/RDAP lookup."),
    skip_screenshot: bool = typer.Option(False, "--skip-screenshot", help="Skip screenshot capture."),
    skip_virustotal: bool = typer.Option(False, "--skip-virustotal", help="Skip VirusTotal check."),
    skip_urlscan: bool = typer.Option(False, "--skip-urlscan", help="Skip urlscan.io check."),
    format: str = typer.Option("json", "--format", "-f", help="Output format: json, markdown, or both."),    push_to_core: bool = typer.Option(False, "--push-to-core", help="Push results to i4g core platform."),
    trigger_dossier: bool = typer.Option(False, "--trigger-dossier", help="Queue dossier generation after push."),) -> None:
    """Run a full investigation against a suspicious URL.

    Performs passive reconnaissance (WHOIS, DNS, SSL, GeoIP, technology fingerprinting,
    screenshot capture, form inventory) and optionally active interaction via AI agent.
    """
    from ssi.investigator.orchestrator import run_investigation
    from ssi.settings import get_settings

    settings = get_settings()
    effective_output = output_dir or Path(settings.evidence.output_dir)
    effective_output.mkdir(parents=True, exist_ok=True)

    console.print(Panel(f"[bold]Investigating:[/bold] {url}", title="SSI", border_style="blue"))

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task("Running investigation...", total=None)
        result = run_investigation(
            url=url,
            output_dir=effective_output,
            passive_only=passive_only,
            skip_whois=skip_whois,
            skip_screenshot=skip_screenshot,
            skip_virustotal=skip_virustotal,
            skip_urlscan=skip_urlscan,
            report_format=format,
        )
        progress.update(task, completed=True)

    # Display warnings before success/failure status
    if result.warnings:
        for warning in result.warnings:
            console.print(f"\n[yellow]⚠[/yellow] {warning}")

    if result.success:
        console.print(f"\n[green]✓[/green] Investigation complete: {result.investigation_id}")
        console.print(f"  Evidence saved to: {result.output_path}")
        if result.taxonomy_result:
            console.print(f"  Risk score: {result.taxonomy_result.risk_score:.1f}/100")
            if result.taxonomy_result.intent:
                from ssi.classification.labels import get_display_label

                intents = ", ".join(
                    f"{get_display_label(l.label)} ({l.confidence:.0%})" for l in result.taxonomy_result.intent
                )
                console.print(f"  Intent: {intents}")
        elif result.classification:
            console.print(f"  Classification: {result.classification}")
        if result.evidence_zip_path:
            console.print(f"  Evidence ZIP: {result.evidence_zip_path}")
        if result.chain_of_custody:
            console.print(f"  Artifacts: {result.chain_of_custody.total_artifacts} files")

        # Push to core if requested
        if push_to_core:
            _push_to_core_cli(result, trigger_dossier=trigger_dossier)
    else:
        console.print(f"\n[red]✗[/red] Investigation failed: {result.error}")
        raise typer.Exit(code=1)


@investigate_app.command("batch")
def investigate_batch(
    file: Path = typer.Argument(..., help="File with URLs (plain text) or JSON batch manifest."),
    output_dir: Optional[Path] = typer.Option(None, "--output", "-o", help="Directory for evidence output."),
    passive_only: bool = typer.Option(False, "--passive", help="Run passive reconnaissance only."),
    format: str = typer.Option("text", "--format", "-f", help="Input format: text (one URL per line) or json."),
    concurrency: int = typer.Option(1, "--concurrency", "-c", min=1, max=10, help="Max concurrent investigations."),
    events: bool = typer.Option(False, "--events", help="Emit JSONL events to stderr."),
    resume: bool = typer.Option(False, "--resume", help="Skip URLs whose output dirs already exist."),
    push_to_core: bool = typer.Option(False, "--push-to-core", help="Push results to i4g core platform."),
    trigger_dossier: bool = typer.Option(False, "--trigger-dossier", help="Queue dossier generation after push."),
) -> None:
    """Investigate multiple URLs from a file.

    Supports plain text (one URL per line, ``#`` for comments) or structured
    JSON input with per-URL options.

    JSON format example::

        [
          {"url": "https://example.com", "passive_only": false, "tags": ["crypto"]},
          {"url": "https://scam.site", "playbook_override": "okdc_cluster_v1"}
        ]
    """
    if not file.exists():
        console.print(f"[red]File not found:[/red] {file}")
        raise typer.Exit(code=1)

    entries = _load_batch_entries(file, format, passive_only)
    if not entries:
        console.print("[yellow]No URLs to process.[/yellow]")
        raise typer.Exit(code=0)

    console.print(f"Loaded {len(entries)} URL(s) from {file}  (concurrency={concurrency})")

    if concurrency > 1:
        results = asyncio.run(
            _run_batch_async(
                entries,
                output_dir=output_dir,
                concurrency=concurrency,
                events=events,
                resume=resume,
                push_to_core=push_to_core,
                trigger_dossier=trigger_dossier,
            )
        )
    else:
        results = _run_batch_sync(
            entries,
            output_dir=output_dir,
            events=events,
            resume=resume,
            push_to_core=push_to_core,
            trigger_dossier=trigger_dossier,
        )

    # Summary
    succeeded = sum(1 for r in results if r.get("success"))
    failed = sum(1 for r in results if not r.get("success"))
    skipped = sum(1 for r in results if r.get("skipped"))
    console.print(f"\n[bold]Batch complete:[/bold] {succeeded} succeeded, {failed} failed, {skipped} skipped")

    if failed:
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# ssi investigate list
# ---------------------------------------------------------------------------


@investigate_app.command("list")
def investigate_list(
    domain: Optional[str] = typer.Option(None, "--domain", "-d", help="Filter by domain."),
    status: Optional[str] = typer.Option(None, "--status", "-s", help="Filter by status (running, completed, failed)."),
    limit: int = typer.Option(20, "--limit", "-n", help="Max results to return."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """List past investigations from the scan store."""
    from ssi.store import build_scan_store

    try:
        store = build_scan_store()
    except Exception as e:
        console.print(f"[red]Cannot connect to scan store:[/red] {e}")
        raise typer.Exit(code=1) from None

    scans = store.list_scans(domain=domain, status=status, limit=limit)

    if not scans:
        console.print("[dim]No investigations found.[/dim]")
        return

    if json_output:
        console.print_json(json.dumps(scans, indent=2, default=str))
        return

    table = Table(title="Investigations")
    table.add_column("Scan ID", style="cyan", max_width=12)
    table.add_column("URL", max_width=50)
    table.add_column("Status")
    table.add_column("Type")
    table.add_column("Created", style="dim")

    for scan in scans:
        scan_id = scan.get("scan_id", "")[:12]
        url = scan.get("url", "")
        st = scan.get("status", "")
        style = {"completed": "[green]", "running": "[yellow]", "failed": "[red]"}.get(st, "")
        table.add_row(
            scan_id,
            url[:50],
            f"{style}{st}[/{style[1:]}" if style else st,
            scan.get("scan_type", ""),
            str(scan.get("created_at", ""))[:19],
        )

    console.print(table)
    console.print(f"\n[bold]{len(scans)}[/bold] result(s)")


# ---------------------------------------------------------------------------
# ssi investigate show <id>
# ---------------------------------------------------------------------------


@investigate_app.command("show")
def investigate_show(
    scan_id: str = typer.Argument(..., help="Scan ID (or prefix) to display."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
    wallets: bool = typer.Option(False, "--wallets", "-w", help="Include extracted wallets."),
) -> None:
    """Display detailed results of a past investigation."""
    from ssi.store import build_scan_store

    try:
        store = build_scan_store()
    except Exception as e:
        console.print(f"[red]Cannot connect to scan store:[/red] {e}")
        raise typer.Exit(code=1) from None

    scan = store.get_scan(scan_id)
    if not scan:
        # Try prefix match
        all_scans = store.list_scans(limit=200)
        matches = [s for s in all_scans if s.get("scan_id", "").startswith(scan_id)]
        if len(matches) == 1:
            scan = matches[0]
            scan_id = scan["scan_id"]
        elif len(matches) > 1:
            console.print(f"[yellow]Ambiguous prefix — {len(matches)} matches:[/yellow]")
            for m in matches[:5]:
                console.print(f"  {m['scan_id'][:12]}  {m.get('url', '')}")
            raise typer.Exit(code=1)
        else:
            console.print(f"[red]Scan not found:[/red] {scan_id}")
            raise typer.Exit(code=1)

    wallet_data = store.get_wallets(scan_id) if wallets else []
    pii_data = store.get_pii_exposures(scan_id)

    if json_output:
        output: dict[str, Any] = {"scan": scan}
        if wallet_data:
            output["wallets"] = wallet_data
        if pii_data:
            output["pii_exposures"] = pii_data
        console.print_json(json.dumps(output, indent=2, default=str))
        return

    console.print(Panel(f"[bold]{scan.get('url', '')}[/bold]", title=f"Scan {scan_id[:12]}", border_style="blue"))
    console.print(f"  Status:    {scan.get('status', '')}")
    console.print(f"  Type:      {scan.get('scan_type', '')}")
    console.print(f"  Domain:    {scan.get('domain', '')}")
    console.print(f"  Created:   {scan.get('created_at', '')}")
    if scan.get("completed_at"):
        console.print(f"  Completed: {scan.get('completed_at', '')}")
    if scan.get("risk_score") is not None:
        console.print(f"  Risk:      {scan.get('risk_score')}")
    if scan.get("case_id"):
        console.print(f"  Case ID:   {scan.get('case_id')}")

    if wallet_data:
        console.print(f"\n[bold]Wallets ({len(wallet_data)}):[/bold]")
        for w in wallet_data:
            console.print(f"  {w.get('token_symbol', '?'):6s}  {w.get('wallet_address', '')}")

    if pii_data:
        console.print(f"\n[bold]PII Exposures ({len(pii_data)}):[/bold]")
        for p in pii_data:
            console.print(f"  {p.get('field_type', '?'):20s}  {p.get('exposure_method', '')}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _push_to_core_cli(result: Any, *, trigger_dossier: bool = False) -> None:
    """Push investigation results to the i4g core platform from the CLI."""
    from ssi.integration.core_bridge import CoreBridge

    console.print("\n  Pushing to i4g core...", end="")
    try:
        bridge = CoreBridge()
        if not bridge.health_check():
            console.print(" [yellow]core API not reachable — skipped[/yellow]")
            bridge.close()
            return

        case_id = bridge.push_investigation(result, trigger_dossier=trigger_dossier)
        bridge.close()
        console.print(f" [green]✓[/green] case_id={case_id}")
    except Exception as e:
        console.print(f" [red]✗[/red] {e}")


def _load_batch_entries(file: Path, fmt: str, default_passive: bool) -> list[dict[str, Any]]:
    """Parse a batch input file into a list of investigation entries.

    Returns:
        List of dicts with at minimum ``url`` and ``passive_only`` keys.
    """
    raw = file.read_text(encoding="utf-8")

    if fmt == "json":
        data = json.loads(raw)
        if isinstance(data, list):
            entries: list[dict[str, Any]] = []
            for item in data:
                if isinstance(item, str):
                    entries.append({"url": item, "passive_only": default_passive})
                elif isinstance(item, dict) and "url" in item:
                    item.setdefault("passive_only", default_passive)
                    entries.append(item)
            return entries
        return []

    # Plain text: one URL per line, # comments
    return [
        {"url": line.strip(), "passive_only": default_passive}
        for line in raw.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def _run_single_investigation(
    entry: dict[str, Any],
    *,
    output_dir: Path | None,
    events: bool,
    push_to_core: bool,
    trigger_dossier: bool,
) -> dict[str, Any]:
    """Run a single investigation for batch mode.

    Returns:
        Dict with ``url``, ``success``, ``skipped``, ``investigation_id``, ``error``.
    """
    from ssi.investigator.orchestrator import run_investigation
    from ssi.settings import get_settings

    url = entry["url"]
    settings = get_settings()
    effective_output = output_dir or Path(settings.evidence.output_dir)
    effective_output.mkdir(parents=True, exist_ok=True)

    # Set up JSONL event sink if requested
    event_sink = None
    if events:
        from ssi.monitoring.event_bus import JsonlSink

        event_sink = JsonlSink(sys.stderr)

    start = time.monotonic()
    try:
        result = run_investigation(
            url=url,
            output_dir=effective_output,
            passive_only=entry.get("passive_only", True),
            skip_whois=entry.get("skip_whois", False),
            skip_screenshot=entry.get("skip_screenshot", False),
            skip_virustotal=entry.get("skip_virustotal", False),
            skip_urlscan=entry.get("skip_urlscan", False),
            report_format=entry.get("format", "json"),
        )

        if result.success and push_to_core:
            _push_to_core_cli(result, trigger_dossier=trigger_dossier)

        duration = time.monotonic() - start
        return {
            "url": url,
            "success": result.success,
            "skipped": False,
            "investigation_id": result.investigation_id,
            "error": result.error or "",
            "duration_sec": round(duration, 1),
        }
    except Exception as e:
        duration = time.monotonic() - start
        return {
            "url": url,
            "success": False,
            "skipped": False,
            "investigation_id": "",
            "error": str(e),
            "duration_sec": round(duration, 1),
        }


def _run_batch_sync(
    entries: list[dict[str, Any]],
    *,
    output_dir: Path | None,
    events: bool,
    resume: bool,
    push_to_core: bool,
    trigger_dossier: bool,
) -> list[dict[str, Any]]:
    """Sequential batch execution."""
    from ssi.settings import get_settings

    settings = get_settings()
    effective_output = output_dir or Path(settings.evidence.output_dir)
    results: list[dict[str, Any]] = []

    for i, entry in enumerate(entries, 1):
        url = entry["url"]
        console.print(f"\n[{i}/{len(entries)}] {url}")

        if resume and _output_exists(url, effective_output):
            console.print("  [dim]Skipped (output already exists)[/dim]")
            results.append({"url": url, "success": True, "skipped": True})
            continue

        outcome = _run_single_investigation(
            entry,
            output_dir=output_dir,
            events=events,
            push_to_core=push_to_core,
            trigger_dossier=trigger_dossier,
        )
        results.append(outcome)

        if outcome["success"]:
            console.print(f"  [green]✓[/green] {outcome['investigation_id']} ({outcome['duration_sec']}s)")
        else:
            console.print(f"  [red]✗[/red] {outcome['error']}")

    return results


async def _run_batch_async(
    entries: list[dict[str, Any]],
    *,
    output_dir: Path | None,
    concurrency: int,
    events: bool,
    resume: bool,
    push_to_core: bool,
    trigger_dossier: bool,
) -> list[dict[str, Any]]:
    """Parallel batch execution using asyncio.Semaphore.

    Each investigation runs in a thread executor since ``run_investigation``
    is synchronous.
    """
    import asyncio
    from concurrent.futures import ThreadPoolExecutor

    from ssi.settings import get_settings

    settings = get_settings()
    effective_output = output_dir or Path(settings.evidence.output_dir)

    sem = asyncio.Semaphore(concurrency)
    results: list[dict[str, Any]] = [{}] * len(entries)
    executor = ThreadPoolExecutor(max_workers=concurrency)

    async def _process(index: int, entry: dict[str, Any]) -> None:
        url = entry["url"]
        if resume and _output_exists(url, effective_output):
            console.print(f"  [{index + 1}/{len(entries)}] [dim]{url} — skipped (exists)[/dim]")
            results[index] = {"url": url, "success": True, "skipped": True}
            return

        async with sem:
            console.print(f"  [{index + 1}/{len(entries)}] {url}...")
            loop = asyncio.get_event_loop()
            outcome = await loop.run_in_executor(
                executor,
                lambda: _run_single_investigation(
                    entry,
                    output_dir=output_dir,
                    events=events,
                    push_to_core=push_to_core,
                    trigger_dossier=trigger_dossier,
                ),
            )
            results[index] = outcome

            if outcome["success"]:
                console.print(f"  [{index + 1}/{len(entries)}] [green]✓[/green] {url} ({outcome['duration_sec']}s)")
            else:
                console.print(f"  [{index + 1}/{len(entries)}] [red]✗[/red] {url}: {outcome['error']}")

    tasks = [_process(i, entry) for i, entry in enumerate(entries)]
    await asyncio.gather(*tasks, return_exceptions=True)
    executor.shutdown(wait=False)
    return results


def _output_exists(url: str, output_dir: Path) -> bool:
    """Check if an output directory already exists for this URL (for --resume)."""
    from urllib.parse import urlparse

    import re

    domain = urlparse(url).netloc
    slug = re.sub(r"[^a-z0-9]+", "-", domain.lower()).strip("-")[:60]
    if not slug:
        return False
    # Check if any subdir starts with the domain slug
    if output_dir.exists():
        for child in output_dir.iterdir():
            if child.is_dir() and child.name.startswith(slug):
                return True
    return False
