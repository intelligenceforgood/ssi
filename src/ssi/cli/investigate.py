"""CLI commands for investigating suspicious URLs."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

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

    if result.success:
        console.print(f"\n[green]✓[/green] Investigation complete: {result.investigation_id}")
        console.print(f"  Evidence saved to: {result.output_path}")
        if result.taxonomy_result:
            console.print(f"  Risk score: {result.taxonomy_result.risk_score:.1f}/100")
            if result.taxonomy_result.intent:
                intents = ", ".join(f"{l.label} ({l.confidence:.0%})" for l in result.taxonomy_result.intent)
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
    file: Path = typer.Argument(..., help="File containing URLs to investigate (one per line)."),
    output_dir: Optional[Path] = typer.Option(None, "--output", "-o", help="Directory for evidence output."),
    passive_only: bool = typer.Option(False, "--passive", help="Run passive reconnaissance only."),
) -> None:
    """Investigate multiple URLs from a file."""
    if not file.exists():
        console.print(f"[red]File not found:[/red] {file}")
        raise typer.Exit(code=1)

    urls = [line.strip() for line in file.read_text().splitlines() if line.strip() and not line.startswith("#")]
    console.print(f"Loaded {len(urls)} URLs from {file}")

    for i, url in enumerate(urls, 1):
        console.print(f"\n[{i}/{len(urls)}] {url}")
        investigate_url(url=url, output_dir=output_dir, passive_only=passive_only)


def _push_to_core_cli(result, *, trigger_dossier: bool = False) -> None:
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
