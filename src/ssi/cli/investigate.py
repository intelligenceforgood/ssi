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
    format: str = typer.Option("json", "--format", "-f", help="Output format: json, markdown, or both."),
) -> None:
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
        )
        progress.update(task, completed=True)

    if result.success:
        console.print(f"\n[green]✓[/green] Investigation complete: {result.investigation_id}")
        console.print(f"  Evidence saved to: {result.output_path}")
        if result.classification:
            console.print(f"  Classification: {result.classification}")
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
