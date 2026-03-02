"""CLI commands for running SSI investigations.

Runs investigations in-process, calling the orchestrator directly.
Suitable for local development and scripting.
"""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path

import typer
from rich.console import Console

job_app = typer.Typer(help="Run SSI investigations (local or service-delegated).")
console = Console()


def _configure_logging() -> None:
    """Set up logging for CLI investigation runs."""
    log_level = "INFO"
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stderr,
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


@job_app.command("investigate")
def job_investigate(
    url: str = typer.Option(..., "--url", "-u", help="Target URL to investigate."),
    scan_type: str = typer.Option(
        "full",
        "--scan-type",
        "-t",
        help="Investigation mode: passive, active, or full.",
    ),
    passive_only: bool = typer.Option(False, "--passive", help="Shorthand for --scan-type passive."),
    push_to_core: bool = typer.Option(False, "--push-to-core", help="Create a case record in the shared database."),
    dataset: str = typer.Option("ssi", "--dataset", help="Dataset label for the core case."),
) -> None:
    """Run an SSI investigation locally (in-process).

    Calls the orchestrator directly and optionally creates a case
    record in the shared database.
    """
    _configure_logging()

    effective_scan_type = "passive" if passive_only else scan_type

    from ssi.investigator.orchestrator import run_investigation
    from ssi.settings import get_settings

    settings = get_settings()
    output_dir = Path(settings.evidence.output_dir)

    console.print(f"[bold]Investigating:[/bold] {url} (scan_type={effective_scan_type})")
    start = time.monotonic()

    result = run_investigation(
        url=url,
        output_dir=output_dir,
        scan_type=effective_scan_type,
        report_format="both",
    )

    elapsed = time.monotonic() - start

    if not result.success:
        console.print(f"[red]Investigation failed: {result.error}[/red]")
        raise typer.Exit(code=1)

    console.print(f"[green]Investigation completed in {elapsed:.1f}s[/green]")

    if push_to_core:
        from ssi.store import build_scan_store

        scan_id = str(result.investigation_id)
        try:
            store = build_scan_store()
            case_id = store.create_case_record(
                scan_id=scan_id,
                result=result,
                dataset=dataset,
            )
            if case_id:
                console.print(f"[green]Created case {case_id}[/green]")
            else:
                console.print("[yellow]Case creation returned None — check logs.[/yellow]")
        except Exception as exc:
            console.print(f"[red]Case creation failed: {exc}[/red]")

    console.print(f"[green]Done. Evidence: {result.output_path}[/green]")


@job_app.command("batch")
def job_batch(
    manifest: str = typer.Option(
        ...,
        "--manifest",
        "-m",
        help="Path to a JSON manifest (local file or gs:// URI).",
    ),
    scan_type: str = typer.Option(
        "full",
        "--scan-type",
        "-t",
        help="Default scan type for entries without one.",
    ),
    push_to_core: bool = typer.Option(False, "--push-to-core", help="Create case records in the shared database."),
    dataset: str = typer.Option("ssi", "--dataset", help="Dataset label for the core cases."),
) -> None:
    """Run batch SSI investigations from a JSON manifest (in-process).

    Reads a manifest file (local or GCS) containing URLs and processes
    each sequentially.

    Manifest format (JSON array)::

        [{"url": "https://scam1.example.com", "scan_type": "full"},
         {"url": "https://scam2.example.com"}]
    """
    _configure_logging()

    from ssi.worker.batch import load_manifest

    try:
        entries = load_manifest(manifest)
    except (FileNotFoundError, ValueError, ImportError) as exc:
        console.print(f"[red]Failed to load manifest: {exc}[/red]")
        raise typer.Exit(code=1)

    console.print(f"[bold]Batch: {len(entries)} URLs, scan_type={scan_type}[/bold]")

    from ssi.investigator.orchestrator import run_investigation
    from ssi.settings import get_settings

    settings = get_settings()
    output_dir = Path(settings.evidence.output_dir)

    succeeded = 0
    failed = 0

    for i, entry in enumerate(entries, 1):
        entry_url = entry["url"].strip()
        entry_scan_type = entry.get("scan_type", scan_type).strip().lower()
        console.print(f"[{i}/{len(entries)}] {entry_url} (scan_type={entry_scan_type})")

        try:
            result = run_investigation(
                url=entry_url,
                output_dir=output_dir,
                scan_type=entry_scan_type,
                report_format="both",
            )
            if result.success:
                succeeded += 1
                risk = result.taxonomy_result.risk_score if result.taxonomy_result else 0
                console.print(f"  [green]✓ risk={risk:.1f}[/green]")

                if push_to_core:
                    from ssi.store import build_scan_store

                    try:
                        store = build_scan_store()
                        case_id = store.create_case_record(
                            scan_id=str(result.investigation_id),
                            result=result,
                            dataset=dataset,
                        )
                        if case_id:
                            console.print(f"  [green]Case: {case_id}[/green]")
                    except Exception as exc:
                        console.print(f"  [yellow]Case creation failed: {exc}[/yellow]")
            else:
                failed += 1
                console.print(f"  [red]✗ {result.error}[/red]")
        except Exception as exc:
            failed += 1
            console.print(f"  [red]✗ {exc}[/red]")

    console.print(f"\n[bold]Batch complete: {succeeded} succeeded, {failed} failed[/bold]")
    if failed > 0:
        raise typer.Exit(code=1)
