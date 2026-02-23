"""CLI commands for running SSI as a Cloud Run Job."""

from __future__ import annotations

import os
from typing import Optional

import typer
from rich.console import Console

job_app = typer.Typer(help="Run SSI jobs (Cloud Run Job compatible).")
console = Console()


@job_app.command("investigate")
def job_investigate(
    url: str = typer.Option(..., "--url", "-u", help="Target URL to investigate.", envvar="SSI_JOB__URL"),
    scan_type: str = typer.Option(
        "full",
        "--scan-type",
        "-t",
        help="Investigation mode: passive, active, or full.",
    ),
    passive_only: bool = typer.Option(False, "--passive", help="Shorthand for --scan-type passive."),
    push_to_core: bool = typer.Option(False, "--push-to-core", help="Push results to i4g core platform."),
    trigger_dossier: bool = typer.Option(False, "--trigger-dossier", help="Queue dossier generation in core."),
    dataset: str = typer.Option("ssi", "--dataset", help="Dataset label for the core case."),
) -> None:
    """Run an SSI investigation as a job.

    Designed for Cloud Run Job execution. Reads SSI_JOB__* env vars
    as defaults. Produces evidence package + classification + optional
    core platform integration.
    """
    # --passive flag overrides --scan-type to "passive"
    effective_scan_type = "passive" if passive_only else scan_type

    # Set env vars so the job module picks them up
    os.environ["SSI_JOB__URL"] = url
    os.environ["SSI_JOB__SCAN_TYPE"] = effective_scan_type
    os.environ["SSI_JOB__PUSH_TO_CORE"] = str(push_to_core).lower()
    os.environ["SSI_JOB__TRIGGER_DOSSIER"] = str(trigger_dossier).lower()
    os.environ["SSI_JOB__DATASET"] = dataset

    from ssi.worker.jobs import main

    exit_code = main()

    if exit_code != 0:
        console.print("[red]Job failed.[/red]")
        raise typer.Exit(code=exit_code)

    console.print("[green]Job completed successfully.[/green]")


@job_app.command("batch")
def job_batch(
    manifest: str = typer.Option(
        ...,
        "--manifest",
        "-m",
        help="Path to a JSON manifest (local file or gs:// URI).",
        envvar="SSI_JOB__MANIFEST",
    ),
    scan_type: str = typer.Option(
        "full",
        "--scan-type",
        "-t",
        help="Default scan type for entries without one.",
    ),
    push_to_core: bool = typer.Option(False, "--push-to-core", help="Push results to i4g core platform."),
    trigger_dossier: bool = typer.Option(False, "--trigger-dossier", help="Queue dossier generation in core."),
    dataset: str = typer.Option("ssi", "--dataset", help="Dataset label for the core cases."),
) -> None:
    """Run batch SSI investigations from a JSON manifest.

    Reads a manifest file (local or GCS) containing URLs and processes
    each sequentially. Designed for Cloud Run Job execution or local use.

    Manifest format (JSON array)::

        [{"url": "https://scam1.example.com", "scan_type": "full"},
         {"url": "https://scam2.example.com"}]
    """
    os.environ["SSI_JOB__MANIFEST"] = manifest
    os.environ["SSI_JOB__SCAN_TYPE"] = scan_type
    os.environ["SSI_JOB__PUSH_TO_CORE"] = str(push_to_core).lower()
    os.environ["SSI_JOB__TRIGGER_DOSSIER"] = str(trigger_dossier).lower()
    os.environ["SSI_JOB__DATASET"] = dataset

    from ssi.worker.batch_jobs import main as batch_main

    exit_code = batch_main()

    if exit_code != 0:
        console.print(f"[red]Batch job finished with failures.[/red]")
        raise typer.Exit(code=exit_code)

    console.print("[green]Batch job completed — all URLs succeeded.[/green]")
