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
    passive_only: bool = typer.Option(False, "--passive", help="Run passive recon only."),
    push_to_core: bool = typer.Option(False, "--push-to-core", help="Push results to i4g core platform."),
    trigger_dossier: bool = typer.Option(False, "--trigger-dossier", help="Queue dossier generation in core."),
    dataset: str = typer.Option("ssi", "--dataset", help="Dataset label for the core case."),
) -> None:
    """Run an SSI investigation as a job.

    Designed for Cloud Run Job execution. Reads SSI_JOB__* env vars
    as defaults. Produces evidence package + classification + optional
    core platform integration.
    """
    # Set env vars so the job module picks them up
    os.environ["SSI_JOB__URL"] = url
    os.environ["SSI_JOB__PASSIVE_ONLY"] = str(passive_only).lower()
    os.environ["SSI_JOB__PUSH_TO_CORE"] = str(push_to_core).lower()
    os.environ["SSI_JOB__TRIGGER_DOSSIER"] = str(trigger_dossier).lower()
    os.environ["SSI_JOB__DATASET"] = dataset

    from ssi.worker.jobs import main

    exit_code = main()

    if exit_code != 0:
        console.print("[red]Job failed.[/red]")
        raise typer.Exit(code=exit_code)

    console.print("[green]Job completed successfully.[/green]")
