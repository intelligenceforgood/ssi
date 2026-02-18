"""CLI commands for inspecting and validating SSI settings."""

from __future__ import annotations

import json

import typer
from rich.console import Console

settings_app = typer.Typer(help="Inspect and validate SSI configuration.")
console = Console()


@settings_app.command("show")
def show_settings() -> None:
    """Display the currently resolved settings."""
    from ssi.settings import get_settings

    settings = get_settings()
    console.print_json(json.dumps(settings.model_dump(mode="json"), indent=2, default=str))


@settings_app.command("validate")
def validate_settings() -> None:
    """Validate settings and report any issues."""
    from ssi.settings import get_settings

    try:
        settings = get_settings()
        console.print("[green]✓[/green] Settings are valid.")
        console.print(f"  Environment: {settings.env}")
        console.print(f"  LLM provider: {settings.llm.provider}")
        console.print(f"  Evidence dir: {settings.evidence.output_dir}")
    except Exception as e:
        console.print(f"[red]✗[/red] Settings validation failed: {e}")
        raise typer.Exit(code=1)
