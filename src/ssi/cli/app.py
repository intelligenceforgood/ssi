"""Unified CLI entry point for Scam Site Investigator.

Config precedence: settings.default.toml -> settings.local.toml -> env vars (SSI_* with double underscores) -> CLI flags.
"""

from __future__ import annotations

import sys
from pathlib import Path

import typer

from ssi.cli.investigate import investigate_app
from ssi.cli.job import job_app
from ssi.cli.settings_cmd import settings_app

try:
    from importlib.metadata import version

    VERSION = version("ssi")
except Exception:
    VERSION = "unknown"

APP_HELP = (
    "ssi — Scam Site Investigator CLI. "
    "AI-driven reconnaissance of suspicious URLs with evidence packaging. "
    "Config precedence: settings.default.toml -> settings.local.toml -> env vars (SSI_* with __) -> CLI flags."
)

PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

app = typer.Typer(add_completion=True, help=APP_HELP)

app.add_typer(investigate_app, name="investigate")
app.add_typer(job_app, name="job")
app.add_typer(settings_app, name="settings")


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context, version: bool = typer.Option(False, "--version", help="Show version and exit.")) -> None:
    """Show help when no subcommand is provided."""
    if version:
        typer.echo(f"ssi {VERSION}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit()


if __name__ == "__main__":
    app()
