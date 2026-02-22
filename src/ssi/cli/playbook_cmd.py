"""CLI commands for playbook management.

Subcommands for listing, inspecting, validating, and testing playbooks
without needing the API server running.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

playbook_app = typer.Typer(help="Manage playbooks — list, show, validate, and test URL matching.")
console = Console()


def _get_playbook_dir() -> Path:
    """Return the resolved playbook directory from settings."""
    from ssi.settings import get_settings

    return Path(get_settings().playbook.playbook_dir)


# ---------------------------------------------------------------------------
# ssi playbook list
# ---------------------------------------------------------------------------


@playbook_app.command("list")
def playbook_list(
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
    directory: Optional[Path] = typer.Option(None, "--dir", "-d", help="Override playbook directory."),
) -> None:
    """List all available playbooks."""
    from ssi.playbook.loader import load_playbooks_from_dir

    pb_dir = directory or _get_playbook_dir()
    playbooks = load_playbooks_from_dir(pb_dir)

    if not playbooks:
        console.print(f"No playbooks found in {pb_dir}")
        return

    if json_output:
        data = [
            {
                "playbook_id": pb.playbook_id,
                "url_pattern": pb.url_pattern,
                "description": pb.description,
                "steps": len(pb.steps),
                "enabled": pb.enabled,
                "version": pb.version,
                "tags": pb.tags,
            }
            for pb in playbooks
        ]
        console.print_json(json.dumps(data, indent=2))
        return

    table = Table(title=f"Playbooks ({pb_dir})")
    table.add_column("ID", style="cyan")
    table.add_column("Pattern", style="dim", max_width=40)
    table.add_column("Steps", justify="right")
    table.add_column("Enabled", justify="center")
    table.add_column("Tags")
    table.add_column("Description", max_width=40)

    for pb in playbooks:
        table.add_row(
            pb.playbook_id,
            pb.url_pattern,
            str(len(pb.steps)),
            "[green]✓[/green]" if pb.enabled else "[red]✗[/red]",
            ", ".join(pb.tags) if pb.tags else "",
            pb.description[:40] if pb.description else "",
        )

    console.print(table)
    console.print(f"\n[bold]{len(playbooks)}[/bold] playbook(s) loaded")


# ---------------------------------------------------------------------------
# ssi playbook show <id>
# ---------------------------------------------------------------------------


@playbook_app.command("show")
def playbook_show(
    playbook_id: str = typer.Argument(..., help="Playbook ID to display."),
    directory: Optional[Path] = typer.Option(None, "--dir", "-d", help="Override playbook directory."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
) -> None:
    """Display full details of a single playbook."""
    from ssi.playbook.loader import load_playbooks_from_dir

    pb_dir = directory or _get_playbook_dir()
    playbooks = load_playbooks_from_dir(pb_dir)
    match = next((pb for pb in playbooks if pb.playbook_id == playbook_id), None)

    if not match:
        console.print(f"[red]Playbook not found:[/red] {playbook_id}")
        available = [pb.playbook_id for pb in playbooks]
        if available:
            console.print(f"  Available: {', '.join(available)}")
        raise typer.Exit(code=1)

    if json_output:
        console.print_json(match.model_dump_json(indent=2))
        return

    console.print(f"[bold cyan]{match.playbook_id}[/bold cyan]  v{match.version}")
    console.print(f"  Pattern:     {match.url_pattern}")
    console.print(f"  Description: {match.description or '(none)'}")
    console.print(f"  Enabled:     {'Yes' if match.enabled else 'No'}")
    console.print(f"  Max time:    {match.max_duration_sec}s")
    if match.tags:
        console.print(f"  Tags:        {', '.join(match.tags)}")
    if match.tested_urls:
        console.print(f"  Tested URLs: {len(match.tested_urls)}")

    console.print(f"\n[bold]Steps ({len(match.steps)}):[/bold]")
    for i, step in enumerate(match.steps, 1):
        retry = f" (retry={step.retry_on_failure})" if step.retry_on_failure else ""
        fallback = " [dim]→ LLM[/dim]" if step.fallback_to_llm else ""
        desc = f" — {step.description}" if step.description else ""
        value_display = f' "{step.value}"' if step.value else ""
        sel_display = f" {step.selector}" if step.selector else ""
        console.print(f"  {i:2d}. [yellow]{step.action.value:8s}[/yellow]{sel_display}{value_display}{desc}{retry}{fallback}")


# ---------------------------------------------------------------------------
# ssi playbook validate
# ---------------------------------------------------------------------------


@playbook_app.command("validate")
def playbook_validate(
    path: Path = typer.Argument(..., help="Path to a playbook JSON file."),
) -> None:
    """Validate a playbook JSON file against the schema."""
    from pydantic import ValidationError

    from ssi.playbook.loader import load_playbook_from_file

    if not path.exists():
        console.print(f"[red]File not found:[/red] {path}")
        raise typer.Exit(code=1)

    try:
        pb = load_playbook_from_file(path)
        console.print(f"[green]✓[/green] Valid playbook: {pb.playbook_id} ({len(pb.steps)} steps)")
    except json.JSONDecodeError as e:
        console.print(f"[red]✗ Invalid JSON:[/red] {e}")
        raise typer.Exit(code=1) from None
    except ValidationError as e:
        console.print(f"[red]✗ Validation errors:[/red]")
        for err in e.errors():
            loc = " → ".join(str(x) for x in err["loc"])
            console.print(f"  {loc}: {err['msg']}")
        raise typer.Exit(code=1) from None


# ---------------------------------------------------------------------------
# ssi playbook test-match <url>
# ---------------------------------------------------------------------------


@playbook_app.command("test-match")
def playbook_test_match(
    url: str = typer.Argument(..., help="URL to test against all registered playbooks."),
    directory: Optional[Path] = typer.Option(None, "--dir", "-d", help="Override playbook directory."),
) -> None:
    """Test which playbook (if any) matches a URL."""
    from ssi.playbook.loader import load_playbooks_from_dir
    from ssi.playbook.matcher import PlaybookMatcher

    pb_dir = directory or _get_playbook_dir()
    playbooks = load_playbooks_from_dir(pb_dir)

    matcher = PlaybookMatcher()
    matcher.register_many(playbooks)

    match = matcher.match(url)
    if match:
        console.print(f"[green]✓ Match:[/green] {match.playbook_id}")
        console.print(f"  Pattern: {match.url_pattern}")
        console.print(f"  Steps:   {len(match.steps)}")
        if match.description:
            console.print(f"  Desc:    {match.description}")
    else:
        console.print(f"[yellow]No playbook matches:[/yellow] {url}")
        console.print(f"  Tested against {len(playbooks)} playbook(s) from {pb_dir}")
