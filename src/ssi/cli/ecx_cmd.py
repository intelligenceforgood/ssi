"""CLI commands for eCrimeX (eCX) integration.

Provides ad-hoc search commands against the eCX API.
"""

from __future__ import annotations

import json

import typer
from rich.console import Console
from rich.table import Table

ecx_app = typer.Typer(help="eCrimeX integration — search phish, domains, IPs, and crypto addresses.")
search_app = typer.Typer(help="Search eCrimeX modules.")
ecx_app.add_typer(search_app, name="search")

console = Console()


def _get_client() -> None:
    """Get an ECXClient or exit with an error message."""
    from ssi.osint.ecrimex import _get_client

    client = _get_client()
    if client is None:
        console.print("[red]eCX is not configured.[/red] Set SSI_ECX__ENABLED=true and SSI_ECX__API_KEY.")
        raise typer.Exit(code=1)
    return client


# ---------------------------------------------------------------------------
# ssi ecx search phish <url>
# ---------------------------------------------------------------------------


@search_app.command("phish")
def search_phish(
    url: str = typer.Argument(..., help="URL or URL fragment to search for."),
    limit: int = typer.Option(10, "--limit", "-n", help="Maximum results."),
    output_json: bool = typer.Option(False, "--json", "-j", help="Output raw JSON."),
) -> None:
    """Search eCrimeX phish module for a URL."""
    client = _get_client()
    results = client.search_phish(url, limit=limit)

    if output_json:
        console.print_json(json.dumps([r.model_dump(mode="json") for r in results], default=str))
        return

    if not results:
        console.print(f"No phish records found for [bold]{url}[/bold]")
        return

    table = Table(title=f"eCX Phish Results ({len(results)})")
    table.add_column("ID", style="cyan")
    table.add_column("URL", max_width=60)
    table.add_column("Brand")
    table.add_column("Confidence", justify="right")
    table.add_column("Status")

    for r in results:
        table.add_row(str(r.id), r.url[:60], r.brand, str(r.confidence), r.status)

    console.print(table)


# ---------------------------------------------------------------------------
# ssi ecx search domain <domain>
# ---------------------------------------------------------------------------


@search_app.command("domain")
def search_domain(
    domain: str = typer.Argument(..., help="Domain name to search for."),
    limit: int = typer.Option(10, "--limit", "-n", help="Maximum results."),
    output_json: bool = typer.Option(False, "--json", "-j", help="Output raw JSON."),
) -> None:
    """Search eCrimeX malicious-domain module."""
    client = _get_client()
    results = client.search_domain(domain, limit=limit)

    if output_json:
        console.print_json(json.dumps([r.model_dump(mode="json") for r in results], default=str))
        return

    if not results:
        console.print(f"No malicious domain records found for [bold]{domain}[/bold]")
        return

    table = Table(title=f"eCX Malicious Domain Results ({len(results)})")
    table.add_column("ID", style="cyan")
    table.add_column("Domain")
    table.add_column("Classification")
    table.add_column("Confidence", justify="right")
    table.add_column("Status")

    for r in results:
        table.add_row(str(r.id), r.domain, r.classification, str(r.confidence), r.status)

    console.print(table)


# ---------------------------------------------------------------------------
# ssi ecx search ip <ip>
# ---------------------------------------------------------------------------


@search_app.command("ip")
def search_ip(
    ip: str = typer.Argument(..., help="IP address to search for."),
    limit: int = typer.Option(10, "--limit", "-n", help="Maximum results."),
    output_json: bool = typer.Option(False, "--json", "-j", help="Output raw JSON."),
) -> None:
    """Search eCrimeX malicious-ip module."""
    client = _get_client()
    results = client.search_ip(ip, limit=limit)

    if output_json:
        console.print_json(json.dumps([r.model_dump(mode="json") for r in results], default=str))
        return

    if not results:
        console.print(f"No malicious IP records found for [bold]{ip}[/bold]")
        return

    table = Table(title=f"eCX Malicious IP Results ({len(results)})")
    table.add_column("ID", style="cyan")
    table.add_column("IP")
    table.add_column("Brand")
    table.add_column("Description", max_width=40)
    table.add_column("Confidence", justify="right")

    for r in results:
        table.add_row(str(r.id), r.ip, r.brand, r.description[:40], str(r.confidence))

    console.print(table)


# ---------------------------------------------------------------------------
# ssi ecx search crypto <address>
# ---------------------------------------------------------------------------


@search_app.command("crypto")
def search_crypto(
    address: str = typer.Argument(..., help="Cryptocurrency wallet address to search for."),
    limit: int = typer.Option(10, "--limit", "-n", help="Maximum results."),
    output_json: bool = typer.Option(False, "--json", "-j", help="Output raw JSON."),
) -> None:
    """Search eCrimeX cryptocurrency-addresses module."""
    client = _get_client()
    results = client.search_crypto(address, limit=limit)

    if output_json:
        console.print_json(json.dumps([r.model_dump(mode="json") for r in results], default=str))
        return

    if not results:
        console.print(f"No cryptocurrency records found for [bold]{address}[/bold]")
        return

    table = Table(title=f"eCX Crypto Results ({len(results)})")
    table.add_column("ID", style="cyan")
    table.add_column("Currency")
    table.add_column("Address", max_width=30)
    table.add_column("Crime Category")
    table.add_column("Confidence", justify="right")

    for r in results:
        table.add_row(str(r.id), r.currency, r.address[:30], r.crime_category, str(r.confidence))

    console.print(table)
