"""CLI commands for eCrimeX (eCX) integration.

Provides ad-hoc search commands against the eCX API and Phase 2 submission
management commands.
"""

from __future__ import annotations

import json

import typer
from rich.console import Console
from rich.table import Table

ecx_app = typer.Typer(
    help="eCrimeX integration — search phish, domains, IPs, crypto addresses, and manage submissions."
)
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


# ---------------------------------------------------------------------------
# ssi ecx submit <investigation-id>
# ---------------------------------------------------------------------------


@ecx_app.command("submit")
def submit_investigation(
    investigation_id: str = typer.Argument(..., help="Scan / investigation ID to submit findings from."),
    output_json: bool = typer.Option(False, "--json", "-j", help="Output raw JSON."),
) -> None:
    """Manually trigger eCX submission for a completed investigation.

    Fetches the persisted scan record, reconstructs a minimal result namespace,
    and routes it through the submission governance service.  High-confidence
    indicators are submitted automatically; medium-confidence indicators are
    queued for analyst review.  Results are displayed in a table or as JSON.
    """
    from ssi.ecx.submission import get_submission_service
    from ssi.store import build_scan_store

    service = get_submission_service()
    if service is None:
        console.print(
            "[red]eCX submission is not configured.[/red] "
            "Check SSI_ECX__SUBMISSION_ENABLED and SSI_ECX__SUBMISSION_AGREEMENT_SIGNED."
        )
        raise typer.Exit(code=1)

    store = build_scan_store()
    scan = store.get_scan(investigation_id)
    if scan is None:
        console.print(f"[red]Investigation {investigation_id!r} not found.[/red]")
        raise typer.Exit(code=1)

    # Rebuild a minimal result namespace from stored scan data so submission
    # logic can extract indicators without re-running the investigation.
    from types import SimpleNamespace

    wallets_raw = scan.get("wallets", [])
    wallets = [
        SimpleNamespace(**w) if isinstance(w, dict) else w
        for w in (wallets_raw if isinstance(wallets_raw, list) else [])
    ]
    result = SimpleNamespace(
        url=scan.get("url", ""),
        classification=SimpleNamespace(
            confidence=scan.get("confidence", 0.0),
            scam_type=scan.get("scam_type", "unknown"),
        ),
        taxonomy_result=None,
        brand_impersonation=scan.get("brand_impersonation", ""),
        dns=SimpleNamespace(a=scan.get("dns_a", [])) if scan.get("dns_a") else None,
        wallets=wallets,
        success=scan.get("status") == "completed",
    )

    rows = service.process_investigation(investigation_id, scan.get("case_id"), result)

    if output_json:
        console.print_json(json.dumps(rows, default=str))
        return

    if not rows:
        console.print(f"[yellow]No submittable indicators found for {investigation_id[:12]}…[/yellow]")
        return

    table = Table(title=f"eCX Submission Results — {investigation_id[:12]}…")
    table.add_column("Module")
    table.add_column("Value", max_width=50)
    table.add_column("Confidence", justify="right")
    table.add_column("Status")
    table.add_column("eCX ID", justify="right")
    for r in rows:
        ecx_id = str(r.get("ecx_record_id") or "—")
        table.add_row(
            r.get("ecx_module", ""),
            r.get("submitted_value", "")[:50],
            str(r.get("confidence", 0)),
            r.get("status", ""),
            ecx_id,
        )
    console.print(table)


# ---------------------------------------------------------------------------
# ssi ecx status <investigation-id>
# ---------------------------------------------------------------------------


@ecx_app.command("status")
def submission_status(
    investigation_id: str = typer.Argument(..., help="Scan / investigation ID."),
    output_json: bool = typer.Option(False, "--json", "-j", help="Output raw JSON."),
) -> None:
    """Show eCX submission status for a completed investigation."""
    from ssi.store import build_scan_store

    store = build_scan_store()
    rows = store.list_ecx_submissions(scan_id=investigation_id)

    if output_json:
        console.print_json(json.dumps(rows, default=str))
        return

    if not rows:
        console.print(f"[yellow]No eCX submissions found for investigation {investigation_id}.[/yellow]")
        return

    table = Table(title=f"eCX Submission Status — {investigation_id[:12]}…")
    table.add_column("Submission ID", max_width=12)
    table.add_column("Module")
    table.add_column("Value", max_width=40)
    table.add_column("Confidence", justify="right")
    table.add_column("Status")
    table.add_column("eCX ID", justify="right")
    table.add_column("Error", max_width=30)
    for r in rows:
        ecx_id = str(r.get("ecx_record_id") or "—")
        err = (r.get("error_message") or "")[:30]
        table.add_row(
            r.get("submission_id", "")[:12],
            r.get("ecx_module", ""),
            r.get("submitted_value", "")[:40],
            str(r.get("confidence", 0)),
            r.get("status", ""),
            ecx_id,
            err,
        )
    console.print(table)


# ---------------------------------------------------------------------------
# ssi ecx retract <submission-id>
# ---------------------------------------------------------------------------


@ecx_app.command("retract")
def retract_submission(
    submission_id: str = typer.Argument(..., help="Submission ID (UUID) to retract."),
    analyst: str = typer.Option("cli", "--analyst", "-a", help="Analyst identifier."),
    output_json: bool = typer.Option(False, "--json", "-j", help="Output raw JSON."),
) -> None:
    """Retract a previously submitted eCX record."""
    from ssi.ecx.submission import get_submission_service

    service = get_submission_service()
    if service is None:
        console.print(
            "[red]eCX submission is not configured.[/red] "
            "Check SSI_ECX__SUBMISSION_ENABLED and SSI_ECX__SUBMISSION_AGREEMENT_SIGNED."
        )
        raise typer.Exit(code=1)

    updated = service.retract(submission_id, analyst)
    if updated is None:
        console.print(
            f"[red]Retraction failed for {submission_id!r}.[/red] " "Submission not found or not in 'submitted' status."
        )
        raise typer.Exit(code=1)

    status = updated.get("status", "")
    err = updated.get("error_message") or ""
    if output_json:
        console.print_json(json.dumps(updated, default=str))
        return
    if status == "retracted":
        console.print(f"[green]Submission {submission_id[:12]}… successfully retracted.[/green]")
    else:
        console.print(f"[yellow]Retraction attempted — status: {status}. Error: {err}[/yellow]")


# ---------------------------------------------------------------------------
# ssi ecx submissions
# ---------------------------------------------------------------------------


@ecx_app.command("submissions")
def list_submissions(
    status: str = typer.Option("", "--status", "-s", help="Filter by status (queued, submitted, …)."),
    limit: int = typer.Option(50, "--limit", "-n", help="Maximum results."),
    output_json: bool = typer.Option(False, "--json", "-j", help="Output raw JSON."),
) -> None:
    """List eCX submission records across all investigations."""
    from ssi.store import build_scan_store

    store = build_scan_store()
    rows = store.list_ecx_submissions(status=status or None, limit=limit)

    if output_json:
        console.print_json(json.dumps(rows, default=str))
        return

    if not rows:
        console.print("[yellow]No eCX submission records found.[/yellow]")
        return

    table = Table(title="eCX Submissions")
    table.add_column("Submission ID", max_width=12)
    table.add_column("Module")
    table.add_column("Value", max_width=40)
    table.add_column("Confidence", justify="right")
    table.add_column("Status")
    table.add_column("eCX ID", justify="right")
    for r in rows:
        ecx_id = str(r.get("ecx_record_id") or "—")
        table.add_row(
            r.get("submission_id", "")[:12],
            r.get("ecx_module", ""),
            r.get("submitted_value", "")[:40],
            str(r.get("confidence", 0)),
            r.get("status", ""),
            ecx_id,
        )
    console.print(table)
