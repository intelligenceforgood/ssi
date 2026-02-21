"""CLI commands for the wallet extraction pipeline.

Subcommands for validating addresses, inspecting the allowlist,
scanning text for wallets, and exporting wallet data.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

wallet_app = typer.Typer(help="Wallet extraction tools — validate addresses, scan text, manage allowlist, and export.")
console = Console()


# ---------------------------------------------------------------------------
# ssi wallet validate <address>
# ---------------------------------------------------------------------------


@wallet_app.command("validate")
def validate_address(
    address: str = typer.Argument(..., help="Cryptocurrency wallet address to validate."),
) -> None:
    """Validate a wallet address against known blockchain patterns."""
    from ssi.wallet.patterns import WalletValidator

    validator = WalletValidator()
    result = validator.validate(address)
    if result:
        console.print(f"[green]✓[/green] Valid {result.pattern.name} address")
        console.print(f"  Symbol:  {result.symbol}")
        console.print(f"  Pattern: {result.pattern.name}")
        console.print(f"  Address: {result.address}")
    else:
        console.print(f"[red]✗[/red] No known pattern matches this address")
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# ssi wallet scan <file-or-text>
# ---------------------------------------------------------------------------


@wallet_app.command("scan")
def scan_text(
    source: str = typer.Argument(..., help="Text string or path to a file to scan for wallet addresses."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output results as JSON."),
) -> None:
    """Scan text or a file for cryptocurrency wallet addresses."""
    from ssi.wallet.patterns import WalletValidator

    path = Path(source)
    if path.exists() and path.is_file():
        text = path.read_text(encoding="utf-8")
        label = str(path)
    else:
        text = source
        label = "<stdin>"

    validator = WalletValidator()
    results = validator.scan_text(text)

    if json_output:
        data = [{"address": r.address, "symbol": r.symbol, "pattern": r.pattern.name} for r in results]
        console.print_json(json.dumps(data, indent=2))
        return

    if not results:
        console.print(f"No wallet addresses found in {label}")
        return

    table = Table(title=f"Wallet Addresses Found in {label}")
    table.add_column("#", style="dim", width=4)
    table.add_column("Symbol", style="cyan", width=8)
    table.add_column("Network", width=24)
    table.add_column("Address", style="green")

    for i, r in enumerate(results, 1):
        table.add_row(str(i), r.symbol, r.pattern.name, r.address)

    console.print(table)
    console.print(f"\n[bold]{len(results)}[/bold] address(es) found")


# ---------------------------------------------------------------------------
# ssi wallet allowlist
# ---------------------------------------------------------------------------


@wallet_app.command("allowlist")
def show_allowlist(
    path: Optional[Path] = typer.Option(None, "--path", "-p", help="Path to custom allowlist JSON file."),
    json_output: bool = typer.Option(False, "--json", "-j", help="Output as JSON."),
    symbol: Optional[str] = typer.Option(None, "--symbol", "-s", help="Filter to a specific token symbol."),
) -> None:
    """Display the token-network allowlist."""
    from ssi.wallet.allowlist import AllowlistFilter, load_allowlist

    pairs = load_allowlist(path)
    filt = AllowlistFilter(pairs)

    if symbol:
        pairs = filt.networks_for_symbol(symbol)
        if not pairs:
            console.print(f"[yellow]No entries for symbol '{symbol}' in allowlist[/yellow]")
            raise typer.Exit(code=1)

    if json_output:
        data = [{"token_name": p.token_name, "token_symbol": p.token_symbol, "network": p.network, "network_short": p.network_short} for p in pairs]
        console.print_json(json.dumps(data, indent=2))
        return

    table = Table(title=f"Wallet Allowlist ({len(pairs)} pairs)")
    table.add_column("Token", style="cyan", width=14)
    table.add_column("Symbol", style="bold", width=8)
    table.add_column("Network", width=24)
    table.add_column("Short", style="dim", width=8)

    for p in pairs:
        table.add_row(p.token_name, p.token_symbol, p.network, p.network_short)

    console.print(table)


# ---------------------------------------------------------------------------
# ssi wallet export
# ---------------------------------------------------------------------------


@wallet_app.command("export")
def export_wallets(
    input_file: Path = typer.Argument(..., help="Path to a JSON file with wallet entries."),
    output_dir: Path = typer.Option(Path("."), "--output", "-o", help="Output directory."),
    format: str = typer.Option("xlsx", "--format", "-f", help="Export format: xlsx, csv, json, or all."),
    filter_allowlist: bool = typer.Option(True, "--filter/--no-filter", help="Apply allowlist filtering."),
    allowlist_path: Optional[Path] = typer.Option(None, "--allowlist", help="Custom allowlist JSON file."),
) -> None:
    """Export wallet entries from a JSON file to XLSX, CSV, or JSON.

    Input JSON should have an "entries" array of wallet objects with fields:
    site_url, token_label, token_symbol, network_label, network_short,
    wallet_address, run_id.
    """
    from ssi.wallet.allowlist import AllowlistFilter
    from ssi.wallet.export import WalletExporter
    from ssi.wallet.models import WalletEntry

    if not input_file.exists():
        console.print(f"[red]File not found:[/red] {input_file}")
        raise typer.Exit(code=1)

    try:
        raw = json.loads(input_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        console.print(f"[red]Invalid JSON:[/red] {e}")
        raise typer.Exit(code=1)

    raw_entries = raw.get("entries", raw) if isinstance(raw, dict) else raw
    if not isinstance(raw_entries, list):
        console.print("[red]Expected a JSON array or object with 'entries' key[/red]")
        raise typer.Exit(code=1)

    entries = []
    for item in raw_entries:
        try:
            entries.append(WalletEntry(**item))
        except Exception as e:
            console.print(f"[yellow]Skipping invalid entry:[/yellow] {e}")

    if not entries:
        console.print("[yellow]No valid wallet entries found in input[/yellow]")
        raise typer.Exit(code=1)

    filt = None
    if filter_allowlist:
        filt = AllowlistFilter.from_json(allowlist_path) if allowlist_path else AllowlistFilter.default()

    exporter = WalletExporter(allowlist_filter=filt)
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = input_file.stem

    formats = ["xlsx", "csv", "json"] if format == "all" else [format]

    for fmt in formats:
        out_path = output_dir / f"{stem}.{fmt}"
        if fmt == "xlsx":
            stats = exporter.to_xlsx(entries, out_path)
        elif fmt == "csv":
            stats = exporter.to_csv(entries, out_path)
        elif fmt == "json":
            stats = exporter.to_json(entries, out_path)
        else:
            console.print(f"[yellow]Unknown format: {fmt}[/yellow]")
            continue

        console.print(
            f"[green]✓[/green] {fmt.upper()}: {stats['exported']} exported, "
            f"{stats['discarded']} discarded → {stats['path']}"
        )


# ---------------------------------------------------------------------------
# ssi wallet patterns
# ---------------------------------------------------------------------------


@wallet_app.command("patterns")
def show_patterns() -> None:
    """Display all supported wallet address patterns with examples."""
    from ssi.wallet.patterns import WALLET_PATTERNS

    table = Table(title=f"Supported Wallet Patterns ({len(WALLET_PATTERNS)})")
    table.add_column("Symbol", style="cyan", width=8)
    table.add_column("Blockchain", width=26)
    table.add_column("Length", style="dim", width=10)
    table.add_column("Example", style="green", max_width=50, overflow="ellipsis")

    for p in WALLET_PATTERNS:
        length = f"{p.min_length}–{p.max_length}" if p.min_length != p.max_length else str(p.min_length)
        table.add_row(p.symbol, p.name, length, p.example or "—")

    console.print(table)
